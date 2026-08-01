"""El canal hacia un modelo. Solo inferencia, nada de herramientas (ADR 0006).

Vive aparte del triaje porque tiene dos consumidores que no se conocen entre si: T2
(propone) y el evaluador adversarial (refuta). Que compartan canal y no rol es justo
el punto — un mismo transporte, lentes distintas.

Las dos condiciones no negociables del canal:

1. **El prompt entra por stdin, nunca por argv.** Lleva telemetria escrita por el
   atacante; por argv acabaria en logs de procesos y en limites de linea de comandos.
2. **La CLI corre sin herramientas.** Un modelo con herramientas seria ejecucion de
   codigo a un prompt inyectado de distancia. Hay un test que vigila los presets.
3. **El modelo esta por encima del suelo de evaluacion.** Todo lo que sale por este
   canal acaba en una medicion (T2 propone, el evaluador refuta, los bancos cuentan),
   y una medicion hecha con un modelo por debajo del suelo no se puede citar. Se
   comprueba al CONSTRUIR el transporte, antes de gastar un token.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol


class TransporteFallido(Exception):
    """El canal no respondio: binario ausente, timeout o salida != 0.

    Es distinto de una respuesta mala. Si el modelo contesta basura, la gramatica la
    descarta y queda auditado; si el canal esta caido, quien llama puede caer al
    camino determinista — el de recuperacion existe justo para esto."""


class Transporte(Protocol):
    """Canal hacia un modelo: recibe el prompt completo y devuelve el texto crudo."""

    def invocar(self, prompt: str) -> str: ...


class ModeloProhibido(ValueError):
    """El comando pide un modelo por debajo del suelo de evaluacion.

    **No hereda de `TransporteFallido` a proposito.** Un canal caido tiene camino de
    recuperacion: el triaje cae al heuristico y lo deja auditado. Si la prohibicion
    viajara por ese camino, pedir un modelo prohibido degradaria en silencio a otra
    cosa y saldria un informe con numeros — la prohibicion no existiria. Un defecto se
    pisa sin querer; una negativa no."""


SUELO_DE_EVALUACION = "opus"
"""El modelo mas debil que se admite. Todo lo que cruza este canal acaba en una
medicion, y una medicion por debajo del suelo no se cita como evidencia."""

# Deny list, y por tanto un SUELO y no un techo: caza los nombres conocidos, no los
# alias que aun no existen. Se compara por subcadena para pillar tambien los ids largos
# ("claude-haiku-4-5-20251001"). Un falso positivo aqui es un rechazo ruidoso; un falso
# negativo seria una medicion invalida presentada como buena. Se falla del lado ruidoso.
MODELOS_BAJO_EL_SUELO: dict[str, str] = {
    "haiku": "prohibido explicitamente para cualquier verificacion o evaluacion",
    "sonnet": f"por debajo del suelo (minimo {SUELO_DE_EVALUACION})",
}


def comprobar_modelo(comando: tuple[str, ...]) -> None:
    """Rechaza un comando que pida un modelo bajo el suelo. Sin bandera que lo pise.

    Que esto sea una excepcion y no un defecto distinto es la regla entera: si cumplirla
    exigiera teclear `--comando-llm ... --model opus`, dependeria de que alguien se
    acuerde. Aqui lo correcto es lo que sale sin escribir nada, y lo prohibido no se
    sobrescribe."""
    for token in comando:
        minuscula = token.lower()
        for nombre, motivo in MODELOS_BAJO_EL_SUELO.items():
            if nombre in minuscula:
                raise ModeloProhibido(
                    f"el comando pide '{nombre}' ({token!r}): {motivo}. "
                    f"El suelo de evaluacion es '{SUELO_DE_EVALUACION}'; lo medido por "
                    f"debajo no se cita como evidencia. Cambia el modelo del comando."
                )


# Presets de solo-inferencia. Sin --bare en claude a proposito: ese modo solo autentica
# por ANTHROPIC_API_KEY y rompe la sesion OAuth de la suscripcion (medido, no supuesto).
#
# El preset de claude fijaba haiku, que esta prohibido: el camino barato era el invalido
# y cumplir la norma exigia acordarse de una bandera. Ahora el preset ya nace sobre el
# suelo y hay un test que lo vigila.
#
# La garantia de gemini es MAS DEBIL que la de claude: plan es "solo lectura", no "sin
# herramientas" (y --skip-trust hace falta porque sin trust el modo plan se degrada a
# default y el proceso headless muere). Se mantiene como transporte alternativo
# disponible y medido, NO como el evaluador adversarial: ese rol dejo de exigir una
# familia distinta en el ADR 0007.
COMANDOS_CLI: dict[str, tuple[str, ...]] = {
    "claude": ("claude", "-p", "--tools", "", "--model", "opus"),
    "gemini": ("gemini", "--skip-trust", "--approval-mode", "plan", "-p", ""),
}


@dataclass(frozen=True)
class TransporteCLI:
    """Habla con el modelo a traves de su CLI oficial, por stdin.

    Por que CLI y no API directa: el transporte queda intercambiable (claude, gemini,
    un modelo local manana) y la autenticacion vive en la CLI, no en este codigo."""

    comando: tuple[str, ...]
    timeout_s: float = 240.0

    def __post_init__(self) -> None:
        # Al construir, no al invocar: el rechazo llega antes de gastar un token, y
        # antes de que un banco haya empezado a acumular resultados que habria que tirar.
        comprobar_modelo(self.comando)

    def invocar(self, prompt: str) -> str:
        ejecutable = shutil.which(self.comando[0])
        if ejecutable is None:
            raise TransporteFallido(f"'{self.comando[0]}' no esta en el PATH")
        try:
            resultado = subprocess.run(
                (ejecutable, *self.comando[1:]),
                input=prompt,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired as e:
            raise TransporteFallido(f"'{self.comando[0]}' agoto {self.timeout_s}s") from e
        if resultado.returncode != 0:
            detalle = (resultado.stderr or resultado.stdout or "").strip()[:200]
            raise TransporteFallido(
                f"'{self.comando[0]}' salio con {resultado.returncode}: {detalle}"
            )
        return resultado.stdout


def extraer_json(texto: str) -> str:
    """Recorta el primer objeto JSON completo de la respuesta del modelo.

    Los modelos envuelven el JSON en prosa o vallas de markdown aunque se les pida que
    no. Recortar NO es interpretar: el objeto extraido pasa entero por la validacion
    que corresponda, que sigue descartando cualquier desviacion. Si no hay ningun
    objeto, se devuelve el texto tal cual para que la validacion lo rechace y el
    descarte quede auditado."""
    decodificador = json.JSONDecoder()
    for i, caracter in enumerate(texto):
        if caracter == "{":
            try:
                objeto, _ = decodificador.raw_decode(texto[i:])
            except json.JSONDecodeError:
                continue
            if isinstance(objeto, dict):
                return json.dumps(objeto)
    return texto
