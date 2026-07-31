"""El canal hacia un modelo. Solo inferencia, nada de herramientas (ADR 0006).

Vive aparte del triaje porque tiene dos consumidores que no se conocen entre si: T2
(propone) y el evaluador adversarial (refuta). Que compartan canal y no rol es justo
el punto — un mismo transporte, lentes distintas.

Las dos condiciones no negociables del canal:

1. **El prompt entra por stdin, nunca por argv.** Lleva telemetria escrita por el
   atacante; por argv acabaria en logs de procesos y en limites de linea de comandos.
2. **La CLI corre sin herramientas.** Un modelo con herramientas seria ejecucion de
   codigo a un prompt inyectado de distancia. Hay un test que vigila los presets.
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


# Presets de solo-inferencia. Sin --bare en claude a proposito: ese modo solo autentica
# por ANTHROPIC_API_KEY y rompe la sesion OAuth de la suscripcion (medido, no supuesto).
#
# La garantia de gemini es MAS DEBIL que la de claude: plan es "solo lectura", no "sin
# herramientas" (y --skip-trust hace falta porque sin trust el modo plan se degrada a
# default y el proceso headless muere). Se mantiene como transporte alternativo
# disponible y medido, NO como el evaluador adversarial: ese rol dejo de exigir una
# familia distinta en el ADR 0007.
COMANDOS_CLI: dict[str, tuple[str, ...]] = {
    "claude": ("claude", "-p", "--tools", "", "--model", "haiku"),
    "gemini": ("gemini", "--skip-trust", "--approval-mode", "plan", "-p", ""),
}


@dataclass(frozen=True)
class TransporteCLI:
    """Habla con el modelo a traves de su CLI oficial, por stdin.

    Por que CLI y no API directa: el transporte queda intercambiable (claude, gemini,
    un modelo local manana) y la autenticacion vive en la CLI, no en este codigo."""

    comando: tuple[str, ...]
    timeout_s: float = 240.0

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
