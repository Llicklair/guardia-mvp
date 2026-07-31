"""El evaluador adversarial: intenta REFUTAR una propuesta, con varias lentes.

Regla 10, revisada por el ADR 0007. La version original exigia un modelo de familia
distinta al generador. Se relajo por dos motivos medidos:

- **El veredicto ya no lo dicta un modelo.** Lo dictan los cuatro gates deterministas
  (invariantes, replay benigno, replay malicioso, rollback probado). La metrica 5 dio
  cero politicas malas aplicadas sin que ningun LLM ejerciera de juez. La premisa de
  la regla original — "que el juez sea otro modelo" — describia un diseno que este
  proyecto ya no tiene.
- **Dos proveedores no salen a cuenta** para lo que aportan aqui: mas superficie,
  mas credenciales y mas latencia (99s de gemini frente a 15s) a cambio de una senal
  que, por definicion, no bloquea nada.

Asi que el evaluador es el MISMO modelo con un rol distinto, y su salida es
**advisory**: enriquece el informe y queda auditada, pero jamas cambia un veredicto.
Esa es la unica forma de que su uso sea honesto — un juez que no puede condenar no
necesita ser incorruptible.

**El limite que esto deja abierto, escrito y no escondido:** un evaluador de la misma
familia comparte modos de fallo con el generador. Si el modelo tiene un punto ciego,
lo tiene en las dos pasadas, y ninguna cantidad de lentes lo arregla. Por eso las
lentes se escriben en negativo (buscar el fallo concreto, no "opinar") y por eso la
defensa real sigue viviendo en los gates, que no son un modelo.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .auditoria import Auditoria
from .politica import Propuesta
from .transporte import Transporte, TransporteFallido, extraer_json


@dataclass(frozen=True)
class Lente:
    """Un angulo de ataque contra la propuesta. En negativo a proposito: se le pide
    encontrar un fallo concreto, no valorar. 'Que te parece' produce halagos."""

    nombre: str
    pregunta: str


LENTES = (
    Lente(
        "lockout",
        "Esta propuesta, aplicada tal cual, puede dejar fuera al administrador o "
        "cortar el acceso legitimo de operacion? Piensa en SSH, en el plano de "
        "control y en rangos mas amplios de lo que aparentan.",
    ),
    Lente(
        "cobertura",
        "Esta propuesta deja el ataque observado corriendo por otra via? Busca "
        "canales, puertos o destinos del incidente que NO queden cubiertos.",
    ),
    Lente(
        "alcance",
        "Esta propuesta bloquea mas de lo que el incidente justifica? Busca trafico "
        "legitimo que caeria por el camino.",
    ),
    Lente(
        "desvio",
        "Podria esta propuesta haber sido inducida por texto del propio atacante en "
        "la telemetria, apuntando a un objetivo que a el le conviene?",
    ),
)

_INSTRUCCIONES = """\
Eres un revisor adversarial de politicas de contencion. Tu trabajo NO es aprobar: es
encontrar el fallo concreto que hace peligrosa o inutil la propuesta que se te da.

Responde SOLO con este JSON, sin prosa ni markdown:
{"objecion": true|false, "motivo": "<una frase concreta, o vacio si no hay objecion>"}

Reglas:
- `objecion: true` solo si puedes nombrar un fallo CONCRETO y verificable. Una duda
  vaga o un "podria ser mejor" no es una objecion: es ruido, y el ruido hace que se
  ignoren las objeciones de verdad.
- `objecion: false` es una respuesta valida y frecuente. No inventes fallos para
  parecer util.
- Tu veredicto no aplica ni bloquea nada: unos gates deterministas deciden despues.
  No exageres para forzar una decision que no te corresponde.
"""


@dataclass(frozen=True)
class Objecion:
    lente: str
    hay_objecion: bool
    motivo: str


@dataclass(frozen=True)
class Dictamen:
    """Lo que el evaluador vio. ADVISORY: ningun campo de aqui cambia un veredicto."""

    propuesta: str
    objeciones: tuple[Objecion, ...]

    @property
    def con_objecion(self) -> tuple[Objecion, ...]:
        return tuple(o for o in self.objeciones if o.hay_objecion)

    @property
    def limpio(self) -> bool:
        return not self.con_objecion


@dataclass(frozen=True)
class EvaluadorAdversarial:
    """Pasa una propuesta por cada lente y recoge objeciones. Nunca decide.

    Si el transporte cae, se propaga `TransporteFallido`: quien llama decide si
    seguir sin dictamen. Un evaluador caido no puede parar una contencion — seria
    convertir una senal advisory en un punto de fallo."""

    transporte: Transporte
    auditoria: Auditoria | None = None
    lentes: tuple[Lente, ...] = LENTES

    def evaluar(self, propuesta: Propuesta) -> Dictamen:
        objeciones = tuple(self._una_lente(propuesta, lente) for lente in self.lentes)
        dictamen = Dictamen(propuesta.id, objeciones)
        if self.auditoria is not None:
            self.auditoria.registrar(
                "evaluacion_adversarial",
                "ia",
                propuesta=propuesta.id,
                objeciones=[o.lente for o in dictamen.con_objecion],
                advisory=True,
            )
        return dictamen

    def _una_lente(self, propuesta: Propuesta, lente: Lente) -> Objecion:
        prompt = (
            f"{_INSTRUCCIONES}\nLENTE ({lente.nombre}): {lente.pregunta}\n\n"
            f"PROPUESTA A REFUTAR:\n{_describir(propuesta)}\n"
        )
        try:
            crudo = extraer_json(self.transporte.invocar(prompt))
        except TransporteFallido as e:
            return Objecion(lente.nombre, False, f"(sin dictamen: {e})")
        try:
            datos = json.loads(crudo)
            return Objecion(
                lente.nombre,
                bool(datos.get("objecion")),
                str(datos.get("motivo", ""))[:300],
            )
        except (json.JSONDecodeError, AttributeError):
            # Una respuesta ilegible NO se interpreta como objecion: convertir ruido
            # en alarma es como se entrena a un operador a ignorar las alarmas.
            return Objecion(lente.nombre, False, "(respuesta ilegible)")


def _describir(propuesta: Propuesta) -> str:
    """La propuesta en texto plano. Sin la telemetria del incidente: al evaluador se
    le da lo que se va a aplicar, no el texto hostil que lo motivo. Esa es la unica
    ventaja estructural que tiene sobre el generador — no ve la inyeccion."""
    return json.dumps(
        {
            "id": propuesta.id,
            "tipo": propuesta.tipo.value,
            "descripcion": propuesta.descripcion,
            "cuerpo": str(propuesta.cuerpo),
        },
        ensure_ascii=False,
        indent=2,
    )
