"""Quien pide una accion. La autoridad se decide por actor, no por argumento.

Regla 3: el LLM no tiene autoridad. Aqui eso deja de ser prosa y pasa a ser un
conjunto cerrado que se comprueba con `in`.
"""

from __future__ import annotations

from enum import Enum


class Actor(str, Enum):
    """Origen de una peticion al plano de control."""

    HUMANO = "humano"
    """Un operador. Unica autoridad que puede descongelar la capa de IA."""

    AUTOMATA = "automata"
    """Codigo determinista del propio sistema (dead-man's switch, gates)."""

    IA = "ia"
    """El LLM. Asesor sin manos: propone, nunca ejecuta."""


AUTORIDAD_PARA_CONGELAR = frozenset({Actor.HUMANO, Actor.AUTOMATA})
"""Quien puede congelar la capa de IA.

La IA queda fuera a proposito: dejarla congelar seria regalarle al atacante un
ataque de disponibilidad por inyeccion de prompt. Congelar es seguro para T0/T1
pero apaga la adaptacion, y esa decision no la toma el modelo.
"""

AUTORIDAD_PARA_DESCONGELAR = frozenset({Actor.HUMANO})
"""Quien puede reactivar la capa de IA.

Solo un humano. Ni siquiera el automata: un descongelado automatico convierte el
interruptor de emergencia en un boton que se resetea solo, que es no tenerlo.
"""


class SinAutoridad(PermissionError):
    """Un actor pidio una accion que su rol no permite. No se interpreta la peticion."""

    def __init__(self, actor: Actor, accion: str) -> None:
        self.actor = actor
        self.accion = accion
        super().__init__(f"el actor '{actor.value}' no tiene autoridad para {accion}")
