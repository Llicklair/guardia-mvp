"""La gramatica cerrada de propuestas. Regla 3: lo que no encaja se descarta.

El LLM emite JSON. Este modulo lo parsea contra un conjunto cerrado de formas y
valores. No hay campo libre que llegue a ejecutarse, no hay `eval`, no hay plantilla
que se rellene con texto del modelo sin pasar por aqui.

La regla practica: si una propuesta no encaja, **no se interpreta ni se intenta
arreglar**. Un validador que "entiende lo que el modelo queria decir" es una
superficie de ataque con forma de amabilidad.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Network, ip_network
from typing import Any


class TipoPolitica(str, Enum):
    """Que clase de artefacto declarativo propone la IA. Conjunto cerrado."""

    REGLA_DETECCION = "regla_deteccion"
    FILTRO_RED = "filtro_red"
    CONFINAMIENTO = "confinamiento"


class Accion(str, Enum):
    BLOQUEAR = "bloquear"
    PERMITIR = "permitir"
    DETECTAR = "detectar"


class Direccion(str, Enum):
    ENTRADA = "entrada"
    SALIDA = "salida"


class Motor(str, Enum):
    FALCO = "falco"
    SIGMA = "sigma"


class PropuestaInvalida(ValueError):
    """La propuesta no encaja en la gramatica. Se descarta sin interpretarse."""


@dataclass(frozen=True)
class FiltroRed:
    accion: Accion
    direccion: Direccion
    puertos: tuple[int, ...]
    cidr: IPv4Network

    def afecta_a(self, otra: IPv4Network) -> bool:
        return self.cidr.overlaps(otra)


@dataclass(frozen=True)
class Confinamiento:
    perfil: str
    rutas_denegadas: tuple[str, ...] = ()
    syscalls_denegadas: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReglaDeteccion:
    motor: Motor
    condicion: str
    salida: str


@dataclass(frozen=True)
class Propuesta:
    """Una propuesta ya validada estructuralmente. Validada != aprobada: todavia le
    faltan los invariantes (regla 7) y los cuatro gates (regla 6)."""

    id: str
    tipo: TipoPolitica
    descripcion: str
    cuerpo: FiltroRed | Confinamiento | ReglaDeteccion
    incidente: str = ""
    origen: str = "ia"
    etiquetas: tuple[str, ...] = field(default_factory=tuple)


_MAX_TEXTO = 512
_MAX_LISTA = 64


def _texto(crudo: dict[str, Any], clave: str, *, obligatorio: bool = True) -> str:
    valor = crudo.get(clave)
    if valor is None and not obligatorio:
        return ""
    if not isinstance(valor, str) or not valor.strip():
        raise PropuestaInvalida(f"'{clave}' debe ser un texto no vacio")
    if len(valor) > _MAX_TEXTO:
        raise PropuestaInvalida(f"'{clave}' excede {_MAX_TEXTO} caracteres")
    return valor.strip()


def _lista_texto(crudo: dict[str, Any], clave: str) -> tuple[str, ...]:
    valor = crudo.get(clave, [])
    if not isinstance(valor, list):
        raise PropuestaInvalida(f"'{clave}' debe ser una lista")
    if len(valor) > _MAX_LISTA:
        raise PropuestaInvalida(f"'{clave}' excede {_MAX_LISTA} elementos")
    for elemento in valor:
        if not isinstance(elemento, str) or not elemento.strip():
            raise PropuestaInvalida(f"'{clave}' solo admite textos no vacios")
        if len(elemento) > _MAX_TEXTO:
            raise PropuestaInvalida(f"un elemento de '{clave}' excede {_MAX_TEXTO} caracteres")
    return tuple(e.strip() for e in valor)


def _enum(tipo: type[Enum], crudo: dict[str, Any], clave: str) -> Any:
    valor = crudo.get(clave)
    try:
        return tipo(valor)
    except ValueError as e:
        admitidos = ", ".join(m.value for m in tipo)
        raise PropuestaInvalida(f"'{clave}'={valor!r} no esta en [{admitidos}]") from e


def _puertos(crudo: dict[str, Any]) -> tuple[int, ...]:
    valor = crudo.get("puertos", [])
    if not isinstance(valor, list) or not valor:
        raise PropuestaInvalida("'puertos' debe ser una lista no vacia")
    if len(valor) > _MAX_LISTA:
        raise PropuestaInvalida(f"'puertos' excede {_MAX_LISTA} elementos")
    puertos = []
    for p in valor:
        # bool es subclase de int en Python y True colaria como puerto 1.
        if isinstance(p, bool) or not isinstance(p, int) or not 0 < p < 65536:
            raise PropuestaInvalida(f"puerto invalido: {p!r}")
        puertos.append(p)
    return tuple(puertos)


def _cidr(crudo: dict[str, Any]) -> IPv4Network:
    valor = crudo.get("cidr")
    if not isinstance(valor, str):
        raise PropuestaInvalida("'cidr' debe ser un texto")
    try:
        red = ip_network(valor, strict=False)
    except ValueError as e:
        raise PropuestaInvalida(f"cidr invalido: {valor!r}") from e
    if not isinstance(red, IPv4Network):
        raise PropuestaInvalida("solo se admite IPv4 en el MVP")
    return red


Cuerpo = FiltroRed | Confinamiento | ReglaDeteccion


def _cuerpo(tipo: TipoPolitica, crudo: dict[str, Any]) -> Cuerpo:
    if tipo is TipoPolitica.FILTRO_RED:
        return FiltroRed(
            accion=_enum(Accion, crudo, "accion"),
            direccion=_enum(Direccion, crudo, "direccion"),
            puertos=_puertos(crudo),
            cidr=_cidr(crudo),
        )
    if tipo is TipoPolitica.CONFINAMIENTO:
        return Confinamiento(
            perfil=_texto(crudo, "perfil"),
            rutas_denegadas=_lista_texto(crudo, "rutas_denegadas"),
            syscalls_denegadas=_lista_texto(crudo, "syscalls_denegadas"),
        )
    return ReglaDeteccion(
        motor=_enum(Motor, crudo, "motor"),
        condicion=_texto(crudo, "condicion"),
        salida=_texto(crudo, "salida"),
    )


def desde_dict(crudo: Any) -> Propuesta:
    """Valida un dict contra la gramatica. Cualquier desviacion es PropuestaInvalida."""
    if not isinstance(crudo, dict):
        raise PropuestaInvalida("la propuesta debe ser un objeto JSON")
    cuerpo_crudo = crudo.get("cuerpo")
    if not isinstance(cuerpo_crudo, dict):
        raise PropuestaInvalida("'cuerpo' debe ser un objeto")
    tipo = _enum(TipoPolitica, crudo, "tipo")
    return Propuesta(
        id=_texto(crudo, "id"),
        tipo=tipo,
        descripcion=_texto(crudo, "descripcion"),
        cuerpo=_cuerpo(tipo, cuerpo_crudo),
        incidente=_texto(crudo, "incidente", obligatorio=False),
        origen=_texto(crudo, "origen", obligatorio=False) or "ia",
        etiquetas=_lista_texto(crudo, "etiquetas"),
    )


def desde_json(texto: str) -> Propuesta:
    """Punto de entrada para la salida cruda del LLM. Texto hostil por defecto."""
    if len(texto) > 64_000:
        raise PropuestaInvalida("la propuesta excede el tamano maximo")
    try:
        return desde_dict(json.loads(texto))
    except json.JSONDecodeError as e:
        raise PropuestaInvalida(f"no es JSON valido: {e}") from e
