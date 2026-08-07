"""Telemetria normalizada: los eventos contra los que se replaya una propuesta.

Regla 4: todo esto es dato hostil. Nombres de proceso, IPs, rutas y cmdline los
controla el atacante. Aqui se parsea a una forma cerrada y se trunca; nada de esto
es una instruccion, y ningun campo se ejecuta.

Un corpus es un JSONL: una linea por evento. El benigno es actividad normal grabada;
el de incidente es el repro de un ataque. Los gates de replay (crisol) corren la
propuesta contra ambos.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, ip_address
from pathlib import Path
from typing import Any

from .json_hostil import demasiado_anidado

_MAX = 512


class TipoEvento(str, Enum):
    PROCESO = "proceso"
    RED = "red"
    FICHERO = "fichero"


class EventoInvalido(ValueError):
    """Una linea del corpus no encaja. El corpus es dato: una linea mala se salta con
    aviso, no tumba el replay — pero el campo obligatorio ausente si es un error."""


class CorpusIlegible(Exception):
    """No se pudo leer el corpus entero: no existe, no es un fichero, no hay permiso
    o los bytes no son UTF-8.

    Es distinto de `EventoInvalido` a proposito: una linea mala se salta con constancia
    (el corpus es dato hostil y se sigue midiendo), pero si no hay corpus no hay nada
    que medir y hay que decirlo. Existe para cumplir la propiedad de frontera que ya
    vale en la gramatica: **toda ruta produce un Corpus o un error de dominio, nunca
    una excepcion cruda de sistema.** Sin ella, un `--incidente` mal tecleado salia por
    la CLI como un traceback de pathlib."""


def _texto(crudo: dict[str, Any], clave: str, *, obligatorio: bool = True) -> str:
    valor = crudo.get(clave)
    if valor is None and not obligatorio:
        return ""
    if not isinstance(valor, str) or (obligatorio and not valor.strip()):
        raise EventoInvalido(f"'{clave}' debe ser texto")
    return valor[:_MAX]


@dataclass(frozen=True)
class EventoProceso:
    """Un proceso que arranca. `ancestros` va del padre hacia arriba: [pname, abuelo…].

    Que sea una lista y no solo el padre es deliberado — es el hallazgo del laboratorio
    (aname vs pname): la shell inversa cuelga de python via sh y bash intermedios."""

    nombre: str
    ancestros: tuple[str, ...]
    cmdline: str = ""
    abre_conexion_saliente: bool = False
    etiqueta: str = ""


@dataclass(frozen=True)
class EventoRed:
    direccion: str  # "entrada" | "salida"
    puerto: int
    ip: IPv4Address
    etiqueta: str = ""


@dataclass(frozen=True)
class EventoFichero:
    ruta: str
    syscall: str
    etiqueta: str = ""


Evento = EventoProceso | EventoRed | EventoFichero


def _proceso(crudo: dict[str, Any]) -> EventoProceso:
    ancestros = crudo.get("ancestros", [])
    if not isinstance(ancestros, list) or any(not isinstance(a, str) for a in ancestros):
        raise EventoInvalido("'ancestros' debe ser una lista de textos")
    return EventoProceso(
        nombre=_texto(crudo, "nombre"),
        ancestros=tuple(a[:_MAX] for a in ancestros[:32]),
        cmdline=_texto(crudo, "cmdline", obligatorio=False),
        abre_conexion_saliente=bool(crudo.get("abre_conexion_saliente", False)),
        etiqueta=_texto(crudo, "etiqueta", obligatorio=False),
    )


def _red(crudo: dict[str, Any]) -> EventoRed:
    direccion = _texto(crudo, "direccion")
    if direccion not in ("entrada", "salida"):
        raise EventoInvalido("'direccion' debe ser 'entrada' o 'salida'")
    puerto = crudo.get("puerto")
    if isinstance(puerto, bool) or not isinstance(puerto, int) or not 0 < puerto < 65536:
        raise EventoInvalido(f"puerto invalido: {puerto!r}")
    try:
        ip = ip_address(crudo.get("ip", ""))
    except ValueError as e:
        raise EventoInvalido(f"ip invalida: {crudo.get('ip')!r}") from e
    if not isinstance(ip, IPv4Address):
        raise EventoInvalido("solo IPv4 en el MVP")
    return EventoRed(direccion, puerto, ip, _texto(crudo, "etiqueta", obligatorio=False))


def _fichero(crudo: dict[str, Any]) -> EventoFichero:
    return EventoFichero(
        ruta=_texto(crudo, "ruta"),
        syscall=_texto(crudo, "syscall"),
        etiqueta=_texto(crudo, "etiqueta", obligatorio=False),
    )


_PARSERS = {
    TipoEvento.PROCESO: _proceso,
    TipoEvento.RED: _red,
    TipoEvento.FICHERO: _fichero,
}


def desde_dict(crudo: Any) -> Evento:
    if not isinstance(crudo, dict):
        raise EventoInvalido("el evento debe ser un objeto")
    try:
        tipo = TipoEvento(crudo.get("tipo"))
    except ValueError as e:
        raise EventoInvalido(f"tipo de evento desconocido: {crudo.get('tipo')!r}") from e
    return _PARSERS[tipo](crudo)


@dataclass(frozen=True)
class Corpus:
    """Un corpus grabado, ya parseado. `saltadas` guarda las lineas malas: el corpus
    es dato hostil, una linea corrupta se salta con constancia, no se finge que no
    estaba."""

    nombre: str
    eventos: tuple[Evento, ...]
    saltadas: tuple[str, ...] = field(default_factory=tuple)

    def __len__(self) -> int:
        return len(self.eventos)


def cargar(ruta: Path | str, nombre: str = "") -> Corpus:
    """Lee un JSONL de eventos. Lineas vacias se ignoran; lineas ilegibles se saltan
    con constancia en `saltadas`.

    Si el corpus entero no se puede leer, `CorpusIlegible` — nunca un OSError crudo:
    el llamante decide que hacer con un corpus que falta, pero no deberia tener que
    conocer las excepciones de pathlib para hacerlo."""
    ruta = Path(ruta)
    try:
        texto = ruta.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        # UnicodeDecodeError no es OSError y el corpus es dato hostil: unos bytes
        # invalidos bastarian para tumbar el ciclo si no se atajara aqui.
        raise CorpusIlegible(f"no se puede leer el corpus '{ruta}': {e}") from e
    eventos: list[Evento] = []
    saltadas: list[str] = []
    for numero, linea in enumerate(texto.splitlines(), start=1):
        if not linea.strip():
            continue
        try:
            if demasiado_anidado(linea):
                # El anidado hostil revienta la pila DENTRO de json.loads y el
                # RecursionError se saltaria el contrato de este bucle (linea mala
                # -> saltada con constancia, nunca una excepcion que tumbe el ciclo).
                raise EventoInvalido("JSON demasiado anidado")
            eventos.append(desde_dict(json.loads(linea)))
        except (json.JSONDecodeError, EventoInvalido) as e:
            saltadas.append(f"linea {numero}: {e}")
        except RecursionError:
            # Segunda linea, como en politica: si el escaner juzgara mal una entrada,
            # la propiedad se mantiene.
            saltadas.append(f"linea {numero}: JSON demasiado anidado")
    return Corpus(nombre or ruta.stem, tuple(eventos), tuple(saltadas))
