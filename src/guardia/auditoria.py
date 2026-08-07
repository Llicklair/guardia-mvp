"""El log de auditoria: append-only y encadenado por hash.

Invariante 7 de ARCHITECTURE.md. Un log que el atacante puede reescribir no es un
log, es una coartada. No se puede impedir por software que alguien con root borre
un fichero, asi que aqui no se finge: lo que se garantiza es que **una manipulacion
se nota**. Cada linea encadena el hash de la anterior, asi que alterar o quitar
cualquiera rompe la cadena a partir de ahi y `verificar()` lo dice.

Exportar el log fuera de la maquina sigue siendo necesario y no lo hace este modulo.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
"""Hash previo de la primera entrada. Ancla la cadena."""


def _ahora() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _canonico(payload: dict[str, Any]) -> str:
    """Serializacion estable: el hash no puede depender del orden de las claves."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(previo: str, payload: dict[str, Any]) -> str:
    return hashlib.sha256(f"{previo}{_canonico(payload)}".encode()).hexdigest()


@dataclass(frozen=True)
class Entrada:
    """Una linea del log, ya verificada estructuralmente."""

    seq: int
    ts: str
    evento: str
    actor: str
    datos: dict[str, Any]
    previo: str
    hash: str

    @property
    def payload(self) -> dict[str, Any]:
        """Lo que entra en el hash. El propio hash queda fuera, obviamente."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "evento": self.evento,
            "actor": self.actor,
            "datos": self.datos,
        }


@dataclass(frozen=True)
class Veredicto:
    """Resultado de verificar la cadena entera."""

    intacta: bool
    entradas: int
    rota_en: int | None = None
    motivo: str | None = None


class CadenaRota(Exception):
    """La cadena de hashes no cuadra: hubo manipulacion o truncado."""


class Auditoria:
    """Log append-only encadenado. Una instancia por fichero."""

    def __init__(self, ruta: Path) -> None:
        self.ruta = Path(ruta)
        self.ruta.parent.mkdir(parents=True, exist_ok=True)

    def registrar(self, evento: str, actor: str, **datos: Any) -> Entrada:
        """Anade una entrada y la devuelve. Escribe y sincroniza antes de volver.

        El fsync no es paranoia decorativa: si el evento que se esta registrando es
        "he congelado la capa de IA porque algo va mal", la maquina puede no llegar
        a cerrar el fichero por su cuenta.
        """
        ultima = self._ultima()
        previo = ultima.hash if ultima else GENESIS
        payload = {
            "seq": (ultima.seq + 1) if ultima else 1,
            "ts": _ahora(),
            "evento": evento,
            "actor": actor,
            "datos": datos,
        }
        entrada = Entrada(**payload, previo=previo, hash=_hash(previo, payload))
        linea = _canonico({**payload, "previo": entrada.previo, "hash": entrada.hash})
        with self.ruta.open("a", encoding="utf-8") as f:
            f.write(linea + "\n")
            f.flush()
            os.fsync(f.fileno())
        return entrada

    def leer(self) -> Iterator[Entrada]:
        """Recorre el log. Una linea ilegible es manipulacion, no un despiste."""
        if not self.ruta.exists():
            return
        with self.ruta.open(encoding="utf-8") as f:
            for numero, linea in enumerate(f, start=1):
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    crudo = json.loads(linea)
                    yield Entrada(
                        seq=crudo["seq"],
                        ts=crudo["ts"],
                        evento=crudo["evento"],
                        actor=crudo["actor"],
                        datos=crudo["datos"],
                        previo=crudo["previo"],
                        hash=crudo["hash"],
                    )
                except (json.JSONDecodeError, KeyError, TypeError, RecursionError) as e:
                    # RecursionError incluido: una linea manipulada con JSON anidado
                    # mataba al detector con la pila en vez de dar CadenaRota — el
                    # veredicto de manipulacion debe salir, no una excepcion cruda.
                    raise CadenaRota(f"linea {numero} ilegible: {e}") from e

    def verificar(self) -> Veredicto:
        """Recalcula la cadena entera. Este es el metodo que hace util al modulo."""
        previo = GENESIS
        esperado_seq = 1
        contadas = 0
        try:
            for entrada in self.leer():
                if entrada.seq != esperado_seq:
                    return Veredicto(
                        False, contadas, entrada.seq, f"seq {entrada.seq}, esperaba {esperado_seq}"
                    )
                if entrada.previo != previo:
                    return Veredicto(False, contadas, entrada.seq, "el enlace previo no cuadra")
                if entrada.hash != _hash(previo, entrada.payload):
                    return Veredicto(False, contadas, entrada.seq, "el contenido fue alterado")
                previo = entrada.hash
                esperado_seq += 1
                contadas += 1
        except CadenaRota as e:
            return Veredicto(False, contadas, esperado_seq, str(e))
        return Veredicto(True, contadas)

    def _ultima(self) -> Entrada | None:
        ultima = None
        for entrada in self.leer():
            ultima = entrada
        return ultima
