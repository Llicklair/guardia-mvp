"""El estado de politica activa, versionado, con rollback que se ejecuta de verdad.

Gate 4 de la regla 6: un cambio sin rollback probado NO se aplica. Aqui "probado" no
es documentado: `aplicar()` guarda el estado anterior, y la forja ejecuta el rollback
en el sandbox y comprueba por hash que el estado vuelve exacto. Un rollback que no se
ejecuta es una promesa, y este proyecto no aplica promesas.

El estado activo es la lista ordenada de propuestas aplicadas, serializada de forma
canonica para que su hash sea estable. En el MVP vive en un fichero; en produccion
seria lo que se empuja a Falco/nftables, pero la mecanica de guardar-aplicar-revertir
-verificar es la misma.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .politica import Propuesta


def _serializar(propuesta: Propuesta) -> dict:
    """La forma canonica de una propuesta aplicada. Solo lo que define la politica —
    no la descripcion en prosa, que es dato del modelo y no debe entrar en el estado."""
    cuerpo = propuesta.cuerpo
    return {
        "id": propuesta.id,
        "tipo": propuesta.tipo.value,
        "cuerpo": {k: _valor(v) for k, v in sorted(vars(cuerpo).items())},
    }


def _valor(v):
    if isinstance(v, tuple):
        return list(v)
    if hasattr(v, "value"):  # Enum
        return v.value
    return str(v) if not isinstance(v, str | int | bool) else v


@dataclass(frozen=True)
class Punto:
    """Un punto de restauracion: el hash del estado antes de aplicar algo. La forja lo
    usa para probar que el rollback restaura exactamente este estado."""

    hash_previo: str
    n_previo: int


class Aplicador:
    """La politica activa sobre un fichero. Serie ordenada de propuestas."""

    def __init__(self, ruta: Path | str) -> None:
        self.ruta = Path(ruta)
        self.ruta.parent.mkdir(parents=True, exist_ok=True)

    def activas(self) -> list[dict]:
        if not self.ruta.exists():
            return []
        return json.loads(self.ruta.read_text(encoding="utf-8"))

    def hash_actual(self) -> str:
        return self._hash(self.activas())

    def aplicar(self, propuesta: Propuesta) -> Punto:
        """Aplica una propuesta y devuelve el punto de restauracion previo. Idempotente
        por id: reaplicar el mismo id reemplaza, no duplica."""
        actuales = self.activas()
        punto = Punto(self._hash(actuales), len(actuales))
        actuales = [p for p in actuales if p["id"] != propuesta.id]
        actuales.append(_serializar(propuesta))
        self._escribir(actuales)
        return punto

    def revertir(self, punto: Punto, propuesta_id: str) -> None:
        """Deshace `aplicar`: quita la propuesta por id. El punto sirve para verificar.

        Toma el id, no el objeto: al revertir un canary por dead-man ya no tenemos la
        propuesta original, solo su id guardado en disco — y es lo unico que hace falta.
        """
        actuales = [p for p in self.activas() if p["id"] != propuesta_id]
        self._escribir(actuales)

    def restaura_a(self, punto: Punto) -> bool:
        """¿El estado actual coincide con el punto guardado? El corazon del gate 4."""
        return self.hash_actual() == punto.hash_previo

    def _hash(self, activas: list[dict]) -> str:
        # Ordenado por id: el estado activo es un conjunto identificado por id (aplicar
        # y revertir ya operan por id), no una secuencia. Asi dos caminos de aplicacion
        # que dejan el mismo conjunto de reglas dan el mismo hash, que es lo que hace
        # comparables los estados y verificable el rollback.
        ordenadas = sorted(activas, key=lambda p: p["id"])
        canonico = json.dumps(ordenadas, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonico.encode()).hexdigest()

    def _escribir(self, activas: list[dict]) -> None:
        temporal = self.ruta.with_suffix(".tmp")
        with temporal.open("w", encoding="utf-8") as f:
            json.dump(activas, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        temporal.replace(self.ruta)
