"""El interruptor de emergencia. Regla 8: se construye antes que nada que escriba.

Congela la capa de IA y fija la politica en el ultimo estado bueno conocido. Es
determinista, no consulta a ningun modelo, y la IA no puede invocarlo ni
desactivarlo (regla 3, via `actores`).

Dos decisiones que parecen detalles y no lo son:

- **Fail-closed.** Sin fichero de estado legible, la capa de IA esta congelada. Un
  despliegue nuevo nace sin capacidad de escritura y hay que armarla a mano. Esto
  no afecta a T0/T1: la regla 2 dice que siguen protegiendo igual, y siguen.
- **Sin cache.** `estado()` lee el disco en cada llamada. Un proceso que cachea el
  estado no se entera de que lo acaban de congelar, y entonces el interruptor solo
  funciona para procesos que aun no han arrancado, que es cuando menos hace falta.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .actores import (
    AUTORIDAD_PARA_CONGELAR,
    AUTORIDAD_PARA_DESCONGELAR,
    Actor,
    SinAutoridad,
)
from .auditoria import Auditoria

NOMBRE_ESTADO = "estado.json"
NOMBRE_AUDITORIA = "auditoria.jsonl"


def _ahora() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Estado:
    """Estado de la capa de IA, tal y como esta en disco ahora mismo."""

    congelado: bool
    motivo: str
    desde: str
    actor: str

    @property
    def operativo(self) -> bool:
        return not self.congelado


class CapaCongelada(RuntimeError):
    """Se intento aplicar politica con la capa de IA congelada. Nunca es recuperable
    desde dentro: lo tiene que descongelar un humano."""

    def __init__(self, estado: Estado) -> None:
        self.estado = estado
        super().__init__(
            f"capa de IA congelada desde {estado.desde} por {estado.actor}: {estado.motivo}"
        )


class ControlInvalido(ValueError):
    """La ruta de control no puede ser un directorio (existe como fichero, el padre es
    un fichero, o no hay permisos). No es fail-closed —eso es 'estado ilegible' y
    congela— es 'no hay donde mirar el estado': quien dio la ruta puede corregirla.
    Error de dominio a proposito: `mkdir(exist_ok=True)` solo tolera directorios, y un
    `--control fichero.json` tecleado por error salia como traceback crudo."""


class Interruptor:
    """El interruptor de emergencia sobre un directorio de control."""

    def __init__(self, directorio: Path | str | None = None) -> None:
        self.directorio = Path(directorio or directorio_por_defecto())
        try:
            self.directorio.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise ControlInvalido(
                f"el directorio de control '{self.directorio}' no se puede usar: {e}"
            ) from e
        self.ruta_estado = self.directorio / NOMBRE_ESTADO
        self.auditoria = Auditoria(self.directorio / NOMBRE_AUDITORIA)

    def estado(self) -> Estado:
        """Lee el estado del disco. Sin fichero o con fichero corrupto: congelado."""
        try:
            crudo = json.loads(self.ruta_estado.read_text(encoding="utf-8"))
            return Estado(
                congelado=bool(crudo["congelado"]),
                motivo=str(crudo["motivo"]),
                desde=str(crudo["desde"]),
                actor=str(crudo["actor"]),
            )
        except FileNotFoundError:
            return Estado(True, "sin estado en disco: la capa nace congelada", "nunca", "sistema")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError, OSError) as e:
            return Estado(True, f"estado ilegible ({e}): fail-closed", "desconocido", "sistema")

    def congelar(self, actor: Actor, motivo: str) -> Estado:
        """Congela la capa de IA. Idempotente: congelar lo congelado no es un error."""
        if actor not in AUTORIDAD_PARA_CONGELAR:
            self.auditoria.registrar(
                "congelar_denegado", actor.value, motivo=motivo, razon="sin autoridad"
            )
            raise SinAutoridad(actor, "congelar la capa de IA")
        estado = Estado(True, motivo, _ahora(), actor.value)
        self._escribir(estado)
        self.auditoria.registrar("congelado", actor.value, motivo=motivo)
        return estado

    def descongelar(self, actor: Actor, motivo: str) -> Estado:
        """Reactiva la capa de IA. Solo un humano, y queda registrado quien fue."""
        if actor not in AUTORIDAD_PARA_DESCONGELAR:
            self.auditoria.registrar(
                "descongelar_denegado", actor.value, motivo=motivo, razon="sin autoridad"
            )
            raise SinAutoridad(actor, "descongelar la capa de IA")
        estado = Estado(False, motivo, _ahora(), actor.value)
        self._escribir(estado)
        self.auditoria.registrar("descongelado", actor.value, motivo=motivo)
        return estado

    def exigir_operativo(self) -> Estado:
        """Puerta obligatoria antes de aplicar cualquier politica. Lee disco, no cache."""
        estado = self.estado()
        if estado.congelado:
            raise CapaCongelada(estado)
        return estado

    def _escribir(self, estado: Estado) -> None:
        """Escritura atomica: un corte a medias dejaria el estado ilegible, y aunque
        eso es fail-closed y por tanto seguro, tambien seria un auto-DoS gratis."""
        payload = {
            "congelado": estado.congelado,
            "motivo": estado.motivo,
            "desde": estado.desde,
            "actor": estado.actor,
        }
        temporal = self.ruta_estado.with_suffix(".tmp")
        with temporal.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        temporal.replace(self.ruta_estado)


def directorio_por_defecto() -> Path:
    """Donde vive el estado de control.

    `GUARDIA_CONTROL_DIR` manda. En Linux, el sitio de un demonio con estado; en
    Windows (desarrollo) bajo LOCALAPPDATA. El proceso de IA no debe tener permiso
    de escritura aqui — regla 5.3, y en el MVP se comprueba en el laboratorio.
    """
    if entorno := os.environ.get("GUARDIA_CONTROL_DIR"):
        return Path(entorno)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA", str(Path.home()))
        return Path(base) / "guardia"
    return Path("/var/lib/guardia")
