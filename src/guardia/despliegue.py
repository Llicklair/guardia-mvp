"""La aplicacion real: canary, dead-man's switch y limite de tasa. Cierra T3.

Aqui es donde un veredicto PASS se convierte en un cambio aplicado a produccion. Y
donde vive la mitigacion de §5.5, que ARQUITECTURA marca como el modo de fallo MAS
probable de todo el sistema: una IA con permiso para escribir reglas se hace un
ataque de disponibilidad a si misma. Tres frenos, todos deterministas:

- **Canary.** Nada se despliega global de golpe. Un cambio se aplica "en observacion"
  con un plazo; solo un humano lo confirma como estable. Sin flota que dividir, el
  canary del MVP es TEMPORAL (observar N segundos) y no espacial (un subconjunto de
  hosts) — dicho de frente, es la mecanica aplicar→observar→confirmar/revertir, no el
  reparto por hosts, que llega con la flota.
- **Dead-man's switch.** Si nadie confirma antes del plazo, se revierte SOLO. Un cambio
  que deja fuera al admin se deshace aunque el admin no pueda entrar a deshacerlo — que
  es justo cuando no puede.
- **Limite de tasa.** Un tope de cambios aplicados por ventana. Pasado el tope, el
  cambio se rechaza aunque supere los gates: es el freno contra el auto-DoS por goteo.

El reloj se inyecta (`ahora`) para que el plazo y la ventana se prueben sin dormir.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .actores import AUTORIDAD_PARA_DESCONGELAR, Actor, SinAutoridad
from .aplicador import Aplicador, Punto
from .forja import Forja, Veredicto
from .politica import Propuesta

NOMBRE_ESTADO = "despliegue.json"
NOMBRE_PRODUCCION = "politica-activa.json"


class Estado(str, Enum):
    APLICADO_CANARY = "aplicado_canary"
    RECHAZADO_GATE = "rechazado_gate"
    RECHAZADO_TASA = "rechazado_tasa"


@dataclass(frozen=True)
class Config:
    """Los frenos, fijados en el despliegue (no por peticion de nadie en runtime)."""

    plazo_canary_s: float = 300.0  # 5 min sin confirmar → reversion automatica
    ventana_tasa_s: float = 3600.0  # 1 h
    max_cambios_ventana: int = 5  # mas de esto en la ventana → auto-DoS, se frena


@dataclass(frozen=True)
class Canario:
    """Un cambio aplicado en observacion. Si no se confirma antes de `plazo`, muere."""

    propuesta_id: str
    hash_previo: str
    n_previo: int
    desplegado_en: float
    plazo: float
    confirmado: bool = False

    def expira_en(self, ahora: float) -> bool:
        return not self.confirmado and ahora >= self.plazo

    def como_dict(self) -> dict:
        return {
            "propuesta_id": self.propuesta_id,
            "hash_previo": self.hash_previo,
            "n_previo": self.n_previo,
            "desplegado_en": self.desplegado_en,
            "plazo": self.plazo,
            "confirmado": self.confirmado,
        }


@dataclass(frozen=True)
class Despacho:
    """El resultado de intentar desplegar. `veredicto` viene de la forja si llego a ella."""

    estado: Estado
    propuesta_id: str
    motivo: str
    veredicto: Veredicto | None = None

    @property
    def aplicado(self) -> bool:
        return self.estado is Estado.APLICADO_CANARY


class Despliegue:
    """Aplica propuestas a produccion con canary, dead-man's switch y limite de tasa."""

    def __init__(
        self,
        forja: Forja,
        directorio: Path | str,
        config: Config | None = None,
        ahora: Callable[[], float] = time.time,
    ) -> None:
        self.forja = forja
        self.config = config or Config()
        self.ahora = ahora
        self.directorio = Path(directorio)
        self.directorio.mkdir(parents=True, exist_ok=True)
        self.produccion = Aplicador(self.directorio / NOMBRE_PRODUCCION)
        self.ruta_estado = self.directorio / NOMBRE_ESTADO
        self.auditoria = forja.interruptor.auditoria

    # -- despliegue ---------------------------------------------------------

    def desplegar(self, propuesta: Propuesta) -> Despacho:
        """Forja → tasa → aplica en canary. El orden importa: los gates primero (un
        REJECT no consume cupo de tasa), la tasa despues (limita cambios APLICADOS)."""
        veredicto = self.forja.evaluar(propuesta)
        if not veredicto.aplicable:
            return self._despacho(Estado.RECHAZADO_GATE, propuesta.id, str(veredicto), veredicto)

        if self._excede_tasa():
            return self._despacho(
                Estado.RECHAZADO_TASA,
                propuesta.id,
                f"limite de tasa: ya hay {self.config.max_cambios_ventana} cambio(s) en "
                f"la ventana de {int(self.config.ventana_tasa_s)}s (freno anti auto-DoS)",
                veredicto,
            )

        ahora = self.ahora()
        punto = self.produccion.aplicar(propuesta)
        canario = Canario(
            propuesta_id=propuesta.id,
            hash_previo=punto.hash_previo,
            n_previo=punto.n_previo,
            desplegado_en=ahora,
            plazo=ahora + self.config.plazo_canary_s,
        )
        self._guardar_canario(canario)
        return self._despacho(
            Estado.APLICADO_CANARY,
            propuesta.id,
            f"aplicado en canary; se revierte solo si nadie confirma antes de "
            f"{int(self.config.plazo_canary_s)}s",
            veredicto,
        )

    def confirmar(self, propuesta_id: str, actor: Actor) -> Canario:
        """Un humano confirma que el canary va bien: pasa a estable, desarma el dead-man.
        Solo humano — la misma autoridad que descongelar (regla 3)."""
        if actor not in AUTORIDAD_PARA_DESCONGELAR:
            self.auditoria.registrar(
                "canary_confirmar_denegado", actor.value, propuesta=propuesta_id
            )
            raise SinAutoridad(actor, "confirmar un canary")
        canarios = self._canarios()
        if propuesta_id not in canarios:
            raise KeyError(f"no hay canary para '{propuesta_id}'")
        confirmado = Canario(**{**canarios[propuesta_id].como_dict(), "confirmado": True})
        canarios[propuesta_id] = confirmado
        self._escribir(canarios)
        self.auditoria.registrar("canary_confirmado", actor.value, propuesta=propuesta_id)
        return confirmado

    def revisar(self) -> list[str]:
        """El dead-man's switch: revierte los canarios que expiraron sin confirmar.
        Determinista, lo llama el automata. Devuelve los ids revertidos."""
        ahora = self.ahora()
        canarios = self._canarios()
        revertidos = []
        for id_, canario in list(canarios.items()):
            if canario.expira_en(ahora):
                self.produccion.revertir(Punto(canario.hash_previo, canario.n_previo), id_)
                del canarios[id_]
                revertidos.append(id_)
                self.auditoria.registrar(
                    "canary_revertido_deadman",
                    "automata",
                    propuesta=id_,
                    restaurado=self.produccion.restaura_a(
                        Punto(canario.hash_previo, canario.n_previo)
                    ),
                )
        if revertidos:
            self._escribir(canarios)
        return revertidos

    # -- consulta -----------------------------------------------------------

    def canarios_activos(self) -> list[Canario]:
        return list(self._canarios().values())

    def politica_activa(self) -> list[dict]:
        return self.produccion.activas()

    # -- interno ------------------------------------------------------------

    def _excede_tasa(self) -> bool:
        limite = self.ahora() - self.config.ventana_tasa_s
        recientes = [t for t in self._historial() if t >= limite]
        return len(recientes) >= self.config.max_cambios_ventana

    def _despacho(
        self, estado: Estado, id_: str, motivo: str, veredicto: Veredicto | None
    ) -> Despacho:
        self.auditoria.registrar("despliegue", "automata", propuesta=id_, estado=estado.value)
        return Despacho(estado, id_, motivo, veredicto)

    def _leer(self) -> dict:
        if not self.ruta_estado.exists():
            return {"canarios": [], "historial": []}
        return json.loads(self.ruta_estado.read_text(encoding="utf-8"))

    def _canarios(self) -> dict[str, Canario]:
        crudo = self._leer().get("canarios", [])
        return {c["propuesta_id"]: Canario(**c) for c in crudo}

    def _historial(self) -> list[float]:
        return list(self._leer().get("historial", []))

    def _guardar_canario(self, canario: Canario) -> None:
        canarios = self._canarios()
        canarios[canario.propuesta_id] = canario
        historial = [*self._historial(), canario.desplegado_en]
        self._escribir(canarios, historial)

    def _escribir(self, canarios: dict[str, Canario], historial: list[float] | None = None) -> None:
        datos = {
            "canarios": [c.como_dict() for c in canarios.values()],
            "historial": historial if historial is not None else self._historial(),
        }
        temporal = self.ruta_estado.with_suffix(".tmp")
        with temporal.open("w", encoding="utf-8") as f:
            json.dump(datos, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        temporal.replace(self.ruta_estado)
