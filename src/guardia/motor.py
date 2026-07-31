"""El motor de replay: ¿esta propuesta dispara sobre este evento? Determinista.

No hay IA aqui y no hay parser de lenguaje de reglas de terceros. El motor evalua la
forma estructurada de una propuesta contra la forma estructurada de un evento. Es a
proposito acotado, y sus limites estan escritos abajo y en docs/evidencia.md — un
motor que finge cubrir mas de lo que cubre es la primera forma de teatro.

**Lo que cubre de verdad, con matching completo:**
- `filtro_red` contra `EventoRed`: direccion + puerto + pertenencia al CIDR.
- `confinamiento` contra `EventoFichero` (ruta denegada) y `EventoProceso` (¿el
  proceso cuelga de algo que el confinamiento prohibiria?).

**Lo que NO cubre:** `regla_deteccion`. Su condicion es lenguaje Falco/Sigma y su
banco de pruebas es el motor de Falco, no este. Replayarla aqui exigiria reimplementar
Falco, que la regla 9 prohibe. Se declara `ReplayNoSoportado` en vez de aproximarlo:
una deteccion que este motor "aprobara" no significaria nada.
"""

from __future__ import annotations

from .eventos import Evento, EventoFichero, EventoProceso, EventoRed
from .politica import Confinamiento, FiltroRed, Propuesta, ReglaDeteccion


class ReplayNoSoportado(Exception):
    """El tipo de propuesta no se puede replayar en este motor determinista. No es un
    fallo del gate: es la frontera honesta de lo que se puede verificar sin Falco."""


def _dispara_filtro(filtro: FiltroRed, evento: Evento) -> bool:
    if not isinstance(evento, EventoRed):
        return False
    return (
        evento.direccion == filtro.direccion.value
        and evento.puerto in filtro.puertos
        and evento.ip in filtro.cidr
    )


def _dispara_confinamiento(conf: Confinamiento, evento: Evento) -> bool:
    if isinstance(evento, EventoFichero):
        # Dispara si el evento toca una ruta denegada (o algo debajo de ella).
        return any(_ruta_bajo(evento.ruta, denegada) for denegada in conf.rutas_denegadas)
    if isinstance(evento, EventoProceso):
        # Un confinamiento que deniega ejecutar shells "dispara" sobre el proceso shell
        # cuando el propio perfil lista esa syscall/ruta; en el MVP lo modelamos por la
        # cmdline denegada via rutas (p.ej. denegar /bin/bash).
        return any(
            _ruta_bajo(f"/bin/{evento.nombre}", denegada) for denegada in conf.rutas_denegadas
        )
    return False


def _ruta_bajo(ruta: str, prefijo: str) -> bool:
    """True si `ruta` esta dentro de `prefijo` por segmentos (no por prefijo de cadena:
    '/var/lib' no contiene a '/var/libreria')."""
    r = [s for s in ruta.strip().split("/") if s]
    p = [s for s in prefijo.strip().split("/") if s]
    return r[: len(p)] == p


def dispara(propuesta: Propuesta, evento: Evento) -> bool:
    """¿La politica de la propuesta actua sobre este evento? Determinista y total para
    los tipos soportados; `ReplayNoSoportado` para regla_deteccion."""
    cuerpo = propuesta.cuerpo
    if isinstance(cuerpo, FiltroRed):
        return _dispara_filtro(cuerpo, evento)
    if isinstance(cuerpo, Confinamiento):
        return _dispara_confinamiento(cuerpo, evento)
    if isinstance(cuerpo, ReglaDeteccion):
        raise ReplayNoSoportado(
            "regla_deteccion se replaya en Falco (T0/T1), no en este motor. Ver docs/evidencia.md."
        )
    raise ReplayNoSoportado(f"tipo de cuerpo no replayable: {type(cuerpo).__name__}")


def eventos_que_disparan(propuesta: Propuesta, eventos) -> list[Evento]:
    """Los eventos del corpus sobre los que la propuesta actua. La base de los gates
    de replay: sobre el benigno deberia ser vacio, sobre el incidente no."""
    return [e for e in eventos if dispara(propuesta, e)]
