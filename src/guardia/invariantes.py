"""Los invariantes intocables. Regla 7: ninguna politica generada puede tocarlos.

Los aplica codigo determinista, no un prompt. Un invariante escrito en el system
prompt es una sugerencia; escrito aqui es una condicion que se comprueba.

Una violacion es BLOCKER: no hay severidad intermedia y no se puede aprobar "con
cuidado". Si hiciera falta relajar uno, se cambia el codigo y se abre un ADR.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Network, ip_network
from pathlib import PurePosixPath

from .politica import Confinamiento, FiltroRed, Propuesta


@dataclass(frozen=True)
class Config:
    """Que es intocable en esta instalacion. Se fija en el despliegue, no en runtime
    por peticion de nadie — y menos del modelo."""

    cidr_admin: IPv4Network = field(default_factory=lambda: ip_network("10.0.0.0/24"))
    puertos_admin: tuple[int, ...] = (22,)
    rutas_protegidas: tuple[str, ...] = (
        "/var/lib/guardia",  # plano de control y su capacidad de rollback
        "/var/log/guardia",  # el log de auditoria
        "/opt/guardia",  # el propio codigo, invariantes incluidos
    )


@dataclass(frozen=True)
class Violacion:
    """Una propuesta choca con un invariante. Siempre BLOCKER."""

    invariante: str
    detalle: str

    def __str__(self) -> str:
        return f"[{self.invariante}] {self.detalle}"


def _ruta_toca_protegida(ruta: str, protegida: str) -> bool:
    """True si `ruta` es la protegida o esta por encima de ella.

    Lo importante es el "por encima": denegar `/` o `/var` deja el plano de control
    igual de muerto que denegarlo por su nombre, y es la forma en que una propuesta
    ancha se lleva por delante un invariante sin mencionarlo.
    """
    try:
        candidata = PurePosixPath(ruta.strip().rstrip("/") or "/")
        objetivo = PurePosixPath(protegida)
    except (ValueError, TypeError):
        return False
    if not candidata.is_absolute():
        return False
    return objetivo == candidata or objetivo.is_relative_to(candidata)


def _canal_admin(propuesta: Propuesta, config: Config) -> list[Violacion]:
    """El canal de administracion no se corta. Es el invariante anti-lockout: la
    forma mas probable de que este sistema se haga dano es dejando fuera al admin."""
    cuerpo = propuesta.cuerpo
    if not isinstance(cuerpo, FiltroRed):
        return []
    if cuerpo.accion.value != "bloquear" or cuerpo.direccion.value != "entrada":
        return []
    if not cuerpo.afecta_a(config.cidr_admin):
        return []
    afectados = sorted(set(cuerpo.puertos) & set(config.puertos_admin))
    if not afectados:
        return []
    return [
        Violacion(
            "canal-admin",
            f"bloquea entrada al puerto {afectados} desde {cuerpo.cidr}, "
            f"que solapa el rango de administracion {config.cidr_admin}",
        )
    ]


def _rutas_protegidas(propuesta: Propuesta, config: Config) -> list[Violacion]:
    """Plano de control, log de auditoria y codigo propio: ni confinar ni denegar."""
    cuerpo = propuesta.cuerpo
    if not isinstance(cuerpo, Confinamiento):
        return []
    violaciones = []
    for ruta in cuerpo.rutas_denegadas:
        for protegida in config.rutas_protegidas:
            if _ruta_toca_protegida(ruta, protegida):
                violaciones.append(
                    Violacion(
                        "rutas-protegidas",
                        f"el perfil '{cuerpo.perfil}' deniega '{ruta}', "
                        f"que alcanza la ruta protegida '{protegida}'",
                    )
                )
    return violaciones


_SYSCALLS_VITALES = frozenset({"write", "fsync", "rename", "openat", "open"})


def _capacidad_de_registro(propuesta: Propuesta, config: Config) -> list[Violacion]:
    """Sin write/fsync/rename no hay log de auditoria ni rollback atomico. Denegarlas
    a lo ancho apaga el testigo sin nombrarlo."""
    cuerpo = propuesta.cuerpo
    if not isinstance(cuerpo, Confinamiento):
        return []
    afectadas = sorted(_SYSCALLS_VITALES & set(cuerpo.syscalls_denegadas))
    if not afectadas:
        return []
    return [
        Violacion(
            "capacidad-de-registro",
            f"el perfil '{cuerpo.perfil}' deniega {afectadas}, que el log de auditoria "
            f"y el rollback necesitan para escribir",
        )
    ]


_COMPROBACIONES = (_canal_admin, _rutas_protegidas, _capacidad_de_registro)


def comprobar(propuesta: Propuesta, config: Config | None = None) -> list[Violacion]:
    """Todas las violaciones de una propuesta. Lista vacia = no toca invariantes.

    Devuelve todas y no la primera: quien lee el veredicto merece la foto completa,
    y una propuesta que viola tres invariantes dice algo distinto de una que viola uno.
    """
    config = config or Config()
    violaciones: list[Violacion] = []
    for comprobacion in _COMPROBACIONES:
        violaciones.extend(comprobacion(propuesta, config))
    return violaciones


def es_admisible(propuesta: Propuesta, config: Config | None = None) -> bool:
    """Azucar para gates. Admisible aqui solo significa "no toca invariantes"."""
    return not comprobar(propuesta, config)


__all__ = ["Config", "Violacion", "comprobar", "es_admisible"]
