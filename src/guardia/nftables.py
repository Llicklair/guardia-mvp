"""El punto de aplicacion real: traduce la politica activa a reglas de nftables.

Cierra el hueco que un LLM no debe tocar y que hasta ahora era un JSON sin efecto. Una
propuesta `filtro_red` que paso los gates y se aplico al estado se convierte AQUI en
reglas `nft` que de verdad cortan el trafico. Es la correlacion propuesta -> ejecucion
hecha explicita: lo que el modelo propuso, lo que los gates aprobaron y lo que el kernel
va a enforcar es la misma cosa, y se puede leer.

Dos mitades, a proposito:

- `ruleset(politicas)` es una funcion PURA: la politica activa -> el texto de un script
  nft. Sin efectos, testeable sin root ni kernel. Es lo que hace la traduccion auditable.
- `aplicar(politicas, dry_run=...)` es lo unico que toca el sistema, y SOLO si dry_run es
  False. Por defecto NO ejecuta: devuelve las reglas y para. El enforcement de verdad
  exige Linux con `nft` y privilegios; donde no los hay, se dice y no se finge. Es la
  misma disciplina que el resto del proyecto: lo barato/seguro sale sin banderas, lo que
  toca el sistema se pide a mano.

Alcance honesto del MVP: solo `filtro_red` (cortar red). `confinamiento` (seccomp/
apparmor) y `regla_deteccion` (Falco) son otros backends, otro dia — una politica que
este adaptador no sabe traducir se SALTA con constancia, nunca en silencio: un ruleset
que dice cubrir algo que no cubre es peor que ninguno.

No importa nada del dominio: trabaja sobre la politica ya serializada (dicts), asi que es
un adaptador de salida, no un camino de autoridad. Quien lee el estado es la CLI.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

TABLA = "guardia"
_TIMEOUT_S = 10.0

# Una cadena por sentido de trafico. `output` para egress (el caso real: cortar el C2),
# `input` para ingress. Solo se crean las que tengan reglas.
_CADENAS = {"egress": "output", "ingress": "input"}

# Como traducir cada direccion de la gramatica: (cadena, campo de match). Egress mira el
# destino (a donde sale el trafico, el C2); ingress mira el origen (de donde entra).
_DIRECCION = {
    "salida": ("egress", "daddr"),
    "entrada": ("ingress", "saddr"),
}


@dataclass(frozen=True)
class Aplicacion:
    """El resultado de intentar enforcar. `reglas` es el script nft (siempre presente,
    para poder leerlo aunque no se aplique). `saltadas` dice que politicas no se
    tradujeron y por que — un hueco callado seria peor que el hueco."""

    reglas: str
    aplicado: bool
    motivo: str
    saltadas: tuple[str, ...] = ()


def _traducir(politica: dict) -> tuple[str | None, str | None, str | None]:
    """Una politica -> (cadena, match nft, None) si se traduce; (None, None, motivo) si
    se salta. No aplica nada: solo forma."""
    ident = politica.get("id", "?")
    if politica.get("tipo") != "filtro_red":
        return None, None, f"{ident}: tipo '{politica.get('tipo')}' no lo traduce el adaptador nft"
    cuerpo = politica.get("cuerpo", {})
    if cuerpo.get("accion") != "bloquear":
        return None, None, f"{ident}: accion '{cuerpo.get('accion')}' no soportada (solo bloquear)"
    destino = _DIRECCION.get(cuerpo.get("direccion"))
    if destino is None:
        return None, None, f"{ident}: direccion '{cuerpo.get('direccion')}' no soportada"
    cadena, campo = destino
    match = f"ip {campo} {cuerpo.get('cidr')}"
    puertos = [int(p) for p in (cuerpo.get("puertos") or [])]
    if puertos:
        match += " tcp dport { " + ", ".join(str(p) for p in puertos) + " }"
    return cadena, match, None


def _clasificar(politicas: list[dict]) -> tuple[dict[str, list[str]], list[str]]:
    por_cadena: dict[str, list[str]] = {}
    saltadas: list[str] = []
    for politica in politicas:
        cadena, match, motivo = _traducir(politica)
        if motivo is not None:
            saltadas.append(motivo)
            continue
        por_cadena.setdefault(cadena, []).append(match)  # type: ignore[arg-type]
    return por_cadena, saltadas


def _script(por_cadena: dict[str, list[str]]) -> str:
    # add/delete/add de la tabla entera: carga atomica que deja un estado limpio aunque
    # ya hubiera reglas de una aplicacion anterior. Si la tabla no existia, el primer add
    # la crea para que el delete no falle. Es el idiom de reemplazo de nftables.
    lineas = [
        f"# Generado por guardia desde la politica activa. Tabla inet {TABLA}.",
        "# NO editar a mano: se sobrescribe en cada aplicacion.",
        f"add table inet {TABLA}",
        f"delete table inet {TABLA}",
        f"add table inet {TABLA}",
    ]
    for cadena, matches in por_cadena.items():
        hook = _CADENAS[cadena]
        lineas.append(
            f"add chain inet {TABLA} {cadena} "
            f"{{ type filter hook {hook} priority 0 ; policy accept ; }}"
        )
        for match in matches:
            lineas.append(f"add rule inet {TABLA} {cadena} {match} drop")
    return "\n".join(lineas) + "\n"


def ruleset(politicas: list[dict]) -> str:
    """La politica activa como script nft. Funcion pura: ni root, ni kernel, ni efectos."""
    por_cadena, _ = _clasificar(politicas)
    return _script(por_cadena)


def aplicar(politicas: list[dict], *, dry_run: bool = True) -> Aplicacion:
    """Traduce y, solo si `dry_run` es False, empuja a nftables con `nft -f -`.

    Por defecto dry_run: devuelve las reglas sin tocar el sistema. El enforcement real
    necesita Linux con `nft` y privilegios; su ausencia se reporta, no se finge."""
    por_cadena, saltadas = _clasificar(politicas)
    reglas = _script(por_cadena)
    saltadas_t = tuple(saltadas)
    if dry_run:
        return Aplicacion(
            reglas,
            False,
            "dry-run: no se toco el sistema. Con --aplicar (Linux + nft + privilegios) se enforca.",
            saltadas_t,
        )
    nft = shutil.which("nft")
    if nft is None:
        return Aplicacion(
            reglas,
            False,
            "nft no esta en el PATH: el enforcement real solo corre en Linux con nftables.",
            saltadas_t,
        )
    try:
        resultado = subprocess.run(
            (nft, "-f", "-"),
            input=reglas,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return Aplicacion(reglas, False, f"nft agoto {_TIMEOUT_S}s", saltadas_t)
    if resultado.returncode != 0:
        detalle = (resultado.stderr or resultado.stdout or "").strip()[:200]
        return Aplicacion(
            reglas, False, f"nft fallo ({resultado.returncode}): {detalle}", saltadas_t
        )
    return Aplicacion(reglas, True, f"aplicado en nftables (tabla inet {TABLA})", saltadas_t)
