"""Los comandos con autoridad sobre el plano de control: el interruptor, el log
encadenado y sus dos proyecciones (el informe HTML y el ruleset de nftables).

Ninguno pasa por un modelo. Es la propiedad que los define: el camino de recuperacion
de un incidente no puede depender de que una inferencia conteste (regla 2).
"""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from .. import informe as informe_html
from .. import nftables
from ..actores import Actor, SinAutoridad
from ..aplicador import Aplicador
from ..despliegue import NOMBRE_PRODUCCION
from ._comun import _interruptor


def _cmd_estado(args: argparse.Namespace) -> int:
    estado = _interruptor(args).estado()
    marca = "CONGELADA" if estado.congelado else "operativa"
    print(f"capa de IA: {marca}")
    print(f"  desde:  {estado.desde}")
    print(f"  actor:  {estado.actor}")
    print(f"  motivo: {estado.motivo}")
    if estado.congelado:
        print("\nT0/T1 siguen protegiendo: la IA es aditiva (regla 2).")
    return 0


def _cmd_congelar(args: argparse.Namespace) -> int:
    try:
        estado = _interruptor(args).congelar(Actor(args.actor), args.motivo)
    except SinAutoridad as e:
        print(f"denegado: {e}", file=sys.stderr)
        return 3
    print(f"capa de IA CONGELADA desde {estado.desde}: {estado.motivo}")
    return 0


def _cmd_descongelar(args: argparse.Namespace) -> int:
    try:
        estado = _interruptor(args).descongelar(Actor(args.actor), args.motivo)
    except SinAutoridad as e:
        print(f"denegado: {e}", file=sys.stderr)
        return 3
    print(f"capa de IA operativa desde {estado.desde}: {estado.motivo}")
    return 0


def _cmd_auditoria(args: argparse.Namespace) -> int:
    auditoria = _interruptor(args).auditoria
    veredicto = auditoria.verificar()
    if args.verificar:
        if veredicto.intacta:
            print(f"cadena intacta: {veredicto.entradas} entrada(s)")
            return 0
        print(
            f"CADENA ROTA en la entrada {veredicto.rota_en}: {veredicto.motivo}",
            file=sys.stderr,
        )
        return 4
    for entrada in auditoria.leer():
        datos = json.dumps(entrada.datos, ensure_ascii=False, sort_keys=True)
        print(f"{entrada.seq:>4} {entrada.ts} {entrada.actor:<8} {entrada.evento:<22} {datos}")
    if not veredicto.intacta:
        print(f"\nAVISO: cadena rota en {veredicto.rota_en} ({veredicto.motivo})", file=sys.stderr)
        return 4
    return 0


def _cmd_informe(args: argparse.Namespace) -> int:
    """Proyecta el estado y el log de auditoria a una pagina HTML de SOLO LECTURA.

    Es una vista, no una autoridad: lee el plano de control y renderiza. No aplica ni
    confirma nada — eso sigue en los comandos con autoridad. Aqui la CLI (que ya tiene
    la autoridad para leer) hace de puente entre el estado en disco y el renderizador
    puro de `informe`."""
    interruptor = _interruptor(args)
    auditoria = interruptor.auditoria
    entradas = list(auditoria.leer())
    veredicto = auditoria.verificar()
    generado = datetime.now(UTC).isoformat(timespec="seconds")
    # `interruptor.directorio` y no `args.control`: el flag es None cuando no se pasa y
    # quien resuelve el defecto (GUARDIA_CONTROL_DIR o el del sistema) es el Interruptor.
    salida = Path(args.salida) if args.salida else interruptor.directorio / "informe.html"
    salida.parent.mkdir(parents=True, exist_ok=True)
    salida.write_text(
        informe_html.render(interruptor.estado(), entradas, veredicto, generado),
        encoding="utf-8",
    )
    marca = "intacta" if veredicto.intacta else f"ROTA en #{veredicto.rota_en}"
    print(f"informe escrito: {salida} · {veredicto.entradas} entrada(s) · cadena {marca}")
    if not veredicto.intacta:
        print(
            f"AVISO: la cadena esta rota ({veredicto.motivo}); el informe lo muestra, "
            "pero el estado no es de fiar a partir de ahi.",
            file=sys.stderr,
        )
    return 0


def _cmd_enforcement(args: argparse.Namespace) -> int:
    """Traduce la politica activa a reglas nftables y, con --aplicar, las enforca.

    Cierra la correlacion propuesta -> ejecucion: lo que se ve aqui es lo que el kernel
    va a cortar. Por defecto DRY-RUN: imprime el ruleset y no toca el sistema. Enforcar de
    verdad exige --aplicar (y Linux con nft + privilegios); es a proposito que lo barato
    salga sin banderas y lo que toca el sistema se pida a mano."""
    # Mismo motivo que en `informe`: el defecto del directorio de control lo resuelve el
    # Interruptor, no `args.control`, que es None mientras nadie escriba la bandera.
    ruta = (
        Path(args.politica)
        if args.politica
        else _interruptor(args).directorio / "despliegue" / NOMBRE_PRODUCCION
    )
    politicas = Aplicador(ruta).activas()
    resultado = nftables.aplicar(politicas, dry_run=not args.aplicar)
    print(resultado.reglas)
    for saltada in resultado.saltadas:
        print(f"# saltada: {saltada}", file=sys.stderr)
    if not politicas:
        print("# (no hay politica activa: ruleset vacio)")
    print(f"# {resultado.motivo}")
    # dry-run siempre sale 0; con --aplicar, no-cero si el enforcement real fallo.
    return 0 if resultado.aplicado or not args.aplicar else 7
