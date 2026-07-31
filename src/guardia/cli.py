"""`guardia` — la linea de mando determinista.

Todo lo que se puede hacer desde aqui es deterministico y no pasa por ningun modelo.
Es a proposito: el camino de recuperacion de un incidente no puede depender de que
una API de inferencia conteste.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .actores import Actor, SinAutoridad
from .invariantes import Config, comprobar
from .kill_switch import Interruptor
from .politica import PropuestaInvalida, desde_json


def _interruptor(args: argparse.Namespace) -> Interruptor:
    return Interruptor(args.control)


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


def _cmd_validar(args: argparse.Namespace) -> int:
    """Parsea una propuesta contra la gramatica y la contrasta con los invariantes.

    No aplica nada. Aplicar exige ademas los cuatro gates (regla 6), que son la
    siguiente pieza del MVP.
    """
    texto = Path(args.fichero).read_text(encoding="utf-8") if args.fichero else sys.stdin.read()
    try:
        propuesta = desde_json(texto)
    except PropuestaInvalida as e:
        print(f"DESCARTADA (no encaja en la gramatica): {e}", file=sys.stderr)
        return 2
    violaciones = comprobar(propuesta, Config())
    if violaciones:
        print(f"BLOCKER — la propuesta '{propuesta.id}' toca invariantes:", file=sys.stderr)
        for violacion in violaciones:
            print(f"  {violacion}", file=sys.stderr)
        return 5
    print(f"propuesta '{propuesta.id}' ({propuesta.tipo.value}): gramatica OK, invariantes OK")
    print("aun NO aplicable: faltan los cuatro gates de la regla 6.")
    return 0


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardia",
        description="Plano de control determinista del sistema de seguridad con capa de IA.",
    )
    parser.add_argument(
        "--control",
        metavar="DIR",
        default=None,
        help="directorio de control (por defecto GUARDIA_CONTROL_DIR o el del sistema)",
    )
    sub = parser.add_subparsers(dest="comando", required=True)

    sub.add_parser("estado", help="estado de la capa de IA").set_defaults(func=_cmd_estado)

    congelar = sub.add_parser("congelar", help="interruptor de emergencia: congela la capa de IA")
    congelar.add_argument("motivo", help="por que se congela (queda en el log)")
    congelar.add_argument(
        "--actor", choices=[Actor.HUMANO.value, Actor.AUTOMATA.value], default=Actor.HUMANO.value
    )
    congelar.set_defaults(func=_cmd_congelar)

    descongelar = sub.add_parser("descongelar", help="reactiva la capa de IA (solo humano)")
    descongelar.add_argument("motivo", help="por que se reactiva (queda en el log)")
    # Admite cualquier actor a proposito: que se pueda INTENTAR descongelar como IA
    # desde la linea de mando es lo que hace demostrable que el codigo lo deniega.
    descongelar.add_argument(
        "--actor", choices=[a.value for a in Actor], default=Actor.HUMANO.value
    )
    descongelar.set_defaults(func=_cmd_descongelar)

    auditoria = sub.add_parser("auditoria", help="lee o verifica el log encadenado")
    auditoria.add_argument(
        "--verificar", action="store_true", help="solo comprobar la cadena de hashes"
    )
    auditoria.set_defaults(func=_cmd_auditoria)

    validar = sub.add_parser("validar", help="valida una propuesta contra gramatica e invariantes")
    validar.add_argument("fichero", nargs="?", help="JSON de la propuesta (por defecto, stdin)")
    validar.set_defaults(func=_cmd_validar)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = construir_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
