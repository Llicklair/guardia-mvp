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
from .aplicador import Aplicador
from .despliegue import Despliegue, Estado
from .eventos import cargar
from .forja import Forja, Resultado
from .invariantes import Config, comprobar
from .kill_switch import Interruptor
from .politica import PropuestaInvalida, desde_json

RAIZ = Path(__file__).resolve().parent.parent.parent
BENIGNO_POR_DEFECTO = RAIZ / "corpus" / "eventos" / "benigno.jsonl"
INCIDENTE_POR_DEFECTO = RAIZ / "corpus" / "eventos" / "incidente-0001.jsonl"


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
    print("para saber si es APLICABLE, pasala por 'guardia forjar' (los cuatro gates).")
    return 0


def _cmd_forjar(args: argparse.Namespace) -> int:
    """Corre la propuesta por los cuatro gates de la regla 6. No aplica a produccion:
    trabaja sobre un sandbox y deja un veredicto. Sin PASS, nada se aplica."""
    texto = Path(args.fichero).read_text(encoding="utf-8") if args.fichero else sys.stdin.read()
    try:
        propuesta = desde_json(texto)
    except PropuestaInvalida as e:
        print(f"DESCARTADA (no encaja en la gramatica): {e}", file=sys.stderr)
        return 2

    interruptor = _interruptor(args)
    forja = Forja(
        interruptor=interruptor,
        aplicador=Aplicador(interruptor.directorio / "sandbox-politica.json"),
        benigno=cargar(args.benigno),
        incidente=cargar(args.incidente),
    )
    veredicto = forja.evaluar(propuesta)
    destino = sys.stdout if veredicto.aplicable else sys.stderr
    print(f"propuesta '{propuesta.id}': {veredicto}", file=destino)
    return {Resultado.PASS: 0, Resultado.REJECT: 6, Resultado.BLOCKER: 5}[veredicto.resultado]


def _despliegue(args: argparse.Namespace) -> Despliegue:
    # confirmar/revisar no forjan, asi que no declaran --benigno/--incidente: getattr
    # con el default cubre esos casos sin obligar a cada subcomando a repetir los flags.
    interruptor = _interruptor(args)
    forja = Forja(
        interruptor=interruptor,
        aplicador=Aplicador(interruptor.directorio / "sandbox-politica.json"),
        benigno=cargar(getattr(args, "benigno", str(BENIGNO_POR_DEFECTO))),
        incidente=cargar(getattr(args, "incidente", str(INCIDENTE_POR_DEFECTO))),
    )
    return Despliegue(forja, interruptor.directorio / "despliegue")


def _cmd_desplegar(args: argparse.Namespace) -> int:
    """Forja + aplicacion real: si pasa los gates y no excede la tasa, se aplica en
    canary con dead-man's switch. Cierra el ciclo T3."""
    texto = Path(args.fichero).read_text(encoding="utf-8") if args.fichero else sys.stdin.read()
    try:
        propuesta = desde_json(texto)
    except PropuestaInvalida as e:
        print(f"DESCARTADA (no encaja en la gramatica): {e}", file=sys.stderr)
        return 2
    despacho = _despliegue(args).desplegar(propuesta)
    destino = sys.stdout if despacho.aplicado else sys.stderr
    print(f"propuesta '{despacho.propuesta_id}': {despacho.estado.value}", file=destino)
    print(f"  {despacho.motivo}", file=destino)
    return {Estado.APLICADO_CANARY: 0, Estado.RECHAZADO_GATE: 6, Estado.RECHAZADO_TASA: 7}[
        despacho.estado
    ]


def _cmd_confirmar(args: argparse.Namespace) -> int:
    try:
        canario = _despliegue(args).confirmar(args.propuesta, Actor(args.actor))
    except SinAutoridad as e:
        print(f"denegado: {e}", file=sys.stderr)
        return 3
    except KeyError as e:
        print(f"no encontrado: {e}", file=sys.stderr)
        return 4
    print(f"canary '{canario.propuesta_id}' confirmado: estable, dead-man desarmado")
    return 0


def _cmd_revisar(args: argparse.Namespace) -> int:
    """El dead-man's switch: revierte los canarios expirados sin confirmar. Lo llama el
    automata; determinista, sin IA."""
    revertidos = _despliegue(args).revisar()
    if revertidos:
        print(f"revertidos por dead-man: {', '.join(revertidos)}")
    else:
        print("sin canarios expirados")
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

    forjar = sub.add_parser("forjar", help="corre una propuesta por los cuatro gates (regla 6)")
    forjar.add_argument("fichero", nargs="?", help="JSON de la propuesta (por defecto, stdin)")
    forjar.add_argument(
        "--benigno", default=str(BENIGNO_POR_DEFECTO), help="corpus benigno (JSONL)"
    )
    forjar.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="repro del incidente (JSONL)"
    )
    forjar.set_defaults(func=_cmd_forjar)

    desplegar = sub.add_parser("desplegar", help="forja + aplica en canary con dead-man's switch")
    desplegar.add_argument("fichero", nargs="?", help="JSON de la propuesta (por defecto, stdin)")
    desplegar.add_argument("--benigno", default=str(BENIGNO_POR_DEFECTO), help="corpus benigno")
    desplegar.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="repro incidente"
    )
    desplegar.set_defaults(func=_cmd_desplegar)

    confirmar = sub.add_parser("confirmar", help="confirma un canary como estable (solo humano)")
    confirmar.add_argument("propuesta", help="id de la propuesta en canary")
    confirmar.add_argument("--actor", choices=[a.value for a in Actor], default=Actor.HUMANO.value)
    confirmar.set_defaults(func=_cmd_confirmar)

    revisar = sub.add_parser("revisar", help="dead-man's switch: revierte canarios expirados")
    revisar.set_defaults(func=_cmd_revisar)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = construir_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
