"""El ciclo de una propuesta: validar, pasarla por los cuatro gates, desplegarla en
canary, confirmarla o dejar que el dead-man's switch la revierta.

Aqui vive la unica autoridad de escritura del sistema (T3, regla 1). `responder` es el
ciclo entero de punta a punta y el unico de este modulo que puede tocar un modelo, en
T2 y solo con --proveedor llm: propone, y lo que decide sigue siendo el crisol.
"""

import argparse
import sys

from ..actores import Actor, SinAutoridad
from ..aplicador import Aplicador
from ..crisol import Crisol, Resultado
from ..despliegue import Despliegue, Estado
from ..eventos import cargar
from ..invariantes import Config, comprobar
from ..politica import PropuestaInvalida, desde_json
from ..transporte import (
    TransporteFallido,
)
from ..triaje import ProveedorHeuristico, Triaje
from ._comun import (
    BENIGNO_POR_DEFECTO,
    INCIDENTE_POR_DEFECTO,
    _interruptor,
    _mostrar_dictamen,
    _proveedor,
    _texto_de_propuesta,
)


def _cmd_validar(args: argparse.Namespace) -> int:
    """Parsea una propuesta contra la gramatica y la contrasta con los invariantes.

    No aplica nada. Aplicar exige ademas los cuatro gates (regla 6), que son la
    siguiente pieza del MVP.
    """
    texto = _texto_de_propuesta(args)
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
    print("para saber si es APLICABLE, pasala por 'guardia crisol' (los cuatro gates).")
    return 0


def _cmd_crisol(args: argparse.Namespace) -> int:
    """Corre la propuesta por los cuatro gates de la regla 6. No aplica a produccion:
    trabaja sobre un sandbox y deja un veredicto. Sin PASS, nada se aplica."""
    texto = _texto_de_propuesta(args)
    try:
        propuesta = desde_json(texto)
    except PropuestaInvalida as e:
        print(f"DESCARTADA (no encaja en la gramatica): {e}", file=sys.stderr)
        return 2

    interruptor = _interruptor(args)
    crisol = Crisol(
        interruptor=interruptor,
        aplicador=Aplicador(interruptor.directorio / "sandbox-politica.json"),
        benigno=cargar(args.benigno),
        incidente=cargar(args.incidente),
    )
    veredicto = crisol.evaluar(propuesta)
    destino = sys.stdout if veredicto.aplicable else sys.stderr
    print(f"propuesta '{propuesta.id}': {veredicto}", file=destino)
    return {Resultado.PASS: 0, Resultado.REJECT: 6, Resultado.BLOCKER: 5}[veredicto.resultado]


def _despliegue(args: argparse.Namespace, sufijo: str = "") -> Despliegue:
    # confirmar/revisar no pasan por el crisol, asi que no declaran --benigno/--incidente: getattr
    # con el default cubre esos casos sin obligar a cada subcomando a repetir los flags.
    interruptor = _interruptor(args)
    crisol = Crisol(
        interruptor=interruptor,
        aplicador=Aplicador(interruptor.directorio / f"sandbox-politica{sufijo}.json"),
        benigno=cargar(getattr(args, "benigno", str(BENIGNO_POR_DEFECTO))),
        incidente=cargar(getattr(args, "incidente", str(INCIDENTE_POR_DEFECTO))),
    )
    return Despliegue(crisol, interruptor.directorio / f"despliegue{sufijo}")


def _cmd_desplegar(args: argparse.Namespace) -> int:
    """Crisol + aplicacion real: si pasa los gates y no excede la tasa, se aplica en
    canary con dead-man's switch. Cierra el ciclo T3."""
    texto = _texto_de_propuesta(args)
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


def _cmd_responder(args: argparse.Namespace) -> int:
    """El ciclo completo: incidente → triaje (T2) → despliegue (T3). Por defecto con
    el proveedor heuristico determinista; `--proveedor llm` conecta el modelo real por
    su CLI (ADR 0006). Si el transporte cae, el ciclo se recupera con el heuristico y
    queda auditado: la respuesta a un incidente no espera a que una inferencia
    conteste."""
    interruptor = _interruptor(args)
    incidente = cargar(args.incidente)
    triaje = Triaje(_proveedor(args), interruptor.auditoria)
    try:
        propuesta = triaje.proponer(incidente)
    except TransporteFallido as e:
        print(f"T2: transporte LLM caido ({e}); recuperando con heuristico", file=sys.stderr)
        interruptor.auditoria.registrar(
            "triaje_transporte_caido", Actor.AUTOMATA.value, motivo=str(e)[:200]
        )
        propuesta = Triaje(ProveedorHeuristico(), interruptor.auditoria).proponer(incidente)
    if propuesta is None:
        print(f"T2: sin propuesta para '{incidente.nombre}' (nada evidente que contener)")
        return 1
    print(f"T2 propone: '{propuesta.id}' ({propuesta.tipo.value})")
    if args.evaluar:
        _mostrar_dictamen(args, propuesta, interruptor)

    despacho = _despliegue(args).desplegar(propuesta)
    destino = sys.stdout if despacho.aplicado else sys.stderr
    print(f"T3: {despacho.estado.value} — {despacho.motivo}", file=destino)
    return {Estado.APLICADO_CANARY: 0, Estado.RECHAZADO_GATE: 6, Estado.RECHAZADO_TASA: 7}[
        despacho.estado
    ]
