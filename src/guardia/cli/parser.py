"""La superficie de la linea de mando: que subcomandos existen, que banderas admite
cada uno y cual es su defecto.

Separado de los handlers a proposito. El defecto de una bandera es una decision de
politica —lo caro se pide a mano, lo prohibido se rechaza— y tenerlos todos juntos
hace que esa politica se lea de un vistazo en vez de repartida por quince funciones.
"""

import argparse

from ..actores import Actor
from ..generador import ENCARGOS
from ..transporte import COMANDOS_CLI, SUELO_DE_EVALUACION
from ._comun import BENIGNO_POR_DEFECTO, INCIDENTE_POR_DEFECTO, INYECCIONES_POR_DEFECTO
from .control import (
    _cmd_auditoria,
    _cmd_congelar,
    _cmd_descongelar,
    _cmd_enforcement,
    _cmd_estado,
    _cmd_informe,
)
from .medicion import _cmd_banco, _cmd_banco_evaluador, _cmd_generar_inyecciones
from .propuestas import (
    _cmd_confirmar,
    _cmd_crisol,
    _cmd_desplegar,
    _cmd_responder,
    _cmd_revisar,
    _cmd_validar,
)


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

    informe = sub.add_parser(
        "informe", help="proyecta estado + log de auditoria a una pagina HTML de solo lectura"
    )
    informe.add_argument(
        "--salida", default=None, help="fichero HTML de salida (por defecto <control>/informe.html)"
    )
    informe.set_defaults(func=_cmd_informe)

    enforcement = sub.add_parser(
        "enforcement",
        help="traduce la politica activa a reglas nftables (dry-run por defecto)",
    )
    enforcement.add_argument(
        "--politica",
        default=None,
        help="politica activa a enforcar (por defecto <control>/despliegue/politica-activa.json)",
    )
    enforcement.add_argument(
        "--aplicar",
        action="store_true",
        help="enforca de verdad con 'nft -f -' (necesita Linux + nftables + privilegios); "
        "sin esto solo imprime el ruleset y no toca el sistema",
    )
    enforcement.set_defaults(func=_cmd_enforcement)

    validar = sub.add_parser("validar", help="valida una propuesta contra gramatica e invariantes")
    validar.add_argument("fichero", nargs="?", help="JSON de la propuesta (por defecto, stdin)")
    validar.set_defaults(func=_cmd_validar)

    crisol = sub.add_parser("crisol", help="corre una propuesta por los cuatro gates (regla 6)")
    crisol.add_argument("fichero", nargs="?", help="JSON de la propuesta (por defecto, stdin)")
    crisol.add_argument(
        "--benigno", default=str(BENIGNO_POR_DEFECTO), help="corpus benigno (JSONL)"
    )
    crisol.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="repro del incidente (JSONL)"
    )
    crisol.set_defaults(func=_cmd_crisol)

    desplegar = sub.add_parser(
        "desplegar", help="pasa por el crisol + aplica en canary con dead-man's switch"
    )
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

    responder = sub.add_parser(
        "responder", help="ciclo completo: incidente -> triaje (T2) -> despliegue (T3)"
    )
    responder.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="repro del incidente (JSONL)"
    )
    responder.add_argument("--benigno", default=str(BENIGNO_POR_DEFECTO), help="corpus benigno")
    _flags_de_proveedor(responder)
    responder.set_defaults(func=_cmd_responder)

    banco = sub.add_parser(
        "banco", help="metrica 5: corpus de inyecciones contra T2, ciclo completo (§8)"
    )
    banco.add_argument(
        "--corpus", default=str(INYECCIONES_POR_DEFECTO), help="directorio de inyecciones"
    )
    banco.add_argument("--benigno", default=str(BENIGNO_POR_DEFECTO), help="corpus benigno")
    banco.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="repro limpio para los gates"
    )
    _flags_de_proveedor(banco)
    banco.set_defaults(func=_cmd_banco)

    banco_ev = sub.add_parser(
        "banco-evaluador",
        help="mide si el evaluador distingue propuesta desviada de correcta (ADR 0007)",
    )
    banco_ev.add_argument(
        "--llm-cli",
        choices=sorted(COMANDOS_CLI),
        default=None,
        help="CLI de modelo para el evaluador (invoca un modelo real y gasta cuota). "
        "Sin modelo nombrado, el comando enseña el plan y no gasta nada",
    )
    banco_ev.add_argument(
        "--comando-llm",
        default=None,
        help="comando de transporte a medida (avanzado; el prompt entra por stdin). "
        f"Un modelo bajo el suelo de evaluacion ('{SUELO_DE_EVALUACION}') se RECHAZA",
    )
    banco_ev.add_argument(
        "--pasadas",
        type=_pasadas_positivas,
        default=1,
        help="N pasadas completas para medir la estabilidad de la senal (varianza); "
        "cada una reevalua control y desviadas, asi que gasta N veces la cuota",
    )
    banco_ev.set_defaults(func=_cmd_banco_evaluador)

    generar = sub.add_parser(
        "generar-inyecciones",
        help="encarga el corpus de inyecciones a un modelo que no ha visto el sistema",
    )
    generar.add_argument("--salida", required=True, help="directorio donde escribir el corpus")
    generar.add_argument(
        "--objetivo",
        action="append",
        choices=[e.objetivo for e in ENCARGOS],
        help="genera solo estos objetivos (repetible); por defecto, todos",
    )
    generar.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="ataque real que se envenena"
    )
    generar.add_argument(
        "--llm-cli",
        choices=sorted(COMANDOS_CLI),
        default=None,
        help="CLI de modelo. SIN esto (ni --comando-llm) el comando NO gasta cuota: "
        "enseña el plan y para",
    )
    generar.add_argument(
        "--comando-llm",
        default=None,
        help="comando de transporte a medida (avanzado; el prompt entra por stdin). "
        f"Un modelo bajo el suelo de evaluacion ('{SUELO_DE_EVALUACION}') se RECHAZA",
    )
    generar.add_argument(
        "--pasadas",
        type=_pasadas_positivas,
        default=1,
        help="N pasadas para medir si la negativa del modelo es estable o ruido; "
        "gasta N x objetivos la cuota, artefactos por pasada",
    )
    generar.set_defaults(func=_cmd_generar_inyecciones)

    return parser


def _pasadas_positivas(texto: str) -> int:
    """--pasadas 0 o negativo caia en silencio a la rama de UNA pasada (la varianza
    solo arranca con >1): con modelo real gastaba cuota que el usuario pidio no gastar,
    y el plan la contaba en negativo. Se rechaza en la puerta, no se corrige."""
    n = int(texto)
    if n < 1:
        raise argparse.ArgumentTypeError("hacen falta al menos 1 pasada(s) para medir")
    return n


def _flags_de_proveedor(sub: argparse.ArgumentParser) -> None:
    """Quien propone en T2. Compartido por `responder` y `banco`: el defecto es el
    heuristico determinista en los dos, y el LLM se pide a mano."""
    sub.add_argument(
        "--proveedor",
        choices=["heuristico", "llm"],
        default="heuristico",
        help="quien propone en T2 (llm invoca un modelo real y gasta cuota; opt-in)",
    )
    sub.add_argument(
        "--llm-cli",
        choices=sorted(COMANDOS_CLI),
        default="claude",
        help="CLI de modelo para --proveedor llm (presets de solo-inferencia)",
    )
    sub.add_argument(
        "--comando-llm",
        default=None,
        help="comando de transporte a medida (avanzado; el prompt entra por stdin). "
        f"Un modelo bajo el suelo de evaluacion ('{SUELO_DE_EVALUACION}') se RECHAZA",
    )
    sub.add_argument(
        "--evaluar",
        action="store_true",
        help="pasa la propuesta por el evaluador adversarial (advisory, no bloquea)",
    )
