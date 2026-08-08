"""Lo que comparten los tres grupos de comandos: como entra una propuesta, como se
resuelve el directorio de control y por que canal se habla con un modelo.

Vive aparte porque el tratamiento tiene que ser IDENTICO en todos los caminos: un
fichero mal tecleado sale como error de uso en los tres comandos que leen propuesta, y
repetir ese cuidado en cada uno es garantizar que el proximo se olvide.
"""

import argparse
import shlex
import sys
from pathlib import Path

from ..evaluador import EvaluadorAdversarial
from ..kill_switch import Interruptor
from ..transporte import (
    COMANDOS_CLI,
    TransporteCLI,
)
from ..triaje import ProveedorHeuristico, ProveedorLLM

# src/guardia/cli/_comun.py -> src/guardia/cli -> src/guardia -> src -> la raiz. Al
# partir el modulo en paquete hizo falta un salto mas, y contar mal aqui no rompe un
# import: deja los corpus por defecto apuntando a un sitio que no existe, y el fallo
# sale lejos, en el banco. Si este fichero se mueve otra vez, este es el numero a mirar.
RAIZ = Path(__file__).resolve().parents[3]
BENIGNO_POR_DEFECTO = RAIZ / "corpus" / "eventos" / "benigno.jsonl"
INCIDENTE_POR_DEFECTO = RAIZ / "corpus" / "eventos" / "incidente-0001.jsonl"
INYECCIONES_POR_DEFECTO = RAIZ / "corpus" / "inyecciones"


class EntradaIlegible(Exception):
    """No se pudo leer el fichero de propuesta que se paso por la linea de mando.

    Hermana de `CorpusIlegible` y por el mismo motivo: la propuesta tambien es dato
    hostil que entra por una ruta, y un fichero mal tecleado tiene que salir como un
    error de uso, no como un traceback."""


def _texto_de_propuesta(args: argparse.Namespace) -> str:
    """La propuesta, del fichero o de stdin. Un solo sitio para los tres comandos que
    la leen (`validar`, `crisol`, `desplegar`): el tratamiento del fichero ausente es
    identico en los tres y repetirlo es garantizar que el proximo se olvide."""
    if not args.fichero:
        return sys.stdin.read()
    try:
        return Path(args.fichero).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise EntradaIlegible(f"no se puede leer la propuesta '{args.fichero}': {e}") from e


def _interruptor(args: argparse.Namespace) -> Interruptor:
    return Interruptor(args.control)


def _comando_llm(args: argparse.Namespace) -> tuple[str, ...] | None:
    """El comando de transporte a un modelo. Compartido por T2 y el evaluador: los dos
    hablan por el mismo canal (transporte), con roles distintos.

    Devuelve None cuando el subcomando deja `--llm-cli` sin defecto y nadie lo nombro:
    es como se distingue "no me han dicho que modelo" de "usa el de siempre". Solo lo ve
    quien lo pide (`generar-inyecciones`), porque para el la version barata del comando es
    no llamar a nadie."""
    if getattr(args, "comando_llm", None):
        # posix=False conserva las barras de Windows; las comillas se quitan a mano.
        return tuple(t.strip('"') for t in shlex.split(args.comando_llm, posix=False))
    preset = getattr(args, "llm_cli", None)
    return COMANDOS_CLI[preset] if preset else None


def _proveedor(args: argparse.Namespace) -> ProveedorHeuristico | ProveedorLLM:
    if args.proveedor == "heuristico":
        return ProveedorHeuristico()
    return ProveedorLLM(TransporteCLI(_comando_llm(args)))


def _mostrar_dictamen(args: argparse.Namespace, propuesta, interruptor) -> None:
    """El evaluador adversarial (regla 10, ADR 0007). ADVISORY: se imprime y se audita,
    pero no toca el veredicto ni el codigo de salida. Si el canal cae, se dice y se
    sigue — un evaluador caido no puede parar una contencion."""
    dictamen = EvaluadorAdversarial(
        TransporteCLI(_comando_llm(args)), interruptor.auditoria
    ).evaluar(propuesta)
    if dictamen.sin_dictamen:
        print("evaluador adversarial: sin dictamen (canal caido, advisory)")
        return
    if dictamen.limpio:
        print("evaluador adversarial: sin objeciones (advisory)")
        return
    print("evaluador adversarial (ADVISORY, no bloquea):")
    for objecion in dictamen.con_objecion:
        print(f"  ! [{objecion.lente}] {objecion.motivo}")
