"""`guardia` — la linea de mando determinista.

Por defecto nada de lo que se hace desde aqui pasa por un modelo. Es a proposito: el
camino de recuperacion de un incidente no puede depender de que una inferencia
conteste. El unico modelo alcanzable es el triaje con `responder --proveedor llm`,
que es opt-in, y si su transporte cae el ciclo se recupera con el heuristico.

El paquete esta partido por AUTORIDAD, no por tamano: `control` manda sobre el
interruptor y el log, `propuestas` recorre el ciclo de una propuesta hasta produccion,
y `medicion` no manda sobre nada — solo mide, y es lo unico que puede gastar cuota.
Esa frontera es la que hace leible el reparto: si un comando de `medicion` acabara
aplicando politica, estaria en el modulo equivocado y se veria.
"""

from __future__ import annotations

import sys

from ..eventos import CorpusIlegible
from ..kill_switch import ControlInvalido
from ..transporte import ModeloProhibido
from ._comun import (
    BENIGNO_POR_DEFECTO,
    INCIDENTE_POR_DEFECTO,
    INYECCIONES_POR_DEFECTO,
    RAIZ,
    EntradaIlegible,
)
from .parser import construir_parser

__all__ = [
    "BENIGNO_POR_DEFECTO",
    "INCIDENTE_POR_DEFECTO",
    "INYECCIONES_POR_DEFECTO",
    "RAIZ",
    "EntradaIlegible",
    "construir_parser",
    "main",
]


def main(argv: list[str] | None = None) -> int:
    args = construir_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (CorpusIlegible, EntradaIlegible) as e:
        # Un fichero que falta es error de USO, no un fallo del sistema: se dice y se
        # sale, sin traceback. Va aqui y no en cada subcomando a proposito — el
        # tratamiento es el mismo para todos y repetirlo garantiza olvidarlo en el
        # proximo. Mismo codigo (2) que una propuesta que no encaja: la entrada que
        # nos dieron no sirve.
        print(f"ENTRADA ILEGIBLE: {e}", file=sys.stderr)
        return 2
    except ControlInvalido as e:
        # La otra mitad del mismo contrato: la ruta de CONTROL tampoco es del sistema,
        # nos la dio quien invoca (--control o GUARDIA_CONTROL_DIR). Prefijo propio
        # porque la correccion es distinta: no es "dame otro fichero", es "esa ruta
        # no puede ser un directorio de control".
        print(f"CONTROL INVALIDO: {e}", file=sys.stderr)
        return 2
    except ModeloProhibido as e:
        # Se presenta como un rechazo con su motivo, no como un traceback ni como un
        # apano silencioso. Codigo propio: quien automatice esto distingue "no se pudo
        # medir por politica" de "se midio y salio mal".
        print(f"RECHAZADO (modelo bajo el suelo de evaluacion): {e}")
        return 10
