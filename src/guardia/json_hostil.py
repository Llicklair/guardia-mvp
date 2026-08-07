"""El guardia de anidamiento para JSON de origen hostil.

Nacio en `politica` (el fuzzing enseno que 20000 corchetes son 40 KB — por debajo
del guardia de tamano — y revientan la pila DENTRO de `json.loads`, con el
`RecursionError` saliendo crudo). Pero el mismo hueco estaba en cada sitio que
parsea JSON escrito por un adversario: la telemetria (`eventos`), la salida de un
modelo (`triaje`, `evaluador`, `generador`) y el log en disco (`auditoria`, donde
una linea manipulada mataba al detector en vez de dar `CadenaRota`).

Cinco consumidores que no se conocen entre si: el guardia vive aqui, en una hoja
que tampoco los conoce — como `transporte`. La propiedad que protege es la misma
en todos: toda entrada -> objeto valido O error del dominio del llamante, nunca
otra excepcion. El pre-chequeo es la primera linea (no quema pila ni CPU);
capturar `RecursionError` en el llamante es la segunda.
"""

from __future__ import annotations

# Un JSON legitimo del sistema anida poco (una propuesta 3 niveles; un evento, 2).
# 32 deja margen de sobra sin dejar que un anidado hostil queme pila o CPU en
# json.loads.
PROFUNDIDAD_MAXIMA = 32


def demasiado_anidado(texto: str) -> bool:
    """Cuenta profundidad estructural sin parsear: O(n) con salida temprana.

    Los corchetes dentro de un string JSON no son estructura — sin distinguirlos,
    una descripcion con corchetes seria un falso positivo y el guardia rechazaria
    entradas validas.
    """
    profundidad = 0
    en_cadena = False
    escapado = False
    for c in texto:
        if en_cadena:
            if escapado:
                escapado = False
            elif c == "\\":
                escapado = True
            elif c == '"':
                en_cadena = False
        elif c == '"':
            en_cadena = True
        elif c in "[{":
            profundidad += 1
            if profundidad > PROFUNDIDAD_MAXIMA:
                return True
        elif c in "]}":
            profundidad -= 1
    return False
