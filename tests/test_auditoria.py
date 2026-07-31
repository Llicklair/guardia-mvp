"""El log encadenado. Invariante 7: una manipulacion se tiene que notar."""

from __future__ import annotations

import json

import pytest

from guardia.auditoria import GENESIS, Auditoria, _hash


@pytest.fixture
def auditoria(tmp_path):
    return Auditoria(tmp_path / "auditoria.jsonl")


def test_log_vacio_es_cadena_intacta(auditoria):
    veredicto = auditoria.verificar()

    assert veredicto.intacta
    assert veredicto.entradas == 0


def test_la_primera_entrada_ancla_en_genesis(auditoria):
    entrada = auditoria.registrar("congelado", "humano", motivo="prueba")

    assert entrada.seq == 1
    assert entrada.previo == GENESIS


def test_las_entradas_encadenan(auditoria):
    primera = auditoria.registrar("congelado", "humano")
    segunda = auditoria.registrar("descongelado", "humano")

    assert segunda.previo == primera.hash
    assert auditoria.verificar().intacta


def test_alterar_el_contenido_rompe_la_cadena(auditoria):
    auditoria.registrar("congelado", "humano", motivo="incidente real")
    auditoria.registrar("descongelado", "humano")

    lineas = auditoria.ruta.read_text(encoding="utf-8").splitlines()
    crudo = json.loads(lineas[0])
    crudo["datos"]["motivo"] = "rutina, nada que ver aqui"
    lineas[0] = json.dumps(crudo, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    auditoria.ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    veredicto = auditoria.verificar()

    assert not veredicto.intacta
    assert veredicto.rota_en == 1


def test_borrar_una_entrada_intermedia_rompe_la_cadena(auditoria):
    for i in range(3):
        auditoria.registrar("evento", "humano", i=i)

    lineas = auditoria.ruta.read_text(encoding="utf-8").splitlines()
    auditoria.ruta.write_text("\n".join([lineas[0], lineas[2]]) + "\n", encoding="utf-8")

    assert not auditoria.verificar().intacta


def test_truncar_por_el_final_no_se_detecta(auditoria):
    """El limite honesto: quitar las ultimas lineas deja una cadena valida mas corta.

    El hash encadenado detecta alteracion y borrado intermedio, no truncado por la
    cola. Para eso hace falta exportar fuera de la maquina — y por eso el invariante
    dice 'idealmente exportado', no 'append-only y ya'.
    """
    for i in range(3):
        auditoria.registrar("evento", "humano", i=i)

    lineas = auditoria.ruta.read_text(encoding="utf-8").splitlines()
    auditoria.ruta.write_text(lineas[0] + "\n", encoding="utf-8")

    veredicto = auditoria.verificar()

    assert veredicto.intacta
    assert veredicto.entradas == 1


def test_una_linea_ilegible_es_cadena_rota(auditoria):
    auditoria.registrar("evento", "humano")
    with auditoria.ruta.open("a", encoding="utf-8") as f:
        f.write("basura que alguien metio a mano\n")

    assert not auditoria.verificar().intacta


def test_el_orden_de_las_claves_no_cambia_el_hash():
    """El hash se calcula sobre serializacion canonica; si dependiera del orden de
    insercion del dict, la verificacion fallaria segun como se hubiera construido el
    payload. Se prueba sobre _hash y no sobre registrar() porque el ts real haria el
    test intermitente al cruzar un segundo."""
    payload = {"seq": 1, "ts": "2026-07-31T10:00:00+00:00", "evento": "x", "actor": "humano"}

    directo = _hash(GENESIS, {**payload, "datos": {"a": 1, "b": 2}})
    al_reves = _hash(GENESIS, {"datos": {"b": 2, "a": 1}, **payload})

    assert directo == al_reves
