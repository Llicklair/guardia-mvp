"""El interruptor de emergencia. Regla 8."""

from __future__ import annotations

import pytest

from guardia.actores import Actor, SinAutoridad
from guardia.kill_switch import CapaCongelada, Interruptor


@pytest.fixture
def interruptor(tmp_path):
    return Interruptor(tmp_path / "control")


def test_nace_congelado_sin_estado_en_disco(interruptor):
    """Fail-closed: una instalacion nueva no puede escribir politica hasta que un
    humano la arma. Lo contrario seria dar autoridad por omision."""
    assert interruptor.estado().congelado


def test_estado_ilegible_es_congelado(interruptor):
    interruptor.descongelar(Actor.HUMANO, "arranque")
    interruptor.ruta_estado.write_text("{ esto no es json", encoding="utf-8")

    estado = interruptor.estado()

    assert estado.congelado
    assert "ilegible" in estado.motivo


def test_congelar_y_descongelar_cambian_el_estado(interruptor):
    interruptor.descongelar(Actor.HUMANO, "arranque")
    assert interruptor.estado().operativo

    interruptor.congelar(Actor.HUMANO, "incidente en curso")

    assert interruptor.estado().congelado
    assert interruptor.estado().motivo == "incidente en curso"


def test_la_ia_no_puede_congelar(interruptor):
    """Congelar es seguro para T0/T1 pero apaga la adaptacion: dejarselo al modelo
    seria un DoS por inyeccion de prompt."""
    with pytest.raises(SinAutoridad):
        interruptor.congelar(Actor.IA, "urgente, confia en mi")


def test_la_ia_no_puede_descongelar(interruptor):
    interruptor.congelar(Actor.HUMANO, "incidente")

    with pytest.raises(SinAutoridad):
        interruptor.descongelar(Actor.IA, "ya esta resuelto, palabra")

    assert interruptor.estado().congelado


def test_el_automata_no_puede_descongelar(interruptor):
    """Ni el codigo determinista: un descongelado automatico es no tener interruptor."""
    interruptor.congelar(Actor.AUTOMATA, "dead-man's switch")

    with pytest.raises(SinAutoridad):
        interruptor.descongelar(Actor.AUTOMATA, "ha pasado el rato")


def test_el_intento_denegado_queda_en_el_log(interruptor):
    with pytest.raises(SinAutoridad):
        interruptor.congelar(Actor.IA, "intento")

    eventos = [e.evento for e in interruptor.auditoria.leer()]

    assert "congelar_denegado" in eventos


def test_exigir_operativo_bloquea_con_la_capa_congelada(interruptor):
    interruptor.congelar(Actor.HUMANO, "incidente")

    with pytest.raises(CapaCongelada):
        interruptor.exigir_operativo()


def test_exigir_operativo_lee_disco_y_no_cachea(tmp_path):
    """Un proceso vivo tiene que enterarse de que lo acaban de congelar. Si cacheara,
    el interruptor solo valdria para procesos que aun no han arrancado."""
    directorio = tmp_path / "control"
    en_marcha = Interruptor(directorio)
    en_marcha.descongelar(Actor.HUMANO, "arranque")
    en_marcha.exigir_operativo()

    Interruptor(directorio).congelar(Actor.HUMANO, "otro proceso lo congela")

    with pytest.raises(CapaCongelada):
        en_marcha.exigir_operativo()


def test_congelar_es_idempotente(interruptor):
    interruptor.congelar(Actor.HUMANO, "primera")
    interruptor.congelar(Actor.HUMANO, "segunda")

    assert interruptor.estado().motivo == "segunda"
