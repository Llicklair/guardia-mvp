"""El interruptor de emergencia. Regla 8."""

from __future__ import annotations

import dataclasses

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


def test_el_estado_leido_no_se_puede_descongelar_en_memoria(interruptor):
    """`frozen=True` en Estado es fail-closed en memoria, no cosmetica: si el
    estado que devuelve estado() fuera mutable, cualquier codigo con una
    referencia podria ponerle `congelado = False` sin pasar por descongelar()
    — es decir, sin actor, sin motivo y sin entrada en la auditoria, que es
    justo lo que la regla 8 existe para impedir.

    Nadie lo afirmaba: quitar el `frozen` dejaba la suite entera en verde
    (encontrado con mutacion, 8-ago)."""
    estado = interruptor.estado()

    with pytest.raises(dataclasses.FrozenInstanceError):
        estado.congelado = False  # type: ignore[misc]


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


def test_ruta_de_control_que_es_un_fichero_es_error_de_dominio(tmp_path):
    """La propiedad de frontera, ahora tambien en la ruta de control: toda ruta →
    Interruptor valido O ControlInvalido, nunca otra excepcion. `mkdir(exist_ok=True)`
    solo tolera directorios: apuntar --control a un fichero salia como FileExistsError
    crudo (lo capturo gb en el barrido del 7-ago por tres rutas distintas)."""
    from guardia.kill_switch import ControlInvalido

    fichero = tmp_path / "no-soy-directorio.json"
    fichero.write_text("{}", encoding="utf-8")

    with pytest.raises(ControlInvalido):
        Interruptor(fichero)
    with pytest.raises(ControlInvalido):
        Interruptor(fichero / "hijo-de-un-fichero")


def test_por_la_cli_control_invalido_se_dice_sin_traceback(tmp_path, capsys):
    """El mismo caso como lo vive quien teclea: exit 2 y un motivo, no un traceback."""
    from guardia.cli import main

    fichero = tmp_path / "estado-que-no-es-dir.json"
    fichero.write_text("{}", encoding="utf-8")

    codigo = main(["--control", str(fichero), "estado"])
    salida = capsys.readouterr()
    assert codigo == 2
    assert "CONTROL INVALIDO" in salida.err
    assert "Traceback" not in salida.err
