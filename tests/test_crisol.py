"""Los cuatro gates de la regla 6. El test que decide si el crisol gatea o es teatro.

Cada gate se prueba con una propuesta escrita para fallar EN ESE gate y pasar los
anteriores, mas el caso que pasa los cuatro. Si cualquiera de estos dejara de
rechazar, un cambio malo llegaria a aplicarse.
"""

from __future__ import annotations

import pytest

from guardia.actores import Actor
from guardia.aplicador import Aplicador
from guardia.crisol import Crisol, Resultado
from guardia.eventos import Corpus, EventoProceso, EventoRed
from guardia.kill_switch import Interruptor
from guardia.politica import desde_dict


def _ip(s):
    import ipaddress

    return ipaddress.ip_address(s)


@pytest.fixture
def benigno():
    return Corpus(
        "benigno",
        (
            EventoRed("salida", 443, _ip("10.0.0.20"), "https-interno"),
            EventoRed("salida", 4444, _ip("10.0.0.40"), "servicio-interno-en-4444"),
        ),
    )


@pytest.fixture
def incidente():
    return Corpus(
        "incidente-0001",
        (
            EventoRed("salida", 4444, _ip("203.0.113.7"), "reverse-shell"),
            EventoProceso("bash", ("bash", "sh", "python3"), "bash -i", True, "shell-inversa"),
        ),
    )


@pytest.fixture
def crisol(tmp_path, benigno, incidente):
    interruptor = Interruptor(tmp_path / "control")
    interruptor.descongelar(Actor.HUMANO, "arranque del test")
    return Crisol(
        interruptor=interruptor,
        aplicador=Aplicador(tmp_path / "sandbox.json"),
        benigno=benigno,
        incidente=incidente,
    )


def _corta_c2(id="ok"):
    """La propuesta correcta: corta el egress al C2 por IP+puerto. Dispara sobre el
    incidente, no sobre el benigno."""
    return desde_dict(
        {
            "id": id,
            "tipo": "filtro_red",
            "descripcion": "corta el C2",
            "cuerpo": {
                "accion": "bloquear",
                "direccion": "salida",
                "puertos": [4444, 9001],
                "cidr": "203.0.113.0/24",
            },
        }
    )


def test_la_propuesta_correcta_pasa_los_cuatro_gates(crisol):
    veredicto = crisol.evaluar(_corta_c2())

    assert veredicto.resultado is Resultado.PASS
    assert veredicto.aplicable


def test_gate_0_con_la_capa_congelada_no_se_evalua(tmp_path, benigno, incidente):
    interruptor = Interruptor(tmp_path / "control")
    interruptor.congelar(Actor.HUMANO, "incidente")
    crisol = Crisol(interruptor, Aplicador(tmp_path / "s.json"), benigno, incidente)

    veredicto = crisol.evaluar(_corta_c2())

    assert veredicto.resultado is Resultado.REJECT
    assert veredicto.gate == "gate-0-interruptor"


def test_gate_1_invariante_es_blocker(crisol):
    """Bloquear el SSH del admin: no llega ni al replay."""
    lockout = desde_dict(
        {
            "id": "lockout",
            "tipo": "filtro_red",
            "descripcion": "cierra ssh",
            "cuerpo": {
                "accion": "bloquear",
                "direccion": "entrada",
                "puertos": [22],
                "cidr": "10.0.0.0/24",
            },
        }
    )

    veredicto = crisol.evaluar(lockout)

    assert veredicto.resultado is Resultado.BLOCKER
    assert veredicto.gate == "gate-1-invariantes"


def test_gate_2_falso_positivo_sobre_benigno(crisol):
    """Bloquear TODO el 4444 saliente pilla el servicio interno legitimo del benigno."""
    ancho = desde_dict(
        {
            "id": "ancho",
            "tipo": "filtro_red",
            "descripcion": "bloquea todo el 4444",
            "cuerpo": {
                "accion": "bloquear",
                "direccion": "salida",
                "puertos": [4444],
                "cidr": "0.0.0.0/0",
            },
        }
    )

    veredicto = crisol.evaluar(ancho)

    assert veredicto.resultado is Resultado.REJECT
    assert veredicto.gate == "gate-2-replay-benigno"


def test_gate_3_no_dispara_sobre_el_incidente(crisol):
    """Una regla que no cubre el repro: bloquea una IP que no es la del C2."""
    fallona = desde_dict(
        {
            "id": "fallona",
            "tipo": "filtro_red",
            "descripcion": "bloquea otra red",
            "cuerpo": {
                "accion": "bloquear",
                "direccion": "salida",
                "puertos": [4444],
                "cidr": "198.51.100.0/24",
            },
        }
    )

    veredicto = crisol.evaluar(fallona)

    assert veredicto.resultado is Resultado.REJECT
    assert veredicto.gate == "gate-3-replay-malicioso"


def test_gate_replay_no_soportado_para_deteccion(crisol):
    """Una regla_deteccion no se puede replayar aqui: REJECT honesto, no falso PASS."""
    regla = desde_dict(
        {
            "id": "det",
            "tipo": "regla_deteccion",
            "descripcion": "shell del servidor",
            "cuerpo": {"motor": "falco", "condicion": "spawned_process", "salida": "x"},
        }
    )

    veredicto = crisol.evaluar(regla)

    assert veredicto.resultado is Resultado.REJECT
    assert veredicto.gate == "gate-replay-no-soportado"


def test_el_crisol_deja_el_sandbox_limpio(crisol):
    """Tras evaluar (pase o falle), el estado del sandbox vuelve a vacio: el gate 4
    aplica y revierte, no deja residuo."""
    crisol.evaluar(_corta_c2())

    assert crisol.aplicador.activas() == []


def test_cada_veredicto_queda_en_la_auditoria(crisol):
    crisol.evaluar(_corta_c2())

    eventos = [e.evento for e in crisol.interruptor.auditoria.leer()]
    assert "crisol_veredicto" in eventos


def test_la_cadena_de_auditoria_sigue_intacta_tras_el_crisol(crisol):
    crisol.evaluar(_corta_c2())

    assert crisol.interruptor.auditoria.verificar().intacta
