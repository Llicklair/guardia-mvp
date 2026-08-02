"""Aplicacion real: canary, dead-man's switch y limite de tasa. §5.5 — el modo de
fallo mas probable del sistema, asi que el que mas tests merece.

El reloj se inyecta: nada de sleeps. `reloj` es una lista mutable de un elemento para
poder avanzar el tiempo a mano y disparar el dead-man de forma determinista.
"""

from __future__ import annotations

import pytest

from guardia.actores import Actor, SinAutoridad
from guardia.aplicador import Aplicador
from guardia.crisol import Crisol
from guardia.despliegue import Config, Despliegue, Estado
from guardia.eventos import Corpus, EventoRed
from guardia.kill_switch import Interruptor
from guardia.politica import desde_dict


def _ip(s):
    import ipaddress

    return ipaddress.ip_address(s)


@pytest.fixture
def reloj():
    t = [1000.0]
    return t


@pytest.fixture
def despliegue(tmp_path, reloj):
    interruptor = Interruptor(tmp_path / "control")
    interruptor.descongelar(Actor.HUMANO, "arranque")
    crisol = Crisol(
        interruptor=interruptor,
        aplicador=Aplicador(tmp_path / "sandbox.json"),
        benigno=Corpus("benigno", (EventoRed("salida", 443, _ip("10.0.0.20"), "https"),)),
        incidente=Corpus("inc", (EventoRed("salida", 4444, _ip("203.0.113.7"), "c2"),)),
    )
    return Despliegue(
        crisol=crisol,
        directorio=tmp_path / "despliegue",
        config=Config(plazo_canary_s=100.0, ventana_tasa_s=1000.0, max_cambios_ventana=3),
        ahora=lambda: reloj[0],
    )


def _corta_c2(id="c2"):
    return desde_dict(
        {
            "id": id,
            "tipo": "filtro_red",
            "descripcion": "corta el C2",
            "cuerpo": {
                "accion": "bloquear",
                "direccion": "salida",
                "puertos": [4444],
                "cidr": "203.0.113.0/24",
            },
        }
    )


def _lockout():
    return desde_dict(
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


def test_una_propuesta_correcta_se_aplica_en_canary(despliegue):
    despacho = despliegue.desplegar(_corta_c2())

    assert despacho.estado is Estado.APLICADO_CANARY
    assert len(despliegue.politica_activa()) == 1
    assert len(despliegue.canarios_activos()) == 1


def test_una_propuesta_que_falla_un_gate_no_se_aplica(despliegue):
    """Un lockout es BLOCKER en el crisol: no llega a produccion."""
    despacho = despliegue.desplegar(_lockout())

    assert despacho.estado is Estado.RECHAZADO_GATE
    assert despliegue.politica_activa() == []


def test_el_deadman_revierte_lo_no_confirmado(despliegue, reloj):
    despliegue.desplegar(_corta_c2())
    assert len(despliegue.politica_activa()) == 1

    reloj[0] += 101  # pasa el plazo de 100s sin confirmar
    revertidos = despliegue.revisar()

    assert revertidos == ["c2"]
    assert despliegue.politica_activa() == []
    assert despliegue.canarios_activos() == []


def test_un_canary_confirmado_sobrevive_al_deadman(despliegue, reloj):
    despliegue.desplegar(_corta_c2())
    despliegue.confirmar("c2", Actor.HUMANO)

    reloj[0] += 500  # muy pasado el plazo
    revertidos = despliegue.revisar()

    assert revertidos == []
    assert len(despliegue.politica_activa()) == 1


def test_solo_un_humano_confirma(despliegue):
    despliegue.desplegar(_corta_c2())

    with pytest.raises(SinAutoridad):
        despliegue.confirmar("c2", Actor.IA)
    with pytest.raises(SinAutoridad):
        despliegue.confirmar("c2", Actor.AUTOMATA)


def test_antes_del_plazo_el_deadman_no_toca_nada(despliegue, reloj):
    despliegue.desplegar(_corta_c2())

    reloj[0] += 99  # aun dentro del plazo de 100s
    assert despliegue.revisar() == []
    assert len(despliegue.politica_activa()) == 1


def test_el_limite_de_tasa_frena_el_goteo(despliegue):
    """max_cambios_ventana=3: el cuarto cambio en la ventana se rechaza aunque pase
    los gates. Es el freno anti auto-DoS."""
    for i in range(3):
        assert despliegue.desplegar(_corta_c2(f"ok{i}")).estado is Estado.APLICADO_CANARY

    cuarto = despliegue.desplegar(_corta_c2("uno-de-mas"))

    assert cuarto.estado is Estado.RECHAZADO_TASA
    assert len(despliegue.politica_activa()) == 3  # el cuarto no entro


def test_la_ventana_de_tasa_se_desliza(despliegue, reloj):
    """Pasada la ventana, el cupo se recupera: el limite es por ventana, no total."""
    for i in range(3):
        despliegue.desplegar(_corta_c2(f"ok{i}"))
    assert despliegue.desplegar(_corta_c2("frenado")).estado is Estado.RECHAZADO_TASA

    reloj[0] += 1001  # toda la ventana de 1000s ha pasado

    assert despliegue.desplegar(_corta_c2("ya-cabe")).estado is Estado.APLICADO_CANARY


def test_el_rechazo_por_tasa_no_consume_cupo(despliegue):
    """Un rechazo por gate no cuenta como cambio aplicado: solo los aplicados gastan
    cupo. Si no, un atacante agotaria el limite con propuestas invalidas."""
    for _ in range(5):
        despliegue.desplegar(_lockout())  # todas BLOCKER, no aplican

    # el cupo sigue intacto: una correcta entra
    assert despliegue.desplegar(_corta_c2()).estado is Estado.APLICADO_CANARY


def test_el_deadman_deja_la_auditoria_intacta(despliegue, reloj):
    despliegue.desplegar(_corta_c2())
    reloj[0] += 101
    despliegue.revisar()

    veredicto = despliegue.auditoria.verificar()
    assert veredicto.intacta
    eventos = [e.evento for e in despliegue.auditoria.leer()]
    assert "canary_revertido_deadman" in eventos
