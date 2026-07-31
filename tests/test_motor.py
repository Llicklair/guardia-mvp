"""El motor de replay determinista."""

from __future__ import annotations

from ipaddress import ip_address

import pytest

from guardia.eventos import EventoFichero, EventoRed
from guardia.motor import ReplayNoSoportado, dispara
from guardia.politica import desde_dict


def _filtro(direccion="salida", puertos=(4444,), cidr="203.0.113.0/24"):
    return desde_dict(
        {
            "id": "f",
            "tipo": "filtro_red",
            "descripcion": "d",
            "cuerpo": {
                "accion": "bloquear",
                "direccion": direccion,
                "puertos": list(puertos),
                "cidr": cidr,
            },
        }
    )


def _red(direccion="salida", puerto=4444, ip="203.0.113.7"):
    return EventoRed(direccion=direccion, puerto=puerto, ip=ip_address(ip))


def test_filtro_dispara_sobre_conexion_del_c2():
    assert dispara(_filtro(), _red())


def test_filtro_no_dispara_sobre_otra_ip():
    """La misma puerta (4444) a una IP interna no es el C2."""
    assert not dispara(_filtro(), _red(ip="10.0.0.40"))


def test_filtro_no_dispara_sobre_otro_puerto():
    assert not dispara(_filtro(), _red(puerto=443))


def test_filtro_no_dispara_en_otra_direccion():
    assert not dispara(_filtro(), _red(direccion="entrada"))


def test_filtro_no_dispara_sobre_evento_de_otro_tipo():
    assert not dispara(_filtro(), EventoFichero(ruta="/etc/passwd", syscall="read"))


def _confinamiento(rutas):
    return desde_dict(
        {
            "id": "c",
            "tipo": "confinamiento",
            "descripcion": "d",
            "cuerpo": {"perfil": "p", "rutas_denegadas": list(rutas), "syscalls_denegadas": []},
        }
    )


def test_confinamiento_dispara_sobre_ruta_denegada():
    evento = EventoFichero(ruta="/etc/shadow", syscall="read")

    assert dispara(_confinamiento(["/etc/shadow"]), evento)


def test_confinamiento_dispara_sobre_ruta_por_debajo():
    evento = EventoFichero(ruta="/root/.ssh/id_rsa", syscall="read")

    assert dispara(_confinamiento(["/root"]), evento)


def test_confinamiento_no_confunde_rutas_vecinas():
    """'/var/lib' no contiene a '/var/libreria' — comparar por segmentos, no por
    prefijo de cadena."""
    evento = EventoFichero(ruta="/var/libreria/datos", syscall="read")

    assert not dispara(_confinamiento(["/var/lib"]), evento)


def test_regla_deteccion_no_es_replayable():
    """Honestidad de alcance: no se aproxima el lenguaje de Falco, se declara."""
    regla = desde_dict(
        {
            "id": "r",
            "tipo": "regla_deteccion",
            "descripcion": "d",
            "cuerpo": {"motor": "falco", "condicion": "spawned_process", "salida": "x"},
        }
    )

    with pytest.raises(ReplayNoSoportado):
        dispara(regla, _red())
