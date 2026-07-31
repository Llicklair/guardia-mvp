"""Los invariantes intocables. Regla 7."""

from __future__ import annotations

from ipaddress import ip_network

import pytest

from guardia.invariantes import Config, comprobar, es_admisible
from guardia.politica import desde_dict


def _filtro(accion="bloquear", direccion="entrada", puertos=(22,), cidr="10.0.0.0/24"):
    return desde_dict(
        {
            "id": "p",
            "tipo": "filtro_red",
            "descripcion": "d",
            "cuerpo": {
                "accion": accion,
                "direccion": direccion,
                "puertos": list(puertos),
                "cidr": cidr,
            },
        }
    )


def _confinamiento(rutas=(), syscalls=()):
    return desde_dict(
        {
            "id": "p",
            "tipo": "confinamiento",
            "descripcion": "d",
            "cuerpo": {
                "perfil": "perfil",
                "rutas_denegadas": list(rutas),
                "syscalls_denegadas": list(syscalls),
            },
        }
    )


def test_bloquear_ssh_del_admin_viola_el_canal():
    violaciones = comprobar(_filtro())

    assert [v.invariante for v in violaciones] == ["canal-admin"]


def test_bloquear_todo_entrante_alcanza_al_admin():
    """0.0.0.0/0 no menciona al admin y aun asi lo deja fuera. Es el modo de fallo
    mas probable del sistema: el defensor tumbandose a si mismo."""
    violaciones = comprobar(_filtro(cidr="0.0.0.0/0", puertos=(22, 80, 443)))

    assert violaciones
    assert violaciones[0].invariante == "canal-admin"


def test_permitir_no_es_lockout():
    assert es_admisible(_filtro(accion="permitir"))


def test_salida_no_es_lockout():
    """Cerrar el 22 de salida no deja fuera al admin: entra, no sale."""
    assert es_admisible(_filtro(direccion="salida"))


def test_otro_puerto_no_toca_el_canal():
    assert es_admisible(_filtro(puertos=(8080,)))


def test_rango_ajeno_no_toca_el_canal():
    assert es_admisible(_filtro(cidr="192.168.50.0/24"))


def test_config_a_medida_cambia_que_es_intocable():
    config = Config(cidr_admin=ip_network("192.168.50.0/24"), puertos_admin=(2222,))

    assert comprobar(_filtro(cidr="192.168.50.0/24", puertos=(2222,)), config)
    assert es_admisible(_filtro(), config)


@pytest.mark.parametrize("ruta", ["/var/lib/guardia", "/var/log/guardia", "/opt/guardia"])
def test_denegar_una_ruta_protegida(ruta):
    violaciones = comprobar(_confinamiento(rutas=[ruta]))

    assert [v.invariante for v in violaciones] == ["rutas-protegidas"]


@pytest.mark.parametrize("ruta", ["/", "/var", "/var/lib", "/opt"])
def test_denegar_por_encima_tambien_alcanza(ruta):
    """Denegar el padre mata al hijo sin nombrarlo. Si esto no se comprobara, el
    invariante se esquivaria escribiendo una ruta mas corta."""
    assert comprobar(_confinamiento(rutas=[ruta]))


@pytest.mark.parametrize("ruta", ["/var/lib/otracosa", "/home", "/etc/shadow", "/var/libreria"])
def test_rutas_vecinas_no_disparan(ruta):
    """'/var/libreria' empieza igual que '/var/lib' en texto plano; comparar cadenas
    en vez de segmentos daria un falso positivo aqui."""
    assert es_admisible(_confinamiento(rutas=[ruta]))


def test_ruta_relativa_no_dispara():
    assert es_admisible(_confinamiento(rutas=["var/lib/guardia"]))


@pytest.mark.parametrize("syscall", ["write", "fsync", "rename", "openat"])
def test_denegar_syscalls_vitales_ciega_el_registro(syscall):
    violaciones = comprobar(_confinamiento(syscalls=[syscall]))

    assert [v.invariante for v in violaciones] == ["capacidad-de-registro"]


def test_denegar_syscalls_peligrosas_si_es_admisible():
    assert es_admisible(_confinamiento(syscalls=["ptrace", "mount", "kexec_load"]))


def test_se_devuelven_todas_las_violaciones():
    """Una propuesta que viola tres invariantes dice algo distinto de una que viola
    uno; parar en la primera esconde esa diferencia."""
    propuesta = _confinamiento(rutas=["/var/lib/guardia", "/opt/guardia"], syscalls=["write"])

    invariantes = [v.invariante for v in comprobar(propuesta)]

    assert invariantes.count("rutas-protegidas") == 2
    assert "capacidad-de-registro" in invariantes


def test_una_regla_de_deteccion_no_toca_invariantes():
    propuesta = desde_dict(
        {
            "id": "p",
            "tipo": "regla_deteccion",
            "descripcion": "d",
            "cuerpo": {"motor": "falco", "condicion": "spawned_process", "salida": "algo"},
        }
    )

    assert es_admisible(propuesta)
