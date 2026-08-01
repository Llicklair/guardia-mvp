"""El informe de estado: una vista de solo lectura, y a prueba de dato hostil.

Lo que se vigila:
1. **Regla 4 en el navegador.** El log lleva texto que escribio el atacante (cmdline,
   etiquetas con inyecciones). Al renderizarlo a HTML es hostil: si no se escapa, una
   etiqueta con `<script>` se ejecuta en el panel del operador. El test lo comprueba con
   un payload real.
2. **Que la vista dice la verdad del estado:** congelada vs operativa, cadena intacta vs
   rota, y que las decisiones del log aparecen.
"""

from __future__ import annotations

import sys

from guardia.auditoria import Entrada, Veredicto
from guardia.cli import main
from guardia.informe import render
from guardia.kill_switch import Estado

_PYTHON = sys.executable


def _estado(congelado=False, motivo="banco de pruebas"):
    return Estado(congelado=congelado, motivo=motivo, desde="2026-08-01T00:00:00", actor="humano")


def _intacta(n=1):
    return Veredicto(intacta=True, entradas=n)


def _ent(seq, evento, actor, datos=None):
    """Una entrada del log con la cadena rellena de relleno: el informe no la usa (solo
    lee seq/ts/evento/actor/datos), asi que previo/hash valen cualquier cosa aqui."""
    return Entrada(
        seq=seq, ts=f"t{seq}", evento=evento, actor=actor, datos=datos or {}, previo="-", hash="-"
    )


# ── Regla 4: el dato hostil se escapa, nunca se ejecuta ──────────────────────

_XSS = '<script>alert("pwned")</script>'


def test_una_inyeccion_en_el_log_se_escapa_no_se_ejecuta():
    """El caso que hace del informe algo seguro y no un agujero: una etiqueta con un
    payload no puede convertirse en markup del panel."""
    entrada = _ent(1, "triaje_propuso", "ia", {"cmdline": f"bash -i {_XSS}"})
    salida = render(_estado(), [entrada], _intacta(), "2026-08-01T00:00:02")
    assert _XSS not in salida  # el payload crudo NO aparece
    assert "&lt;script&gt;" in salida  # aparece escapado, como texto


def test_tambien_se_escapa_el_motivo_del_estado_y_el_evento():
    """El escape es de todo lo dinamico, no solo de los datos: el motivo lo puede fijar
    un humano, pero el evento y el actor vienen de un log que es dato."""
    estado = _estado(congelado=True, motivo=_XSS)
    salida = render(estado, [_ent(1, _XSS, "automata")], _intacta(), "gen")
    assert _XSS not in salida
    assert salida.count("&lt;script&gt;") >= 2  # motivo + evento


# ── La vista dice la verdad ──────────────────────────────────────────────────


def test_muestra_la_capa_congelada():
    salida = render(_estado(congelado=True), [], _intacta(0), "gen")
    assert "CONGELADA" in salida
    assert "T0/T1 siguen protegiendo" in salida


def test_muestra_la_capa_operativa():
    salida = render(_estado(congelado=False), [], _intacta(0), "gen")
    assert "operativa" in salida
    assert "CONGELADA" not in salida


def test_muestra_la_cadena_intacta():
    salida = render(_estado(), [], Veredicto(intacta=True, entradas=7), "gen")
    assert "intacta" in salida
    assert "7" in salida


def test_muestra_la_cadena_rota_y_avisa_de_que_el_estado_no_es_de_fiar():
    roto = Veredicto(intacta=False, entradas=3, rota_en=2, motivo="el enlace previo no cuadra")
    salida = render(_estado(), [], roto, "gen")
    assert "CADENA ROTA" in salida
    assert "#2" in salida
    assert "NO es de fiar" in salida


def test_las_decisiones_del_log_aparecen_en_la_linea_de_tiempo():
    entradas = [
        _ent(1, "descongelado", "humano", {"motivo": "arranque"}),
        _ent(2, "triaje_propuso", "ia", {"id": "corta-c2"}),
        _ent(3, "canary_aplicado", "automata"),
    ]
    salida = render(_estado(), entradas, _intacta(3), "gen")
    for evento in ("descongelado", "triaje_propuso", "canary_aplicado"):
        assert evento in salida
    # los tres actores, con su chip
    for actor in ("humano", "ia", "automata"):
        assert actor in salida


def test_el_log_vacio_no_miente_con_una_tabla_en_blanco():
    salida = render(_estado(), [], _intacta(0), "gen")
    assert "Sin entradas" in salida


def test_lo_mas_nuevo_va_arriba():
    entradas = [_ent(1, "primero", "humano"), _ent(2, "ultimo", "humano")]
    salida = render(_estado(), entradas, _intacta(2), "gen")
    assert salida.index("ultimo") < salida.index("primero")


# ── Por la CLI: escribe el fichero, y no toca la autoridad ───────────────────


def test_la_cli_escribe_el_informe(tmp_path, capsys):
    control = tmp_path / "control"
    # deja un rastro real en el log antes de proyectarlo
    assert main(["--control", str(control), "descongelar", "arranque del panel"]) == 0
    salida = tmp_path / "panel.html"
    codigo = main(["--control", str(control), "informe", "--salida", str(salida)])
    texto = capsys.readouterr()
    assert codigo == 0, texto.err
    assert salida.exists()
    html = salida.read_text(encoding="utf-8")
    assert "<!doctype html>" in html
    assert "operativa" in html  # se descongeló arriba
    assert "descongelado" in html  # la decisión quedó en el log y se ve


def test_la_cli_usa_un_default_bajo_el_control_si_no_se_da_salida(tmp_path, capsys):
    control = tmp_path / "control"
    assert main(["--control", str(control), "estado"]) == 0
    codigo = main(["--control", str(control), "informe"])
    assert codigo == 0, capsys.readouterr().err
    assert (control / "informe.html").exists()
