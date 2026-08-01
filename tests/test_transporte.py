"""El suelo de evaluacion: que modelos pueden cruzar el canal, y que pasa si no.

Por que existe este fichero. La norma es "minimo opus; haiku prohibido para cualquier
verificacion o evaluacion". Estaba escrita, y aun asi el preset por defecto de claude
fijaba `--model haiku`: el camino barato era el invalido, y cumplir la norma exigia
acordarse de teclear `--comando-llm 'claude -p --tools "" --model opus'` cada vez. Una
regla que depende de que alguien se acuerde falla tarde o temprano.

Lo que se vigila aqui es que la norma viva en el DEFECTO: sale bien sin escribir nada, y
lo prohibido no se pisa con una bandera — se RECHAZA con su motivo.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from guardia.cli import main
from guardia.transporte import (
    COMANDOS_CLI,
    MODELOS_BAJO_EL_SUELO,
    SUELO_DE_EVALUACION,
    ModeloProhibido,
    TransporteCLI,
    TransporteFallido,
    comprobar_modelo,
)

_PYTHON = sys.executable


# ── El defecto, que es donde vive la norma ───────────────────────────────────


def test_ningun_preset_pide_un_modelo_bajo_el_suelo():
    """La regresion que motivo todo esto. Si alguien vuelve a fijar haiku en un preset,
    este test es el que grita — no una revision a ojo tres semanas despues."""
    for nombre, comando in COMANDOS_CLI.items():
        comprobar_modelo(comando)  # levanta ModeloProhibido si el preset esta bajo suelo
        assert comando, f"el preset '{nombre}' esta vacio"


def test_el_preset_por_defecto_nombra_el_suelo_explicitamente():
    """No basta con que no diga 'haiku': un preset que no nombra modelo hereda el que
    tenga configurado la CLI de turno, y entonces lo que se mide depende de la maquina."""
    assert SUELO_DE_EVALUACION in COMANDOS_CLI["claude"]


# ── La negativa, que no se puede pisar ───────────────────────────────────────


@pytest.mark.parametrize("modelo", sorted(MODELOS_BAJO_EL_SUELO))
def test_un_modelo_bajo_el_suelo_se_rechaza(modelo):
    with pytest.raises(ModeloProhibido, match=modelo):
        TransporteCLI(("claude", "-p", "--tools", "", "--model", modelo))


def test_se_caza_tambien_el_id_largo_del_modelo():
    """Los ids completos son la via facil para colar un modelo prohibido sin escribir
    la palabra suelta. Se compara por subcadena justo por esto."""
    with pytest.raises(ModeloProhibido, match="haiku"):
        TransporteCLI(("claude", "-p", "--model", "claude-haiku-4-5-20251001"))


def test_el_rechazo_dice_el_motivo_y_el_suelo():
    """Un rechazo sin motivo se lee como un fallo del programa y acaba en un workaround.
    Con motivo se lee como lo que es: una decision."""
    with pytest.raises(ModeloProhibido) as fallo:
        TransporteCLI(("claude", "--model", "haiku"))
    mensaje = str(fallo.value)
    assert "evaluacion" in mensaje
    assert SUELO_DE_EVALUACION in mensaje


def test_el_rechazo_llega_antes_de_gastar_un_token(monkeypatch):
    """Al construir, no al invocar. Si el rechazo esperase a la primera llamada, un banco
    de N incidentes ya habria gastado cuota que hay que tirar."""

    def prohibido(*a, **k):
        raise AssertionError("no se puede lanzar ningun subproceso: el modelo esta vetado")

    monkeypatch.setattr(subprocess, "run", prohibido)
    with pytest.raises(ModeloProhibido):
        TransporteCLI(("claude", "--model", "haiku"))


def test_un_modelo_sobre_el_suelo_pasa():
    """La otra mitad: el guardia rechaza lo prohibido y no estorba a lo demas."""
    TransporteCLI(("claude", "-p", "--tools", "", "--model", "opus"))
    TransporteCLI((_PYTHON, "-c", "pass"))  # un modelo local futuro, sin nombre conocido


# ── Por que NO es un TransporteFallido ───────────────────────────────────────


def test_la_prohibicion_no_viaja_por_el_camino_de_recuperacion():
    """`TransporteFallido` tiene fallback: el triaje cae al heuristico y lo audita. Si
    la prohibicion heredara de el, pedir haiku degradaria en silencio a otra cosa y
    saldria un informe con numeros como si nada. La negativa tiene que doler."""
    assert not issubclass(ModeloProhibido, TransporteFallido)


def test_pedir_un_modelo_prohibido_por_la_cli_no_cae_al_heuristico(tmp_path, capsys):
    """La comprobacion de arriba a nivel de tipo, aqui de punta a punta: la CLI no
    responde el incidente con el heuristico fingiendo que el LLM 'no estaba'."""
    control = tmp_path / "control"
    assert main(["--control", str(control), "descongelar", "banco de pruebas"]) == 0
    codigo = main(
        [
            "--control",
            str(control),
            "responder",
            "--proveedor",
            "llm",
            "--comando-llm",
            'claude -p --tools "" --model haiku',
        ]
    )
    salida = capsys.readouterr()
    assert codigo == 10, salida.out
    assert "RECHAZADO" in salida.out
    assert "haiku" in salida.out
    # Y no ha respondido el incidente por otra via: el rechazo corta, no sustituye.
    assert "APLICADO" not in salida.out.upper()
