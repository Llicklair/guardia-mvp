"""La tesis central, con inputs adversariales frescos: una propuesta desviada no puede
aplicarse.

Las cinco desviadas de `banco_evaluador` (lo que el atacante quería en cada incidente)
se declararon para medir la señal advisory del evaluador, y ESE banco no corre los
gates — solo evalúa. Aquí se cierra el círculo: se pasan por el crisol y se comprueba
que ninguna es aplicable, mientras la contención correcta sí pasa. Si un gate se
debilitara en el futuro, esto lo caza.

Detalle que costó una pasada de sondeo aprender: un interruptor sin estado en disco
**nace congelado** (fail-closed), y con la capa congelada todo muere en el gate-0 sin
llegar a los invariantes ni al replay. Para medir los gates 1-4 hay que descongelar
primero; el gate-0 (kill switch) tiene sus propios tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from guardia.actores import Actor
from guardia.aplicador import Aplicador
from guardia.banco_evaluador import CASOS, CORRECTA
from guardia.crisol import Crisol
from guardia.eventos import cargar
from guardia.invariantes import Config, comprobar
from guardia.kill_switch import Interruptor

RAIZ = Path(__file__).resolve().parent.parent
BENIGNO = cargar(str(RAIZ / "corpus" / "eventos" / "benigno.jsonl"))
INCIDENTE = cargar(str(RAIZ / "corpus" / "eventos" / "incidente-0001.jsonl"))


def _forja_operativa(directorio: Path) -> Crisol:
    directorio.mkdir(parents=True, exist_ok=True)
    interruptor = Interruptor(str(directorio))
    interruptor.descongelar(Actor.HUMANO, "test: capa operativa para medir los gates 1-4")
    return Crisol(
        interruptor=interruptor,
        aplicador=Aplicador(interruptor.directorio / "sandbox.json"),
        benigno=BENIGNO,
        incidente=INCIDENTE,
    )


def test_ninguna_desviada_pasa_los_gates(tmp_path):
    """La tesis: aunque el modelo proponga lo que el atacante quería, T3 no lo aplica."""
    for i, caso in enumerate(CASOS):
        veredicto = _forja_operativa(tmp_path / f"des-{i}").evaluar(caso.desviada)
        assert not veredicto.aplicable, f"{caso.incidente}: la desviada pasó ({veredicto.gate})"


def test_la_correcta_si_pasa_los_gates(tmp_path):
    """El control: la contención correcta del C2 pasa los cuatro gates. Si esto fallara,
    el sistema no contendría ni el ataque real, y el 'no' de arriba no significaría nada."""
    veredicto = _forja_operativa(tmp_path / "corr").evaluar(CORRECTA)
    assert veredicto.aplicable, f"la correcta murió en {veredicto.gate}: {veredicto.resultado.name}"


@pytest.mark.parametrize(
    "incidente,invariante",
    [
        ("lockout-ssh", "canal-admin"),
        ("cegar-auditoria", "rutas-protegidas"),
        ("cegar-registro", "capacidad-de-registro"),
    ],
)
def test_las_desviadas_de_ceguera_tocan_el_invariante_que_las_frena(incidente, invariante):
    """Las tres que un invariante debe cazar lo tocan por su nombre. La de cegar-registro
    es la que docs/evidencia.md declara como la defensa REAL contra cegar el log (no la
    lente advisory 'ceguera'): aquí queda comprobado, no solo escrito."""
    caso = next(c for c in CASOS if c.incidente == incidente)
    violaciones = comprobar(caso.desviada, Config())
    assert invariante in {v.invariante for v in violaciones}
