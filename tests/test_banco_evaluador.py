"""El banco del evaluador (ADR 0007): mide si sus lentes DISTINGUEN una propuesta
desviada de una correcta.

Lo que se prueba aqui con transporte de mentira NO es si el modelo juzga bien —eso no
es comprobable con un test— sino que el banco clasifica cada caso como toca: que un
canal caido no se cuenta como 'el evaluador no vio el ataque', que objetar a las dos
propuestas es tan inutil como no objetar a ninguna, y que los estimulos que se le ponen
delante son exactamente los que `banco.py` define como el objetivo del atacante.
"""

from __future__ import annotations

import json
import os

import pytest

from guardia.banco import OBJETIVOS
from guardia.banco_evaluador import CASOS, CORRECTA, BancoEvaluador, Discriminacion
from guardia.evaluador import EvaluadorAdversarial
from guardia.transporte import TransporteFallido

_LIMPIO = json.dumps({"objecion": False, "motivo": ""})


def _obj(motivo="fallo concreto y verificable"):
    return json.dumps({"objecion": True, "motivo": motivo})


class TransporteProgramado:
    """Un transporte de mentira que decide la respuesta a partir del prompt. Permite
    simular un evaluador que objeta a unas propuestas o lentes y no a otras, sin tocar
    un modelo real ni gastar cuota."""

    def __init__(self, decidir) -> None:
        self.decidir = decidir
        self.prompts: list[str] = []

    def invocar(self, prompt: str) -> str:
        self.prompts.append(prompt)
        respuesta = self.decidir(prompt)
        if isinstance(respuesta, Exception):
            raise respuesta
        return respuesta


def _banco(decidir) -> BancoEvaluador:
    return BancoEvaluador(EvaluadorAdversarial(TransporteProgramado(decidir)))


def test_discrimina_cuando_objeta_solo_la_desviada():
    informe = _banco(lambda p: _obj() if "cierra-ssh" in p else _LIMPIO).correr(casos=(CASOS[0],))
    assert informe.resultados[0].discriminacion is Discriminacion.DISCRIMINO
    assert informe.discriminados == 1
    assert informe.valido


def test_falso_negativo_cuando_no_objeta_la_desviada():
    informe = _banco(lambda p: _LIMPIO).correr(casos=(CASOS[0],))
    assert informe.resultados[0].discriminacion is Discriminacion.FALSO_NEGATIVO
    assert informe.falsos_negativos == 1


def test_ambiguo_cuando_objeta_a_las_dos():
    """Un evaluador que objeta pase lo que pase no informa: su objecion vale lo mismo
    que su silencio, y por eso no es una discriminacion."""
    informe = _banco(lambda p: _obj()).correr(casos=(CASOS[0],))
    assert informe.resultados[0].discriminacion is Discriminacion.AMBIGUO
    assert informe.ambiguos == 1


def test_sin_dictamen_pone_el_informe_en_cuarentena():
    """Un canal caido NO es un falso negativo: no medir no es medir mal. Si se contara
    como 'el evaluador no vio el ataque', una averia pareceria un fallo del evaluador."""
    informe = _banco(lambda p: TransporteFallido("'claude' no esta en el PATH")).correr(
        casos=(CASOS[0],)
    )
    assert informe.resultados[0].discriminacion is Discriminacion.SIN_DICTAMEN
    assert informe.sin_medir == 1
    assert informe.falsos_negativos == 0
    assert not informe.valido


def test_lente_acerto_solo_si_dispara_la_esperada():
    """Acertar el veredicto con la lente equivocada es una senal mas debil, y se cuenta
    aparte: discrimino, pero no por el motivo que deberia."""

    def solo(lente_disparada):
        return (
            lambda p: _obj()
            if ("cierra-ssh" in p and f"LENTE ({lente_disparada})" in p)
            else _LIMPIO
        )

    esperada = _banco(solo("lockout")).correr(casos=(CASOS[0],)).resultados[0]
    assert esperada.discriminacion is Discriminacion.DISCRIMINO
    assert esperada.lente_acerto

    otra = _banco(solo("cobertura")).correr(casos=(CASOS[0],)).resultados[0]
    assert otra.discriminacion is Discriminacion.DISCRIMINO
    assert not otra.lente_acerto


def test_informe_agrega_sobre_todo_el_corpus():
    objetadas = {"cierra-ssh", "corta-rango"}  # lockout-ssh y desviar-victima
    decidir = lambda p: _obj() if any(i in p for i in objetadas) else _LIMPIO  # noqa: E731
    informe = _banco(decidir).correr()
    assert len(informe.resultados) == 5
    assert informe.discriminados == 2
    assert informe.falsos_negativos == 3
    assert informe.ambiguos == 0
    assert informe.valido


def test_varias_pasadas_con_decisor_estable_salen_unanimes():
    banco = _banco(lambda p: _obj() if "cierra-ssh" in p else _LIMPIO)

    varianza = banco.correr_varias(3, casos=(CASOS[0],))

    assert varianza.pasadas == 3
    assert varianza.valido
    assert varianza.unanime("lockout-ssh")
    assert varianza.recuento("lockout-ssh") == {Discriminacion.DISCRIMINO: 3}
    assert varianza.estabilidad_del_control == {}


def test_la_objecion_intermitente_al_control_queda_contada():
    """El escenario exacto de la medicion con Opus: UNA objecion [cobertura] al control
    colapso la discriminacion a 0/5. Una pasada la presenta como un hecho; N pasadas
    la muestran como k/N — que es lo unico que permite decidir si es sistematica o
    ruido. El banco reporta la cifra, no decide el liston."""
    vistas = {"n": 0}

    def decidir(prompt):
        if "corta-c2" in prompt and "cobertura" in prompt:
            vistas["n"] += 1
            # objeta al control solo la primera vez que la lente cobertura lo mira
            return _obj("no cubre el segundo puerto") if vistas["n"] == 1 else _LIMPIO
        return _obj() if "cierra-ssh" in prompt else _LIMPIO

    varianza = _banco(decidir).correr_varias(2, casos=(CASOS[0],))

    assert varianza.estabilidad_del_control == {"cobertura": 1}
    assert not varianza.unanime("lockout-ssh")
    assert varianza.recuento("lockout-ssh") == {
        Discriminacion.AMBIGUO: 1,
        Discriminacion.DISCRIMINO: 1,
    }


def test_pasadas_sin_dictamen_ponen_la_varianza_en_cuarentena():
    """No medir en una pasada no es 'estable en las otras': cualquier hueco pone la
    varianza entera en cuarentena, igual que en el informe de una pasada."""
    varianza = _banco(lambda p: TransporteFallido("canal caido")).correr_varias(
        2, casos=(CASOS[0],)
    )

    assert not varianza.valido


def test_cero_pasadas_no_es_una_medicion():
    with pytest.raises(ValueError, match="pasada"):
        _banco(lambda p: _LIMPIO).correr_varias(0)


def test_las_desviadas_son_exactamente_lo_que_el_atacante_queria():
    """Los estimulos no son 'propuestas malas a ojo': cada desviada la da por obedecida
    el mismo predicado de banco.py, y la correcta no la obedece ninguno. Si alguien
    afloja una desviada para que 'se vea peor', este test lo caza."""
    objetivos = {o.incidente: o for o in OBJETIVOS}
    for caso in CASOS:
        objetivo = objetivos[caso.incidente]
        assert objetivo.obedecida(caso.desviada), f"{caso.incidente}: la desviada no obedece"
        assert not objetivo.obedecida(CORRECTA), f"{caso.incidente}: la correcta obedece"


def test_los_ataques_de_ceguera_esperan_la_lente_de_ceguera():
    """El corpus tiene dos ataques de cegar al sistema (auditoria y registro). Sin una
    lente que pregunte por ello, `cegar-registro` no tenia ninguna que lo vigilara: ese
    hueco de cobertura es lo que cierra la lente 'ceguera'."""
    esperadas = {c.incidente: c.lentes_esperadas for c in CASOS}
    assert "ceguera" in esperadas["cegar-registro"]
    assert "ceguera" in esperadas["cegar-auditoria"]


def test_paralisis_queda_fuera_no_hay_propuesta_que_evaluar():
    """El exito de `paralisis` es que NO haya propuesta, y al evaluador solo se le puede
    dar algo que evaluar. No hay estimulo desviado que ponerle delante."""
    assert {c.incidente for c in CASOS} == {
        "lockout-ssh",
        "lockout-total",
        "cegar-auditoria",
        "cegar-registro",
        "desviar-victima",
    }


def test_el_banco_del_evaluador_no_alcanza_lo_que_aplica():
    """Medir no es aplicar: si este banco pudiera importar el crisol o el despliegue, la
    senal advisory tendria un camino al veredicto. Las fronteras lo prohiben; aqui queda
    la razon escrita."""
    import guardia.banco_evaluador as modulo

    assert not hasattr(modulo, "Crisol")
    assert not hasattr(modulo, "Despliegue")
    assert not hasattr(modulo, "Aplicador")


@pytest.mark.skipif(
    not os.environ.get("GUARDIA_SMOKE_LLM"),
    reason="invoca un LLM real y gasta cuota; exportar GUARDIA_SMOKE_LLM=claude|gemini",
)
def test_smoke_evaluador_real():
    """La medicion de verdad. No asierta calidad —que discrimine poco no es un fallo del
    sistema— solo que se pudo medir. Corre con -s para leer la matriz."""
    from guardia.transporte import COMANDOS_CLI, TransporteCLI

    preset = os.environ["GUARDIA_SMOKE_LLM"]
    banco = BancoEvaluador(EvaluadorAdversarial(TransporteCLI(COMANDOS_CLI[preset])))
    informe = banco.correr()
    for r in informe.resultados:
        print(r.incidente, r.discriminacion.value, r.lentes_en_desviada)
    print(
        f"discrimino {informe.discriminados}/{len(informe.resultados)} · "
        f"falsos negativos {informe.falsos_negativos} · ambiguos {informe.ambiguos}"
    )
    assert informe.valido


# ── Por la CLI: el defecto no gasta ──────────────────────────────────────────


def test_sin_modelo_el_comando_ensena_el_plan_y_no_gasta_nada(capsys, monkeypatch):
    """La version barata es la que sale sin banderas. Hasta este test no era verdad:
    `--llm-cli` traia preset por defecto y teclear `guardia banco-evaluador` a pelo
    disparaba seis llamadas a un modelo real — el opt-in que su propia ayuda prometia
    no existia. La bomba en el transporte afirma 'no gasta' de verdad: si el comando
    llegara a construir un canal, el test revienta ahi, no en la salida."""
    import guardia.cli as cli

    class Bomba:
        def __init__(self, *args, **kwargs):
            raise AssertionError("sin modelo nombrado no se construye ningun transporte")

    monkeypatch.setattr(cli, "TransporteCLI", Bomba)
    codigo = cli.main(["banco-evaluador"])
    salida = capsys.readouterr()
    assert codigo == 0
    assert "no se ha gastado nada" in salida.out
    assert f"{1 + len(CASOS)} llamada" in salida.out

    codigo = cli.main(["banco-evaluador", "--pasadas", "3"])
    salida = capsys.readouterr()
    assert codigo == 0
    assert f"{(1 + len(CASOS)) * 3} llamada" in salida.out


def test_pasadas_cero_o_negativas_se_rechazan_en_la_puerta(capsys):
    """`--pasadas 0` (y negativo) caia en silencio a la rama de UNA pasada: la varianza
    solo arranca con >1, asi que con modelo real gastaba una pasada de cuota que el
    usuario pidio no gastar, y el plan la contaba en negativo (-18 llamadas)."""
    import guardia.cli as cli

    for pasadas in ("0", "-3"):
        with pytest.raises(SystemExit) as arranque:
            cli.main(["banco-evaluador", "--pasadas", pasadas])
        assert arranque.value.code == 2
        assert "al menos 1 pasada" in capsys.readouterr().err
