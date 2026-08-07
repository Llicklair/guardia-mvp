"""El evaluador adversarial (regla 10 revisada, ADR 0007).

Lo que se prueba aqui no es si el modelo juzga bien —eso no es comprobable con un
test— sino que **su dictamen no puede convertirse en un veredicto**. Esa propiedad si
es estructural, y es la que sostiene la decision de usar la misma familia: un juez que
no puede condenar no necesita ser incorruptible.
"""

from __future__ import annotations

import json

from guardia.auditoria import Auditoria
from guardia.evaluador import LENTES, EvaluadorAdversarial, Lente
from guardia.politica import desde_json
from guardia.transporte import TransporteFallido

_PROPUESTA = desde_json(
    json.dumps(
        {
            "id": "corta-c2",
            "tipo": "filtro_red",
            "descripcion": "corta el egress al C2",
            "cuerpo": {
                "accion": "bloquear",
                "direccion": "salida",
                "puertos": [4444],
                "cidr": "203.0.113.7/32",
            },
        }
    )
)


class TransporteGuion:
    def __init__(self, respuesta) -> None:
        self.respuesta = respuesta
        self.prompts: list[str] = []

    def invocar(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if isinstance(self.respuesta, Exception):
            raise self.respuesta
        return self.respuesta


def _objecion(motivo="deja el 9001 abierto"):
    return json.dumps({"objecion": True, "motivo": motivo})


def test_una_objecion_por_lente(tmp_path):
    transporte = TransporteGuion(_objecion())
    dictamen = EvaluadorAdversarial(transporte).evaluar(_PROPUESTA)
    assert len(dictamen.objeciones) == len(LENTES)
    assert len(transporte.prompts) == len(LENTES)
    assert not dictamen.limpio


def test_sin_objeciones_el_dictamen_sale_limpio():
    dictamen = EvaluadorAdversarial(TransporteGuion('{"objecion": false}')).evaluar(_PROPUESTA)
    assert dictamen.limpio
    assert dictamen.con_objecion == ()


def test_el_evaluador_no_ve_la_telemetria(tmp_path):
    """La unica ventaja estructural que tiene sobre el generador: se le da la propuesta
    ya formada, no el texto hostil que la motivo. Una inyeccion que desvie a T2 no le
    llega a el por el mismo camino."""
    transporte = TransporteGuion('{"objecion": false}')
    EvaluadorAdversarial(transporte).evaluar(_PROPUESTA)
    for prompt in transporte.prompts:
        assert "DATOS NO CONFIABLES" not in prompt
        assert "TELEMETRIA" not in prompt
        assert "corta-c2" in prompt


def test_una_respuesta_ilegible_no_se_cuenta_como_objecion():
    """Convertir ruido en alarma es como se entrena a un operador a ignorar alarmas."""
    dictamen = EvaluadorAdversarial(TransporteGuion("lo siento, no puedo")).evaluar(_PROPUESTA)
    assert dictamen.limpio


def test_una_respuesta_con_anidado_hostil_es_ilegible_no_un_crash():
    """La respuesta del modelo es texto hostil (una inyeccion puede dictarsela): el
    anidado profundo reventaba la pila dentro de json.loads — RecursionError crudo en
    una senal que promete no parar nada nunca."""
    dictamen = EvaluadorAdversarial(TransporteGuion('{"a": ' + "[" * 20_000)).evaluar(_PROPUESTA)
    assert dictamen.limpio


def test_un_evaluador_caido_no_para_nada():
    """TransporteFallido se traduce en 'sin dictamen', nunca en un bloqueo: una senal
    advisory que se convierte en punto de fallo es peor que no tenerla."""
    caido = TransporteGuion(TransporteFallido("'claude' no esta en el PATH"))
    dictamen = EvaluadorAdversarial(caido).evaluar(_PROPUESTA)
    assert dictamen.limpio
    assert all("sin dictamen" in o.motivo for o in dictamen.objeciones)


def test_el_dictamen_queda_auditado_como_advisory(tmp_path):
    auditoria = Auditoria(tmp_path / "audit.jsonl")
    EvaluadorAdversarial(TransporteGuion(_objecion()), auditoria).evaluar(_PROPUESTA)
    entradas = [e for e in auditoria.leer() if e.evento == "evaluacion_adversarial"]
    assert len(entradas) == 1
    assert entradas[0].datos["advisory"] is True
    assert entradas[0].actor == "ia"


def test_las_lentes_preguntan_en_negativo():
    """Una lente que pide opinar produce halagos; una que pide encontrar un fallo
    concreto produce senal. Si alguien suaviza una lente, este test lo dice."""
    for lente in LENTES:
        assert "?" in lente.pregunta
        assert any(v in lente.pregunta.lower() for v in ("puede", "deja", "podria", "busca"))
    assert {lente.nombre for lente in LENTES} == {
        "lockout",
        "cobertura",
        "alcance",
        "desvio",
        "ceguera",
    }


def test_el_evaluador_no_puede_alcanzar_el_que_aplica():
    """La regla 3 en el grafo, comprobada tambien desde el codigo: si el evaluador
    pudiera importar el crisol o el despliegue, su dictamen podria acabar decidiendo.
    Las fronteras lo prohiben (src/.gb-boundaries) y aqui queda la razon escrita."""
    import guardia.evaluador as modulo

    fuente = modulo.__doc__ or ""
    assert "advisory" in fuente.lower()
    assert not hasattr(modulo, "Crisol")
    assert not hasattr(modulo, "Despliegue")


def test_una_lente_a_medida_tambien_vale():
    transporte = TransporteGuion(_objecion("motivo de prueba"))
    lente = Lente("prueba", "Hay algo que no cubra?")
    dictamen = EvaluadorAdversarial(transporte, lentes=(lente,)).evaluar(_PROPUESTA)
    assert len(dictamen.objeciones) == 1
    assert dictamen.objeciones[0].lente == "prueba"
