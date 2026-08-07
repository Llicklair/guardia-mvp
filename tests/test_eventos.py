"""La frontera de entrada del corpus: toda ruta da un Corpus o un error de dominio.

Es la misma propiedad que ya vigila la gramatica de politica (`toda entrada -> Propuesta
o PropuestaInvalida, nunca otra excepcion`), aplicada al otro sitio por donde entra dato
hostil al sistema: los ficheros de telemetria.

La leccion que la motivo no es teorica. `guardia responder --incidente no-existe.jsonl`
escupia un traceback de pathlib: un fichero mal tecleado se presentaba como un fallo del
sistema en vez de como lo que era, un error de uso. Y peor en el camino del banco, donde
el mismo FileNotFoundError tumbaba una medicion entera.
"""

from __future__ import annotations

import pytest

from guardia.cli import main
from guardia.eventos import Corpus, CorpusIlegible, cargar

_LINEA = (
    '{"tipo": "red", "direccion": "salida", "puerto": 4444, '
    '"ip": "203.0.113.7", "etiqueta": "c2"}'
)


def test_un_corpus_normal_se_carga(tmp_path):
    ruta = tmp_path / "inc.jsonl"
    ruta.write_text(_LINEA + "\n", encoding="utf-8")

    corpus = cargar(ruta)

    assert isinstance(corpus, Corpus)
    assert len(corpus) == 1
    assert corpus.saltadas == ()


def test_una_linea_mala_se_salta_pero_el_corpus_se_carga(tmp_path):
    """El contraste que da sentido a `CorpusIlegible`: una linea corrupta NO es un
    corpus ilegible. El corpus es dato hostil y una linea mala se salta con constancia;
    seguir midiendo con lo que queda es lo correcto."""
    ruta = tmp_path / "inc.jsonl"
    ruta.write_text(_LINEA + "\nesto no es json\n", encoding="utf-8")

    corpus = cargar(ruta)

    assert len(corpus) == 1
    assert len(corpus.saltadas) == 1


@pytest.mark.parametrize(
    "preparar",
    [
        pytest.param(lambda d: d / "no-existe.jsonl", id="ausente"),
        pytest.param(lambda d: d, id="es-un-directorio"),
        pytest.param(
            lambda d: _escribir_bytes(d / "binario.jsonl", b"\xff\xfe\x00binario"),
            id="bytes-no-utf8",
        ),
    ],
)
def test_lo_que_no_se_puede_leer_es_error_de_dominio(preparar, tmp_path):
    """La propiedad: ninguna de estas rutas puede salir por OSError ni UnicodeDecodeError
    crudos. `bytes-no-utf8` importa especialmente — el corpus lo puede escribir un
    atacante y UnicodeDecodeError no es un OSError, asi que un `except OSError` solo
    habria dejado ese hueco abierto."""
    ruta = preparar(tmp_path)

    with pytest.raises(CorpusIlegible):
        cargar(ruta)


def test_la_cli_no_escupe_un_traceback_por_un_fichero_mal_tecleado(tmp_path, capsys):
    """El fallo tal y como aparecio, por la superficie real. Antes: traceback de pathlib
    y galaxy-brain capturando el crash. Ahora: un mensaje y exit 2, el mismo codigo que
    una propuesta que no encaja en la gramatica — la entrada que nos dieron no sirve."""
    codigo = main(
        [
            "--control",
            str(tmp_path / "control"),
            "responder",
            "--incidente",
            str(tmp_path / "no-existe.jsonl"),
        ]
    )
    salida = capsys.readouterr()

    assert codigo == 2
    assert "CORPUS ILEGIBLE" in salida.err
    assert "Traceback" not in salida.err


def _escribir_bytes(ruta, contenido: bytes):
    ruta.write_bytes(contenido)
    return ruta
