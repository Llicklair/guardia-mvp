"""El adaptador de enforcement: la propuesta -> reglas nft, y el sistema solo se toca a mano.

Lo que se vigila:
1. **La traduccion es correcta y auditable.** Un `filtro_red` que corta el C2 produce una
   regla nft que dropea el destino en esos puertos. Es la correlacion propuesta->ejecucion
   hecha texto.
2. **El defecto no toca el sistema.** Dry-run no lanza `nft`; enforcar de verdad exige la
   bandera. Un adaptador que enforca por accidente al ejecutarlo seria justo lo contrario
   de la disciplina del proyecto.
3. **Lo que no se sabe traducir se salta con constancia**, nunca en silencio.
"""

from __future__ import annotations

import json
import subprocess

from guardia.cli import main
from guardia.nftables import Aplicacion, aplicar, ruleset

_C2 = {
    "id": "corta-c2",
    "tipo": "filtro_red",
    "cuerpo": {
        "accion": "bloquear",
        "direccion": "salida",
        "puertos": [4444, 9001],
        "cidr": "203.0.113.7/32",
    },
}

_CONFINAMIENTO = {"id": "confina", "tipo": "confinamiento", "cuerpo": {"perfil": "contencion"}}


# ── La traduccion (funcion pura) ─────────────────────────────────────────────


def test_un_filtro_red_se_traduce_a_una_regla_nft_de_drop():
    reglas = ruleset([_C2])
    assert "table inet guardia" in reglas
    assert "hook output" in reglas  # salida -> egress -> output
    assert "ip daddr 203.0.113.7/32" in reglas  # destino, el C2
    assert "tcp dport { 4444, 9001 }" in reglas
    assert reglas.strip().endswith("drop")


def test_la_carga_es_atomica_e_idempotente():
    """add/delete/add de la tabla: reaplicar deja un estado limpio, no acumula reglas."""
    reglas = ruleset([_C2])
    assert "add table inet guardia" in reglas
    assert "delete table inet guardia" in reglas
    assert reglas.count("add table inet guardia") == 2  # el idiom de reemplazo


def test_una_entrada_mira_el_origen_no_el_destino():
    entrada = {
        "id": "bloquea-entrada",
        "tipo": "filtro_red",
        "cuerpo": {
            "accion": "bloquear",
            "direccion": "entrada",
            "puertos": [22],
            "cidr": "10.0.0.0/24",
        },
    }
    reglas = ruleset([entrada])
    assert "hook input" in reglas
    assert "ip saddr 10.0.0.0/24" in reglas  # origen, no destino


def test_sin_puertos_bloquea_toda_la_ip():
    pol = {
        "id": "toda-la-ip",
        "tipo": "filtro_red",
        "cuerpo": {
            "accion": "bloquear",
            "direccion": "salida",
            "puertos": [],
            "cidr": "203.0.113.7/32",
        },
    }
    reglas = ruleset([pol])
    assert "ip daddr 203.0.113.7/32 drop" in reglas
    assert "dport" not in reglas


def test_varias_politicas_varias_reglas():
    otra = {
        "id": "otra",
        "tipo": "filtro_red",
        "cuerpo": {
            "accion": "bloquear",
            "direccion": "salida",
            "puertos": [8080],
            "cidr": "198.51.100.5/32",
        },
    }
    reglas = ruleset([_C2, otra])
    assert reglas.count("add rule inet guardia egress") == 2


# ── Lo que no se traduce se salta, con motivo ────────────────────────────────


def test_un_confinamiento_se_salta_con_constancia():
    """El MVP solo hace red. Un confinamiento (seccomp/apparmor) no se traduce — pero no
    desaparece en silencio: se reporta, porque un ruleset que dice cubrirlo mentiria."""
    resultado = aplicar([_C2, _CONFINAMIENTO], dry_run=True)
    assert "add rule inet guardia egress" in resultado.reglas  # el filtro sí
    assert any("confina" in s and "confinamiento" in s for s in resultado.saltadas)


def test_una_accion_desconocida_no_se_cuela():
    raro = {
        "id": "raro",
        "tipo": "filtro_red",
        "cuerpo": {"accion": "permitir", "direccion": "salida"},
    }
    resultado = aplicar([raro], dry_run=True)
    assert any("accion" in s for s in resultado.saltadas)
    assert "add rule" not in resultado.reglas


# ── El defecto NO toca el sistema ────────────────────────────────────────────


def test_dry_run_no_lanza_nft(monkeypatch):
    """La garantia central: por defecto se traduce y se para. Ningun subproceso."""

    def prohibido(*a, **k):
        raise AssertionError("dry-run no puede lanzar ningun proceso")

    monkeypatch.setattr(subprocess, "run", prohibido)
    resultado = aplicar([_C2], dry_run=True)
    assert not resultado.aplicado
    assert "dry-run" in resultado.motivo
    assert resultado.reglas  # pero sí devuelve las reglas, para poder leerlas


def test_enforcar_de_verdad_empuja_el_ruleset_a_nft_por_stdin(monkeypatch):
    """Con dry_run=False y nft presente: corre `nft -f -` con el ruleset por stdin."""
    llamadas = {}

    def falso_which(nombre):
        return "/usr/sbin/nft" if nombre == "nft" else None

    def falso_run(cmd, **kwargs):
        llamadas["cmd"] = cmd
        llamadas["input"] = kwargs.get("input")

        class R:
            returncode = 0
            stderr = ""
            stdout = ""

        return R()

    monkeypatch.setattr("guardia.nftables.shutil.which", falso_which)
    monkeypatch.setattr(subprocess, "run", falso_run)
    resultado = aplicar([_C2], dry_run=False)
    assert resultado.aplicado
    assert llamadas["cmd"][0] == "/usr/sbin/nft"
    assert "-f" in llamadas["cmd"] and "-" in llamadas["cmd"]
    assert "ip daddr 203.0.113.7/32" in llamadas["input"]  # el prompt del kernel es el ruleset


def test_sin_nft_en_el_path_no_finge_haber_enforcado(monkeypatch):
    """En Windows/Mac (o Linux sin nftables) no hay `nft`. Se dice, no se finge."""
    monkeypatch.setattr("guardia.nftables.shutil.which", lambda n: None)
    resultado = aplicar([_C2], dry_run=False)
    assert not resultado.aplicado
    assert "nft no esta en el PATH" in resultado.motivo


def test_nft_que_falla_se_reporta_no_se_traga(monkeypatch):
    monkeypatch.setattr("guardia.nftables.shutil.which", lambda n: "/usr/sbin/nft")

    def run_falla(cmd, **kwargs):
        class R:
            returncode = 1
            stderr = "permiso denegado (hace falta root)"
            stdout = ""

        return R()

    monkeypatch.setattr(subprocess, "run", run_falla)
    resultado = aplicar([_C2], dry_run=False)
    assert not resultado.aplicado
    assert "nft fallo" in resultado.motivo
    assert "root" in resultado.motivo


def test_es_una_Aplicacion():
    assert isinstance(aplicar([], dry_run=True), Aplicacion)


# ── Por la CLI ───────────────────────────────────────────────────────────────


def test_la_cli_dry_run_imprime_el_ruleset_y_no_toca_nada(tmp_path, capsys):
    politica = tmp_path / "politica-activa.json"
    politica.write_text(json.dumps([_C2]), encoding="utf-8")
    codigo = main(
        ["--control", str(tmp_path / "control"), "enforcement", "--politica", str(politica)]
    )
    salida = capsys.readouterr()
    assert codigo == 0
    assert "ip daddr 203.0.113.7/32" in salida.out
    assert "dry-run" in salida.out


def test_la_cli_sin_politica_activa_no_peta(tmp_path, capsys):
    codigo = main(["--control", str(tmp_path / "control"), "enforcement"])
    assert codigo == 0
    assert "ruleset vacio" in capsys.readouterr().out
