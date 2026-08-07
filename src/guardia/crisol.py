"""El crisol: los cuatro gates de la regla 6. El unico camino para aplicar politica.

Un cambio se aplica si y solo si pasa, en orden y todos:

  Gate 0 — Interruptor operativo. Con la capa de IA congelada, no se aplica nada.
  Gate 1 — Invariantes. Toca una proteccion intocable → BLOCKER (regla 7).
  Gate 2 — Replay benigno. Dispara sobre actividad normal → falso positivo → REJECT.
  Gate 3 — Replay malicioso. No dispara sobre el repro del incidente → REJECT.
  Gate 4 — Rollback probado. Se aplica en sandbox, se revierte de verdad, y si el
           estado no vuelve al hash exacto → REJECT.

El resultado de un gate nunca lo decide un LLM. El crisol es determinista de principio
a fin: es la parte del sistema en la que el atacante mas querria colar algo, asi que
es la que menos margen de interpretacion tiene.

Aplicar de verdad (canary incluido) es el paso siguiente; este crisol produce el
VEREDICTO y deja el estado del sandbox limpio. Sin veredicto PASS, nada se aplica.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .aplicador import Aplicador
from .eventos import Corpus
from .invariantes import Config, comprobar
from .kill_switch import CapaCongelada, Interruptor
from .motor import ReplayNoSoportado, eventos_que_disparan
from .politica import Propuesta


class Resultado(str, Enum):
    PASS = "PASS"
    REJECT = "REJECT"
    BLOCKER = "BLOCKER"


_GATE_INTERRUPTOR = "gate-0-interruptor"


@dataclass(frozen=True)
class Veredicto:
    """Lo que dictan los gates. `motivos` explica cada decision para el log y el humano."""

    resultado: Resultado
    gate: str
    motivos: tuple[str, ...] = field(default_factory=tuple)

    @property
    def aplicable(self) -> bool:
        return self.resultado is Resultado.PASS

    @property
    def interruptor_cerrado(self) -> bool:
        """El rechazo vino del gate 0: la capa estaba congelada y la propuesta nunca
        llego a invariantes ni replay. Quien mida sobre este veredicto no midio nada."""
        return self.gate == _GATE_INTERRUPTOR

    def __str__(self) -> str:
        cabeza = f"{self.resultado.value} en {self.gate}"
        if not self.motivos:
            return cabeza
        return cabeza + "\n" + "\n".join(f"  - {m}" for m in self.motivos)


@dataclass(frozen=True)
class Crisol:
    """Orquesta los gates sobre un sandbox. No toca el estado de produccion."""

    interruptor: Interruptor
    aplicador: Aplicador
    benigno: Corpus
    incidente: Corpus
    config: Config = field(default_factory=Config)

    def evaluar(self, propuesta: Propuesta) -> Veredicto:
        for gate in (
            self._gate_interruptor,
            self._gate_invariantes,
            self._gate_replay,
            self._gate_rollback,
        ):
            veredicto = gate(propuesta)
            if veredicto is not None:
                self._registrar(propuesta, veredicto)
                return veredicto
        ok = Veredicto(Resultado.PASS, "todos", ("gramatica, invariantes, replay y rollback OK",))
        self._registrar(propuesta, ok)
        return ok

    def _gate_interruptor(self, _propuesta: Propuesta) -> Veredicto | None:
        try:
            self.interruptor.exigir_operativo()
        except CapaCongelada as e:
            return Veredicto(Resultado.REJECT, _GATE_INTERRUPTOR, (str(e),))
        return None

    def _gate_invariantes(self, propuesta: Propuesta) -> Veredicto | None:
        violaciones = comprobar(propuesta, self.config)
        if violaciones:
            return Veredicto(
                Resultado.BLOCKER, "gate-1-invariantes", tuple(str(v) for v in violaciones)
            )
        return None

    def _gate_replay(self, propuesta: Propuesta) -> Veredicto | None:
        try:
            falsos = eventos_que_disparan(propuesta, self.benigno.eventos)
            if falsos:
                etiquetas = [e.etiqueta or "evento" for e in falsos]
                return Veredicto(
                    Resultado.REJECT,
                    "gate-2-replay-benigno",
                    (f"dispara sobre {len(falsos)} evento(s) benigno(s): {etiquetas}",),
                )
            aciertos = eventos_que_disparan(propuesta, self.incidente.eventos)
            if not aciertos:
                return Veredicto(
                    Resultado.REJECT,
                    "gate-3-replay-malicioso",
                    (
                        f"no dispara sobre ninguno de los {len(self.incidente)} evento(s) "
                        f"del repro '{self.incidente.nombre}'",
                    ),
                )
        except ReplayNoSoportado as e:
            return Veredicto(Resultado.REJECT, "gate-replay-no-soportado", (str(e),))
        return None

    def _gate_rollback(self, propuesta: Propuesta) -> Veredicto | None:
        """Aplica en el sandbox, revierte de verdad, y exige que el estado vuelva
        exacto. Cualquier fallo deja el sandbox como estaba: se revierte pase lo que
        pase."""
        punto = self.aplicador.aplicar(propuesta)
        try:
            if self.aplicador.hash_actual() == punto.hash_previo:
                return Veredicto(
                    Resultado.REJECT,
                    "gate-4-rollback",
                    ("aplicar no cambio el estado: no hay nada que revertir con sentido",),
                )
        finally:
            self.aplicador.revertir(punto, propuesta.id)
        if not self.aplicador.restaura_a(punto):
            return Veredicto(
                Resultado.REJECT,
                "gate-4-rollback",
                ("el rollback no restauro el estado exacto (hash distinto)",),
            )
        return None

    def _registrar(self, propuesta: Propuesta, veredicto: Veredicto) -> None:
        self.interruptor.auditoria.registrar(
            "crisol_veredicto",
            "automata",
            propuesta=propuesta.id,
            resultado=veredicto.resultado.value,
            gate=veredicto.gate,
        )
