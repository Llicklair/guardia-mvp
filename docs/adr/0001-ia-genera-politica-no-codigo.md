# 0001 — La IA genera política declarativa, no código de producción en caliente

Estado: aceptada · Fecha: 2026-07-31

## Contexto

La idea original era "la IA modifica y reestructura el código en tiempo real para
defenderse". Dos hechos la invalidan tal cual: (a) un exploit se ejecuta en
microsegundos y una inferencia LLM tarda segundos — 4-5 órdenes de magnitud tarde;
(b) un LLM con permiso de escritura sobre código en producción, alimentado con
telemetría que controla el atacante, convierte la inyección de prompt en primitiva de
escalada de privilegios.

## Decisión

La IA produce **política declarativa** (Sigma, YARA, seccomp/AppArmor, nftables,
OPA/Rego; eBPF solo desde plantillas parametrizadas), versionada y firmada, validada
por gates antes de aplicarse. **Código** solo cuando la causa raíz es un defecto del
software propio, y solo vía el pipeline de galaxy-brain: rama, repro, gates, veredicto
adversarial, PR — en minutos u horas, nunca en caliente.

## Consecuencias

- El combate "IA vs IA en tiempo real" se reformula: la contribución de la IA defensiva
  al milisegundo del ataque es la regla que escribió y verificó minutos antes.
- El radio de daño de una propuesta mala queda acotado a una regla mala (reversible),
  no a ejecución arbitraria.
- Regla 5 de [ARCHITECTURE.md](../../ARCHITECTURE.md). Revertir esta ADR exige
  evidencia de que un LLM puede decidir en <100 ms con entrada hostil, que hoy no existe.
