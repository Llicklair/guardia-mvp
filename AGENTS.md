# live code

Contexto ejecutable para agentes. Formato [AGENTS.md](https://agents.md), que leen
Claude Code, Codex, Cursor, Copilot, Gemini CLI y Aider — a diferencia de un fichero
de una sola herramienta.

Sistema de seguridad a nivel SO con capa de IA. La ley de diseño (reglas citables) está
en [ARCHITECTURE.md](ARCHITECTURE.md); el alcance y lo descartado, en [SCOPE.md](SCOPE.md);
la justificación extensa, en [ARQUITECTURA.md](ARQUITECTURA.md); las decisiones, en
[docs/adr/](docs/adr/); las mediciones, en [docs/evidencia.md](docs/evidencia.md).

## Comandos

Lo de esta seccion se EJECUTA, asi que no puede pudrirse en silencio: si miente, falla.

```bash
bash check.sh                 # TODOS los gates en un comando; 0 = verde
python -m pytest tests/ -q    # solo la suite
python -m ruff check src tests && python -m ruff format --check src tests
gb graph src --gate           # ciclos de imports + fronteras (src/.gb-boundaries)
gb floor                      # el suelo del proyecto: qué falta antes de construir
python -m guardia.cli --help  # la linea de mando (PYTHONPATH=src)
python -m guardia.cli crisol <prop.json>   # corre una propuesta por los 4 gates (regla 6)
```

La CLI `guardia`: `estado` / `congelar` / `descongelar` (interruptor de emergencia),
`auditoria [--verificar]` (log encadenado), `validar` (gramática + invariantes),
`crisol` (los cuatro gates → PASS/REJECT/BLOCKER, exit 0/6/5) sobre sandbox, y el ciclo
de aplicación real: `desplegar` (crisol + canary con dead-man's switch + límite de tasa,
exit 0/6/7), `confirmar <id>` (marca un canary estable, solo humano) y `revisar` (el
dead-man's switch: revierte los canarios expirados; lo llama el automata) y el ciclo
completo `responder` (incidente → triaje T2 → despliegue T3). Sin PASS, nada se aplica;
nada se aplica global de golpe.

T2 (triaje) toma un proveedor intercambiable: `ProveedorHeuristico` (determinista, sin
IA, el que usa `responder`) y `ProveedorLLM` (detrás de la misma interfaz, **no
conectado** — lanza en vez de gastar cuota; conectarlo exige OK explícito, ADR 0005).
T2 solo propone; la propuesta pasa por la gramática cerrada y los gates de T3, así que
un triaje envenenado por inyección de prompt no consigue aplicar política mala.

El fichero de fronteras vive en [src/.gb-boundaries](src/.gb-boundaries), **no** en la
raíz: `gb graph src` lo busca dentro del path que analiza, y en la raíz cargaría cero
reglas pasando en verde sin comprobar nada.

## Gates

`check.sh` corre lint, formato, tests y fronteras. Son deterministas y van **ANTES**
de cualquier revisión por LLM (H1 del informe de galaxy-brain). Ningún commit entra
con `check.sh` en rojo.

Además, para cambios de diseño: toda decisión cita una regla numerada de
[ARCHITECTURE.md](ARCHITECTURE.md) o abre un ADR. Si una propuesta viola una regla, la
respuesta por defecto es no.

Cuando entre la capa de IA (T2), se suma el evaluador adversarial de modelo de familia
distinta a la del generador — regla 10.

## Arquitectura

Cuatro niveles por presupuesto temporal: T0 kernel (µs, sin IA) → T1 detección
determinista (ms, sin IA) → T2 triaje LLM (segundos, solo lee) → T3 crisol
galaxy-brain (minutos, único nivel que escribe, con gates y rollback).
Detalle completo: [ARQUITECTURA.md §2](ARQUITECTURA.md).

## Convenciones de commit y PR

- Commits en español, imperativo, prefijo de área: `docs:`, `t0:`, `t1:`, `t2:`,
  `crisol:`, `infra:`. Una decisión de diseño en el commit = referencia a regla o ADR.
- Nunca auto-merge: un agente commitea en rama y deja PR; el merge lo dirige Marcos.
- Un PR que toque política de seguridad o los invariantes (reglas 7–8 de
  ARCHITECTURE.md) no entra sin ADR.
