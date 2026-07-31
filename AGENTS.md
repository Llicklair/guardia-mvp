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
gb floor          # el suelo del proyecto: qué falta antes de construir
```

No hay código todavía (fase documental). Cuando entre la primera línea de código, esta
sección declara el comando de tests ANTES de ese commit — regla de suelo, no opcional.

## Gates

Sin código no hay lint ni tipos aún. El gate vigente en fase documental: toda decisión
de diseño debe citar una regla numerada de [ARCHITECTURE.md](ARCHITECTURE.md) o abrir
un ADR. Si una propuesta viola una regla, la respuesta por defecto es no.

Cuando haya código: gates deterministas (lint, tipos, tests) en un comando, ANTES de
cualquier revisión por LLM, y evaluador adversarial de modelo de familia distinta después.

## Arquitectura

Cuatro niveles por presupuesto temporal: T0 kernel (µs, sin IA) → T1 detección
determinista (ms, sin IA) → T2 triaje LLM (segundos, solo lee) → T3 forja
galaxy-brain (minutos, único nivel que escribe, con gates y rollback).
Detalle completo: [ARQUITECTURA.md §2](ARQUITECTURA.md).

## Convenciones de commit y PR

- Commits en español, imperativo, prefijo de área: `docs:`, `t0:`, `t1:`, `t2:`,
  `forja:`, `infra:`. Una decisión de diseño en el commit = referencia a regla o ADR.
- Nunca auto-merge: un agente commitea en rama y deja PR; el merge lo dirige Marcos.
- Un PR que toque política de seguridad o los invariantes (reglas 7–8 de
  ARCHITECTURE.md) no entra sin ADR.
