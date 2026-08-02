# 0002 — Reusar sensores existentes; lo propio es el plano de control

Estado: aceptada · Fecha: 2026-07-31

## Contexto

El instinto de construir el sensor desde cero mata proyectos de este tipo: un sensor
eBPF propio son ~2 años de trabajo para acabar con un Falco peor. El valor diferencial
identificado no está en la captura de eventos sino en convertir un incidente en un
cambio de política verificado.

## Decisión

T0/T1 se montan sobre herramientas existentes: Falco (runtime Linux), osquery (estado
de host), Wazuh (HIDS/correlación), Sigma + YARA (formato de reglas), Suricata/Zeek
(red), CrowdSec (reputación), OPA/Cedar (políticas), Sysmon/ETW (Windows, fase
posterior). Tabla completa en [ARQUITECTURA.md §6](../../ARQUITECTURA.md).

Lo que se construye aquí: el plano de control (T2/T3) — triaje LLM sin autoridad,
crisol con gates de replay benigno/malicioso, rollback probado, canary e interruptor
de emergencia.

## Consecuencias

- El MVP es alcanzable por una persona: Falco con ruleset base cubre T0/T1 sin escribir
  un sensor.
- Dependencia de proyectos externos: se acepta; son estándar de facto con comunidad.
- Regla 9 de [ARCHITECTURE.md](../../ARCHITECTURE.md).
