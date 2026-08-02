# live code — la ley de diseño

Reglas **numeradas**, y lo de numeradas no es cosmético: una regla con número se cita
en una revisión ("esto viola la 3") y una cita decide. La justificación extensa de cada
una vive en [ARQUITECTURA.md](ARQUITECTURA.md); aquí está la forma citable.

1. **Cada mecanismo vive en el nivel cuyo presupuesto temporal cumple.**
   T0 (µs–ms, kernel) y T1 (ms–100 ms, motor determinista) no contienen IA. T2 (1–30 s,
   LLM) solo lee. T3 (minutos, crisol) es el único nivel que escribe cambios. Un
   mecanismo que no cabe en su presupuesto no entra en ese nivel.
2. **Ningún nivel llama hacia arriba de forma bloqueante.** T1 nunca espera a T2. Con
   el LLM caído, lento o alucinando, T0/T1 protegen igual: la ausencia de IA degrada
   calidad, nunca disponibilidad.
3. **El LLM no tiene autoridad.** Emite propuestas estructuradas (JSON con esquema) que
   un validador determinista comprueba contra gramática cerrada y allowlist. Propuesta
   que no encaja se descarta sin interpretarse.
4. **Toda entrada del LLM es hostil.** La telemetría (nombres de fichero, argv,
   cabeceras, logs) la controla el atacante: se marca como dato no confiable, se trunca
   y se normaliza. La inyección de prompt es el canal de entrada esperado, no un edge case.
5. **La IA produce política declarativa, no código de producción.** Reglas Sigma/YARA,
   perfiles seccomp/AppArmor, filtros de red, políticas OPA — versionadas y firmadas.
   eBPF solo desde plantillas parametrizadas. Código solo vía crisol (rama, repro, gates,
   PR), nunca parche caliente.
6. **Ningún cambio se aplica sin sus cuatro gates:** replay benigno sin disparos, replay
   malicioso con disparo, rollback ejecutado y verificado en sandbox, y canary antes de
   extender.
7. **Los invariantes intocables están fuera del alcance de toda política generada:**
   canal de administración, plano de control del agente y su capacidad de rollback, log
   de auditoría append-only, y el propio conjunto de invariantes. Los aplica código
   determinista, no prompt.
8. **El interruptor de emergencia se construye antes que cualquier capacidad de
   escritura.** Es determinista, congela la capa de IA, fija el último estado bueno, y
   la IA no puede invocarlo ni desactivarlo.
9. **No se reimplementan sensores.** Falco, osquery, Wazuh, Sigma, Suricata/Zeek,
   CrowdSec, OPA/Cedar (tabla en ARQUITECTURA.md §6). Lo propio es el plano de control.
10. **Generador ≠ evaluador, en rol.** El veredicto lo dictan los gates deterministas
    (regla 6), nunca un modelo. Sobre eso, un evaluador adversarial —mismo modelo, rol
    de refutar, sin ver la telemetría— aporta señal **advisory** que no bloquea nada.
    *Relajada por [ADR 0007](docs/adr/0007-evaluador-misma-familia-lente-distinta.md);
    la versión original exigía familia distinta y presuponía un LLM juez, que este
    diseño ya no tiene. Si un modelo volviera a dictar veredictos, vuelve a aplicar.*
11. **Anti-lockout es un requisito, no un nice-to-have.** Límite de tasa de cambios por
    ventana, dead-man's switch con reversión automática, y camino de recuperación fuera
    de banda. El auto-DoS es el modo de fallo más probable del sistema.

## Cómo se cambia esto

Las reglas las cambia Marcos. Retirar o relajar una regla exige un ADR en
[docs/adr/](docs/adr/) que la cite por número y explique qué evidencia nueva la
invalida. Sin ADR, la regla sigue vigente aunque el código diga otra cosa.
