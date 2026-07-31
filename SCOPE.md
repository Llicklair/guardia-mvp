# live code — alcance

> Nombre del proyecto: pendiente. "live code" es el directorio, no el nombre.

## En una frase

Un plano de control que convierte un incidente de seguridad real en un cambio de
política verificado — con repro ejecutable, veredicto adversarial, canary y rollback
probado — montado sobre sensores deterministas que ya existen.

## Lo que NO entra

- **IA reescribiendo código de producción en tiempo real.** Descartado en
  [ARQUITECTURA.md §1](../ARQUITECTURA.md): un exploit corre en microsegundos y un LLM
  piensa en segundos, y un LLM con permiso de escritura en caliente es la primitiva de
  escalada perfecta. La IA genera política declarativa; código solo vía forja con gates.
- **Sensor eBPF propio, SIEM propio, motor IDS propio, DSL de reglas propio.** Se usa
  Falco, osquery, Wazuh, Sigma/YARA, Suricata/Zeek, OPA (ARQUITECTURA.md §6). El valor
  está en el plano de control, no en reimplementar sensores.
- **LLM con autoridad de ejecución.** El LLM propone JSON contra gramática cerrada; la
  contención la decide T1 con reglas deterministas. Siempre.
- **Equipos personales / escritorio en el MVP.** El corpus benigno de un portátil es
  impredecible y los falsos positivos se disparan. Servidores primero; escritorio es
  una fase posterior, no una feature que colar.
- **Windows en el MVP.** Entra después, detrás de una abstracción de sensor. Linux
  (contenedor/VM sobre WSL2 + Docker) primero.
- **Despliegue global de una política de golpe.** Todo pasa por canary con dead-man's
  switch, sin excepciones.

## Criterio de terminado

El MVP está terminado cuando, sobre un corpus de N incidentes grabados y un corpus de
actividad benigna grabada, se puede responder SÍ a las cuatro:

1. Las reglas generadas por el pipeline **bloquean el repro** de cada incidente
   (replay malicioso dispara).
2. **Cero disparos sobre el corpus benigno** (replay benigno no dispara).
3. El evaluador adversarial **rechaza las propuestas envenenadas** que se le inyectan
   a propósito — tasa de rechazo estrictamente mayor que cero. Si nunca dice REJECT,
   el sistema es teatro y NO está terminado.
4. Con la capa de IA congelada por el interruptor de emergencia, la **disponibilidad
   de T0/T1 es idéntica** — la IA es aditiva, no un punto único de fallo.
