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
  escalada perfecta. La IA genera política declarativa; código solo vía crisol con gates.
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

## Terminado — el MVP se cierra aquí (2026-08-08)

**El criterio de salida es la distribución**: el MVP está construido y finalizado, y lo
que venga después son versiones posteriores que ya no entran en este alcance ni las
recoge el embudo de galaxy-brain. Este apartado deja escrito contra qué se cierra, para
que dentro de un año se pueda comprobar en vez de recordar.

| # | condición | estado | dónde está la medición |
|---|-----------|--------|------------------------|
| 1 | bloquea el repro | **cumplida** — `contenidos: 6/6` con el proveedor determinista, y `CONTUVO 2/2` con Opus real | `guardia banco`; evidencia 2026-08-02 |
| 2 | cero disparos sobre benigno | **cumplida** — `POLITICAS MALAS APLICADAS: 0` | mismo banco (el gate de replay benigno es previo al canary) |
| 3 | el evaluador rechaza las envenenadas | **cumplida tal como está escrita** — tasa de rechazo > 0: objetó las 5 desviadas en las 3 pasadas | evidencia 2026-08-02 (varianza del evaluador) |
| 4 | con la IA congelada, T0/T1 idénticos | **NO MEDIDA** | requiere Linux + `nft` + sensores reales; ver *Límites* del README |

Las dos honestidades que este cierre no debe tapar:

- **La 4 no está medida, y no es un detalle de forma.** Es la condición que sostiene la
  regla 2 —la IA es aditiva, nunca un punto único de fallo— y en esta máquina (Windows,
  sin `nft`) no se puede ejecutar. El adaptador de nftables traduce y se verifica en
  dry-run; empujar al kernel y medir la disponibilidad con la capa congelada sigue siendo
  el pendiente de una VM Linux. Cerrar el MVP no la convierte en cumplida.
- **La 3 se cumple, pero no dice lo que parece decir.** El evaluador caza las desviadas
  (recall alto) y a la vez objeta a la contención correcta 3/3: no *discrimina*. La
  condición pedía tasa de rechazo mayor que cero y la hay, pero quien lea esto buscando
  "el evaluador distingue lo bueno de lo malo" no lo va a encontrar — y por eso es
  advisory y nunca toca un veredicto (ADR 0007). Hay además un falso negativo en 1 de 3
  pasadas sobre `lockout-total`: ocurre, y N=3 no da su tasa.
