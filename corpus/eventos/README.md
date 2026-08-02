# Corpus de eventos

Telemetría grabada, un evento por línea (JSONL), contra la que el crisol replaya las
propuestas. Dos corpus con papeles opuestos:

| Fichero | Papel | Qué exige el gate |
|---|---|---|
| `benigno.jsonl` | Actividad normal grabada | La propuesta **no** debe disparar sobre ninguno (si dispara → falso positivo → REJECT) |
| `incidente-0001.jsonl` | El repro del ataque (shell inversa) | La propuesta **sí** debe disparar sobre al menos uno (si no → REJECT) |

El benigno incluye trampas a propósito: una conexión interna legítima al puerto 4444
(el mismo que usa el C2 del incidente) pero a una IP interna `10.x`. Una propuesta que
bloquee "todo el 4444" pasaría el replay malicioso pero **fallaría el benigno** — que
es justo lo que debe pasar. La propuesta correcta discrimina por IP+puerto, no solo
por puerto.

## Procedencia (decisión abierta de ARQUITECTURA §9)

Estos corpus son sintéticos, escritos a mano para el MVP. El corpus benigno real tiene
un problema sin resolver: si el atacante ya estaba dentro cuando se grabó, su actividad
queda etiquetada como normal. Cualquier corpus benigno de producción necesita una
estrategia de procedencia antes de confiar en él. Aquí no aplica porque son inventados,
y eso mismo es su límite.
