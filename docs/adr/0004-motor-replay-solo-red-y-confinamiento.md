# 0004 — El motor de replay del MVP cubre red y confinamiento, no detección

Estado: aceptada · Fecha: 2026-07-31

## Contexto

Los gates de replay (regla 6) necesitan evaluar de forma determinista si una propuesta
dispara sobre un corpus de eventos. Para `filtro_red` y `confinamiento` esa evaluación
es un matching estructural completo (¿la conexión cae en el CIDR+puerto? ¿el acceso toca
una ruta denegada?). Para `regla_deteccion`, la condición es lenguaje Falco/Sigma y su
único banco de pruebas correcto es el motor de Falco.

## Decisión

El motor de replay (`guardia.motor`) soporta `filtro_red` y `confinamiento`. Para
`regla_deteccion` lanza `ReplayNoSoportado`, y el crisol lo convierte en REJECT explícito
(`gate-replay-no-soportado`) — nunca en PASS. No se aproxima ni se reimplementa el
lenguaje de Falco (regla 9).

## Consecuencias

- El ciclo completo del MVP (incidente → propuesta → gates → veredicto) se demuestra hoy
  con el filtro de egress que corta el C2, que es una respuesta de contención válida al
  mismo incidente que la regla de detección.
- Una `regla_deteccion` no puede pasar el crisol todavía. Cuando el banco de Falco sea
  fiable (hoy no lo es en WSL2, ver docs/evidencia.md), se añade un replay que la corra
  contra Falco en el sandbox y este ADR se revisa.
- El límite es explícito en código y en la salida de la CLI: un PASS nunca significa
  "detección verificada" por accidente.
