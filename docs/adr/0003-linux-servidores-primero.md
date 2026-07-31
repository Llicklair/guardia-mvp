# 0003 — MVP en Linux y para servidores; escritorio y Windows después

Estado: aceptada · Fecha: 2026-07-31

## Contexto

El objetivo declarado es proteger servidores y ordenadores personales, en Linux y
Windows. Hacerlo todo a la vez multiplica la superficie: en Windows el equivalente de
eBPF exige driver firmado, y en un equipo personal el corpus "benigno" es impredecible,
lo que dispara los falsos positivos — la métrica que hunde estos sistemas.

## Decisión

MVP: Linux, en contenedor/VM (WSL2 + Docker Desktop ya disponibles), protegiendo un
servidor con un único escenario de ataque end-to-end (shell inversa desde proceso hijo
de un servidor web). Windows entra después detrás de una abstracción de sensor
(Sysmon/ETW). Escritorio es una fase posterior con estrategia propia de corpus benigno.

## Consecuencias

- El criterio de terminado del MVP ([SCOPE.md](../../SCOPE.md)) es medible sobre un
  entorno reproducible.
- La abstracción de sensor debe diseñarse desde el principio para no casar el plano de
  control con Falco.
- Nada de lo aprendido sobre falsos positivos en servidores se extrapola al escritorio
  sin medirlo de nuevo.
