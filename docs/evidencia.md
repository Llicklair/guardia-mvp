# Evidencia — la libreta

Cada medicion real: que se probo, que salio, que cambio por ello.

**Los resultados negativos se escriben con el mismo detalle que los positivos, o mas.**
Un proyecto que solo registra lo que funciono no tiene evidencia: tiene publicidad. Y el
dato que no esta en el repo, no existe — la memoria de nadie cuenta.

## Formato

`## AAAA-MM-DD · que se probo — VEREDICTO`, y debajo: montaje, resultado, consecuencia.

## Qué se va a medir (declarado antes de medir, ARQUITECTURA.md §8)

1. Tasa de rechazo del evaluador (si es cero, el gate no gatea).
2. Falsos positivos de reglas generadas por IA contra el corpus benigno.
3. Tiempo de contención (T0/T1) medido APARTE del tiempo de análisis (T2).
4. Tasa y tiempo medio de rollback — probado, no documentado.
5. Resistencia a inyección de prompt vía telemetría (objetivo: 0 políticas aplicadas).
6. Disponibilidad con la IA apagada (debe ser idéntica).

---

## 2026-07-31 · El gate de fronteras, ¿gatea de verdad? — PASA, con una trampa

**Montaje.** Escrito `.gb-boundaries` con 17 reglas y ejecutado `gb graph src --gate`
sobre el paquete limpio; después inyectada a propósito una violación real
(`guardia.actores` importando `guardia.politica`, que es justo lo que la regla 3
prohíbe) y repetido.

**Resultado.** Limpio: salida 0. Con la violación: salida 1 y el cruce señalado por
nombre. El gate gatea.

**La trampa, que es lo que hace útil esta entrada.** En el primer intento el gate pasó
en verde **con la violación puesta**. Causa: `.gb-boundaries` estaba en la raíz del
proyecto y `gb graph src` lo busca dentro del path que analiza. Cargaba cero reglas y
no lo decía en la salida corta. Un fichero de invariantes en el sitio equivocado no
falla ruidosamente: pasa en verde, que es el peor modo de fallo posible para un gate.

**Consecuencia.** El fichero se movió a `src/.gb-boundaries`. Y la lección general, que
vale para todos los gates de este proyecto: **un gate se verifica rompiéndolo a
propósito**, nunca comprobando que pasa. Es el mismo argumento del punto 3 del criterio
de terminado aplicado a nuestras propias herramientas.

## 2026-07-31 · Corpus adversarial contra el validador determinista — PASA

**Montaje.** 13 propuestas JSON en [corpus/propuestas/](../corpus/propuestas/), con el
veredicto esperado declarado en el nombre del fichero: 3 legítimas, 4 que violan
invariantes (lockout de SSH, lockout total entrante, cegado del log de auditoría,
denegación de rutas del plano de control), 1 que ciega el registro por syscalls, y 4
malformadas para la gramática (tipo inventado, motor inventado, puerto 70000, CIDR
alucinado).

**Resultado.** 84 tests en verde. Las 10 envenenadas se rechazan y **por el motivo
esperado**, no por casualidad: el test compara el invariante violado contra el prefijo
del nombre. Códigos de salida de la CLI: 0 legítima, 5 violación de invariante, 2
descartada por gramática.

**Consecuencia.** La tasa de rechazo es distinta de cero contra un adversario escrito a
mano. Esto **no** mide todavía lo que dice la métrica 5 (resistencia a inyección de
prompt), porque aquí no hay LLM: mide que el validador determinista que hay debajo del
LLM rechaza lo que debe. Cuando entre T2, este mismo corpus se envuelve en telemetría
hostil y se vuelve a medir.

**Negativo honesto.** El corpus lo escribí yo sabiendo qué comprueba el validador. Un
corpus escrito por quien conoce las respuestas mide menos de lo que parece; el corpus
que cuenta es el que sale de incidentes reales y el que escriba un modelo distinto
intentando colar cosas.
