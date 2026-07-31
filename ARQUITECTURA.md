# Sistema de seguridad a nivel SO con capa de IA — arquitectura y valoración

> Estado: documento fundacional. No hay código todavía.
> Nombre del proyecto: pendiente.

---

## 1. Veredicto honesto antes de nada

La idea tiene tres partes y no valen lo mismo.

**Parte real y construible:** un agente a nivel SO con detección determinista y triggers.
Esto es tecnología conocida (eBPF, auditd, ETW, Sigma, YARA). Funciona, es medible, y es
la base sin la cual todo lo demás es una demo.

**Parte real y diferencial:** una IA que *fabrica y endurece política de defensa* —
reglas de detección, perfiles de confinamiento, filtros — validada por un pipeline de
verificación antes de aplicarse. Aquí es donde galaxy-brain aporta algo que casi nadie
tiene: no el LLM, sino el arnés que hace que un cambio escrito por un LLM sea confiable.

**Parte que hoy es teatro:** "la IA reescribe el código en tiempo real para defenderse".
Tal como suena, no se sostiene, por dos razones independientes y ambas fatales:

1. **Presupuesto temporal.** Un exploit se ejecuta en microsegundos. Una inferencia de LLM
   tarda entre 1 y 30 segundos. No pueden estar en el mismo lazo. Cuando el LLM termina de
   pensar, el atacante ya tiene shell. La IA no llega tarde por lenta: llega tarde por
   cuatro o cinco órdenes de magnitud.
2. **Superficie de ataque.** Un LLM con privilegios para modificar código en producción es
   la mejor primitiva de escalada de privilegios que se le puede regalar a un atacante. Su
   condición de victoria pasa a ser "conseguir que el defensor reescriba su propio código",
   y los datos que alimentan al LLM (logs, nombres de fichero, User-Agent, línea de comando
   de procesos) los controla él. Inyección de prompt no es un riesgo teórico aquí: es el
   canal de entrada principal.

La solución no es abandonar la idea, es **reencuadrarla**: la IA no reescribe el código de
producción bajo fuego. La IA reescribe *política declarativa* de forma continua, y reescribe
*código* solo a través del pipeline de forja, con gates, en minutos, reversible.

**El combate "IA atacante vs IA defensiva en tiempo real" sí ocurre — pero la IA defensiva
ya luchó antes.** Su contribución al milisegundo del ataque es la regla que escribió y
verificó cinco minutos antes. Esa es la formulación honesta y sigue siendo un producto fuerte.

---

## 2. La ley que ordena toda la arquitectura: presupuestos de tiempo

Cada nivel tiene un presupuesto y **solo puede contener mecanismos que quepan dentro**.
Violar esto es la causa raíz de que casi todo el "AI security" del mercado sea una demo.

| Nivel | Presupuesto | Quién decide | Autoridad de escritura |
|-------|-------------|--------------|------------------------|
| **T0 — Aplicación** | µs – ms | Kernel: eBPF/LSM, seccomp, AppArmor, WFP | Bloquea/permite. Sin IA. |
| **T1 — Detección** | ms – 100 ms | Motor determinista: Sigma, YARA, heurística, clasificador local pequeño | Emite evento. Puede contener (matar proceso, aislar red). Sin IA. |
| **T2 — Triaje** | 1 – 30 s | LLM | **Ninguna.** Solo lee. Produce hipótesis y propuesta. |
| **T3 — Forja** | 1 – 30 min | LLM + galaxy-brain | Propone cambio → gates → aplicar con rollback. |

Reglas invariantes:

- **Ningún nivel puede llamar hacia arriba de forma bloqueante.** T1 nunca espera a T2.
  Si el LLM está caído, lento o alucinando, T0 y T1 siguen protegiendo igual. La IA es
  estrictamente aditiva: su ausencia degrada la calidad, nunca la disponibilidad.
- **La contención es determinista.** Matar un proceso, aislar una IP o congelar una cuenta
  lo decide T1 con reglas, no el LLM. El LLM puede *sugerir* contención; un validador
  determinista la aprueba contra una gramática cerrada.

---

## 3. El reencuadre central: la IA genera política, no código de producción

Esta es la decisión de diseño más importante del proyecto.

**Por qué política y no código:**

| | Código de producción | Política declarativa |
|---|---|---|
| Verificable antes de aplicar | Difícil (requiere build + tests + despliegue) | Sí (dry-run, replay sobre tráfico grabado) |
| Reversible | Parcialmente | Sí, atómicamente |
| Radio de daño si es incorrecto | Ilimitado (RCE, corrupción de datos) | Acotado (falsos positivos, denegación) |
| Auditable por un humano | Minutos por diff | Segundos por regla |
| Superficie si el atacante lo dirige | Ejecución arbitraria | Como mucho, una regla mala |

**Artefactos que la IA sí debe producir (todos declarativos, versionados, firmados):**

- Reglas de detección (Sigma, YARA, consultas osquery).
- Perfiles de confinamiento (seccomp, AppArmor/SELinux, capabilities, cgroups).
- Filtros de red (nftables, políticas de egress, reglas WAF).
- Políticas de autorización (OPA/Rego, Cedar).
- Programas eBPF **desde plantillas parametrizadas**, nunca texto libre.

**Y cuándo sí toca código:** cuando el análisis de T2 concluye que la causa raíz es un
defecto en el software propio (una validación ausente, un path traversal, una deserialización
insegura). Entonces se abre una tarea de forja — no un parche caliente. Sale una rama, un
test que reproduce, un arreglo, un veredicto adversarial y una PR. En minutos u horas, no
en tiempo real. Y eso está bien: el ataque ya lo contuvo T0/T1.

---

## 4. Dónde encaja galaxy-brain: T3 es la forja

El pipeline existente mapea casi uno a uno. No hay que inventar nada, hay que instanciarlo
sobre un dominio nuevo.

| Rol de galaxy-brain | Función en el sistema de seguridad |
|---|---|
| **`/goal`** — condición de parada objetiva | "El repro del incidente #N deja de reproducir y no hay regresión en el corpus de tráfico benigno." |
| **`loop-finder`** — explora con una lente | Lentes de seguridad: superficie de ataque, validación de entrada, autorización, secretos, deserialización. |
| **`loop-tester`** — escribe el repro | **Pieza clave.** Convierte un incidente real en un test ejecutable. Sin esto no se puede saber si el arreglo arregla algo. |
| **`loop-fixer`** — implementa en worktree, commitea, no mergea | Escribe la regla o el parche aislado. El worktree es aquí una frontera de seguridad, no una comodidad. |
| **`loop-evaluator`** — asume roto, corre gates reales, modelo distinto | El guardián. Si REJECT, el cambio no se aplica. Que use otro modelo importa más aquí que en desarrollo normal: si el atacante envenena a un modelo, no envenena al juez. |
| **Hook anti-auto-merge** | Se convierte en control de seguridad, no en higiene de proceso. |

**Gates específicos que T3 debe correr y que no existen en el pipeline actual:**

1. **Replay benigno.** La regla nueva se corre contra un corpus grabado de actividad normal.
   Si dispara, es falso positivo → REJECT. Sin esto, la IA aprende a bloquear todo.
2. **Replay malicioso.** Se corre contra el repro del incidente. Si no dispara → REJECT.
3. **Verificación de invariantes.** ¿La regla toca alguna de las protecciones intocables
   (§5)? → BLOCKER inmediato.
4. **Prueba de reversibilidad.** El rollback se ejecuta de verdad en el sandbox y se
   comprueba que restaura el estado exacto. Un cambio sin rollback probado no se aplica.
5. **Canary.** Se aplica primero a un subconjunto mínimo, se observa, y solo después se
   extiende. Nunca despliegue global de golpe.

---

## 5. El propio sistema es el objetivo de mayor valor

Un agente con root en cada máquina, con un LLM dentro, es el sueño de cualquier atacante.
Estas restricciones no son opcionales y hay que diseñarlas desde el primer commit, porque
retrofitearlas es imposible.

**5.1 — El LLM no tiene autoridad, nunca.**
No ejecuta acciones. Emite una propuesta estructurada (JSON con esquema) que un validador
determinista comprueba contra una gramática cerrada y un allowlist. Si la propuesta no
encaja en la gramática, se descarta sin interpretarse. El LLM es un *asesor sin manos*.

**5.2 — La entrada del LLM es hostil por definición.**
El atacante controla nombres de fichero, argumentos de proceso, cabeceras HTTP, contenido de
logs — todo lo que va al contexto. Por tanto: todo dato de telemetría se marca explícitamente
como *datos no confiables*, jamás como instrucción; se trunca y se normaliza; y las
propuestas se validan aunque el modelo jure que son urgentes. Asumir que llegará una
inyección de prompt: llegará.

**5.3 — Aislamiento del proceso de IA.**
Corre sin privilegios, en su propio usuario/namespace, sin acceso al sistema de ficheros del
host salvo a su cola de entrada, sin red salvo al endpoint del modelo. Comprometer el
componente de IA no debe dar nada por sí solo.

**5.4 — Invariantes intocables.**
Un conjunto de protecciones que **ninguna política generada puede modificar**, aplicado por
código determinista, no por prompt:
- El canal de administración (SSH desde el rango del admin).
- El plano de control del propio agente y su capacidad de recibir un rollback.
- El log de auditoría (append-only, idealmente exportado fuera de la máquina).
- El propio conjunto de invariantes.

**5.5 — Anti-lockout y anti-autoDoS.**
Una IA con permiso para escribir reglas de firewall puede dejar al administrador fuera o
tumbar el servicio ella sola. Eso es un ataque de disponibilidad que el defensor se hace a
sí mismo, y es el modo de fallo *más probable* de todo el sistema. Mitigación: límite de
tasa de cambios por ventana, dead-man's switch (si nadie confirma en N minutos, revierte
automáticamente), y camino de recuperación fuera de banda.

**5.6 — Interruptor de emergencia.**
Un comando determinista que congela la capa de IA y fija la política en el último estado
bueno conocido. No lo puede invocar ni desactivar la IA. Es la primera cosa que hay que
construir, antes que ninguna capacidad de escritura.

---

## 6. Qué NO construir

El instinto de construir el sensor desde cero es el que mata este proyecto. Un sensor eBPF
propio son dos años de trabajo para acabar con un Falco peor. El valor está arriba.

| Capa | Usar esto | No reimplementar |
|---|---|---|
| Sensor de runtime (Linux) | **Falco** (eBPF, motor de reglas) | Instrumentación de syscalls propia |
| Estado del host | **osquery** | Inventario propio |
| HIDS / integridad / correlación | **Wazuh** | SIEM propio |
| Formato de reglas | **Sigma** (+ YARA para ficheros) | DSL propio |
| Red | **Suricata**, **Zeek** | Motor IDS propio |
| Reputación colaborativa de IP | **CrowdSec** (modelo bouncer ≈ T0/T1) | — |
| Motor de políticas | **OPA/Rego** o **Cedar** | Evaluador propio |
| Confinamiento | seccomp, AppArmor/SELinux, WFP | — |
| Windows | **Sysmon** + ETW | — |

**Lo que sí es tuyo y no existe hoy:** el plano de control que convierte un incidente en un
cambio de política verificado, con repro, veredicto adversarial, canary y rollback probado.
Eso es galaxy-brain aplicado a defensa, y es defendible.

---

## 7. MVP: lo mínimo que demuestra la tesis y es falsable

Objetivo del MVP: **un incidente real produce una regla nueva, verificada, que bloquea la
repetición del ataque — y el sistema demuestra que la regla no rompe nada.**

Alcance deliberadamente estrecho:

- **Plataforma: Linux primero**, en contenedor o VM. Es donde están los servidores, y eBPF
  hace tratable lo que en Windows exige un driver firmado. Windows entra después, detrás
  de una abstracción de sensor. (Tienes WSL2 + Docker Desktop; el entorno ya está.)
- **Un único escenario de ataque** end-to-end. Por ejemplo: shell inversa lanzada desde un
  proceso hijo de un servidor web.
- **T0/T1:** Falco con su ruleset base. Sin IA.
- **T2:** el evento va a un LLM sin privilegios que produce un JSON estructurado: hipótesis,
  clasificación, propuesta de regla Sigma/Falco.
- **T3:** la propuesta pasa por replay benigno + replay malicioso + prueba de rollback, con
  el evaluador adversarial dictando PASS/REJECT.
- **Aplicación:** canary, con dead-man's switch.
- **Interruptor de emergencia:** desde el día uno.

**Criterio de éxito falsable.** El MVP funciona si, sobre un corpus de N incidentes
grabados, el pipeline produce reglas que (a) bloquean el ataque, (b) no disparan sobre el
corpus benigno, y (c) el evaluador rechaza correctamente las propuestas malas que se le
inyectan a propósito. Ese tercer punto es el que mide si el arnés vale algo. **Si el
evaluador nunca dice REJECT, el sistema es teatro** — y hay que meterle propuestas
envenenadas a propósito para comprobarlo.

---

## 8. Métricas que separan lo real del teatro

Cualquiera puede enseñar un LLM narrando un ataque. Estas son las que no se pueden fingir:

1. **Tasa de rechazo del evaluador.** Debe ser claramente mayor que cero. Si es cero, el gate
   no gatea.
2. **Falsos positivos introducidos por reglas generadas por IA**, medidos contra el corpus
   benigno. Es *la* métrica que hunde estos sistemas en producción.
3. **Tiempo de contención (T0/T1) medido aparte del tiempo de análisis (T2).** Mezclarlos es
   la mentira estándar del sector.
4. **Tasa de rollback y tiempo medio de rollback.** Probado, no documentado.
5. **Resistencia a inyección de prompt:** porcentaje de intentos, inyectados vía telemetría,
   que consiguen que se aplique una política. Objetivo: cero, y hay que atacarse a uno mismo
   para saberlo.
6. **Disponibilidad con la IA apagada.** Debe ser idéntica. Es la prueba de que la IA es
   aditiva y no un punto único de fallo.

---

## 9. Decisiones abiertas

- **Modelo local vs API.** Un servidor comprometido no debería filtrar telemetría a una API
  externa, y la dependencia de red es un punto de fallo. Un modelo local pequeño para T2 y
  uno grande para T3 (que no es urgente) es probablemente la respuesta.
- **Un agente por máquina vs plano de control central.** El central da corpus compartido y
  mejores reglas; el distribuido no crea un único objetivo que comprometa toda la flota.
- **Servidores vs equipos personales.** Son productos distintos: en un portátil el corpus
  "benigno" es impredecible y la tasa de falsos positivos se dispara. Recomendación: elegir
  servidores para el MVP y tratar el escritorio como una fase posterior.
- **Confianza en el corpus benigno.** Si el atacante ya estaba dentro cuando se grabó, su
  actividad queda etiquetada como normal. Hace falta una estrategia de procedencia.
