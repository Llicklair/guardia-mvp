# guardia

**MVP de un plano de control de seguridad a nivel de sistema operativo con una capa de IA
verificada.** La tesis, en una frase: la IA propone, pero **el veredicto lo dictan cuatro
gates deterministas, no el modelo**. Construido sobre el pipeline de verificación de
galaxy-brain.

> Estado: prueba de concepto. El plano de control (T2/T3) está construido y medido; el
> *enforcement* real contra un kernel no se ha ejecutado (ver [Límites](#límites-dichos-de-frente)).

## La idea

Un exploit corre en microsegundos; un LLM tarda segundos. Poner a la IA a **reescribir
código en caliente** durante un incidente sería, además de inútil por lento, una primitiva
de escalada por inyección de prompt. Así que aquí la IA **no toca el código ni el kernel**:
genera **política declarativa** (una gramática cerrada), y esa política solo se aplica si
sobrevive a una batería de gates. El código, cuando hace falta, se forja aparte en minutos,
no en caliente.

El sistema se organiza por **presupuesto temporal**, en cuatro niveles:

| Nivel | Qué hace | ¿Escribe? |
|------|----------|-----------|
| **T0** | Kernel / mecanismos base | — |
| **T1** | Detección determinista (reglas, sin IA) | no |
| **T2** | Triaje: un LLM **lee** la telemetría y **propone** política | no, solo propone |
| **T3** | **El crisol**: verifica la propuesta y, si pasa, la aplica | sí, el único |

La IA vive en T2 y **no tiene autoridad**: propone y nada más. Quien decide es T3.

## El crisol (T3) — los gates

Toda propuesta pasa, en orden, por:

0. **Interruptor** — un *kill switch* fail-closed. Sin estado en disco **nace congelado**:
   si algo va mal, no se aplica nada.
1. **Invariantes** — canal de administración intacto, rutas protegidas, capacidad de
   registro. Una propuesta que cierre el SSH del admin o ciegue la auditoría muere aquí.
2. **Replay benigno** — la política se reproduce contra tráfico legítimo grabado: si rompe
   lo bueno (auto-DoS), fuera.
3. **Replay malicioso** — se reproduce contra el incidente: si no contiene el ataque, fuera.
4. **Rollback probado** — la reversión se verifica por hash antes de dar nada por aplicado.

El veredicto es de los cinco gates. El modelo puede equivocarse, o incluso ser desviado por
una inyección de prompt: mientras su propuesta no pase los gates, no se aplica.

## Instalación

Sin dependencias externas. Python ≥ 3.11.

```bash
pip install -e .
```

El entrypoint es el comando `guardia` (no hay `python -m guardia`).

## Uso

```bash
guardia estado                 # estado del interruptor
guardia descongelar "motivo"   # activar la capa (queda en el log encadenado)
guardia responder incidente.jsonl   # ciclo completo: incidente → T2 → T3
guardia crisol propuesta.json       # pasar una propuesta por los gates a mano
guardia auditoria              # ver el log encadenado por hash
guardia informe --salida panel.html # panel de operador (HTML, sin servidor)
guardia enforcement            # traducir la política activa a un ruleset nftables (dry-run)
```

Instrumentos de medición (algunos gastan cuota de un LLM real; son opt-in):

```bash
guardia banco                  # métrica 5: corpus de inyecciones contra T2, ciclo completo
guardia banco-evaluador        # ¿el evaluador distingue una propuesta desviada de la correcta?
guardia generar-inyecciones    # encarga un corpus de ataques a un modelo ciego
```

Por defecto, todo lo que costaría cuota **enseña el plan y no gasta**; ejecutar de verdad
exige nombrar el modelo a mano.

## Verificación

```bash
bash check.sh   # ruff + pytest + gate del grafo de dependencias (gb graph src --gate)
```

259 tests deterministas + 2 *smokes* con cuota (marcados `skip` salvo opt-in). El grafo de
imports se mantiene sin ciclos y con fronteras declaradas en `src/.gb-boundaries`: por
ejemplo, el evaluador **no** puede importar `crisol`/`despliegue`/`aplicador` (no manda), y
el generador de ataques **no** ve la gramática (ataca a ciegas).

## Evidencia

`docs/evidencia.md` es la libreta del proyecto: **cada medición real, con los negativos
escritos con el mismo detalle que los positivos.** Un proyecto que solo registra lo que
funcionó no tiene evidencia, tiene publicidad. Allí están, entre otras cosas: la métrica de
contención bajo inyección de prompt, la varianza del generador de ataques (un modelo
alineado se niega sistemáticamente a los objetivos de daño dirigido), y la del evaluador
adversarial (por qué es *advisory* y no bloquea).

## Sobre los modelos

La verificación asume, como norma del proyecto, **mínimo Opus**. El "evaluador adversarial"
no es otro proveedor: es el mismo modelo con una **lente distinta** (encuadre de refutación),
y su salida es *advisory* — nunca toca un veredicto. Los ADR 0006/0007 explican el porqué.

## Límites dichos de frente

- El *enforcement* real **no se ha corrido contra un kernel**: esta máquina de desarrollo es
  Windows, sin `nft`. El adaptador de nftables traduce y funciona en dry-run; empujar al
  kernel es el pendiente de una VM Linux, igual que el replay contra Falco.
- `aplicador.aplicar()` escribe el estado de la política; el *enforcement* espacial es un
  paso explícito aparte, nunca automático en el canary.
- No hay ingestión en vivo: los incidentes entran como ficheros.
- Los corpus generados por un LLM (`corpus/generadas*/`) **no son canónicos**: un modelo no
  es determinista, otra tirada da otra cosa. Se conservan como registro de cada medición.

## Documentos

- `ARQUITECTURA.md` / `ARCHITECTURE.md` — doc fundacional y ley de diseño (11 reglas).
- `SCOPE.md` — alcance.
- `docs/` — ADRs, evidencia y logs de medición.
