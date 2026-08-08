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

El interruptor es la puerta 0 —precede al crisol y no lo forma—; el veredicto lo dictan los
**cuatro gates**, nunca el modelo. Este puede equivocarse, o incluso ser desviado por una
inyección de prompt: mientras su propuesta no pase los gates, no se aplica.

## Instalación

Sin dependencias externas. Python ≥ 3.11.

```bash
pip install -e .
```

El entrypoint es el comando `guardia` (no hay `python -m guardia`).

## Uso

Todo comando acepta `--control DIR` (por defecto, `GUARDIA_CONTROL_DIR` o el del sistema).

**El interruptor y el log** — nace congelado; reactivar exige motivo, y el motivo queda escrito:

```bash
guardia estado                      # estado de la capa de IA
guardia congelar "motivo"           # kill switch (--actor humano|automata)
guardia descongelar "motivo"        # reactivar (--actor humano|automata|ia)
guardia auditoria                   # ver el log encadenado por hash (--verificar solo comprueba la cadena)
guardia informe                     # panel de operador HTML (--salida, por defecto <control>/informe.html)
```

**El ciclo de una propuesta** — de JSON a política activa, con canary y reversión:

```bash
guardia validar propuesta.json      # gramática e invariantes (sin fichero, lee de stdin)
guardia crisol propuesta.json       # los cuatro gates a mano (--benigno, --incidente)
guardia desplegar propuesta.json    # crisol + canary con dead-man's switch
guardia confirmar <id>              # promover un canary a estable (solo humano)
guardia revisar                     # dead-man's switch: revierte los canarios expirados
guardia responder incidente.jsonl   # el ciclo entero: incidente → T2 → T3
guardia enforcement                 # la política activa a ruleset nftables; dry-run salvo --aplicar
```

`enforcement --aplicar` es el único comando que toca el sistema (`nft -f -`: necesita Linux,
nftables y privilegios). Sin esa bandera solo imprime el ruleset.

**Instrumentos de medición** (gastan cuota de un LLM real; opt-in):

```bash
guardia banco                       # métrica 5: corpus de inyecciones contra T2, ciclo completo
guardia banco-evaluador             # ¿el evaluador distingue una propuesta desviada de la correcta?
guardia generar-inyecciones --salida DIR   # encarga un corpus de ataques a un modelo ciego
```

Por defecto, todo lo que costaría cuota **enseña el plan y no gasta**: hay que nombrar el
modelo a mano (`--proveedor llm` en `banco`/`responder`, `--llm-cli` en el resto). `--pasadas N`
repite la medición para ver la varianza y gasta N veces la cuota. Un modelo por debajo del
suelo de evaluación (`opus`) se **rechaza**, no se degrada en silencio.

## Verificación

```bash
bash check.sh   # ruff + pytest + gate del grafo de dependencias (gb graph src --gate)
```

279 tests deterministas + 2 *smokes* con cuota (`skip` salvo `GUARDIA_SMOKE_LLM=claude|gemini`).
El grafo de
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
