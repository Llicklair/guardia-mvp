# 0007 — El evaluador adversarial es el mismo modelo con otra lente, y es advisory

Estado: aceptada · Fecha: 2026-07-31 · Modifica: **regla 10** de ARCHITECTURE.md

## Contexto

La regla 10 decia: *"Generador ≠ evaluador. El veredicto lo dicta un modelo de familia
distinta al que genero la propuesta; si el atacante envenena a un modelo, no envenena
al juez."* ARCHITECTURE exige un ADR para relajar una regla, citandola por numero y
explicando **que evidencia nueva la invalida**. Esta es esa evidencia.

**1. El veredicto ya no lo dicta un modelo.** Cuando se escribio la regla 10, el diseno
contemplaba un LLM juez dictando PASS/REJECT. El sistema que existe hoy no funciona
asi: el veredicto lo dictan los cuatro gates deterministas de la regla 6 —
invariantes, replay benigno, replay malicioso y rollback probado— sobre corpus que el
atacante no controla. La medicion de la metrica 5 (docs/evidencia.md, 2026-07-31) dio
**cero politicas malas aplicadas con seis inyecciones reales y ningun LLM ejerciendo de
juez**. La premisa de la regla describia un diseno que este proyecto ya no tiene.

**2. Dos proveedores no salen a cuenta para una senal que no bloquea.** Mantener una
segunda familia significa una credencial mas, una superficie mas y otro modo de fallo
que vigilar. Medido en este mismo repo: gemini tardo 99s frente a los 15s de claude, y
su aislamiento es mas debil (`plan` es "solo lectura", no "sin herramientas", y exige
`--skip-trust`). Pagar eso por una salida que por diseno no puede cambiar un veredicto
no es una compensacion razonable.

## Decision

La regla 10 pasa a: **generador ≠ evaluador en rol, no necesariamente en familia**, y
el evaluador es **advisory**.

- El evaluador adversarial (`guardia.evaluador`) usa el **mismo transporte y el mismo
  modelo** que T2, con un rol distinto: se le pide **refutar**, no valorar, desde
  varias lentes en negativo (lockout, cobertura, alcance, desvio).
- Su salida **jamas cambia un veredicto**. Enriquece el informe y queda en la auditoria
  marcada `advisory: true`. Un juez que no puede condenar no necesita ser incorruptible.
- Tiene **una ventaja estructural sobre el generador, y solo una**: no ve la telemetria.
  Se le da la propuesta ya formada, no el texto hostil que la motivo. Una inyeccion que
  desvie a T2 no llega al evaluador por el mismo camino.
- Un evaluador caido **no puede parar una contencion**: `TransporteFallido` se traduce
  en "sin dictamen", nunca en un bloqueo. Convertir una senal advisory en punto de
  fallo seria peor que no tenerla.
- `gemini` se mantiene como transporte alternativo disponible y medido, pero **ya no
  es parte del diseno**: nada depende de el.

## Consecuencias

- **El limite, escrito y no escondido:** un evaluador de la misma familia comparte
  modos de fallo con el generador. Si el modelo tiene un punto ciego, lo tiene en las
  dos pasadas, y ninguna cantidad de lentes lo arregla. Este ADR **no** afirma que dos
  pasadas del mismo modelo equivalgan a dos familias: afirma que la diferencia no
  compensa **dado que el juez real es determinista**. Si algun dia un LLM volviera a
  dictar veredictos, la regla 10 original recupera toda su fuerza y este ADR debe
  revisarse.
- Lo que hay que vigilar para saber si esto fue un error: si las objeciones del
  evaluador empiezan a correlacionar demasiado con lo que ya dicen los gates, no esta
  aportando informacion — esta repitiendo. Y si nunca objeta nada, es decorativo. Las
  dos cosas son medibles sobre el corpus de inyecciones.
- El evaluador no entra en el camino caliente de contencion (T0/T1 siguen sin IA). Es
  una pasada mas en T2/T3, cuya cota temporal ya es de segundos.
