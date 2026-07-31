# 0005 — T2 con proveedor intercambiable; el LLM real no se conecta sin OK

Estado: aceptada · Fecha: 2026-07-31

## Contexto

T2 es el nivel donde vive el LLM (ARQUITECTURA §2). Pero conectar un LLM real gasta
cuota de API y manda telemetría del incidente a un endpoint externo — y un servidor
comprometido no debería filtrar telemetría fuera (§9, decisión abierta modelo local vs
API). Además, la regla de trabajo del proyecto exige OK explícito antes de gastar cuota.

Al mismo tiempo, el ciclo completo incidente→propuesta→gates→despliegue tiene que poder
demostrarse y testearse sin depender de una API.

## Decisión

El triaje (T2) toma un `Proveedor` intercambiable (interfaz `sugerir(contexto) -> str`).
Se implementan:

- `ProveedorHeuristico`: determinista, sin IA. Baseline y camino de recuperación si el
  LLM está caído. Propone la contención evidente (cortar egress externo).
- `ProveedorLLM`: detrás de la misma interfaz, **no conectado**. `sugerir` lanza
  `NotImplementedError` en vez de llamar a nada, para que gastar cuota sea imposible por
  accidente. Se conecta solo tras OK explícito.

La salida de cualquier proveedor pasa por la gramática cerrada (`politica.desde_json`) y
después por los cuatro gates de T3. T2 no tiene autoridad: propone, nunca aplica.

## Consecuencias

- El ciclo completo se demuestra y testea sin cuota (`guardia responder`, proveedor
  heurístico).
- La resistencia a inyección de prompt se puede medir simulando un proveedor envenenado
  (ver docs/evidencia.md): el veneno muere en los gates de T3, no en T2.
- Que la base sea determinista encaja con la tesis: la IA es el plus, no el cimiento.
- Conectar el LLM real es un cambio futuro con su propio OK y su decisión local-vs-API.
