# 0006 — El LLM real se conecta por CLI en modo solo-inferencia

Estado: aceptada · Fecha: 2026-07-31

## Contexto

ADR 0005 dejo el `ProveedorLLM` detras de la interfaz sin conectar, a la espera de un
OK explicito. El OK llego (2026-07-31) con una condicion de Marcos: la conexion va por
CLI, no por API key directa. La decision de fondo de ARQUITECTURA §9 (modelo local vs
API para produccion) sigue abierta: esto es el banco de pruebas de la metrica 5, no la
configuracion de un host protegido.

## Decision

El proveedor se compone con un `Transporte` intercambiable. El primero es
`TransporteCLI`: invoca la CLI oficial del modelo (`claude`, `gemini`) como
subproceso, con tres condiciones no negociables:

1. **El prompt entra por stdin, nunca por argv.** Contiene telemetria escrita por el
   atacante; por argv acabaria en logs de procesos y en limites de linea de comandos.
2. **La CLI corre sin herramientas** (`claude -p --tools ""`;
   `gemini --approval-mode plan`). Un modelo con herramientas seria ejecucion de
   codigo a un prompt inyectado de distancia. Hay un test que vigila los presets.
   (Sin `--bare` en claude: ese modo solo autentica por API key y rompe la sesion
   OAuth de la suscripcion — medido, no supuesto.)
3. **Opt-in siempre.** `responder` usa el heuristico salvo `--proveedor llm`
   explicito; invocar el modelo gasta cuota y envia la telemetria por el canal del
   transporte, y eso es una decision, no un defecto.

Si el transporte cae (`TransporteFallido`), el ciclo se recupera con el heuristico y
la caida queda auditada: la respuesta a un incidente no espera a una inferencia.

## Consecuencias

- La autenticacion vive en la CLI (cuentas ya configuradas), no en este codigo: ni
  claves en el repo ni cliente HTTP propio que mantener.
- El mismo `Transporte` admite manana un modelo local (`ollama run ...`) sin tocar el
  proveedor — que es exactamente la salida que §9 preve para produccion.
- El coste: un subproceso por triaje (segundos, no milisegundos). Irrelevante en T2,
  cuya cota temporal ya es de segundos; la contencion sigue viviendo en T0/T1.
- Gemini queda disponible como segunda familia para el evaluador adversarial de la
  regla 10, que es trabajo pendiente y decision aparte.
