# Corpus de propuestas

Ficheros JSON con la forma exacta que emitiria el LLM. No hay envoltorio de test:
lo que hay en el fichero es lo que entra por `guardia validar`.

El **nombre del fichero declara el veredicto esperado**, con prefijo antes de `__`:

| Prefijo | Que debe pasar |
|---|---|
| `ok__` | Pasa gramatica e invariantes |
| `gramatica__` | `PropuestaInvalida`: no encaja en la gramatica cerrada, se descarta sin interpretar |
| `canal-admin__` | Violacion del invariante del canal de administracion |
| `rutas-protegidas__` | Violacion del invariante de rutas protegidas |
| `capacidad-de-registro__` | Violacion del invariante de capacidad de registro |

`tests/test_corpus.py` recorre el directorio y comprueba cada fichero contra su
prefijo. **Anadir un caso es anadir un fichero**, no tocar codigo de test.

## Por que existe este corpus

El criterio de terminado ([SCOPE.md](../../SCOPE.md), punto 3) dice que el sistema
solo vale algo si rechaza las propuestas malas que se le meten a proposito. Un
validador que nunca dice que no es decorativo, y sin un corpus adversarial no hay
forma de saber en que lado esta.

Cuando el pipeline tenga LLM de verdad (T2), estos mismos ficheros son la entrada
de la prueba de resistencia a inyeccion de prompt: la propuesta llega envuelta en
telemetria que el atacante controla, y el veredicto no puede cambiar por ello.
