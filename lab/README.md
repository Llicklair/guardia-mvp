# Laboratorio del MVP

Un escenario de ataque reproducible, end-to-end, sobre Linux en contenedores. Es el
"entorno donde equivocarse sale barato" y a la vez la fuente del corpus: sin un
incidente que se pueda repetir a voluntad no hay forma de saber si una regla sirve.

**Escenario único** ([SCOPE.md](../SCOPE.md)): shell inversa lanzada desde un proceso
hijo de un servidor web.

## Piezas

| Servicio | Papel | Nivel |
|---|---|---|
| `objetivo` | Servidor web con inyección de comandos deliberada | la víctima |
| `atacante` | Lanza el exploit y escucha la shell inversa | el adversario |
| `falco` | Sensor de runtime con su ruleset base + reglas locales | T0/T1 |

La vulnerabilidad del `objetivo` es intencionada y está aislada en la red del
laboratorio, sin puertos publicados al host. No es código de producción y no debe
salir de aquí.

## Uso

```bash
docker compose up -d --build      # levanta el laboratorio
./atacar.sh                       # dispara el escenario de ataque
docker compose logs falco         # qué vio el sensor
docker compose down -v            # lo tira todo
```

## El punto que mide algo

Falco detecta este escenario **con su ruleset base y sin IA de por medio** — es la
regla 1 en la práctica: la contención vive en T0/T1 y se mide en milisegundos. Lo que
la IA aportará después (T2/T3) es una regla más ajustada al incidente concreto, escrita
en minutos y verificada contra los cuatro gates. Nunca al revés.

Si el escenario solo se detectase gracias al LLM, el sistema sería exactamente lo que
[ARQUITECTURA.md §1](../ARQUITECTURA.md) llama teatro.

## Limitación conocida

Falco necesita ver el kernel del host. Bajo Docker Desktop en Windows ese kernel es el
de la VM de WSL2, y `modern_ebpf` exige BTF, que no todos los kernels de WSL2 traen.
Si el sensor no arranca en este entorno, se anota en
[docs/evidencia.md](../docs/evidencia.md) como resultado negativo y el laboratorio se
mueve a una VM Linux — no se maquilla con un sensor de mentira.
