#!/usr/bin/env bash
# Dispara el escenario de ataque contra el laboratorio ya levantado.
# Uso: ./atacar.sh   (antes: docker compose up -d --build)
set -uo pipefail

cd "$(dirname "$0")"

echo "== disparando el escenario dentro del contenedor atacante =="
docker compose exec -T atacante ./exploit.sh

echo
echo "== lo que vio Falco (T0/T1, sin IA) =="
# La linea que importa: la regla que detecta la shell del servidor web.
docker compose logs falco 2>&1 | grep -iE "shell|servidor web|CRITICAL" || {
  echo "(Falco no registro la deteccion; revisa 'docker compose logs falco')"
  echo "si es por BTF/eBPF en WSL2, va a docs/evidencia.md como negativo (ver lab/README)."
}
