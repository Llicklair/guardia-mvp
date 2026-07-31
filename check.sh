#!/usr/bin/env bash
# Los gates deterministas, en un comando. Van ANTES de cualquier revision por LLM
# (H1 del informe de galaxy-brain: el feedback determinista es la mejor verificacion).
#
# Uso: ./check.sh    Salida 0 = todo verde. Cualquier otra cosa = no se commitea.
set -uo pipefail

cd "$(dirname "$0")"
fallos=0

paso() {
  local nombre="$1"
  shift
  echo "── $nombre"
  if "$@"; then
    echo "   OK"
  else
    echo "   FALLA"
    fallos=$((fallos + 1))
  fi
}

paso "lint (ruff)" python -m ruff check src tests
paso "formato (ruff)" python -m ruff format --check src tests
paso "tests (pytest)" python -m pytest tests/ -q
paso "fronteras y ciclos (gb)" gb graph src --gate

echo
if [ "$fallos" -eq 0 ]; then
  echo "gates: todo verde"
else
  echo "gates: $fallos gate(s) en rojo"
fi
exit "$fallos"
