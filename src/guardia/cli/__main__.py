"""`python -m guardia.cli`. El entrypoint instalado es `guardia` (pyproject), pero
este camino existia con el modulo monolitico y partir el fichero no es motivo para
quitarselo a quien lo tenga tecleado."""

from . import main

raise SystemExit(main())
