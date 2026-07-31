"""Servidor web VULNERABLE A PROPOSITO. Solo para el laboratorio.

La ruta /ping pasa entrada del usuario a un shell sin sanear: es una inyeccion de
comandos de manual. Existe para tener un incidente reproducible, no para copiarse.
Aislado en la red del laboratorio, sin puertos al host.

Solo libreria estandar para que la imagen sea minima y el arranque, inmediato.
"""

from __future__ import annotations

import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PUERTO = 8080


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802  (la firma la fija http.server)
        partes = urlparse(self.path)
        if partes.path != "/ping":
            self._responder(404, "prueba /ping?host=127.0.0.1\n")
            return

        host = parse_qs(partes.query).get("host", ["127.0.0.1"])[0]
        # LA VULNERABILIDAD: shell=True con entrada del usuario. Deliberada.
        salida = subprocess.run(
            f"ping -c 1 {host}",
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self._responder(200, salida.stdout + salida.stderr)

    def _responder(self, codigo: int, cuerpo: str) -> None:
        datos = cuerpo.encode("utf-8", "replace")
        self.send_response(codigo)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(datos)))
        self.end_headers()
        self.wfile.write(datos)

    def log_message(self, *_args) -> None:
        return  # el ruido de acceso no aporta nada al laboratorio


if __name__ == "__main__":
    print(f"objetivo escuchando en :{PUERTO} (VULNERABLE A PROPOSITO)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PUERTO), Handler).serve_forever()
