"""El informe de estado: una proyeccion de SOLO LECTURA del plano de control a HTML.

Por que existe. Un operador necesita ver el estado y la historia de decisiones sin leer
JSONL a pelo. Esto lo renderiza. Y lo que NO es importa igual: es una VISTA, no una
autoridad. No importa nada del dominio — recibe los datos ya leidos (el estado del
interruptor, las entradas de auditoria, el veredicto de integridad) y devuelve HTML. No
decide, no aplica, no confirma; esas acciones siguen pasando por la CLI y la autoridad de
`actores` (regla 3). Un panel con autoridad propia seria otra vez darle poder a algo que
no debe tenerlo — la vista mira, la autoridad sigue siendo el conjunto cerrado de actores.

**La regla 4 tambien vive aqui.** El log contiene datos que escribio el atacante: cmdline,
etiquetas con inyecciones de prompt. Al pintarlos en HTML son texto hostil, asi que TODO
lo dinamico se escapa con `html.escape` — una etiqueta con `<script>` se muestra como
texto, nunca se convierte en markup en el panel del operador. La telemetria se muestra,
nunca se ejecuta: ni en el kernel ni en el navegador.

Recibe los datos por parametro (no los lee del disco) a proposito: asi el renderizador es
una funcion pura, testeable sin ficheros y sin reloj, y quien lee el estado es la CLI, que
ya tiene la autoridad para hacerlo.
"""

from __future__ import annotations

import html
import json
from typing import Any, Protocol


class _Estado(Protocol):
    congelado: bool
    motivo: str
    desde: str
    actor: str


class _Entrada(Protocol):
    seq: int
    ts: str
    evento: str
    actor: str
    datos: dict[str, Any]


class _Veredicto(Protocol):
    intacta: bool
    entradas: int
    rota_en: int | None
    motivo: str | None


# Cada actor pinta distinto porque cada uno significa algo distinto: el humano es la unica
# autoridad para congelar/confirmar, la ia solo propone (advisory), el automata dicta los
# veredictos deterministas. El color deja leer "quien hizo que" de un vistazo.
_ACTORES = {
    "humano": ("humano", "#f0a637"),
    "ia": ("ia", "#45d4e6"),
    "automata": ("automata", "#3ddc97"),
    "sistema": ("sistema", "#8494a6"),
}


def _e(valor: object) -> str:
    """Escapa cualquier valor para HTML. El log es dato hostil; nada entra como markup."""
    return html.escape(str(valor), quote=True)


def _chip_actor(actor: str) -> str:
    etiqueta, color = _ACTORES.get(actor, (actor, "#8494a6"))
    return f'<span class="actor" style="--c:{color}">{_e(etiqueta)}</span>'


def _fila(entrada: _Entrada) -> str:
    datos = json.dumps(entrada.datos, ensure_ascii=False, sort_keys=True)
    datos_html = f'<pre class="datos">{_e(datos)}</pre>' if entrada.datos else ""
    return (
        "<tr>"
        f'<td class="seq">{_e(entrada.seq)}</td>'
        f'<td class="ts">{_e(entrada.ts)}</td>'
        f"<td>{_chip_actor(entrada.actor)}</td>"
        f'<td class="ev"><b>{_e(entrada.evento)}</b>{datos_html}</td>'
        "</tr>"
    )


def _tarjeta_estado(estado: _Estado) -> str:
    congelada = estado.congelado
    marca = "CONGELADA" if congelada else "operativa"
    clase = "mal" if congelada else "bien"
    nota = (
        '<p class="nota">T0/T1 siguen protegiendo: la capa de IA es aditiva (regla 2).</p>'
        if congelada
        else '<p class="nota">La capa de IA puede proponer; el veredicto sigue en los gates.</p>'
    )
    return f"""
    <div class="tarjeta">
      <span class="rotulo">Capa de IA</span>
      <div class="grande {clase}">{marca}</div>
      <dl>
        <dt>desde</dt><dd>{_e(estado.desde)}</dd>
        <dt>actor</dt><dd>{_chip_actor(estado.actor)}</dd>
        <dt>motivo</dt><dd>{_e(estado.motivo)}</dd>
      </dl>
      {nota}
    </div>"""


def _tarjeta_integridad(veredicto: _Veredicto) -> str:
    if veredicto.intacta:
        cuerpo = (
            '<div class="grande bien">intacta</div>'
            f"<dl><dt>entradas</dt><dd>{_e(veredicto.entradas)}</dd></dl>"
            '<p class="nota">Cada entrada encadena por hash con la anterior: '
            "el log no se ha reescrito.</p>"
        )
    else:
        cuerpo = (
            '<div class="grande mal">CADENA ROTA</div>'
            f"<dl><dt>rota en</dt><dd>#{_e(veredicto.rota_en)}</dd>"
            f"<dt>motivo</dt><dd>{_e(veredicto.motivo)}</dd></dl>"
            '<p class="nota">Alguien reescribio el log despues de escrito. '
            "El estado que se muestra abajo NO es de fiar a partir de esa entrada.</p>"
        )
    return f"""
    <div class="tarjeta">
      <span class="rotulo">Integridad de la cadena</span>
      {cuerpo}
    </div>"""


def render(
    estado: _Estado,
    entradas: list[_Entrada],
    veredicto: _Veredicto,
    generado_en: str,
) -> str:
    """La proyeccion completa a HTML. Funcion pura: los datos entran ya leidos y el
    instante de generacion se inyecta, para que el informe sea determinista en test."""
    if entradas:
        filas = "\n".join(_fila(e) for e in reversed(entradas))  # lo mas nuevo, arriba
        tabla = f"""
      <table class="log">
        <thead><tr><th>#</th><th>cuando</th><th>actor</th><th>evento</th></tr></thead>
        <tbody>{filas}</tbody>
      </table>"""
    else:
        tabla = '<p class="vacio">Sin entradas: la capa aun no ha registrado ninguna decision.</p>'

    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>guardia · informe de estado</title>
<style>
  :root{{--fondo:#0a0d14;--panel:#10151f;--panel2:#161d29;--linea:rgba(255,255,255,.09);
    --tinta:#e8edf3;--suave:#93a2b5;--tenue:#5b6a7d;--bien:#3ddc97;--mal:#ff5d73;--cian:#45d4e6;
    --mono:"JetBrains Mono","Cascadia Code",ui-monospace,"SF Mono",Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,Roboto,sans-serif;}}
  *{{box-sizing:border-box}}
  body{{margin:0;background:var(--fondo);color:var(--tinta);font-family:var(--sans);
    line-height:1.55;font-size:15px}}
  .env{{max-width:1000px;margin:0 auto;padding:0 20px}}
  header{{border-bottom:1px solid var(--linea);background:rgba(10,13,20,.9);
    position:sticky;top:0;backdrop-filter:blur(10px)}}
  header .env{{display:flex;align-items:center;gap:14px;padding:14px 20px;flex-wrap:wrap}}
  .marca{{font-family:var(--mono);font-weight:700;font-size:17px;color:#fff}}
  .marca .g{{color:var(--cian)}}
  .solo-lectura{{font-family:var(--mono);font-size:11px;letter-spacing:.08em;text-transform:uppercase;
    color:var(--cian);border:1px solid rgba(69,212,230,.35);border-radius:999px;padding:4px 10px}}
  .gen{{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--tenue)}}
  h1{{font-family:var(--mono);font-size:22px;margin:26px 0 4px;letter-spacing:-.01em}}
  .intro{{color:var(--suave);max-width:70ch;margin:0 0 22px}}
  .tarjetas{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:26px}}
  .tarjeta{{border:1px solid var(--linea);border-radius:14px;background:var(--panel);padding:18px}}
  .rotulo{{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--suave)}}
  .grande{{font-family:var(--mono);font-weight:750;font-size:30px;
    letter-spacing:-.02em;margin:8px 0 12px}}
  .grande.bien{{color:var(--bien)}} .grande.mal{{color:var(--mal)}}
  dl{{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;margin:0;font-size:14px}}
  dt{{font-family:var(--mono);font-size:12px;color:var(--tenue);text-transform:uppercase;letter-spacing:.06em}}
  dd{{margin:0;color:var(--tinta)}}
  .nota{{margin:12px 0 0;font-size:12.5px;color:var(--tenue);line-height:1.5}}
  .actor{{font-family:var(--mono);font-size:12px;color:var(--c);white-space:nowrap;
    border:1px solid color-mix(in srgb,var(--c) 40%,transparent);
    background:color-mix(in srgb,var(--c) 10%,transparent);border-radius:999px;padding:2px 9px}}
  table.log{{width:100%;border-collapse:collapse;font-size:13.5px}}
  .log th{{text-align:left;font-family:var(--mono);font-size:11px;letter-spacing:.1em;
    text-transform:uppercase;color:var(--tenue);padding:8px 12px;
    border-bottom:1px solid var(--linea)}}
  .log td{{padding:11px 12px;border-bottom:1px solid rgba(255,255,255,.05);vertical-align:top}}
  .log tr:hover td{{background:rgba(255,255,255,.02)}}
  .seq{{font-family:var(--mono);color:var(--tenue);font-variant-numeric:tabular-nums}}
  .ts{{font-family:var(--mono);font-size:12px;color:var(--suave);white-space:nowrap}}
  .ev b{{font-family:var(--mono);font-weight:600;color:var(--tinta)}}
  .datos{{margin:6px 0 0;font-family:var(--mono);font-size:11.5px;color:var(--suave);
    white-space:pre-wrap;word-break:break-word;max-width:52ch;background:var(--panel2);
    border:1px solid var(--linea);border-radius:8px;padding:8px 10px;overflow-x:auto}}
  .vacio{{color:var(--tenue);border:1px dashed var(--linea);
    border-radius:12px;padding:24px;text-align:center}}
  .seccion-rotulo{{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;
    color:var(--cian);margin:0 0 12px}}
  footer{{margin:34px 0 60px;padding-top:18px;border-top:1px solid var(--linea);
    color:var(--tenue);font-size:12.5px;line-height:1.6}}
  footer code{{font-family:var(--mono);color:var(--suave)}}
  .scrollx{{overflow-x:auto}}
</style></head>
<body>
<header><div class="env">
  <span class="marca"><span class="g">guardia</span> · informe</span>
  <span class="solo-lectura">solo lectura</span>
  <span class="gen">generado {_e(generado_en)}</span>
</div></header>
<div class="env">
  <h1>Estado del plano de control</h1>
  <p class="intro">Proyeccion del log de auditoria y el estado del interruptor. Es una vista:
    no aplica ni confirma nada — para actuar, la CLI a traves de la autoridad de actores.</p>
  <div class="tarjetas">
    {_tarjeta_estado(estado)}
    {_tarjeta_integridad(veredicto)}
  </div>
  <p class="seccion-rotulo">Linea de tiempo · decisiones e incidentes (lo mas nuevo, arriba)</p>
  <div class="scrollx">{tabla}</div>
  <footer>
    Vista de <b>solo lectura</b>: los datos del atacante (cmdline, etiquetas) van escapados —
    se muestran, nunca se ejecutan. Para actuar (<code>congelar</code>, <code>confirmar</code>
    un canary) usa la CLI; la autoridad sigue en el conjunto cerrado de actores, no en este panel.
  </footer>
</div>
</body></html>"""
