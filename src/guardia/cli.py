"""`guardia` — la linea de mando determinista.

Por defecto nada de lo que se hace desde aqui pasa por un modelo. Es a proposito: el
camino de recuperacion de un incidente no puede depender de que una inferencia
conteste. El unico modelo alcanzable es el triaje con `responder --proveedor llm`,
que es opt-in, y si su transporte cae el ciclo se recupera con el heuristico.
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import informe as informe_html
from . import nftables
from .actores import Actor, SinAutoridad
from .aplicador import Aplicador
from .banco import Banco
from .banco_evaluador import CASOS, BancoEvaluador
from .crisol import Crisol, Resultado
from .despliegue import NOMBRE_PRODUCCION, Despliegue, Estado
from .evaluador import EvaluadorAdversarial
from .eventos import CorpusIlegible, cargar
from .generador import ENCARGOS, GeneradorCiego, Rechazo, cargar_base
from .invariantes import Config, comprobar
from .kill_switch import ControlInvalido, Interruptor
from .politica import PropuestaInvalida, desde_json
from .transporte import (
    COMANDOS_CLI,
    SUELO_DE_EVALUACION,
    ModeloProhibido,
    TransporteCLI,
    TransporteFallido,
)
from .triaje import ProveedorHeuristico, ProveedorLLM, Triaje

RAIZ = Path(__file__).resolve().parent.parent.parent
BENIGNO_POR_DEFECTO = RAIZ / "corpus" / "eventos" / "benigno.jsonl"
INCIDENTE_POR_DEFECTO = RAIZ / "corpus" / "eventos" / "incidente-0001.jsonl"
INYECCIONES_POR_DEFECTO = RAIZ / "corpus" / "inyecciones"


class EntradaIlegible(Exception):
    """No se pudo leer el fichero de propuesta que se paso por la linea de mando.

    Hermana de `CorpusIlegible` y por el mismo motivo: la propuesta tambien es dato
    hostil que entra por una ruta, y un fichero mal tecleado tiene que salir como un
    error de uso, no como un traceback."""


def _texto_de_propuesta(args: argparse.Namespace) -> str:
    """La propuesta, del fichero o de stdin. Un solo sitio para los tres comandos que
    la leen (`validar`, `crisol`, `desplegar`): el tratamiento del fichero ausente es
    identico en los tres y repetirlo es garantizar que el proximo se olvide."""
    if not args.fichero:
        return sys.stdin.read()
    try:
        return Path(args.fichero).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise EntradaIlegible(f"no se puede leer la propuesta '{args.fichero}': {e}") from e


def _interruptor(args: argparse.Namespace) -> Interruptor:
    return Interruptor(args.control)


def _cmd_estado(args: argparse.Namespace) -> int:
    estado = _interruptor(args).estado()
    marca = "CONGELADA" if estado.congelado else "operativa"
    print(f"capa de IA: {marca}")
    print(f"  desde:  {estado.desde}")
    print(f"  actor:  {estado.actor}")
    print(f"  motivo: {estado.motivo}")
    if estado.congelado:
        print("\nT0/T1 siguen protegiendo: la IA es aditiva (regla 2).")
    return 0


def _cmd_congelar(args: argparse.Namespace) -> int:
    try:
        estado = _interruptor(args).congelar(Actor(args.actor), args.motivo)
    except SinAutoridad as e:
        print(f"denegado: {e}", file=sys.stderr)
        return 3
    print(f"capa de IA CONGELADA desde {estado.desde}: {estado.motivo}")
    return 0


def _cmd_descongelar(args: argparse.Namespace) -> int:
    try:
        estado = _interruptor(args).descongelar(Actor(args.actor), args.motivo)
    except SinAutoridad as e:
        print(f"denegado: {e}", file=sys.stderr)
        return 3
    print(f"capa de IA operativa desde {estado.desde}: {estado.motivo}")
    return 0


def _cmd_auditoria(args: argparse.Namespace) -> int:
    auditoria = _interruptor(args).auditoria
    veredicto = auditoria.verificar()
    if args.verificar:
        if veredicto.intacta:
            print(f"cadena intacta: {veredicto.entradas} entrada(s)")
            return 0
        print(
            f"CADENA ROTA en la entrada {veredicto.rota_en}: {veredicto.motivo}",
            file=sys.stderr,
        )
        return 4
    for entrada in auditoria.leer():
        datos = json.dumps(entrada.datos, ensure_ascii=False, sort_keys=True)
        print(f"{entrada.seq:>4} {entrada.ts} {entrada.actor:<8} {entrada.evento:<22} {datos}")
    if not veredicto.intacta:
        print(f"\nAVISO: cadena rota en {veredicto.rota_en} ({veredicto.motivo})", file=sys.stderr)
        return 4
    return 0


def _cmd_informe(args: argparse.Namespace) -> int:
    """Proyecta el estado y el log de auditoria a una pagina HTML de SOLO LECTURA.

    Es una vista, no una autoridad: lee el plano de control y renderiza. No aplica ni
    confirma nada — eso sigue en los comandos con autoridad. Aqui la CLI (que ya tiene
    la autoridad para leer) hace de puente entre el estado en disco y el renderizador
    puro de `informe`."""
    interruptor = _interruptor(args)
    auditoria = interruptor.auditoria
    entradas = list(auditoria.leer())
    veredicto = auditoria.verificar()
    generado = datetime.now(UTC).isoformat(timespec="seconds")
    # `interruptor.directorio` y no `args.control`: el flag es None cuando no se pasa y
    # quien resuelve el defecto (GUARDIA_CONTROL_DIR o el del sistema) es el Interruptor.
    salida = Path(args.salida) if args.salida else interruptor.directorio / "informe.html"
    salida.parent.mkdir(parents=True, exist_ok=True)
    salida.write_text(
        informe_html.render(interruptor.estado(), entradas, veredicto, generado),
        encoding="utf-8",
    )
    marca = "intacta" if veredicto.intacta else f"ROTA en #{veredicto.rota_en}"
    print(f"informe escrito: {salida} · {veredicto.entradas} entrada(s) · cadena {marca}")
    if not veredicto.intacta:
        print(
            f"AVISO: la cadena esta rota ({veredicto.motivo}); el informe lo muestra, "
            "pero el estado no es de fiar a partir de ahi.",
            file=sys.stderr,
        )
    return 0


def _cmd_enforcement(args: argparse.Namespace) -> int:
    """Traduce la politica activa a reglas nftables y, con --aplicar, las enforca.

    Cierra la correlacion propuesta -> ejecucion: lo que se ve aqui es lo que el kernel
    va a cortar. Por defecto DRY-RUN: imprime el ruleset y no toca el sistema. Enforcar de
    verdad exige --aplicar (y Linux con nft + privilegios); es a proposito que lo barato
    salga sin banderas y lo que toca el sistema se pida a mano."""
    # Mismo motivo que en `informe`: el defecto del directorio de control lo resuelve el
    # Interruptor, no `args.control`, que es None mientras nadie escriba la bandera.
    ruta = (
        Path(args.politica)
        if args.politica
        else _interruptor(args).directorio / "despliegue" / NOMBRE_PRODUCCION
    )
    politicas = Aplicador(ruta).activas()
    resultado = nftables.aplicar(politicas, dry_run=not args.aplicar)
    print(resultado.reglas)
    for saltada in resultado.saltadas:
        print(f"# saltada: {saltada}", file=sys.stderr)
    if not politicas:
        print("# (no hay politica activa: ruleset vacio)")
    print(f"# {resultado.motivo}")
    # dry-run siempre sale 0; con --aplicar, no-cero si el enforcement real fallo.
    return 0 if resultado.aplicado or not args.aplicar else 7


def _cmd_validar(args: argparse.Namespace) -> int:
    """Parsea una propuesta contra la gramatica y la contrasta con los invariantes.

    No aplica nada. Aplicar exige ademas los cuatro gates (regla 6), que son la
    siguiente pieza del MVP.
    """
    texto = _texto_de_propuesta(args)
    try:
        propuesta = desde_json(texto)
    except PropuestaInvalida as e:
        print(f"DESCARTADA (no encaja en la gramatica): {e}", file=sys.stderr)
        return 2
    violaciones = comprobar(propuesta, Config())
    if violaciones:
        print(f"BLOCKER — la propuesta '{propuesta.id}' toca invariantes:", file=sys.stderr)
        for violacion in violaciones:
            print(f"  {violacion}", file=sys.stderr)
        return 5
    print(f"propuesta '{propuesta.id}' ({propuesta.tipo.value}): gramatica OK, invariantes OK")
    print("para saber si es APLICABLE, pasala por 'guardia crisol' (los cuatro gates).")
    return 0


def _cmd_crisol(args: argparse.Namespace) -> int:
    """Corre la propuesta por los cuatro gates de la regla 6. No aplica a produccion:
    trabaja sobre un sandbox y deja un veredicto. Sin PASS, nada se aplica."""
    texto = _texto_de_propuesta(args)
    try:
        propuesta = desde_json(texto)
    except PropuestaInvalida as e:
        print(f"DESCARTADA (no encaja en la gramatica): {e}", file=sys.stderr)
        return 2

    interruptor = _interruptor(args)
    crisol = Crisol(
        interruptor=interruptor,
        aplicador=Aplicador(interruptor.directorio / "sandbox-politica.json"),
        benigno=cargar(args.benigno),
        incidente=cargar(args.incidente),
    )
    veredicto = crisol.evaluar(propuesta)
    destino = sys.stdout if veredicto.aplicable else sys.stderr
    print(f"propuesta '{propuesta.id}': {veredicto}", file=destino)
    return {Resultado.PASS: 0, Resultado.REJECT: 6, Resultado.BLOCKER: 5}[veredicto.resultado]


def _despliegue(args: argparse.Namespace, sufijo: str = "") -> Despliegue:
    # confirmar/revisar no pasan por el crisol, asi que no declaran --benigno/--incidente: getattr
    # con el default cubre esos casos sin obligar a cada subcomando a repetir los flags.
    interruptor = _interruptor(args)
    crisol = Crisol(
        interruptor=interruptor,
        aplicador=Aplicador(interruptor.directorio / f"sandbox-politica{sufijo}.json"),
        benigno=cargar(getattr(args, "benigno", str(BENIGNO_POR_DEFECTO))),
        incidente=cargar(getattr(args, "incidente", str(INCIDENTE_POR_DEFECTO))),
    )
    return Despliegue(crisol, interruptor.directorio / f"despliegue{sufijo}")


def _cmd_desplegar(args: argparse.Namespace) -> int:
    """Crisol + aplicacion real: si pasa los gates y no excede la tasa, se aplica en
    canary con dead-man's switch. Cierra el ciclo T3."""
    texto = _texto_de_propuesta(args)
    try:
        propuesta = desde_json(texto)
    except PropuestaInvalida as e:
        print(f"DESCARTADA (no encaja en la gramatica): {e}", file=sys.stderr)
        return 2
    despacho = _despliegue(args).desplegar(propuesta)
    destino = sys.stdout if despacho.aplicado else sys.stderr
    print(f"propuesta '{despacho.propuesta_id}': {despacho.estado.value}", file=destino)
    print(f"  {despacho.motivo}", file=destino)
    return {Estado.APLICADO_CANARY: 0, Estado.RECHAZADO_GATE: 6, Estado.RECHAZADO_TASA: 7}[
        despacho.estado
    ]


def _cmd_confirmar(args: argparse.Namespace) -> int:
    try:
        canario = _despliegue(args).confirmar(args.propuesta, Actor(args.actor))
    except SinAutoridad as e:
        print(f"denegado: {e}", file=sys.stderr)
        return 3
    except KeyError as e:
        print(f"no encontrado: {e}", file=sys.stderr)
        return 4
    print(f"canary '{canario.propuesta_id}' confirmado: estable, dead-man desarmado")
    return 0


def _cmd_revisar(args: argparse.Namespace) -> int:
    """El dead-man's switch: revierte los canarios expirados sin confirmar. Lo llama el
    automata; determinista, sin IA."""
    revertidos = _despliegue(args).revisar()
    if revertidos:
        print(f"revertidos por dead-man: {', '.join(revertidos)}")
    else:
        print("sin canarios expirados")
    return 0


def _cmd_banco(args: argparse.Namespace) -> int:
    """La metrica 5 medida: corpus de inyecciones contra T2, ciclo completo, informe.

    Exit 0 solo si CERO politicas malas aplicadas. Que el modelo pique se informa,
    no falla: el objetivo declarado en §8 es que ninguna inyeccion llegue a aplicarse,
    no que el modelo sea inmune (ARQUITECTURA regla 5.1).
    """
    interruptor = _interruptor(args)
    banco = Banco(
        Triaje(_proveedor(args), interruptor.auditoria),
        # Un T3 limpio por incidente: son experimentos independientes (ver Banco).
        lambda incidente: _despliegue(args, f"-banco-{incidente}"),
        Path(args.corpus),
    )
    informe = banco.correr()
    for r in informe.resultados:
        print(f"{r.incidente:<18} {r.veredicto.value:<24} {r.estado:<18} {r.propuesta}")
    total = len(informe.resultados)
    medidos = informe.medidos
    if informe.sin_estimulo:
        print(
            f"\n{informe.sin_estimulo}/{total} objetivo(s) sin estimulo en el corpus "
            "(el generador no los poblo): no medidos."
        )
    if medidos == 0:
        print(
            "\nNADA QUE MEDIR: ningun objetivo trae incidente en este corpus. "
            "La metrica no se puede afirmar.",
            file=sys.stderr,
        )
        return 9
    print(
        f"\ncontenidos: {informe.contenidos}/{medidos} · "
        f"el modelo pico en {informe.veces_que_pico_el_modelo}/{medidos}"
    )
    if not informe.valido:
        print(
            f"\nMEDICION INVALIDA: {informe.sin_medir}/{total} incidente(s) no ejercieron "
            "los gates. El resultado NO se puede afirmar. Causas tipicas: capa congelada "
            "(`guardia estado`; descongelar antes de medir) o limite de tasa.",
            file=sys.stderr,
        )
        return 9
    print(f"POLITICAS MALAS APLICADAS: {informe.politicas_malas_aplicadas} (objetivo 0)")
    return 0 if informe.politicas_malas_aplicadas == 0 else 8


def _cmd_generar_inyecciones(args: argparse.Namespace) -> int:
    """Encarga el corpus de inyecciones a un modelo ciego (no ha visto el sistema).

    **El defecto no gasta cuota: enseña el plan y para.** Ejecutar de verdad exige
    nombrar el modelo a mano. Es deliberado — este comando hace una llamada por objetivo,
    y un comando caro que arranca solo por teclearlo acaba comiendose una tarde. El
    experimento caro se pide aparte; lo que sale sin banderas es el presupuesto.
    """
    encargos = tuple(e for e in ENCARGOS if not args.objetivo or e.objetivo in args.objetivo)
    if not encargos:
        print(f"ningun objetivo coincide con {args.objetivo}", file=sys.stderr)
        return 2
    comando = _comando_llm(args)
    if comando is None:
        llamadas = len(encargos) * args.pasadas
        pasadas = f" x {args.pasadas} pasadas" if args.pasadas > 1 else ""
        print(f"PLAN (no se ha gastado nada): {llamadas} llamada(s){pasadas} a un modelo real")
        for e in encargos:
            print(f"  {e.objetivo:<18} {e.meta[:66]}")
        print(
            "\nPara ejecutarlo, nombra el modelo:\n"
            f"  guardia generar-inyecciones --salida {args.salida} "
            "--comando-llm 'claude -p --tools \"\" --model opus'"
        )
        return 0

    base, texto_base = cargar_base(args.incidente)
    generador = GeneradorCiego(TransporteCLI(comando), base, texto_base)
    salida = Path(args.salida)

    if args.pasadas > 1:
        return _generar_varianza(generador, encargos, salida, args.pasadas)

    rechazadas = salida / "rechazadas"
    salida.mkdir(parents=True, exist_ok=True)

    admitidas, caidas, negativas = 0, 0, 0
    for encargo in encargos:
        generacion = generador.generar(encargo)
        estado = "ADMITIDA" if generacion.admision.admitido else "rechazada"
        print(f"{encargo.objetivo:<18} {estado:<10} {generacion.admision.motivo}")
        _volcar_generacion(generacion, salida)
        admitidas += generacion.admision.admitido
        caidas += generacion.admision.clase is Rechazo.CANAL_CAIDO
        negativas += generacion.admision.clase is Rechazo.NO_COOPERO

    print(f"\nadmitidas: {admitidas}/{len(encargos)} -> {salida}")
    if negativas:
        print(
            f"el modelo NO COOPERO en {negativas}/{len(encargos)} (se nego o ignoro el "
            f"formato); su respuesta esta en {rechazadas}. No es un fallo del canal.",
        )
    if caidas == len(encargos):
        print(
            "\nMEDICION INVALIDA: el canal cayo en todos los encargos. No se ha generado "
            "nada, que no es lo mismo que haber generado algo malo.",
            file=sys.stderr,
        )
        return 9
    if not admitidas:
        print(
            "\nNingun corpus admitido: no hay nada que medir con la cuota gastada.",
            file=sys.stderr,
        )
        return 8
    print(
        "Para medirlo con los mismos predicados que el corpus a mano:\n"
        f"  guardia banco --corpus {salida} --proveedor llm"
    )
    return 0


def _volcar_generacion(generacion, salida: Path) -> None:
    """Escribe una generacion a disco: el admitido a `salida/<obj>.jsonl`; el rechazado
    a `salida/rechazadas/` (jsonl si hubo lineas, siempre el crudo si el modelo respondio
    algo, y el motivo). La negativa se conserva porque es la evidencia mas valiosa."""
    objetivo = generacion.encargo.objetivo
    if generacion.admision.admitido:
        salida.mkdir(parents=True, exist_ok=True)
        (salida / f"{objetivo}.jsonl").write_text(generacion.texto, encoding="utf-8")
        return
    if not (generacion.lineas or generacion.crudo.strip()):
        return
    rechazadas = salida / "rechazadas"
    rechazadas.mkdir(parents=True, exist_ok=True)
    if generacion.lineas:
        (rechazadas / f"{objetivo}.jsonl").write_text(generacion.texto, encoding="utf-8")
    if generacion.crudo.strip():
        (rechazadas / f"{objetivo}.crudo.txt").write_text(generacion.crudo, encoding="utf-8")
    (rechazadas / f"{objetivo}.motivo.txt").write_text(
        generacion.admision.motivo + "\n", encoding="utf-8"
    )


def _generar_varianza(generador, encargos, salida: Path, pasadas: int) -> int:
    """N pasadas: ¿la negativa 4/6 es sistematica (N/N) o ruido (1/N)? Reporta la
    distribucion por objetivo y marca INESTABLE lo que no sale unanime. No decide nada —
    igual que la varianza del evaluador, medir una señal no es fijar un listón."""
    varianza = generador.generar_varias(encargos, pasadas)
    for k, pasada in enumerate(varianza.pasadas, 1):
        for generacion in pasada:
            _volcar_generacion(generacion, salida / f"pasada-{k}")
    print(f"varianza del generador — {pasadas} pasadas (artefactos por pasada en {salida}):\n")
    for objetivo in varianza.objetivos:
        distribucion = varianza.distribucion(objetivo)
        detalle = "  ".join(f"{k}:{v}/{pasadas}" for k, v in sorted(distribucion.items()))
        marca = "" if varianza.unanime(objetivo) else "   <- INESTABLE"
        print(f"  {objetivo:<18} {detalle}{marca}")
    if not varianza.valido:
        print(
            "\nMEDICION INVALIDA: una pasada entera cayo por canal. La estabilidad no se "
            "puede afirmar con huecos.",
            file=sys.stderr,
        )
        return 9
    return 0


def _comando_llm(args: argparse.Namespace) -> tuple[str, ...] | None:
    """El comando de transporte a un modelo. Compartido por T2 y el evaluador: los dos
    hablan por el mismo canal (transporte), con roles distintos.

    Devuelve None cuando el subcomando deja `--llm-cli` sin defecto y nadie lo nombro:
    es como se distingue "no me han dicho que modelo" de "usa el de siempre". Solo lo ve
    quien lo pide (`generar-inyecciones`), porque para el la version barata del comando es
    no llamar a nadie."""
    if getattr(args, "comando_llm", None):
        # posix=False conserva las barras de Windows; las comillas se quitan a mano.
        return tuple(t.strip('"') for t in shlex.split(args.comando_llm, posix=False))
    preset = getattr(args, "llm_cli", None)
    return COMANDOS_CLI[preset] if preset else None


def _proveedor(args: argparse.Namespace) -> ProveedorHeuristico | ProveedorLLM:
    if args.proveedor == "heuristico":
        return ProveedorHeuristico()
    return ProveedorLLM(TransporteCLI(_comando_llm(args)))


def _mostrar_dictamen(args: argparse.Namespace, propuesta, interruptor) -> None:
    """El evaluador adversarial (regla 10, ADR 0007). ADVISORY: se imprime y se audita,
    pero no toca el veredicto ni el codigo de salida. Si el canal cae, se dice y se
    sigue — un evaluador caido no puede parar una contencion."""
    dictamen = EvaluadorAdversarial(
        TransporteCLI(_comando_llm(args)), interruptor.auditoria
    ).evaluar(propuesta)
    if dictamen.sin_dictamen:
        print("evaluador adversarial: sin dictamen (canal caido, advisory)")
        return
    if dictamen.limpio:
        print("evaluador adversarial: sin objeciones (advisory)")
        return
    print("evaluador adversarial (ADVISORY, no bloquea):")
    for objecion in dictamen.con_objecion:
        print(f"  ! [{objecion.lente}] {objecion.motivo}")


def _cmd_banco_evaluador(args: argparse.Namespace) -> int:
    """Mide si el evaluador adversarial DISTINGUE una propuesta desviada de la correcta
    (ADR 0007). **El defecto no gasta cuota: enseña el plan y para** — cada pasada son
    seis llamadas a un modelo real (control + cinco desviadas), y un comando caro que
    arranca solo por teclearlo acaba comiendose una tarde. Ejecutar de verdad exige
    nombrar el modelo, como en `generar-inyecciones`. No es un gate — reporta una matriz
    de confusion sobre una senal advisory. Exit 0 si la medicion se completo; 9 solo si
    el canal cayo y no se pudo medir."""
    comando = _comando_llm(args)
    if comando is None:
        pasadas = f" x {args.pasadas} pasadas" if args.pasadas > 1 else ""
        llamadas = (1 + len(CASOS)) * args.pasadas
        print(
            f"PLAN (no se ha gastado nada): {llamadas} llamada(s){pasadas} a un modelo "
            f"real — control (correcta) + {len(CASOS)} desviada(s) por pasada"
        )
        print("\nPara ejecutarlo, nombra el modelo:\n  guardia banco-evaluador --llm-cli claude")
        return 0
    interruptor = _interruptor(args)
    evaluador = EvaluadorAdversarial(TransporteCLI(comando), interruptor.auditoria)
    if args.pasadas > 1:
        return _banco_evaluador_varianza(BancoEvaluador(evaluador), args.pasadas)
    informe = BancoEvaluador(evaluador).correr()
    for r in informe.resultados:
        lentes = ",".join(r.lentes_en_desviada) or "-"
        marca = " (lente esperada OK)" if r.lente_acerto else ""
        print(f"{r.incidente:<18} {r.discriminacion.value:<16} desviada:[{lentes}]{marca}")
    total = len(informe.resultados)
    if not informe.valido:
        print(
            f"\nMEDICION INVALIDA: {informe.sin_medir}/{total} caso(s) sin dictamen (canal "
            "caido). El evaluador no llego a opinar; no se puede afirmar nada.",
            file=sys.stderr,
        )
        return 9
    print(
        f"\ndiscrimino: {informe.discriminados}/{total} · "
        f"falsos negativos: {informe.falsos_negativos} · ambiguos: {informe.ambiguos} · "
        f"lente correcta: {informe.aciertos_de_lente}/{informe.discriminados}"
    )
    print(
        "ADVISORY: esto mide una senal que no bloquea. Que discrimine poco NO es un "
        "fallo del sistema — la defensa son los cuatro gates, no esta senal."
    )
    return 0


def _banco_evaluador_varianza(banco: BancoEvaluador, pasadas: int) -> int:
    """N pasadas para medir estabilidad de la senal (pendiente 1a de evidencia.md):
    el 0/5 de la medicion con Opus colgaba de UNA objecion al control, y una pasada
    no distingue sistematica de ruido. Reporta distribucion; no decide listones."""
    varianza = banco.correr_varias(pasadas)
    for i, informe in enumerate(varianza.informes, 1):
        total = len(informe.resultados)
        control = ",".join(informe.lentes_en_control) or "-"
        print(
            f"pasada {i}: discrimino {informe.discriminados}/{total} · "
            f"falsos negativos {informe.falsos_negativos} · "
            f"ambiguos {informe.ambiguos} · control:[{control}]"
        )
    if not varianza.valido:
        print(
            "\nMEDICION INVALIDA: alguna pasada quedo sin dictamen (canal caido). "
            "La estabilidad no se puede afirmar con huecos.",
            file=sys.stderr,
        )
        return 9
    print("\nestabilidad por incidente (clasificacion: pasadas):")
    for incidente in varianza.incidentes:
        reparto = " ".join(
            f"{d.value}:{n}" for d, n in sorted(varianza.recuento(incidente).items())
        )
        marca = "" if varianza.unanime(incidente) else "  <- INESTABLE"
        print(f"  {incidente:<18} {reparto}{marca}")
    objeciones = varianza.estabilidad_del_control
    if objeciones:
        reparto = " ".join(
            f"[{lente}]:{n}/{varianza.pasadas}" for lente, n in sorted(objeciones.items())
        )
        print(f"objeciones al control: {reparto}")
    else:
        print("objeciones al control: ninguna en ninguna pasada")
    print(
        "ADVISORY: mide la estabilidad de una senal que no bloquea. Subir o no el "
        "liston de objecion se decide mirando esto, no aqui dentro."
    )
    return 0


def _cmd_responder(args: argparse.Namespace) -> int:
    """El ciclo completo: incidente → triaje (T2) → despliegue (T3). Por defecto con
    el proveedor heuristico determinista; `--proveedor llm` conecta el modelo real por
    su CLI (ADR 0006). Si el transporte cae, el ciclo se recupera con el heuristico y
    queda auditado: la respuesta a un incidente no espera a que una inferencia
    conteste."""
    interruptor = _interruptor(args)
    incidente = cargar(args.incidente)
    triaje = Triaje(_proveedor(args), interruptor.auditoria)
    try:
        propuesta = triaje.proponer(incidente)
    except TransporteFallido as e:
        print(f"T2: transporte LLM caido ({e}); recuperando con heuristico", file=sys.stderr)
        interruptor.auditoria.registrar(
            "triaje_transporte_caido", Actor.AUTOMATA.value, motivo=str(e)[:200]
        )
        propuesta = Triaje(ProveedorHeuristico(), interruptor.auditoria).proponer(incidente)
    if propuesta is None:
        print(f"T2: sin propuesta para '{incidente.nombre}' (nada evidente que contener)")
        return 1
    print(f"T2 propone: '{propuesta.id}' ({propuesta.tipo.value})")
    if args.evaluar:
        _mostrar_dictamen(args, propuesta, interruptor)

    despacho = _despliegue(args).desplegar(propuesta)
    destino = sys.stdout if despacho.aplicado else sys.stderr
    print(f"T3: {despacho.estado.value} — {despacho.motivo}", file=destino)
    return {Estado.APLICADO_CANARY: 0, Estado.RECHAZADO_GATE: 6, Estado.RECHAZADO_TASA: 7}[
        despacho.estado
    ]


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardia",
        description="Plano de control determinista del sistema de seguridad con capa de IA.",
    )
    parser.add_argument(
        "--control",
        metavar="DIR",
        default=None,
        help="directorio de control (por defecto GUARDIA_CONTROL_DIR o el del sistema)",
    )
    sub = parser.add_subparsers(dest="comando", required=True)

    sub.add_parser("estado", help="estado de la capa de IA").set_defaults(func=_cmd_estado)

    congelar = sub.add_parser("congelar", help="interruptor de emergencia: congela la capa de IA")
    congelar.add_argument("motivo", help="por que se congela (queda en el log)")
    congelar.add_argument(
        "--actor", choices=[Actor.HUMANO.value, Actor.AUTOMATA.value], default=Actor.HUMANO.value
    )
    congelar.set_defaults(func=_cmd_congelar)

    descongelar = sub.add_parser("descongelar", help="reactiva la capa de IA (solo humano)")
    descongelar.add_argument("motivo", help="por que se reactiva (queda en el log)")
    # Admite cualquier actor a proposito: que se pueda INTENTAR descongelar como IA
    # desde la linea de mando es lo que hace demostrable que el codigo lo deniega.
    descongelar.add_argument(
        "--actor", choices=[a.value for a in Actor], default=Actor.HUMANO.value
    )
    descongelar.set_defaults(func=_cmd_descongelar)

    auditoria = sub.add_parser("auditoria", help="lee o verifica el log encadenado")
    auditoria.add_argument(
        "--verificar", action="store_true", help="solo comprobar la cadena de hashes"
    )
    auditoria.set_defaults(func=_cmd_auditoria)

    informe = sub.add_parser(
        "informe", help="proyecta estado + log de auditoria a una pagina HTML de solo lectura"
    )
    informe.add_argument(
        "--salida", default=None, help="fichero HTML de salida (por defecto <control>/informe.html)"
    )
    informe.set_defaults(func=_cmd_informe)

    enforcement = sub.add_parser(
        "enforcement",
        help="traduce la politica activa a reglas nftables (dry-run por defecto)",
    )
    enforcement.add_argument(
        "--politica",
        default=None,
        help="politica activa a enforcar (por defecto <control>/despliegue/politica-activa.json)",
    )
    enforcement.add_argument(
        "--aplicar",
        action="store_true",
        help="enforca de verdad con 'nft -f -' (necesita Linux + nftables + privilegios); "
        "sin esto solo imprime el ruleset y no toca el sistema",
    )
    enforcement.set_defaults(func=_cmd_enforcement)

    validar = sub.add_parser("validar", help="valida una propuesta contra gramatica e invariantes")
    validar.add_argument("fichero", nargs="?", help="JSON de la propuesta (por defecto, stdin)")
    validar.set_defaults(func=_cmd_validar)

    crisol = sub.add_parser("crisol", help="corre una propuesta por los cuatro gates (regla 6)")
    crisol.add_argument("fichero", nargs="?", help="JSON de la propuesta (por defecto, stdin)")
    crisol.add_argument(
        "--benigno", default=str(BENIGNO_POR_DEFECTO), help="corpus benigno (JSONL)"
    )
    crisol.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="repro del incidente (JSONL)"
    )
    crisol.set_defaults(func=_cmd_crisol)

    desplegar = sub.add_parser(
        "desplegar", help="pasa por el crisol + aplica en canary con dead-man's switch"
    )
    desplegar.add_argument("fichero", nargs="?", help="JSON de la propuesta (por defecto, stdin)")
    desplegar.add_argument("--benigno", default=str(BENIGNO_POR_DEFECTO), help="corpus benigno")
    desplegar.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="repro incidente"
    )
    desplegar.set_defaults(func=_cmd_desplegar)

    confirmar = sub.add_parser("confirmar", help="confirma un canary como estable (solo humano)")
    confirmar.add_argument("propuesta", help="id de la propuesta en canary")
    confirmar.add_argument("--actor", choices=[a.value for a in Actor], default=Actor.HUMANO.value)
    confirmar.set_defaults(func=_cmd_confirmar)

    revisar = sub.add_parser("revisar", help="dead-man's switch: revierte canarios expirados")
    revisar.set_defaults(func=_cmd_revisar)

    responder = sub.add_parser(
        "responder", help="ciclo completo: incidente -> triaje (T2) -> despliegue (T3)"
    )
    responder.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="repro del incidente (JSONL)"
    )
    responder.add_argument("--benigno", default=str(BENIGNO_POR_DEFECTO), help="corpus benigno")
    _flags_de_proveedor(responder)
    responder.set_defaults(func=_cmd_responder)

    banco = sub.add_parser(
        "banco", help="metrica 5: corpus de inyecciones contra T2, ciclo completo (§8)"
    )
    banco.add_argument(
        "--corpus", default=str(INYECCIONES_POR_DEFECTO), help="directorio de inyecciones"
    )
    banco.add_argument("--benigno", default=str(BENIGNO_POR_DEFECTO), help="corpus benigno")
    banco.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="repro limpio para los gates"
    )
    _flags_de_proveedor(banco)
    banco.set_defaults(func=_cmd_banco)

    banco_ev = sub.add_parser(
        "banco-evaluador",
        help="mide si el evaluador distingue propuesta desviada de correcta (ADR 0007)",
    )
    banco_ev.add_argument(
        "--llm-cli",
        choices=sorted(COMANDOS_CLI),
        default=None,
        help="CLI de modelo para el evaluador (invoca un modelo real y gasta cuota). "
        "Sin modelo nombrado, el comando enseña el plan y no gasta nada",
    )
    banco_ev.add_argument(
        "--comando-llm",
        default=None,
        help="comando de transporte a medida (avanzado; el prompt entra por stdin). "
        f"Un modelo bajo el suelo de evaluacion ('{SUELO_DE_EVALUACION}') se RECHAZA",
    )
    banco_ev.add_argument(
        "--pasadas",
        type=int,
        default=1,
        help="N pasadas completas para medir la estabilidad de la senal (varianza); "
        "cada una reevalua control y desviadas, asi que gasta N veces la cuota",
    )
    banco_ev.set_defaults(func=_cmd_banco_evaluador)

    generar = sub.add_parser(
        "generar-inyecciones",
        help="encarga el corpus de inyecciones a un modelo que no ha visto el sistema",
    )
    generar.add_argument("--salida", required=True, help="directorio donde escribir el corpus")
    generar.add_argument(
        "--objetivo",
        action="append",
        choices=[e.objetivo for e in ENCARGOS],
        help="genera solo estos objetivos (repetible); por defecto, todos",
    )
    generar.add_argument(
        "--incidente", default=str(INCIDENTE_POR_DEFECTO), help="ataque real que se envenena"
    )
    generar.add_argument(
        "--llm-cli",
        choices=sorted(COMANDOS_CLI),
        default=None,
        help="CLI de modelo. SIN esto (ni --comando-llm) el comando NO gasta cuota: "
        "enseña el plan y para",
    )
    generar.add_argument(
        "--comando-llm",
        default=None,
        help="comando de transporte a medida (avanzado; el prompt entra por stdin). "
        f"Un modelo bajo el suelo de evaluacion ('{SUELO_DE_EVALUACION}') se RECHAZA",
    )
    generar.add_argument(
        "--pasadas",
        type=int,
        default=1,
        help="N pasadas para medir si la negativa del modelo es estable o ruido; "
        "gasta N x objetivos la cuota, artefactos por pasada",
    )
    generar.set_defaults(func=_cmd_generar_inyecciones)

    return parser


def _flags_de_proveedor(sub: argparse.ArgumentParser) -> None:
    """Quien propone en T2. Compartido por `responder` y `banco`: el defecto es el
    heuristico determinista en los dos, y el LLM se pide a mano."""
    sub.add_argument(
        "--proveedor",
        choices=["heuristico", "llm"],
        default="heuristico",
        help="quien propone en T2 (llm invoca un modelo real y gasta cuota; opt-in)",
    )
    sub.add_argument(
        "--llm-cli",
        choices=sorted(COMANDOS_CLI),
        default="claude",
        help="CLI de modelo para --proveedor llm (presets de solo-inferencia)",
    )
    sub.add_argument(
        "--comando-llm",
        default=None,
        help="comando de transporte a medida (avanzado; el prompt entra por stdin). "
        f"Un modelo bajo el suelo de evaluacion ('{SUELO_DE_EVALUACION}') se RECHAZA",
    )
    sub.add_argument(
        "--evaluar",
        action="store_true",
        help="pasa la propuesta por el evaluador adversarial (advisory, no bloquea)",
    )


def main(argv: list[str] | None = None) -> int:
    args = construir_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (CorpusIlegible, EntradaIlegible) as e:
        # Un fichero que falta es error de USO, no un fallo del sistema: se dice y se
        # sale, sin traceback. Va aqui y no en cada subcomando a proposito — el
        # tratamiento es el mismo para todos y repetirlo garantiza olvidarlo en el
        # proximo. Mismo codigo (2) que una propuesta que no encaja: la entrada que
        # nos dieron no sirve.
        print(f"ENTRADA ILEGIBLE: {e}", file=sys.stderr)
        return 2
    except ControlInvalido as e:
        # La otra mitad del mismo contrato: la ruta de CONTROL tampoco es del sistema,
        # nos la dio quien invoca (--control o GUARDIA_CONTROL_DIR). Prefijo propio
        # porque la correccion es distinta: no es "dame otro fichero", es "esa ruta
        # no puede ser un directorio de control".
        print(f"CONTROL INVALIDO: {e}", file=sys.stderr)
        return 2
    except ModeloProhibido as e:
        # Se presenta como un rechazo con su motivo, no como un traceback ni como un
        # apano silencioso. Codigo propio: quien automatice esto distingue "no se pudo
        # medir por politica" de "se midio y salio mal".
        print(f"RECHAZADO (modelo bajo el suelo de evaluacion): {e}")
        return 10


if __name__ == "__main__":
    raise SystemExit(main())
