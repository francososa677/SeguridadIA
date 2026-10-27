"""
main.py
=============================================================================
CLI Unificado de Auditoría SAST + SCA Asistida por IA (Semgrep + Trivy + LLM)
=============================================================================
Este archivo es el punto de entrada principal (Orquestador CLI) de la plataforma.
Permite ejecutar de forma modular o combinada cada una de las fases del pipeline:

Comandos disponibles:
  1. ping        : Comprueba la conexión con el servidor del modelo LLM (vía túnel ngrok).
  2. scan-code   : Ejecuta Semgrep en modo permisivo para detectar riesgos en código fuente (SAST).
  3. trace       : Rastrea el flujo de datos inter-archivo (Call-Sites) hacia los sumideros (Sinks).
  4. scan-deps   : Ejecuta Trivy para detectar CVEs en dependencias de terceros (SCA).
  5. audit       : Pipeline completo: escanea código, rastrea flujos inter-archivo, analiza
                   dependencias y envía los hallazgos al LLM para triage (APR).
  6. evaluate    : Compara las predicciones de Semgrep + Taint Tracker + LLM contra ground_truth.json
                   para calcular métricas formales de rendimiento (Recall, Precision, F1-Score).
"""

from __future__ import annotations
import argparse
import json
import os
import sys
import time
from typing import Optional

# -----------------------------------------------------------------------------
# Configuración del entorno de consola
# -----------------------------------------------------------------------------
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# -----------------------------------------------------------------------------
# Importaciones de los módulos del paquete 'sast'
# -----------------------------------------------------------------------------
from sast.semgrep_scanner import scan_con_semgrep
from sast.trivy_scanner import scan_con_trivy
from sast.taint_tracker import (
    enriquecer_hallazgos_con_flujo,
    rastrear_flujo_hallazgo,
)
from sast.llm_client import (
    ping_server,
    auditar_codigo,
    auditar_hallazgo_semgrep,
    auditar_hallazgo_trivy,
    obtener_ngrok_url
)
from sast.evaluator import evaluar_hallazgos_ground_truth, generar_reporte_metricas
from sast.reporter import (
    compilar_matriz_comparativa,
    generar_reporte_html,
    generar_reporte_markdown
)

# -----------------------------------------------------------------------------
# Rutas y constantes globales del proyecto
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_REPOS_DIR = os.path.join(BASE_DIR, "dataset_repos")
GROUND_TRUTH_PATH = os.path.join(DATASET_REPOS_DIR, "ground_truth.json")


# =============================================================================
# COMANDO: ping
# =============================================================================
def cmd_ping(args: argparse.Namespace) -> None:
    """Verifica el estado de salud de la conexión con el servidor LLM."""
    url = args.url or obtener_ngrok_url()
    print(f"[*] Comprobando conexión con el servidor LLM en: {url} ...")
    
    res = ping_server(url)
    if res.get("ok"):
        print(f"✅ CONEXIÓN EXITOSA (Latencia: {res.get('latency_seconds')}s)")
        print(f"Respuesta del servidor: {res.get('response')}")
    else:
        print(f"❌ FALLA DE CONEXIÓN")
        print(f"Detalle: {res.get('error') or res.get('status_code')}")
        print("💡 Verifica que la celda de inferencia en Colab/Kaggle y el túnel de ngrok estén activos.")


# =============================================================================
# COMANDO: scan-code (SAST con Semgrep)
# =============================================================================
def cmd_scan_code(args: argparse.Namespace) -> None:
    """Ejecuta el análisis estático de código fuente con Semgrep."""
    target_path = os.path.abspath(args.path) if args.path else DATASET_REPOS_DIR

    if not os.path.exists(target_path):
        print(f"❌ Error: La ruta especificada no existe: {target_path}")
        sys.exit(1)

    config = args.config or "p/security-audit"
    print(f"[*] Ejecutando Semgrep (Config: '{config}') sobre: {target_path} ...")
    
    start = time.time()
    hallazgos = scan_con_semgrep(target_path, config=config)
    
    # Si se pide rastreo inter-archivo en el escaneo
    if getattr(args, "trace", False):
        print(f"[*] Rastreando flujo inter-archivo para {len(hallazgos)} hallazgos...")
        hallazgos = enriquecer_hallazgos_con_flujo(hallazgos, target_path)

    duracion = round(time.time() - start, 2)
    print(f"✅ Semgrep completado en {duracion}s. Se encontraron {len(hallazgos)} hallazgos sospechosos.\n")

    for idx, h in enumerate(hallazgos[:args.limit] if args.limit else hallazgos, start=1):
        flujo = h.get("flujo_inter_archivo", {})
        flujo_info = f" ({flujo.get('tipo_flujo')})" if flujo else ""
        print(f"[{idx}] {h['archivo']}:{h['linea']} [{h['severidad']}]{flujo_info}")
        print(f"    CWE     : {h['cwe']}")
        print(f"    OWASP   : {h['owasp']}")
        if flujo.get("origen_principal"):
            orig = flujo["origen_principal"]
            print(f"    Invocador: {orig['archivo_origen']}:{orig['linea_origen']}")
        print(f"    Mensaje : {h['mensaje'][:120]}...")
        print()

    if args.limit and len(hallazgos) > args.limit:
        print(f"... y {len(hallazgos) - args.limit} hallazgos más (usa --limit para ver más).")

    if args.out:
        out_path = os.path.abspath(args.out)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(hallazgos, f, indent=2, ensure_ascii=False)
        print(f"[+] Hallazgos exportados a: {out_path}")


# =============================================================================
# COMANDO: trace (Rastreo Inter-Archivo de Call-Sites hacia Sumideros)
# =============================================================================
def cmd_trace(args: argparse.Namespace) -> None:
    """Rastrea la cadena de llamadas inter-archivo desde orígenes hacia sumideros."""
    target_path = os.path.abspath(args.path) if args.path else DATASET_REPOS_DIR
    if not os.path.exists(target_path):
        print(f"❌ Error: La ruta no existe: {target_path}")
        sys.exit(1)

    print(f"==================================================================")
    print(f"   🔗 RASTREO DE FLUJO INTER-ARCHIVO (TAINT TRACKER)             ")
    print(f"==================================================================")
    print(f"Objetivo: {target_path}\n")

    # 1. Escaneo rápido de Sinks con Semgrep
    print(f"[*] Identificando puntos sumideros (Sinks) con Semgrep...")
    hallazgos = scan_con_semgrep(target_path)
    print(f"    -> {len(hallazgos)} sumideros identificados.")

    # 2. Análisis de flujo inter-archivo
    print(f"[*] Rastreando llamadas inter-módulo en el repositorio...")
    hallazgos_enriquecidos = enriquecer_hallazgos_con_flujo(hallazgos, target_path)

    inter_count = sum(1 for h in hallazgos_enriquecidos if h.get("flujo_inter_archivo", {}).get("tipo_flujo") == "INTER_FILE_FLOW")
    intra_count = len(hallazgos_enriquecidos) - inter_count

    print(f"\n📊 Resumen de Flujos Detectados:")
    print(f"  • Flujos Inter-Archivo (Llamadas externas conectadas): {inter_count}")
    print(f"  • Flujos Intra-Archivo (Variables locales al archivo) : {intra_count}\n")

    for idx, h in enumerate(hallazgos_enriquecidos[:args.limit] if args.limit else hallazgos_enriquecidos, start=1):
        flujo = h["flujo_inter_archivo"]
        tipo = flujo["tipo_flujo"]
        print(f"[{idx}] {h['archivo']}:{h['linea']} -> Función: {flujo['funcion_sink']} [{tipo}]")
        print(f"    Ruta: {flujo['ruta_flujo']}")
        
        if flujo["llamadas_externas"]:
            print(f"    Invocadores externos encontrados ({len(flujo['llamadas_externas'])}):")
            for cs in flujo["llamadas_externas"]:
                print(f"      ↳ {cs['archivo_origen']}:{cs['linea_origen']}")
        print()

    if args.out:
        out_path = os.path.abspath(args.out)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(hallazgos_enriquecidos, f, indent=2, ensure_ascii=False)
        print(f"[+] Mapa de flujos exportado a: {out_path}")


# =============================================================================
# COMANDO: scan-deps (SCA con Trivy)
# =============================================================================
def cmd_scan_deps(args: argparse.Namespace) -> None:
    """Ejecuta el análisis de composición de software (SCA) con Trivy."""
    target_path = os.path.abspath(args.path) if args.path else DATASET_REPOS_DIR

    if not os.path.exists(target_path):
        print(f"❌ Error: La ruta especificada no existe: {target_path}")
        sys.exit(1)

    print(f"[*] Ejecutando Trivy (SCA) sobre: {target_path} ...")
    start = time.time()
    vulns = scan_con_trivy(target_path)
    duracion = round(time.time() - start, 2)

    print(f"✅ Trivy completado en {duracion}s. Se encontraron {len(vulns)} vulnerabilidades de librerías.\n")

    for idx, v in enumerate(vulns[:args.limit] if args.limit else vulns, start=1):
        print(f"[{idx}] {v['manifiesto']} -> {v['paquete']} ({v['version_instalada']}) [{v['severidad']}]")
        print(f"    CVE    : {v['cve_id']}")
        print(f"    Fix    : {v['version_corregida']}")
        print(f"    Título : {v['titulo'][:100]}...")
        print()

    if args.limit and len(vulns) > args.limit:
        print(f"... y {len(vulns) - args.limit} dependencias más.")

    if args.out:
        out_path = os.path.abspath(args.out)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(vulns, f, indent=2, ensure_ascii=False)
        print(f"[+] Vulnerabilidades exportadas a: {out_path}")


# =============================================================================
# COMANDO: audit (Pipeline Completo: Semgrep + Taint Tracker + Trivy + Agente LLM)
# =============================================================================
def cmd_audit(args: argparse.Namespace) -> None:
    """
    Ejecuta el ciclo de auditoría integral combinando herramientas estáticas,
    rastreo de flujo inter-archivo e inteligencia artificial.
    """
    target_path = os.path.abspath(args.path)
    if not os.path.exists(target_path):
        print(f"❌ Error: La ruta no existe: {target_path}")
        sys.exit(1)

    print(f"==================================================================")
    print(f"   🛡️ AUDITORÍA INTEGRAL DE SEGURIDAD ASISTIDA POR IA           ")
    print(f"==================================================================")
    print(f"Objetivo: {target_path}\n")

    # 1. Escaneo de código con Semgrep
    print(f"[*] Paso 1: Escaneando código fuente con Semgrep (SAST)...")
    hallazgos_code = scan_con_semgrep(target_path)
    print(f"    -> {len(hallazgos_code)} posibles debilidades en código detectadas.")

    # 2. Rastreo de flujo inter-archivo (Taint Tracking)
    print(f"[*] Paso 2: Analizando flujos de datos inter-archivo (Taint Tracking)...")
    hallazgos_code = enriquecer_hallazgos_con_flujo(hallazgos_code, target_path)
    inter_count = sum(1 for h in hallazgos_code if h.get("flujo_inter_archivo", {}).get("tipo_flujo") == "INTER_FILE_FLOW")
    print(f"    -> {inter_count} flujos inter-archivo detectados entre módulos.")

    # 3. Escaneo de dependencias con Trivy
    print(f"[*] Paso 3: Escaneando dependencias con Trivy (SCA)...")
    hallazgos_deps = scan_con_trivy(target_path)
    print(f"    -> {len(hallazgos_deps)} vulnerabilidades de librerías detectadas.\n")

    # Aplicamos límite si el usuario lo especificó
    if args.limit and args.limit > 0:
        hallazgos_code = hallazgos_code[:args.limit]

    # 4. Triage y Reparación con Agente LLM
    print(f"[*] Paso 4: Iniciando triage y reparación automática (APR) con LLM...")
    auditorias_completadas = []

    for idx, h in enumerate(hallazgos_code, start=1):
        flujo = h.get("flujo_inter_archivo", {})
        ruta = flujo.get("ruta_flujo", f"{h['archivo']}:{h['linea']}")
        print(f"\n--- [{idx}/{len(hallazgos_code)}] Auditando: {ruta} ---")
        print(f"Regla Semgrep : {h['mensaje'][:90]}...")
        print("Consultando al Agente IA...")

        start = time.time()
        veredicto = auditar_hallazgo_semgrep(h)
        dur = round(time.time() - start, 2)

        estado = veredicto.get("estado", "ERROR")
        cwe = h.get("cwe", "Desconocido")
        owasp = h.get("owasp", "Desconocido")

        print(f"Veredicto IA : {estado} ({dur}s)")
        print(f"Taxonomía    : CWE: {cwe} | OWASP: {owasp}")
        print(f"Explicación  : {veredicto.get('explicacion', '')[:140]}")

        if veredicto.get("codigo_parchado") and estado == "VULNERABLE":
            print("\nParche Sugerido (APR):")
            print("```")
            print(veredicto.get("codigo_parchado")[:300] + "...")
            print("```")


        auditorias_completadas.append({
            "semgrep": h,
            "flujo_inter_archivo": flujo,
            "veredicto_ia": veredicto
        })
        time.sleep(0.3)

    if args.out:
        out_path = os.path.abspath(args.out)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({
                "codigo": auditorias_completadas,
                "dependencias": hallazgos_deps
            }, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Auditoría completa exportada a: {out_path}")


# =============================================================================
# COMANDO: evaluate (Evaluación frente al Ground Truth)
# =============================================================================
def cmd_evaluate(args: argparse.Namespace) -> None:
    """Evalúa la precisión y el rendimiento del sistema contrastándolo con ground_truth.json."""
    if not os.path.exists(GROUND_TRUTH_PATH):
        print(f"❌ Error: No se encontró ground_truth.json en: {GROUND_TRUTH_PATH}")
        sys.exit(1)

    print(f"[*] Escaneando dataset_repos con Semgrep en modo permisivo...")
    hallazgos = scan_con_semgrep(DATASET_REPOS_DIR)

    if args.repo:
        hallazgos = [h for h in hallazgos if h.get("repo") == args.repo]
        print(f"[*] Filtrando para el repositorio: '{args.repo}' ({len(hallazgos)} hallazgos)")

    # Enriquecer con flujo inter-archivo
    print(f"[*] Rastreando flujo inter-archivo para los casos a evaluar...")
    hallazgos = enriquecer_hallazgos_con_flujo(hallazgos, DATASET_REPOS_DIR)

    if args.limit and args.limit > 0:
        hallazgos = hallazgos[:args.limit]
        print(f"[*] Limitando evaluación a los primeros {len(hallazgos)} casos.")

    print(f"[*] Enviando {len(hallazgos)} casos al Agente LLM para verificación y evaluación...")

    resultados = []
    for idx, h in enumerate(hallazgos, start=1):
        flujo = h.get("flujo_inter_archivo", {})
        ruta = flujo.get("ruta_flujo", f"{h['archivo']}:{h['linea']}")
        print(f"[{idx}/{len(hallazgos)}] Auditando {h['repo']} -> {ruta} ...", end=" ", flush=True)

        start = time.time()
        pred = auditar_hallazgo_semgrep(h)
        dur = round(time.time() - start, 2)

        estado = pred.get("estado", "ERROR")
        owasp = h.get("owasp", "Desconocido")
        cwe = h.get("cwe", "Desconocido")
        print(f"{estado} ({dur}s)")

        resultados.append({
            "repo": h["repo"],
            "archivo": h["archivo"],
            "linea": h["linea"],
            "flujo_inter_archivo": flujo,
            "estado": estado,
            "owasp_categoria": owasp,
            "cwe": cwe,
            "explicacion": pred.get("explicacion", ""),
            "tiempo_segundos": dur
        })
        time.sleep(0.2)


    print("\n[*] Contrastando resultados contra ground_truth.json...")
    eval_res = evaluar_hallazgos_ground_truth(resultados, GROUND_TRUTH_PATH, repo_filter=args.repo)
    informe = generar_reporte_metricas(eval_res)
    print("\n" + informe)

    if args.out:
        out_file = os.path.abspath(args.out)
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump({
                "resultados_inferencia": resultados,
                "evaluacion": eval_res
            }, f, indent=2, ensure_ascii=False)
        print(f"\n[+] Reporte de evaluación guardado en: {out_file}")


# =============================================================================
# COMANDO: benchmark (Evaluación Integral y Dashboard Comparativo Visual)
# =============================================================================
def cmd_benchmark(args: argparse.Namespace) -> None:
    """
    Ejecuta el benchmark unificado sobre todo dataset_repos (o repositorio específico),
    contrastando Semgrep (SAST), Trivy (SCA) y el Agente IA frente a las 40 vulnerabilidades del Ground Truth,
    midiendo la reducción de falsos positivos y generando reportes visuales en HTML y Markdown.
    """
    if not os.path.exists(GROUND_TRUTH_PATH):
        print(f"❌ Error: No se encontró ground_truth.json en: {GROUND_TRUTH_PATH}")
        sys.exit(1)

    with open(GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
        gt_list = json.load(f)

    if args.repo:
        gt_list = [gt for gt in gt_list if gt.get("repo") == args.repo]
        print(f"[*] Filtrando benchmark para el repositorio: '{args.repo}' ({len(gt_list)} debilidades en Ground Truth)")

    print(f"==================================================================")
    print(f"   📊 BENCHMARK COMPARATIVO MULTICAPA (SAST + SCA + AGENTE IA)   ")
    print(f"==================================================================")
    target_scan = os.path.join(DATASET_REPOS_DIR, args.repo) if args.repo else DATASET_REPOS_DIR
    print(f"Objetivo: {target_scan}\n")

    # 1. Escaneo de código con Semgrep
    print(f"[*] Paso 1: Escaneando código fuente con Semgrep (SAST)...")
    hallazgos_semgrep = scan_con_semgrep(target_scan)
    if args.repo:
        hallazgos_semgrep = [h for h in hallazgos_semgrep if h.get("repo") == args.repo]
    print(f"    -> {len(hallazgos_semgrep)} alertas potenciales detectadas por Semgrep.")

    # 2. Enriquecimiento con flujo inter-archivo
    print(f"[*] Paso 2: Rastreando flujos inter-archivo con Taint Tracker...")
    hallazgos_semgrep = enriquecer_hallazgos_con_flujo(hallazgos_semgrep, target_scan)
    inter_count = sum(1 for h in hallazgos_semgrep if h.get("flujo_inter_archivo", {}).get("tipo_flujo") == "INTER_FILE_FLOW")
    print(f"    -> {inter_count} flujos inter-archivo detectados entre módulos.")

    # 3. Escaneo de dependencias con Trivy
    print(f"[*] Paso 3: Escaneando dependencias con Trivy (SCA)...")
    hallazgos_trivy = scan_con_trivy(target_scan)
    if args.repo:
        hallazgos_trivy = [t for t in hallazgos_trivy if t.get("repo") == args.repo]
    print(f"    -> {len(hallazgos_trivy)} vulnerabilidades de librerías detectadas por Trivy.\n")

    # 4. Manejo de caché incremental de inferencias
    cache_path = os.path.abspath(args.cache) if args.cache else os.path.join(BASE_DIR, "benchmark_cache.json")
    cache: dict = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
            print(f"[*] Caché cargado: {len(cache)} inferencias previas disponibles.")
        except Exception as e:
            print(f"[-] Advertencia al leer caché ({e}), se iniciará nuevo.")

    # 5. Inferencia con Agente LLM
    print(f"[*] Paso 4: Triage semántico con el Agente IA...")
    hallazgos_auditados = []
    pendientes_count = 0

    for idx, h in enumerate(hallazgos_semgrep, start=1):
        flujo = h.get("flujo_inter_archivo", {})
        ruta = flujo.get("ruta_flujo", f"{h['archivo']}:{h['linea']}")
        cache_key = f"{h['repo']}::{h['archivo']}::{h['linea']}::{h.get('regla_id', '')}"

        if cache_key in cache:
            veredicto = cache[cache_key]
            h["estado"] = veredicto.get("estado", "SEGURO")
            h["explicacion"] = veredicto.get("explicacion", "")
            h["tiempo_segundos"] = veredicto.get("tiempo_segundos", 0.0)
            hallazgos_auditados.append(h)
        else:
            if getattr(args, "report_only", False):
                h["estado"] = "NO_EVALUADO"
                h["explicacion"] = "Pendiente de auditoría por LLM"
                hallazgos_auditados.append(h)
                continue

            if args.limit and pendientes_count >= args.limit:
                h["estado"] = "NO_EVALUADO"
                h["explicacion"] = "Omitido por límite de ejecución"
                hallazgos_auditados.append(h)
                continue

            pendientes_count += 1
            print(f"[{idx}/{len(hallazgos_semgrep)}] Auditando con IA: {h['repo']} -> {ruta} ...", end=" ", flush=True)
            start = time.time()
            veredicto = auditar_hallazgo_semgrep(h)
            dur = round(time.time() - start, 2)
            estado = veredicto.get("estado", "ERROR")
            print(f"{estado} ({dur}s)")

            veredicto["tiempo_segundos"] = dur
            cache[cache_key] = veredicto
            h["estado"] = estado
            h["explicacion"] = veredicto.get("explicacion", "")
            h["tiempo_segundos"] = dur
            hallazgos_auditados.append(h)

            try:
                with open(cache_path, "w", encoding="utf-8") as cf:
                    json.dump(cache, cf, indent=2, ensure_ascii=False)
            except Exception:
                pass

            time.sleep(0.2)

    # 6. Compilar matriz comparativa
    print(f"\n[*] Paso 5: Compilando matriz cruzada y métricas de rendimiento...")
    matriz_datos = compilar_matriz_comparativa(
        ground_truth_list=gt_list,
        hallazgos_semgrep_auditados=hallazgos_auditados,
        hallazgos_trivy=hallazgos_trivy
    )

    # 7. Generar reporte HTML interactivo
    html_out = os.path.abspath(args.html) if getattr(args, "html", None) else os.path.join(BASE_DIR, "reporte_benchmark.html")
    generar_reporte_html(matriz_datos, html_out)
    print(f"✅ Dashboard interactivo generado en: {html_out}")

    # 8. Generar reporte Markdown
    md_out = os.path.abspath(args.md) if getattr(args, "md", None) else os.path.join(BASE_DIR, "reporte_benchmark.md")
    generar_reporte_markdown(matriz_datos, md_out)
    print(f"✅ Informe Markdown generado en: {md_out}")

    # 9. Mostrar resumen ejecutivo en consola
    m = matriz_datos["metricas"]
    print("\n" + "=" * 66)
    print("   📊 RESUMEN EJECUTIVO DEL BENCHMARK COMPARATIVO")
    print("=" * 66)
    print(f"• Total debilidades reales en Ground Truth : {m['total_ground_truth']}")
    print(f"• Detectadas por Semgrep (Recall Semgrep)  : {m['semgrep_detectados']} / {m['total_ground_truth']} ({m['semgrep_recall']}%)")
    print(f"• Falsos Positivos de Semgrep (Ruido)     : {m['semgrep_total_ruido']} alertas irrelevantes")
    print(f"• Verdaderos Positivos confirmados por IA : {m['agente_tp']} (TP)")
    print(f"• Ruido eliminado exitosamente por la IA  : {m['agente_tn']} / {m['semgrep_total_ruido']} ({m['reduccion_ruido_pct']}% reducción)")
    print("-" * 66)
    print(f"🎯 Precisión del Agente (Precision)       : {m['precision']}%")
    print(f"🔍 Sensibilidad Global (Recall)           : {m['recall']}%")
    print(f"⭐ F1-Score                               : {m['f1_score']}%")
    print("=" * 66)

    # 10. Abrir en navegador si se solicitó
    if getattr(args, "open", False):
        try:
            import webbrowser
            webbrowser.open(f"file:///{html_out}")
            print(f"[+] Abriendo dashboard en el navegador...")
        except Exception:
            pass


# =============================================================================
# Función Principal y Definición de Argumentos CLI (argparse)
# =============================================================================
def main() -> None:
    parser = argparse.ArgumentParser(
        description="SAST Antigravity - Plataforma de Seguridad Híbrida (Semgrep SAST + Taint Tracker + Trivy SCA + Agente LLM)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")

    # 1. ping
    p_ping = subparsers.add_parser("ping", help="Verificar conexión con el servidor LLM (ngrok)")
    p_ping.add_argument("--url", type=str, default=None, help="URL de ngrok a verificar (opcional)")

    # 2. scan-code
    p_sc = subparsers.add_parser("scan-code", help="Escanear código con Semgrep (SAST permisivo)")
    p_sc.add_argument("path", nargs="?", default=None, help="Ruta de archivo o repositorio a escanear")
    p_sc.add_argument("--config", type=str, default="p/security-audit", help="Pack de reglas de Semgrep (default: p/security-audit)")
    p_sc.add_argument("--trace", action="store_true", help="Activar rastreo de flujos inter-archivo")
    p_sc.add_argument("--limit", type=int, default=15, help="Límite de hallazgos a mostrar en consola")
    p_sc.add_argument("--out", type=str, default=None, help="Ruta de archivo JSON de salida")

    # 3. trace
    p_tr = subparsers.add_parser("trace", help="Rastrear flujo inter-archivo (Call-Sites) hacia los sumideros")
    p_tr.add_argument("path", nargs="?", default=None, help="Ruta de archivo o repositorio a rastrear")
    p_tr.add_argument("--limit", type=int, default=15, help="Límite de flujos a mostrar en consola")
    p_tr.add_argument("--out", type=str, default=None, help="Ruta de archivo JSON de salida")

    # 4. scan-deps
    p_sd = subparsers.add_parser("scan-deps", help="Escanear dependencias con Trivy (SCA)")
    p_sd.add_argument("path", nargs="?", default=None, help="Ruta de archivo o repositorio a escanear")
    p_sd.add_argument("--limit", type=int, default=15, help="Límite de dependencias a mostrar en consola")
    p_sd.add_argument("--out", type=str, default=None, help="Ruta de archivo JSON de salida")

    # 5. audit
    p_au = subparsers.add_parser("audit", help="Auditoría completa con Semgrep, Taint Tracker, Trivy y Agente LLM")
    p_au.add_argument("path", help="Ruta de archivo o repositorio a auditar")
    p_au.add_argument("--limit", type=int, default=5, help="Límite de hallazgos a enviar al LLM")
    p_au.add_argument("--out", type=str, default=None, help="Ruta de archivo JSON de salida")

    # 6. evaluate
    p_ev = subparsers.add_parser("evaluate", help="Evaluar Semgrep + LLM frente a ground_truth.json")
    p_ev.add_argument("--repo", type=str, default=None, help="Filtrar por repositorio específico")
    p_ev.add_argument("--limit", type=int, default=None, help="Límite de casos a evaluar")
    p_ev.add_argument("--out", type=str, default=None, help="Ruta de archivo JSON de salida")

    # 7. benchmark (Evaluación Completa de Todo el Dataset + Reportes Visuales)
    p_bm = subparsers.add_parser("benchmark", help="Benchmark completo sobre dataset_repos con Dashboard HTML y Markdown")
    p_bm.add_argument("--repo", type=str, default=None, help="Filtrar por repositorio específico (opcional)")
    p_bm.add_argument("--limit", type=int, default=None, help="Límite de llamadas nuevas al LLM")
    p_bm.add_argument("--cache", type=str, default=None, help="Ruta del archivo de caché de inferencias (default: benchmark_cache.json)")
    p_bm.add_argument("--html", type=str, default=None, help="Ruta del reporte visual HTML (default: reporte_benchmark.html)")
    p_bm.add_argument("--md", type=str, default=None, help="Ruta del informe Markdown (default: reporte_benchmark.md)")
    p_bm.add_argument("--report-only", action="store_true", help="Generar reportes a partir de datos ya en caché sin invocar el LLM")
    # 8. pure-llm (Estudio de Ablación: Extracción AST + LLM puro sin Semgrep)
    p_pllm = subparsers.add_parser("pure-llm", help="Estudio de Ablación: Extracción AST y auditoría con LLM puro sin Semgrep")
    p_pllm.add_argument("--repos", type=str, default=DATASET_REPOS_DIR, help="Ruta de repositorios (default: dataset_repos/)")
    p_pllm.add_argument("--ground-truth", type=str, default=GROUND_TRUTH_PATH, help="Ruta ground_truth.json")
    p_pllm.add_argument("--repo", type=str, default=None, help="Filtrar por repositorio específico")
    p_pllm.add_argument("--limit", type=int, default=None, help="Límite de funciones a auditar")
    p_pllm.add_argument("--cache", type=str, default=None, help="Ruta del archivo de caché de inferencias")
    p_pllm.add_argument("--html", type=str, default=None, help="Ruta de salida del reporte visual HTML")
    p_pllm.add_argument("--md", type=str, default=None, help="Ruta de salida del informe Markdown")
    p_pllm.add_argument("--report-only", action="store_true", help="Generar reportes a partir de datos en caché")
    p_pllm.add_argument("--open", action="store_true", help="Abrir automáticamente el reporte HTML")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    from run_benchmark import ejecutar_modo_pure_llm

    handlers = {
        "ping": cmd_ping,
        "scan-code": cmd_scan_code,
        "trace": cmd_trace,
        "scan-deps": cmd_scan_deps,
        "audit": cmd_audit,
        "evaluate": cmd_evaluate,
        "benchmark": cmd_benchmark,
        "pure-llm": ejecutar_modo_pure_llm
    }

    handlers[args.command](args)


if __name__ == "__main__":
    main()
