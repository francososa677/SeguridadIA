"""
run_benchmark.py
=============================================================================
Runner del Benchmark de Seguridad: Modo Híbrido y Modo Ablación (Pure LLM)
=============================================================================
Permite ejecutar el benchmark de evaluación con Semgrep (modo hybrid) o
desacoplando completamente Semgrep (modo pure-llm / Ablation Study) para
evaluar la capacidad pura del LLM analizando funciones troceadas mediante AST.

Sintaxis de uso:
  python run_benchmark.py --mode pure-llm --repos dataset_repos/ --ground-truth dataset_repos/ground_truth.json
  python run_benchmark.py --mode pure-llm --repo python_pyjwt --limit 10
  python run_benchmark.py --mode hybrid --repo python_colorama
"""

from __future__ import annotations
import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

# Configuración de codificación UTF-8 en Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Importaciones del paquete sast
from sast.ast_extractor import extraer_funciones_directorio
from sast.llm_client import (
    auditar_funcion_ast,
    auditar_hallazgo_semgrep,
    ping_server,
    obtener_ngrok_url
)
from sast.semgrep_scanner import scan_con_semgrep
from sast.taint_tracker import enriquecer_hallazgos_con_flujo
from sast.trivy_scanner import scan_con_trivy
from sast.evaluator import evaluar_hallazgos_ground_truth, generar_reporte_metricas
from sast.reporter import (
    compilar_matriz_comparativa,
    generar_reporte_html,
    generar_reporte_markdown
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REPOS_DIR = os.path.join(BASE_DIR, "dataset_repos")
DEFAULT_GROUND_TRUTH = os.path.join(DEFAULT_REPOS_DIR, "ground_truth.json")


def ejecutar_modo_pure_llm(args: argparse.Namespace) -> None:
    """
    Ejecuta el Ablation Study: Trocea los archivos en funciones mediante AST
    y las evalúa directamente con el LLM sin usar Semgrep.
    """
    repos_dir = os.path.abspath(args.repos) if args.repos else DEFAULT_REPOS_DIR
    gt_path = os.path.abspath(args.ground_truth) if args.ground_truth else DEFAULT_GROUND_TRUTH

    if not os.path.exists(gt_path):
        print(f"❌ Error: No se encontró ground_truth.json en: {gt_path}")
        sys.exit(1)

    with open(gt_path, "r", encoding="utf-8") as f:
        gt_list = json.load(f)

    if args.repo:
        gt_list = [gt for gt in gt_list if gt.get("repo") == args.repo]
        print(f"[*] Filtrando evaluación para el repositorio: '{args.repo}' ({len(gt_list)} debilidades en Ground Truth)")

    print(f"==================================================================")
    print(f"   🔬 ESTUDIO DE ABLACIÓN: BENCHMARK PURE-LLM (SIN SEMGREP)      ")
    print(f"==================================================================")
    print(f"Directorio de código : {repos_dir}")
    print(f"Ground Truth         : {gt_path}\n")

    # 1. Extracción de funciones mediante AST
    print(f"[*] Paso 1: Extrayendo funciones y métodos mediante AST...")
    target_scan = os.path.join(repos_dir, args.repo) if args.repo and not repos_dir.endswith(args.repo) else repos_dir
    funciones = extraer_funciones_directorio(target_scan, repo_filtro=args.repo)
    print(f"    -> {len(funciones)} funciones troceadas extraídas en el dataset.")

    # 2. Carga de caché incremental
    cache_path = os.path.abspath(args.cache) if args.cache else os.path.join(BASE_DIR, "pure_llm_cache.json")
    cache: Dict[str, Any] = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache = json.load(f)
            print(f"[*] Caché cargado: {len(cache)} inferencias previas disponibles.")
        except Exception as e:
            print(f"[-] Advertencia al leer caché ({e}), se iniciará nuevo.")

    # 3. Auditoría de Taint con el LLM función por función
    print(f"[*] Paso 2: Ejecutando auditoría de Taint con el LLM (Sources -> Flow -> Sinks)...")
    funciones_auditadas: List[Dict[str, Any]] = []
    pendientes_count = 0

    for idx, func in enumerate(funciones, start=1):
        cache_key = f"{func['repo']}::{func['archivo']}::{func['nombre_funcion']}::{func['linea_inicio']}"
        ruta_display = f"{func['archivo']}:{func['linea_inicio']}-{func['linea_fin']} [{func['nombre_funcion']}]"

        if cache_key in cache:
            veredicto = cache[cache_key]
            func["estado"] = veredicto.get("estado", "SEGURO")
            func["cwe_id"] = veredicto.get("cwe_id", "N/A")
            func["owasp_categoria"] = veredicto.get("owasp_categoria", "N/A")
            func["linea_impacto"] = veredicto.get("linea_impacto")
            func["explicacion"] = veredicto.get("explicacion", "")
            func["tiempo_segundos"] = veredicto.get("tiempo_segundos", 0.0)
            funciones_auditadas.append(func)
        else:
            if getattr(args, "report_only", False):
                func["estado"] = "NO_EVALUADO"
                func["explicacion"] = "Pendiente de auditoría por LLM"
                funciones_auditadas.append(func)
                continue

            if args.limit and pendientes_count >= args.limit:
                func["estado"] = "NO_EVALUADO"
                func["explicacion"] = "Omitido por límite de ejecución"
                funciones_auditadas.append(func)
                continue

            pendientes_count += 1
            print(f"[{idx}/{len(funciones)}] Pure LLM: {func['repo']} -> {ruta_display} ...", end=" ", flush=True)
            start = time.time()
            veredicto = auditar_funcion_ast(func)
            dur = round(time.time() - start, 2)
            estado = veredicto.get("estado", "ERROR")
            cwe = veredicto.get("cwe_id", "N/A")
            print(f"{estado} [{cwe}] ({dur}s)")

            veredicto["tiempo_segundos"] = dur
            cache[cache_key] = veredicto

            func["estado"] = estado
            func["cwe_id"] = veredicto.get("cwe_id", "N/A")
            func["owasp_categoria"] = veredicto.get("owasp_categoria", "N/A")
            func["linea_impacto"] = veredicto.get("linea_impacto")
            func["explicacion"] = veredicto.get("explicacion", "")
            func["tiempo_segundos"] = dur
            funciones_auditadas.append(func)

            # Guardar en caché incremental
            try:
                with open(cache_path, "w", encoding="utf-8") as cf:
                    json.dump(cache, cf, indent=2, ensure_ascii=False)
            except Exception:
                pass

            time.sleep(0.2)

    # 4. Evaluación frente al Ground Truth
    print(f"\n[*] Paso 3: Evaluando resultados frente a ground_truth.json...")
    eval_res = evaluar_hallazgos_ground_truth(
        funciones_auditadas,
        gt_path,
        tolerancia_lineas=15,
        repo_filter=args.repo
    )

    # 5. Compilar matriz cruzada para reportería visual
    matriz_datos = compilar_matriz_comparativa(
        ground_truth_list=gt_list,
        hallazgos_semgrep_auditados=funciones_auditadas,
        hallazgos_trivy=[],
        modo="pure-llm"
    )

    # Sobrescribir métricas con las calculadas en la evaluación
    m_eval = eval_res["metricas"]
    matriz_datos["metricas"].update({
        "agente_tp": m_eval["tp"],
        "agente_fp": m_eval["fp"],
        "agente_fn": m_eval["fn"],
        "agente_tn": m_eval["tn"],
        "precision": m_eval["precision"],
        "recall": m_eval["recall"],
        "f1_score": m_eval["f1_score"],
    })

    # 6. Generar reportes HTML y Markdown
    html_out = os.path.abspath(args.html) if getattr(args, "html", None) else os.path.join(BASE_DIR, "reporte_pure_llm.html")
    generar_reporte_html(matriz_datos, html_out)
    print(f"✅ Dashboard Pure LLM generado en: {html_out}")

    md_out = os.path.abspath(args.md) if getattr(args, "md", None) else os.path.join(BASE_DIR, "reporte_pure_llm.md")
    generar_reporte_markdown(matriz_datos, md_out)
    print(f"✅ Informe Markdown generado en: {md_out}")

    # 7. Mostrar resumen formal de evaluación
    print("\n" + generar_reporte_metricas(eval_res))

    # 8. Abrir en navegador si se solicitó
    if getattr(args, "open", False):
        try:
            import webbrowser
            webbrowser.open(f"file:///{html_out}")
            print(f"[+] Abriendo dashboard en el navegador...")
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Runner de Benchmark de Seguridad: Modo Pure-LLM (Ablation Study) y Modo Híbrido"
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="pure-llm",
        choices=["pure-llm", "hybrid"],
        help="Modo de ejecución: 'pure-llm' (Ablación sin Semgrep) o 'hybrid' (Pipeline completo)"
    )
    parser.add_argument(
        "--repos",
        type=str,
        default=DEFAULT_REPOS_DIR,
        help="Ruta al directorio de repositorios de prueba (default: dataset_repos/)"
    )
    parser.add_argument(
        "--ground-truth",
        type=str,
        default=DEFAULT_GROUND_TRUTH,
        help="Ruta al archivo ground_truth.json (default: dataset_repos/ground_truth.json)"
    )
    parser.add_argument(
        "--repo",
        type=str,
        default=None,
        help="Filtrar por repositorio específico (ej: python_pyjwt, python_colorama)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Límite máximo de funciones a enviar al LLM"
    )
    parser.add_argument(
        "--cache",
        type=str,
        default=None,
        help="Ruta al archivo de caché de inferencias"
    )
    parser.add_argument(
        "--html",
        type=str,
        default=None,
        help="Ruta de salida del reporte visual HTML"
    )
    parser.add_argument(
        "--md",
        type=str,
        default=None,
        help="Ruta de salida del informe Markdown"
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Generar reportes a partir de datos ya en caché sin invocar el LLM"
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Abrir automáticamente el reporte HTML en el navegador"
    )

    args = parser.parse_args()

    if args.mode == "pure-llm":
        ejecutar_modo_pure_llm(args)
    else:
        # Reutilizar el benchmark híbrido de main.py
        from main import cmd_benchmark
        cmd_benchmark(args)


if __name__ == "__main__":
    main()
