"""
=============================================================================
PASO 2: Rastreador de Flujo de Datos Inter-Archivo (Taint Tracker)
=============================================================================

¿Qué hace este script?
----------------------
Toma cada candidato a sumidero (Sink) generado en el Paso 1 ('sinks_candidates.json')
y rastrea hacia atrás el flujo de la variable involucrada:

1. Rastreo Local (Intra-archivo):
   - Averigua si la variable proviene de una constante fija, una asignación intermedia
     o de los parámetros de la función contenedora.

2. Rastreo Inter-Módulo (Inter-archivo):
   - Si la variable entra como parámetro de una función pública/exportada, busca en el
     resto de los archivos del repositorio quién llama a esa función (Call Sites) o
     dónde se originan los datos.

3. Armado de Paquetes de Contexto Mínimo:
   - Empaqueta el snippet del Origen (Módulo A) + el snippet del Sumidero (Módulo B)
     en un formato compacto y estructurado para que el modelo de IA (Paso 3) tenga
     la historia completa sin saturar su memoria de contexto.
"""

from __future__ import annotations
import ast
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple


def find_enclosing_function_python(filepath: str, line_no: int) -> Tuple[Optional[str], Optional[List[str]], Optional[str]]:
    """
    Encuentra la función o método que envuelve una línea específica en Python usando AST.
    Retorna: (nombre_funcion, lista_de_parametros, snippet_funcion)
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        tree = ast.parse(content, filename=filepath)
        lines = content.splitlines()
    except Exception:
        return None, None, None

    target_func = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start_line = node.lineno
            end_line = getattr(node, "end_lineno", start_line + 20)
            if start_line <= line_no <= end_line:
                target_func = node
                break

    if target_func:
        args = [a.arg for a in target_func.args.args if a.arg not in ("self", "cls")]
        f_start = max(0, target_func.lineno - 1)
        f_end = min(len(lines), getattr(target_func, "end_lineno", target_func.lineno + 15))
        func_snippet = "\n".join(lines[f_start:f_end])
        return target_func.name, args, func_snippet

    return None, None, None


def find_enclosing_function_generic(filepath: str, line_no: int) -> Tuple[Optional[str], Optional[List[str]], Optional[str]]:
    """
    Encuentra la función contenedora en lenguajes JS, C/C++, Go, Java usando análisis de bloques.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None, None, None

    # Buscar hacia arriba desde line_no la cabecera de la función más cercana
    func_pattern = re.compile(r"(?:function\s+([a-zA-Z0-9_$]+)|([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*(?:\{|throws|->)|func\s+(?:\([^)]+\)\s*)?([a-zA-Z0-9_$]+)\s*\(([^)]*)\)|public\s+[\w<>]+\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\))")
    
    start_idx = max(0, line_no - 1)
    for i in range(start_idx, max(-1, start_idx - 50), -1):
        line = lines[i]
        match = func_pattern.search(line)
        if match:
            # Extraer nombre
            name = next((g for g in (match.group(1), match.group(2), match.group(4), match.group(6)) if g), "anonymous_func")
            # Extraer contexto
            f_end = min(len(lines), i + 25)
            snippet = "".join(lines[i:f_end])
            return name, [], snippet

    return None, None, None


def search_call_sites_in_repo(repo_dir: str, target_func_name: str, exclude_file: str) -> List[Dict[str, Any]]:
    """
    Busca llamadas a 'target_func_name' en todos los demás archivos del repositorio (Mapeo Inter-Archivo).
    """
    call_sites = []
    if not target_func_name or target_func_name in ("__init__", "init", "main", "anonymous_func"):
        return call_sites

    pattern = re.compile(rf"\b{re.escape(target_func_name)}\s*\(([^)]*)\)")

    for root, _, files in os.walk(repo_dir):
        for file in files:
            full_p = os.path.join(root, file)
            rel_p = os.path.relpath(full_p, repo_dir).replace("\\", "/")
            if rel_p == exclude_file:
                continue

            # Solo buscar en archivos de código fuente
            if not file.endswith((".py", ".js", ".ts", ".c", ".cpp", ".h", ".go", ".java")):
                continue

            try:
                with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                for l_idx, line in enumerate(lines, start=1):
                    if pattern.search(line):
                        c_start = max(0, l_idx - 3)
                        c_end = min(len(lines), l_idx + 2)
                        snippet = "".join(lines[c_start:c_end])
                        call_sites.append({
                            "source_file": rel_p,
                            "source_line": l_idx,
                            "source_snippet": snippet.strip()
                        })
                        if len(call_sites) >= 3:  # Limitar a los 3 primeros sitios más relevantes
                            return call_sites
            except Exception:
                continue

    return call_sites


def trace_candidate(dataset_base: str, candidate: Dict[str, Any]) -> Dict[str, Any]:
    """
    Rastrea el flujo de datos completo para un candidato a Sink específico.
    """
    repo = candidate["repo"]
    rel_file = candidate["archivo"]
    line_no = candidate["linea"]
    var_inv = candidate["variable_involucrada"]
    sink_fn = candidate["funcion_sink"]
    cat = candidate["categoria"]
    snippet_sink = candidate["snippet"]

    full_filepath = os.path.join(dataset_base, repo, rel_file)
    repo_dir = os.path.join(dataset_base, repo)

    # 1. Identificar la función contenedora del Sink
    is_python = rel_file.endswith(".py")
    if is_python:
        func_name, params, func_snippet = find_enclosing_function_python(full_filepath, line_no)
    else:
        func_name, params, func_snippet = find_enclosing_function_generic(full_filepath, line_no)

    # 2. Determinar si la variable proviene de los argumentos de la función o de variables locales
    is_parameter = False
    if params and any(p in var_inv for p in params):
        is_parameter = True

    # 3. Buscar llamadas inter-módulo en el resto del repositorio
    call_sites = []
    if func_name:
        call_sites = search_call_sites_in_repo(repo_dir, func_name, rel_file)

    # 4. Construir el paquete de contexto de Taint Analysis
    if call_sites:
        primary_source = call_sites[0]
        taint_type = "INTER_MODULE_FLOW"
        source_file = primary_source["source_file"]
        source_line = primary_source["source_line"]
        source_snippet = primary_source["source_snippet"]
        flow_path = f"{source_file}:{source_line} -> {rel_file}:{line_no} ({func_name})"
    else:
        taint_type = "INTRA_MODULE_FLOW"
        source_file = rel_file
        source_line = line_no
        source_snippet = func_snippet if func_snippet else snippet_sink
        flow_path = f"{rel_file}:{line_no} [{func_name or 'global_scope'}]"

    return {
        "candidate_id": f"{repo}::{rel_file}::{line_no}",
        "repo": repo,
        "categoria": cat,
        "funcion_sink": sink_fn,
        "variable_rastreada": var_inv,
        "tipo_flujo": taint_type,
        "origen_es_parametro": is_parameter,
        "ruta_flujo": flow_path,
        "modulo_destino_sink": {
            "archivo": rel_file,
            "linea": line_no,
            "funcion_contenedora": func_name or "global",
            "snippet": snippet_sink
        },
        "modulo_origen_source": {
            "archivo": source_file,
            "linea": source_line,
            "snippet": source_snippet
        }
    }


def process_all_candidates(dataset_base: str, sinks_json: str, output_json: str) -> List[Dict[str, Any]]:
    """
    Lee todos los Sinks de 'sinks_candidates.json', ejecuta el rastreo de flujo
    y genera el archivo consolidado 'taint_context_packages.json'.
    """
    with open(sinks_json, "r", encoding="utf-8") as f:
        candidates = json.load(f)

    print(f"[*] Procesando {len(candidates)} candidatos de sumideros para Taint Tracking...")
    packages = []

    for idx, cand in enumerate(candidates, start=1):
        package = trace_candidate(dataset_base, cand)
        packages.append(package)

        if idx % 100 == 0 or idx == len(candidates):
            print(f"    - Rastreados {idx}/{len(candidates)} flujos...")

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(packages, f, indent=2, ensure_ascii=False)

    print(f"[+] Paquetes de contexto generados exitosamente: {len(packages)}")
    print(f"[+] Archivo de salida: {output_json}")
    return packages


# =============================================================================
# PUNTO DE ENTRADA PRINCIPAL
# =============================================================================
if __name__ == "__main__":
    dataset_dir = r"c:\Users\Franco Sosa\Documents\SeguridadIA\dataset_repos"
    input_sinks = os.path.join(dataset_dir, "sinks_candidates.json")
    output_taint = os.path.join(dataset_dir, "taint_context_packages.json")

    packages = process_all_candidates(dataset_dir, input_sinks, output_taint)

    # Resumen de estadísticas del flujo
    inter_count = sum(1 for p in packages if p["tipo_flujo"] == "INTER_MODULE_FLOW")
    intra_count = sum(1 for p in packages if p["tipo_flujo"] == "INTRA_MODULE_FLOW")
    param_count = sum(1 for p in packages if p["origen_es_parametro"])

    print("\n--- Resumen de Flujo de Datos Taint Tracker ---")
    print(f"  • Flujos Inter-Módulo (conectados entre archivos) : {inter_count}")
    print(f"  • Flujos Intra-Módulo (locales/estructurales)       : {intra_count}")
    print(f"  • Sinks que reciben parámetros externos            : {param_count}")
