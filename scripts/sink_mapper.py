"""
=============================================================================
PASO 1: Mapeo Estático de Sumideros (Sinks) para Análisis SAST Multimodular
=============================================================================

¿Qué hace este script?
----------------------
Escanea estáticamente el código fuente de los repositorios buscando "Sinks"
(puntos críticos de ejecución donde una entrada de usuario maliciosa podría
provocar una vulnerabilidad de seguridad, ej: open, subprocess, strcpy, etc.).

¿Cuándo se ejecuta?
-------------------
1. En benchmarking: Se ejecuta UNA VEZ sobre la carpeta 'dataset_repos/' para
   generar 'sinks_candidates.json'. Los pasos posteriores (Taint Tracker y LLM)
   consumen ese JSON directamente.
2. Si agregas o modificas código en algún repositorio, simplemente vuelves a
   ejecutar este script para actualizar los candidatos en pocos segundos.
3. En producción: Puede ser importado como función (scan_dataset o scan_file_for_sinks)
   para correr al vuelo en cualquier repositorio nuevo antes de llamar a la IA.
"""

from __future__ import annotations
import ast
import json
import os
import re
from typing import Any, Dict, List

# =============================================================================
# CATÁLOGO DE PATRONES DE SUMIDEROS (SINKS) POR LENGUAJE Y CATEGORÍA OWASP
# =============================================================================
# Cada patrón define:
# - category: El tipo de impacto o vulnerabilidad asociada.
# - regex: La expresión regular para capturar la llamada y el argumento principal.
# - sink_name: Nombre legible de la API o función sumidero detectada.

SINK_PATTERNS = {
    "python": [
        # Inyección de Comandos (A03:2021 / CWE-78)
        {
            "category": "COMMAND_INJECTION",
            "regex": r"(?:subprocess\.(?:run|Popen|call|check_output)|os\.(?:system|popen))\s*\(([^,\)]+)",
            "sink_name": "subprocess/os.system"
        },
        # Inyección SQL (A03:2021 / CWE-89)
        {
            "category": "SQL_INJECTION",
            "regex": r"(?:cursor\.execute|db_cursor\.execute|session\.execute|engine\.execute)\s*\(([^,\)]+)",
            "sink_name": "db_cursor.execute"
        },
        # Path Traversal / Manipulación de Archivos (A01:2021 / CWE-22)
        {
            "category": "PATH_TRAVERSAL",
            "regex": r"(?:open|os\.path\.join)\s*\(([^,\)]+)",
            "sink_name": "open/os.path.join"
        },
        # Deserialización Insegura (A08:2021 / CWE-502)
        {
            "category": "INSECURE_DESERIALIZATION",
            "regex": r"(?:pickle\.loads|pickle\.load|yaml\.unsafe_load|yaml\.load)\s*\(([^,\)]+)",
            "sink_name": "pickle.loads"
        },
        # Server-Side Request Forgery (A10:2021 / CWE-918)
        {
            "category": "SSRF",
            "regex": r"(?:urllib\.request\.urlopen|requests\.(?:get|post|request))\s*\(([^,\)]+)",
            "sink_name": "urllib.request.urlopen"
        },
        # Fuga de Secretos en Logs / Debug (A09:2021 / CWE-532 / CWE-117)
        {
            "category": "LOG_INJECTION_OR_LEAK",
            "regex": r"(?:logging\.(?:info|debug|warning|error)|print)\s*\(([^,\)]+)",
            "sink_name": "logging/print"
        }
    ],
    "javascript": [
        # Inyección de Comandos en Node.js (A03:2021 / CWE-78)
        {
            "category": "COMMAND_INJECTION",
            "regex": r"(?:child_process\.(?:exec|spawn|execSync)|exec)\s*\(([^,\)]+)",
            "sink_name": "child_process.exec"
        },
        # Peticiones de red sin validar (A10:2021 / CWE-918)
        {
            "category": "SSRF",
            "regex": r"(?:http\.get|https\.get|fetch|axios\.(?:get|post))\s*\(([^,\)]+)",
            "sink_name": "http.get/fetch"
        },
        # Inyección de Cabeceras / CRLF (A03:2021 / CWE-113)
        {
            "category": "HEADER_INJECTION",
            "regex": r"(?:response\.setHeader|res\.setHeader|setRawUnsafeHeader)\s*\(([^,\)]+)",
            "sink_name": "setHeader"
        },
        # Cross-Site Scripting Reflejado / DOM (A03:2021 / CWE-79)
        {
            "category": "XSS",
            "regex": r"(?:innerHTML|renderUnsafeUserHtml|document\.write)\s*=?\s*\(?([^;\n\)]+)",
            "sink_name": "innerHTML/renderHtml"
        },
        # Generador de Números Pseudoaleatorios Débil (A02:2021 / CWE-330)
        {
            "category": "WEAK_PRNG",
            "regex": r"Math\.random\s*\(\)",
            "sink_name": "Math.random"
        }
    ],
    "c_cpp": [
        # Desbordamiento de Búfer / Seguridad de Memoria (A06:2021 / CWE-120 / CWE-121)
        {
            "category": "BUFFER_OVERFLOW",
            "regex": r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(([^,\)]+)",
            "sink_name": "strcpy/sprintf"
        },
        # Doble Liberación de Memoria / Use After Free (A06:2021 / CWE-415 / CWE-416)
        {
            "category": "DOUBLE_FREE",
            "regex": r"\b(free|cJSON_Delete)\s*\(([^,\)]+)",
            "sink_name": "free/cJSON_Delete"
        },
        # Cadena de Formato No Controlada (A03:2021 / CWE-134)
        {
            "category": "FORMAT_STRING",
            "regex": r"\b(printf|fprintf|syslog)\s*\(([^,\)]+)\)",
            "sink_name": "printf"
        }
    ],
    "go": [
        # Path Traversal en Go (A01:2021 / CWE-22)
        {
            "category": "PATH_TRAVERSAL",
            "regex": r"(?:os\.ReadFile|os\.Open|ioutil\.ReadFile)\s*\(([^,\)]+)",
            "sink_name": "os.ReadFile"
        },
        # SSRF en Go (A10:2021 / CWE-918)
        {
            "category": "SSRF",
            "regex": r"(?:http\.Get|http\.Post|http\.NewRequest)\s*\(([^,\)]+)",
            "sink_name": "http.Get"
        },
        # Criptografía Débil / Hash Roto (A02:2021 / CWE-327)
        {
            "category": "WEAK_CRYPTO",
            "regex": r"(?:md5\.Sum|md5\.New)\s*\(([^,\)]+)",
            "sink_name": "md5.Sum"
        }
    ],
    "java": [
        # Inyección de Código o Comandos en Java (A03:2021 / CWE-94 / CWE-78)
        {
            "category": "CODE_OR_COMMAND_INJECTION",
            "regex": r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|out\.append|emitRawSnippetUnsafe)\s*\(([^,\)]+)",
            "sink_name": "Runtime.exec/out.append"
        },
        # Permisos Excesivos de Archivo (A05:2021 / CWE-732)
        {
            "category": "INSECURE_PERMISSIONS",
            "regex": r"(?:setReadable|setWritable|setExecutable)\s*\(([^,\)]+)",
            "sink_name": "setReadable/setWritable"
        }
    ]
}


def detect_language(filepath: str) -> str | None:
    """
    Identifica el lenguaje de programación a partir de la extensión del archivo.
    Retorna el identificador del lenguaje o None si no es un archivo de código soportado.
    """
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".py":
        return "python"
    elif ext in (".js", ".ts"):
        return "javascript"
    elif ext in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"):
        return "c_cpp"
    elif ext == ".go":
        return "go"
    elif ext == ".java":
        return "java"
    return None


def scan_python_with_ast(filepath: str, code_content: str) -> List[Dict[str, Any]]:
    """
    Analizador semántico basado en AST (Abstract Syntax Tree) para Python.
    
    ¿Por qué usar AST en lugar de solo Regex?
    Porque el AST comprende la estructura sintáctica real del código:
    - Sabe si una llamada es 'pickle.loads(variable)' o un comentario.
    - Extrae el argumento exacto (nombre de variable, f-string o constante).
    - Evita falsos positivos de cadenas de texto que solo contienen el nombre de la función.
    """
    ast_sinks = []
    try:
        tree = ast.parse(code_content, filename=filepath)
    except Exception:
        # Si el archivo tiene errores de sintaxis Python, retornamos lista vacía
        return ast_sinks

    lines = code_content.splitlines()

    # Recorremos todos los nodos del árbol sintáctico
    for node in ast.walk(tree):
        # Buscamos nodos de tipo 'Llamada de Función' (ast.Call)
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                # e.g., pickle.loads, subprocess.run, os.system
                val_name = getattr(node.func.value, "id", "")
                func_name = f"{val_name}.{node.func.attr}" if val_name else node.func.attr

            # Clasificamos según la categoría de riesgo
            target_category = None
            if func_name in ("pickle.loads", "pickle.load"):
                target_category = "INSECURE_DESERIALIZATION"
            elif func_name in ("os.system", "os.popen", "subprocess.run", "subprocess.Popen"):
                target_category = "COMMAND_INJECTION"
            elif func_name in ("open", "os.path.join"):
                target_category = "PATH_TRAVERSAL"
            elif func_name in ("urllib.request.urlopen", "requests.get", "requests.post"):
                target_category = "SSRF"

            if target_category:
                line_idx = getattr(node, "lineno", 1) - 1
                arg_repr = ""
                # Extraemos la variable o argumento que entra a la función peligrosa
                if node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Name):
                        arg_repr = first_arg.id
                    elif isinstance(first_arg, ast.Constant):
                        arg_repr = repr(first_arg.value)
                    elif isinstance(first_arg, ast.JoinedStr):
                        arg_repr = f"f-string: {[p.value.id if isinstance(p, ast.FormattedValue) and isinstance(p.value, ast.Name) else '...' for p in first_arg.values]}"
                    else:
                        arg_repr = ast.unparse(first_arg) if hasattr(ast, "unparse") else "expression"

                # Extraemos un snippet de contexto (líneas antes y después)
                start_ctx = max(0, line_idx - 2)
                end_ctx = min(len(lines), line_idx + 3)
                snippet = "\n".join(lines[start_ctx:end_ctx])

                ast_sinks.append({
                    "linea": line_idx + 1,
                    "funcion_sink": func_name,
                    "categoria": target_category,
                    "variable_involucrada": arg_repr.strip(),
                    "snippet": snippet,
                    "detector": "AST_PYTHON"
                })
    return ast_sinks


def scan_file_for_sinks(repo_name: str, rel_path: str, full_path: str) -> List[Dict[str, Any]]:
    """
    Escanea un archivo individual y extrae todos los sumideros candidatos.
    Combina el análisis AST (para Python) con el motor de firmas Regex estructurado.
    """
    lang = detect_language(full_path)
    if not lang:
        return []

    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            code_content = f.read()
    except Exception:
        return []

    lines = code_content.splitlines()
    candidates: List[Dict[str, Any]] = []
    seen_lines = set()

    # 1. Ejecutar análisis AST si el archivo es Python
    if lang == "python":
        ast_results = scan_python_with_ast(full_path, code_content)
        for r in ast_results:
            seen_lines.add(r["linea"])
            candidates.append({
                "repo": repo_name,
                "archivo": rel_path.replace("\\", "/"),
                **r
            })

    # 2. Ejecutar análisis con catálogo de firmas Regex estructuradas
    patterns = SINK_PATTERNS.get(lang, [])
    for line_idx, line in enumerate(lines, start=1):
        # Si la línea ya fue detectada con mayor precisión por el AST, la omitimos
        if line_idx in seen_lines:
            continue

        # Ignorar comentarios puros para reducir ruido
        stripped = line.strip()
        if stripped.startswith(("//", "#", "/*", "*", "<!--")):
            if not any(k in stripped for k in ("unsafe", "insecure", "strcpy", "system")):
                continue

        # Evaluar patrones del lenguaje actual
        for p in patterns:
            match = re.search(p["regex"], line)
            if match:
                var_inv = match.group(1).strip() if match.groups() else "N/A"
                start_ctx = max(0, line_idx - 3)
                end_ctx = min(len(lines), line_idx + 2)
                snippet = "\n".join(lines[start_ctx:end_ctx])

                candidates.append({
                    "repo": repo_name,
                    "archivo": rel_path.replace("\\", "/"),
                    "linea": line_idx,
                    "funcion_sink": p["sink_name"],
                    "categoria": p["category"],
                    "variable_involucrada": var_inv,
                    "snippet": snippet,
                    "detector": "REGEX_PATTERN"
                })
                break

    return candidates


def scan_dataset(base_dir: str) -> List[Dict[str, Any]]:
    """
    Recorre recursivamente todos los repositorios dentro de 'base_dir'
    y recopila todos los candidatos a sumideros (Sinks).
    """
    all_candidates = []
    # Listar subdirectorios que representan cada repositorio
    repos = [
        d for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d)) and not d.startswith(".")
    ]

    for repo in sorted(repos):
        repo_dir = os.path.join(base_dir, repo)
        for root, _, files in os.walk(repo_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, repo_dir)
                res = scan_file_for_sinks(repo, rel_path, full_path)
                all_candidates.extend(res)

    return all_candidates


# =============================================================================
# PUNTO DE ENTRADA PRINCIPAL (CLI)
# =============================================================================
if __name__ == "__main__":
    dataset_path = r"c:\Users\Franco Sosa\Documents\SeguridadIA\dataset_repos"
    output_json = os.path.join(dataset_path, "sinks_candidates.json")

    print(f"[*] Iniciando Paso 1: Mapeo de Sinks en {dataset_path}...")
    candidates = scan_dataset(dataset_path)

    # Exportar el resultado consolidado a JSON
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(candidates, f, indent=2, ensure_ascii=False)

    print(f"[+] Total de Sinks candidatos identificados: {len(candidates)}")
    print(f"[+] Candidatos exportados a: {output_json}")

    # Mostrar resumen estadístico por categoría
    summary = {}
    for c in candidates:
        cat = c["categoria"]
        summary[cat] = summary.get(cat, 0) + 1

    print("\n--- Distribución por Categoría de Sink ---")
    for cat, count in sorted(summary.items(), key=lambda x: x[1], reverse=True):
        print(f"  • {cat:30s}: {count} candidatos")
