"""
sast/taint_tracker.py
=============================================================================
Paso 2 (Taint Analysis): Rastreador de Flujo de Datos Inter-Archivo
=============================================================================
Este módulo resuelve la limitación de Semgrep Open Source (que solo analiza
código dentro del mismo archivo / intra-file).

¿Cómo funciona?
1. Identifica la función contenedora del Sink (sumidero vulnerable) y sus argumentos.
2. Si la variable sospechosa proviene de los argumentos de la función, busca en todos
   los demás archivos del repositorio quién invoca a esa función (Call-Sites).
3. Construye un paquete de flujo inter-archivo:
   [Archivo Invocador / Source] ---> [Archivo Sumidero / Sink]
4. Proporciona a la IA la visión completa del camino que recorre el dato para que
   pueda validar con certeza si la entrada es controlada por el usuario o no.
"""

from __future__ import annotations
import ast
import os
import re
from typing import Any, Dict, List, Optional, Tuple

# Extensiones de código reconocidas para búsqueda inter-archivo
CODE_EXTENSIONS = (
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".c", ".cpp", ".cc", ".h", ".hpp",
    ".go", ".java"
)

# Nombres comunes o genéricos que no conviene rastrear para evitar falsos call-sites masivos
IGNORED_FUNCTION_NAMES = {
    "__init__", "init", "main", "test", "setUp", "tearDown",
    "run", "get", "set", "close", "toString", "handler",
    "execute", "process", "load", "save", "render", "anonymous_func"
}

# Carpetas que se deben omitir al recorrer el repositorio
IGNORED_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__",
    ".idea", ".vscode", "dist", "build", "target"
}


def encontrar_funcion_contenedora_python(
    filepath: str,
    linea: int
) -> Tuple[Optional[str], List[str], Optional[str]]:
    """
    Encuentra la función o método de Python que envuelve la línea indicada utilizando AST.
    
    Retorna:
        (nombre_funcion, lista_de_argumentos, snippet_codigo)
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
            lines = source.splitlines(keepends=True)
    except Exception:
        return None, [], None

    # Intentar parseo con el árbol sintáctico de Python (AST)
    try:
        tree = ast.parse(source, filename=filepath)
        target_node = None

        # Recorremos el árbol buscando la función más interna que contenga la línea
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", node.lineno + 20)
                if start <= linea <= end:
                    # Si encontramos una más específica (anidada), la preferimos
                    if target_node is None or node.lineno >= target_node.lineno:
                        target_node = node

        if target_node:
            func_name = target_node.name
            args = [
                a.arg for a in target_node.args.args
                if a.arg not in ("self", "cls")
            ]
            f_start = max(0, target_node.lineno - 1)
            f_end = min(len(lines), getattr(target_node, "end_lineno", target_node.lineno + 25))
            snippet = "".join(lines[f_start:f_end])
            return func_name, args, snippet

    except Exception:
        pass

    # Fallback con expresiones regulares si el archivo tiene errores de sintaxis
    func_pattern = re.compile(r"^\s*def\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)", re.MULTILINE)
    closest_name = None
    closest_args: List[str] = []
    closest_line = -1

    for idx, line in enumerate(lines[:linea], start=1):
        m = func_pattern.search(line)
        if m:
            closest_name = m.group(1)
            raw_args = m.group(2)
            closest_args = [
                arg.strip().split(":")[0].strip()
                for arg in raw_args.split(",")
                if arg.strip() and arg.strip() not in ("self", "cls")
            ]
            closest_line = idx

    if closest_name and closest_line > 0:
        f_start = max(0, closest_line - 1)
        f_end = min(len(lines), closest_line + 25)
        return closest_name, closest_args, "".join(lines[f_start:f_end])

    return None, [], None


def encontrar_funcion_contenedora_generica(
    filepath: str,
    linea: int
) -> Tuple[Optional[str], List[str], Optional[str]]:
    """
    Encuentra la cabecera de función contenedora para C, C++, Go, Java, JS buscando hacia arriba.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None, [], None

    # Patrones comunes de declaración de funciones en C/C++/Java/Go/JS
    func_pattern = re.compile(
        r"(?:function\s+([a-zA-Z0-9_$]+)|"                       # JS: function foo(...)
        r"([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*(?:\{|throws|->)|"    # C/Java/JS: void foo(...) {
        r"func\s+(?:\([^)]+\)\s*)?([a-zA-Z0-9_$]+)\s*\(([^)]*)\)|" # Go: func (r) Foo(...)
        r"(?:public|private|protected)?\s*[\w<>[\]]+\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\))" # Java
    )

    KEYWORD_EXCLUSIONS = {
        "if", "while", "for", "switch", "catch", "return", "eval",
        "sizeof", "typeof", "require", "import", "export", "else"
    }

    start_idx = max(0, linea - 1)
    # Buscamos hacia arriba hasta 60 líneas
    for i in range(start_idx, max(-1, start_idx - 60), -1):
        line = lines[i].strip()
        # Ignorar comentarios
        if line.startswith(("//", "*", "/*", "#")):
            continue

        match = func_pattern.search(line)
        if match:
            name = next((g for g in (match.group(1), match.group(2), match.group(4), match.group(6)) if g), None)
            if name and name not in KEYWORD_EXCLUSIONS:
                f_end = min(len(lines), i + 25)
                snippet = "".join(lines[i:f_end])
                return name, [], snippet

    return None, [], None


def encontrar_funcion_contenedora(
    filepath: str,
    linea: int
) -> Tuple[Optional[str], List[str], Optional[str]]:
    """
    Despacha la detección de función contenedora según la extensión del archivo.
    """
    if filepath.endswith(".py"):
        return encontrar_funcion_contenedora_python(filepath, linea)
    return encontrar_funcion_contenedora_generica(filepath, linea)


def buscar_llamadas_en_repositorio(
    repo_dir: str,
    nombre_funcion: str,
    archivo_excluido: str,
    max_llamadas: int = 3
) -> List[Dict[str, Any]]:
    """
    Busca llamadas a `nombre_funcion` en todos los archivos del repositorio (excluyendo el archivo destino).
    
    Parámetros:
        repo_dir: Ruta raíz del repositorio o proyecto a analizar.
        nombre_funcion: Nombre de la función donde reside el sink.
        archivo_excluido: Archivo donde ya está definida la función (para no reportar autoreferencias).
        max_llamadas: Límite de call-sites a capturar.
        
    Retorna:
        Lista de call-sites encontrados (archivo, línea, snippet del invocador).
    """
    call_sites: List[Dict[str, Any]] = []

    if not nombre_funcion or nombre_funcion in IGNORED_FUNCTION_NAMES:
        return call_sites

    # Regex para detectar llamadas del estilo: nombre_funcion(...) o objeto.nombre_funcion(...)
    pattern = re.compile(rf"\b{re.escape(nombre_funcion)}\s*\(")

    for root, dirs, files in os.walk(repo_dir):
        # Excluir carpetas irrelevantes
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for file in files:
            if not file.endswith(CODE_EXTENSIONS):
                continue

            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, repo_dir).replace("\\", "/")

            if rel_path == archivo_excluido or full_path == archivo_excluido:
                continue

            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for l_idx, line in enumerate(lines, start=1):
                    if pattern.search(line):
                        c_start = max(0, l_idx - 3)
                        c_end = min(len(lines), l_idx + 3)
                        snippet = "".join(lines[c_start:c_end])

                        call_sites.append({
                            "archivo_origen": rel_path,
                            "linea_origen": l_idx,
                            "snippet_origen": snippet.strip()
                        })

                        if len(call_sites) >= max_llamadas:
                            return call_sites
            except Exception:
                continue

    return call_sites


def rastrear_flujo_hallazgo(
    hallazgo: Dict[str, Any],
    repo_base_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analiza un hallazgo individual de Semgrep y rastrea si existe un flujo de llamadas
    inter-archivo que alimente la función vulnerable.
    """
    archivo_abs = hallazgo.get("archivo_absoluto", "")
    linea = hallazgo.get("linea", 1)
    rel_file = hallazgo.get("archivo", "")

    # Determinar la carpeta raíz del repositorio
    if repo_base_dir:
        repo_dir = repo_base_dir
    elif os.path.exists(archivo_abs):
        # Intentar ubicar la raíz del repo (si contiene dataset_repos o un .git cercano)
        current = os.path.dirname(archivo_abs)
        repo_dir = current
        while current and current != os.path.dirname(current):
            if os.path.exists(os.path.join(current, ".git")) or os.path.basename(os.path.dirname(current)) == "dataset_repos":
                repo_dir = current
                break
            current = os.path.dirname(current)
    else:
        repo_dir = os.getcwd()

    # 1. Encontrar la función contenedora del Sink
    func_name, params, func_snippet = encontrar_funcion_contenedora(archivo_abs, linea)

    # 2. Buscar llamadas externas (Call-Sites) en el resto del repositorio
    call_sites = []
    if func_name:
        call_sites = buscar_llamadas_en_repositorio(repo_dir, func_name, rel_file)

    # 3. Determinar tipo de flujo y ruta
    if call_sites:
        tipo_flujo = "INTER_FILE_FLOW"
        primary = call_sites[0]
        ruta = f"{primary['archivo_origen']}:{primary['linea_origen']} -> {rel_file}:{linea} ({func_name})"
    else:
        tipo_flujo = "INTRA_FILE_FLOW"
        ruta = f"{rel_file}:{linea} [{func_name or 'global'}]"

    return {
        "tipo_flujo": tipo_flujo,
        "funcion_sink": func_name or "ámbito_global",
        "argumentos_funcion": params,
        "ruta_flujo": ruta,
        "llamadas_externas": call_sites,
        "origen_principal": call_sites[0] if call_sites else None,
        "snippet_funcion_sink": func_snippet
    }


def enriquecer_hallazgos_con_flujo(
    hallazgos: List[Dict[str, Any]],
    repo_base_dir: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Toma una lista de hallazgos de Semgrep y le añade a cada uno el bloque
    'flujo_inter_archivo' con la información de invocadores y Call-Sites.
    """
    for h in hallazgos:
        h["flujo_inter_archivo"] = rastrear_flujo_hallazgo(h, repo_base_dir)
    return hallazgos
