"""
sast/ast_extractor.py
=============================================================================
Extractor Automático de Funciones basado en AST y Análisis Sintáctico
=============================================================================
Recorre repositorios de código fuente, trocea los archivos en funciones y
métodos individuales y extrae su metadata completa (nombre, archivo, líneas
inicial y final, cuerpo de código) para permitir auditorías semánticas puras
con modelos de lenguaje (Ablation Study: Pure LLM sin Semgrep).
"""

from __future__ import annotations
import ast
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# Extensiones de código soportadas por lenguaje
EXTENSIONES_SOPORTADAS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c_header",
    ".hpp": "cpp_header",
    ".go": "go",
    ".java": "java",
}

# Carpetas o patrones a omitir durante el recorrido
DIRECTORIOS_IGNORADOS: Set[str] = {
    ".git", ".github", ".venv", "venv", "node_modules", "__pycache__",
    ".idea", ".vscode", "dist", "build", "target", "vendor",
    "docs", "documentation", "htmlcov", "coverage", ".pytest_cache",
    "tests", "test", "testing", "spec", "specs", "mocks"
}

# Archivos específicos a ignorar (documentación, minificados, tests unitarios masivos)
ARCHIVOS_IGNORADOS: Set[str] = {
    "jquery.js", "dynsections.js", "clipboard.js", "bootstrap.js",
    "conf.py", "setup.py", "version.py"
}


# =============================================================================
# 1. PARSEO DE PYTHON MEDIANTE AST NATIVO
# =============================================================================

def _es_funcion_trivial_python(node: ast.FunctionDef | ast.AsyncFunctionDef, lines: List[str]) -> bool:
    """Detecta si una función de Python es vacía o trivial (pass, return None, solo docstring)."""
    # Si tiene solo 1 o 2 líneas
    start = node.lineno
    end = getattr(node, "end_lineno", start)
    if end - start <= 1:
        return True

    # Analizar el cuerpo de instrucciones
    body = [n for n in node.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
    if not body:
        return True  # Solo contenía un docstring

    if len(body) == 1:
        single = body[0]
        if isinstance(single, ast.Pass):
            return True
        if isinstance(single, ast.Return):
            # return None, return True, return False, etc.
            if single.value is None or (isinstance(single.value, ast.Constant) and single.value.value in (None, True, False, 0, 1, "")):
                return True

    return False


def extraer_funciones_python(
    filepath: str,
    repo_name: str,
    archivo_rel_repo: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Extrae todas las funciones y métodos de un archivo Python usando ast nativo."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
            lines = source.splitlines(keepends=True)
    except Exception:
        return []

    if not source.strip():
        return []

    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []

    rel_archivo = archivo_rel_repo or os.path.basename(filepath)
    funciones: List[Dict[str, Any]] = []

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.class_stack: List[str] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.class_stack.append(node.name)
            self.generic_visit(node)
            self.class_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._procesar_funcion(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._procesar_funcion(node)
            self.generic_visit(node)

        def _procesar_funcion(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            if _es_funcion_trivial_python(node, lines):
                return

            prefix = ".".join(self.class_stack)
            full_name = f"{prefix}.{node.name}" if prefix else node.name

            start_line = node.lineno
            end_line = getattr(node, "end_lineno", min(len(lines), start_line + 30))

            # Capturar el cuerpo del código completo
            codigo_bloque = "".join(lines[start_line - 1 : end_line])

            # Omitir si el código resultante es demasiado corto
            if len(codigo_bloque.strip().splitlines()) <= 2:
                return

            # Extraer nombres de argumentos
            args_list = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]

            funciones.append({
                "repo": repo_name,
                "archivo": rel_archivo,
                "archivo_nombre": os.path.basename(filepath),
                "ruta_relativa": os.path.normpath(filepath).replace("\\", "/"),
                "archivo_absoluto": os.path.abspath(filepath),
                "nombre_funcion": full_name,
                "linea": start_line,
                "linea_inicio": start_line,
                "linea_fin": end_line,
                "num_lineas": end_line - start_line + 1,
                "argumentos": args_list,
                "lenguaje": "python",
                "codigo": codigo_bloque.strip()
            })

    visitor = Visitor()
    visitor.visit(tree)
    return funciones


# =============================================================================
# 2. PARSEO DE C, C++, GO, JAVA Y JAVASCRIPT CON BALANCE DE LLAVES
# =============================================================================

def _encontrar_cierre_llave(lines: List[str], start_line_idx: int) -> int:
    """
    Rastrea el balance de llaves { y } a partir de start_line_idx para encontrar
    el fin del cuerpo de la función. Devuelve el número de línea (1-indexado).
    """
    brace_count = 0
    encontro_primera = False

    for idx in range(start_line_idx, min(len(lines), start_line_idx + 250)):
        line = lines[idx]
        # Omitir comentarios de línea completa
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue

        for char in line:
            if char == "{":
                brace_count += 1
                encontro_primera = True
            elif char == "}":
                brace_count -= 1
                if encontro_primera and brace_count == 0:
                    return idx + 1  # 1-indexado

    # Si no se cerró en el límite, devolver un rango razonable
    return min(len(lines), start_line_idx + 40)


def extraer_funciones_c_java_js_go(
    filepath: str,
    repo_name: str,
    lenguaje: str,
    archivo_rel_repo: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Extrae funciones en lenguajes basados en llaves usando regex y balance de bloques."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return []

    if not lines:
        return []

    rel_archivo = archivo_rel_repo or os.path.basename(filepath)

    # Expresiones regulares para cabeceras de funciones
    patrones_por_lenguaje = {
        "javascript": re.compile(
            r"^(?:\s*(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)|"
            r"\s*(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>|"
            r"\s*(?:async\s+)?([a-zA-Z0-9_$]+)\s*\(([^)]*)\)\s*\{)"
        ),
        "typescript": re.compile(
            r"^(?:\s*(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(([^)]*)\)|"
            r"\s*(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>|"
            r"\s*(?:public|private|protected)?\s*(?:async\s+)?([a-zA-Z0-9_$]+)\s*\(([^)]*)\))"
        ),
        "go": re.compile(
            r"^func\s+(?:\([^)]+\)\s*)?([a-zA-Z0-9_]+)\s*\(([^)]*)\)"
        ),
        "java": re.compile(
            r"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:[\w<>[\]]+)\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{?"
        ),
        "c": re.compile(
            r"^(?:(?:static|inline|extern)\s+)*[\w*]+\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*(?:\{|$)"
        ),
        "cpp": re.compile(
            r"^(?:(?:static|inline|virtual|explicit)\s+)*[\w*:<>]+\s+([a-zA-Z0-9_:]+)\s*\(([^)]*)\)\s*(?:const)?\s*(?:\{|$)"
        )
    }

    pattern = patrones_por_lenguaje.get(lenguaje, patrones_por_lenguaje["c"])
    KEYWORD_EXCLUSIONS = {
        "if", "while", "for", "switch", "catch", "return", "sizeof",
        "typeof", "import", "export", "else", "case", "default"
    }

    funciones: List[Dict[str, Any]] = []
    i = 0
    total_lines = len(lines)

    while i < total_lines:
        line = lines[i]
        line_strip = line.strip()

        # Omitir líneas vacías o comentarios directos
        if not line_strip or line_strip.startswith(("//", "/*", "*", "#")):
            i += 1
            continue

        match = pattern.search(line)
        if match:
            # Obtener el nombre de la función del grupo coincidente
            groups = [g for g in match.groups() if g]
            nombre_func = groups[0] if groups else None

            if nombre_func and nombre_func not in KEYWORD_EXCLUSIONS:
                start_line = i + 1
                # Si la llave de apertura no está en esta línea, buscarla en las 2 siguientes
                brace_start_idx = i
                if "{" not in line:
                    for next_idx in range(i + 1, min(total_lines, i + 4)):
                        if "{" in lines[next_idx]:
                            brace_start_idx = next_idx
                            break

                end_line = _encontrar_cierre_llave(lines, brace_start_idx)
                codigo_bloque = "".join(lines[start_line - 1 : end_line]).strip()

                # Descartar funciones de menos de 3 líneas o vacías
                if end_line - start_line >= 2 and len(codigo_bloque.splitlines()) >= 2:
                    funciones.append({
                        "repo": repo_name,
                        "archivo": rel_archivo,
                        "archivo_nombre": os.path.basename(filepath),
                        "ruta_relativa": os.path.normpath(filepath).replace("\\", "/"),
                        "archivo_absoluto": os.path.abspath(filepath),
                        "nombre_funcion": nombre_func,
                        "linea": start_line,
                        "linea_inicio": start_line,
                        "linea_fin": end_line,
                        "num_lineas": end_line - start_line + 1,
                        "argumentos": [],
                        "lenguaje": lenguaje,
                        "codigo": codigo_bloque
                    })
                    # Avanzar el puntero hasta después del cierre de la función
                    i = max(i + 1, end_line)
                    continue

        i += 1

    return funciones


# =============================================================================
# 3. EXTRAECTOR PRINCIPAL DE REPOSITORIOS Y DIRECTORIOS
# =============================================================================

def extraer_funciones_archivo(
    filepath: str,
    repo_name: str,
    archivo_rel_repo: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Extrae las funciones de un archivo según su extensión de lenguaje."""
    ext = os.path.splitext(filepath)[1].lower()
    lenguaje = EXTENSIONES_SOPORTADAS.get(ext)
    if not lenguaje:
        return []

    if lenguaje == "python":
        return extraer_funciones_python(filepath, repo_name, archivo_rel_repo=archivo_rel_repo)
    return extraer_funciones_c_java_js_go(filepath, repo_name, lenguaje, archivo_rel_repo=archivo_rel_repo)


def extraer_funciones_directorio(
    directorio_raiz: str,
    repo_filtro: Optional[str] = None,
    max_funciones: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Recorre recursivamente un directorio o repositorio extrayendo todas sus funciones.
    
    Parámetros:
        directorio_raiz: Ruta de la carpeta raíz (ej: 'dataset_repos').
        repo_filtro: Nombre opcional de un repositorio a limitar (ej: 'python_pyjwt').
        max_funciones: Límite máximo de funciones a extraer.
        
    Retorna:
        Lista de diccionarios con la metadata de cada función extraída.
    """
    todas_funciones: List[Dict[str, Any]] = []

    if not os.path.exists(directorio_raiz):
        return []

    for root, dirs, files in os.walk(directorio_raiz):
        # Filtrar directorios ignorados in-place para que os.walk no entre en ellos
        dirs[:] = [d for d in dirs if d not in DIRECTORIOS_IGNORADOS and not d.startswith(".")]

        # Determinar el nombre del repositorio relativo y la carpeta raíz del repo
        rel_root = os.path.relpath(root, directorio_raiz)
        partes = rel_root.replace("\\", "/").split("/")
        base_dir_name = os.path.basename(os.path.normpath(directorio_raiz))

        if repo_filtro and (base_dir_name == repo_filtro or base_dir_name.startswith(repo_filtro)):
            repo_actual = repo_filtro
            repo_dir = directorio_raiz
        else:
            repo_actual = partes[0] if partes and partes[0] != "." else base_dir_name
            repo_dir = os.path.join(directorio_raiz, repo_actual)
            # Si se especificó un filtro de repositorio, ignorar otros
            if repo_filtro and repo_actual != repo_filtro and not repo_actual.startswith(repo_filtro):
                continue

        for filename in sorted(files):
            # Omitir archivos ignorados o minificados
            if filename in ARCHIVOS_IGNORADOS or filename.endswith(".min.js") or filename.endswith(".bundle.js"):
                continue

            ext = os.path.splitext(filename)[1].lower()
            if ext not in EXTENSIONES_SOPORTADAS:
                continue

            filepath = os.path.join(root, filename)
            # Calcular ruta del archivo relativa al repositorio (ej: 'jwt/api_jwk.py')
            try:
                archivo_rel = os.path.relpath(filepath, repo_dir).replace("\\", "/")
            except ValueError:
                archivo_rel = filename

            funciones_archivo = extraer_funciones_archivo(
                filepath,
                repo_actual,
                archivo_rel_repo=archivo_rel
            )
            todas_funciones.extend(funciones_archivo)

            if max_funciones and len(todas_funciones) >= max_funciones:
                return todas_funciones[:max_funciones]

    return todas_funciones
