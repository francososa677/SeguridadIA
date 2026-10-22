"""
sast/semgrep_scanner.py
=============================================================================
Paso 1 (SAST): Escáner de Código Fuente con Semgrep en Modo Permisivo
=============================================================================
Este módulo se encarga de ejecutar Semgrep sobre el código fuente para detectar
posibles fallas y debilidades de seguridad (Static Application Security Testing).

¿Por qué se usa en modo permisivo (alto recall)?
- Se utiliza una configuración amplia (como 'p/security-audit' o 'auto') para
  capturar la mayor cantidad posible de sospechas de vulnerabilidad.
- El objetivo no es filtrar todo aquí, sino pasar estos candidatos a la IA
  (LLM) para que ella haga el triage fino (eliminar falsos positivos) y sugiera
  parches automáticos (APR).
"""

from __future__ import annotations
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional


def obtener_ejecutable_semgrep() -> str:
    """
    Localiza la ruta al ejecutable de Semgrep en el sistema operativo.
    
    Utiliza `shutil.which` para buscar en la variable de entorno PATH.
    Si lo encuentra, devuelve la ruta absoluta; de lo contrario, devuelve
    el comando simple 'semgrep' asumiendo que el shell lo resolverá.
    """
    exe = shutil.which("semgrep")
    if exe:
        return exe
    return "semgrep"


def leer_fragmento_codigo(filepath: str, linea: int, ventana: int = 15) -> str:
    """
    Lee un fragmento de código contextual alrededor de la línea reportada.
    
    Parámetros:
        filepath: Ruta completa del archivo que contiene el hallazgo.
        linea: Número de línea donde Semgrep detectó la vulnerabilidad (1-indexado).
        ventana: Cantidad total de líneas a capturar (mitad antes, mitad después).
    
    Retorna:
        Un string con el bloque de código circundante, necesario para que el
        modelo de lenguaje (LLM) tenga contexto suficiente para analizarlo y parcharlo.
    """
    try:
        # Abrimos el archivo ignorando posibles errores de codificación raros
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        # Calculamos los límites inferior y superior asegurando no salirnos del rango
        start = max(0, linea - ventana // 2 - 1)
        end = min(len(lines), linea + ventana // 2)
        
        # Unimos las líneas seleccionadas y las devolvemos
        return "".join(lines[start:end])
    except Exception:
        # Si el archivo no se puede leer (por ejemplo, binario o permisos), devolvemos texto vacío
        return ""


def scan_con_semgrep(
    target_path: str,
    config: str = "auto",
    severity: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Ejecuta Semgrep sobre la ruta indicada y normaliza los resultados en un formato común.
    
    Parámetros:
        target_path: Carpeta o archivo que se desea analizar.
        config: Reglas o pack de Semgrep a aplicar (por defecto 'auto' o 'p/security-audit').
        severity: Filtro opcional de severidad (INFO, WARNING, ERROR). Por defecto None para capturar todo.
        
    Retorna:
        Lista de diccionarios, donde cada elemento representa un hallazgo normalizado
        con archivo, línea, CWE, OWASP, mensaje y fragmento de código.
    """
    # 1. Obtener la ruta del ejecutable de Semgrep
    semgrep_bin = obtener_ejecutable_semgrep()
    
    # 2. Construir la línea de comandos
    # --json: Para recibir la salida estructurada y poder procesarla programáticamente
    # --config: Define el set de reglas de seguridad a evaluar
    comando = [
        semgrep_bin,
        "scan",
        "--config", config,
        "--json"
    ]

    # Si se especificó un filtro de severidad, se agrega a los argumentos
    if severity:
        comando.extend(["--severity", severity])

    # Se agrega la ruta objetivo al final del comando
    comando.append(target_path)

    # 3. Ejecutar el comando en el sistema operativo mediante un subproceso
    try:
        res = subprocess.run(
            comando,
            capture_output=True,  # Captura stdout y stderr
            text=True,            # Decodifica los bytes a string
            encoding="utf-8",
            check=False           # No lanza excepción si Semgrep retorna código de salida != 0
        )
    except Exception as e:
        print(f"[-] Error al invocar Semgrep: {e}")
        return []

    # 4. Limpieza de salida: Semgrep a veces imprime mensajes de consola antes del JSON
    stdout = res.stdout.strip()
    idx_start = stdout.find("{")  # Buscamos la primera llave para encontrar dónde empieza el JSON válido
    if idx_start == -1:
        return []

    # 5. Parsear el texto capturado a un diccionario de Python
    try:
        raw_json = json.loads(stdout[idx_start:])
    except Exception as e:
        print(f"[-] Error parseando JSON de Semgrep: {e}")
        return []

    hallazgos: List[Dict[str, Any]] = []
    base_dir = os.path.abspath(target_path)

    # 6. Iterar sobre cada resultado retornado por Semgrep y extraer campos clave
    for item in raw_json.get("results", []):
        file_path = os.path.abspath(item.get("path", ""))
        linea = int(item.get("start", {}).get("line", 1))
        meta = item.get("extra", {}).get("metadata", {})

        # Extracción limpia de la categoría CWE (Common Weakness Enumeration)
        cwe_raw = meta.get("cwe", ["Desconocido"])
        cwe = cwe_raw[0] if isinstance(cwe_raw, list) and cwe_raw else str(cwe_raw)
        
        # Extracción limpia de la categoría OWASP Top 10
        owasp_raw = meta.get("owasp", ["Desconocido"])
        owasp = owasp_raw[0] if isinstance(owasp_raw, list) and owasp_raw else str(owasp_raw)

        # Identificar el repositorio de origen si estamos escaneando dentro de dataset_repos
        repo_name = "general"
        if "dataset_repos" in file_path:
            parts = file_path.split("dataset_repos")[-1].lstrip(r"\/").split(os.sep)
            if parts:
                repo_name = parts[0]

        # Ruta relativa respecto al directorio base analizado para que la visualización sea limpia
        rel_path = os.path.relpath(file_path, base_dir).replace("\\", "/")

        # 7. Construir el objeto estandarizado del hallazgo
        hallazgos.append({
            "repo": repo_name,
            "archivo": rel_path,
            "archivo_absoluto": file_path,
            "linea": linea,
            "regla_id": item.get("check_id", ""),
            "mensaje": item.get("extra", {}).get("message", ""),
            "cwe": cwe,
            "owasp": owasp,
            "severidad": item.get("extra", {}).get("severity", "WARNING"),
            # Extraemos las líneas de código alrededor para enviárselas al modelo LLM
            "fragmento_codigo": leer_fragmento_codigo(file_path, linea)
        })

    return hallazgos
