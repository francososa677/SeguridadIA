"""
sast/trivy_scanner.py
=============================================================================
Paso 1 (SCA): Escáner de Dependencias y Manifiestos con Trivy
=============================================================================
Este módulo se encarga del análisis de composición de software (SCA - Software
Composition Analysis) utilizando Trivy.

¿Qué hace exactamente?
- Inspecciona manifiestos de dependencias (tales como requirements.txt,
  package.json, pom.xml, go.mod, etc.) en busca de librerías de terceros con
  vulnerabilidades conocidas publicadas en bases de datos de seguridad (CVEs).
- Identifica tanto la versión vulnerable que está instalada como la versión
  corregida recomendada para actualizarla.
"""

from __future__ import annotations
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional


def obtener_ejecutable_trivy() -> str:
    """
    Localiza la ruta al binario ejecutable de Trivy en el sistema.
    
    Estrategia de búsqueda:
    1. Revisa la variable de entorno PATH con `shutil.which`.
    2. Si no está en PATH (común en Windows si se instaló mediante WinGet sin reiniciar la terminal),
       recorre la carpeta de paquetes de WinGet en `%LOCALAPPDATA%` buscando 'trivy.exe'.
    3. Si no lo encuentra, devuelve 'trivy' como fallback general.
    """
    # 1. Búsqueda rápida en PATH
    exe = shutil.which("trivy")
    if exe:
        return exe

    # 2. Búsqueda de respaldo en la ruta estándar de WinGet en Windows
    appdata = os.environ.get("LOCALAPPDATA", "")
    winget_pkg_dir = os.path.join(appdata, "Microsoft", "WinGet", "Packages")
    if os.path.isdir(winget_pkg_dir):
        for root, _, files in os.walk(winget_pkg_dir):
            if "trivy.exe" in files:
                return os.path.join(root, "trivy.exe")

    # 3. Fallback genérico
    return "trivy"


def scan_con_trivy(
    target_path: str,
    severities: str = "LOW,MEDIUM,HIGH,CRITICAL"
) -> List[Dict[str, Any]]:
    """
    Ejecuta Trivy sobre 'target_path' y extrae la lista normalizada de CVEs encontrados.
    
    Parámetros:
        target_path: Ruta a la carpeta o archivo donde se encuentran los manifiestos de paquetes.
        severities: Lista separada por comas de los niveles de severidad a incluir.
        
    Retorna:
        Lista de diccionarios, donde cada elemento describe una dependencia vulnerable,
        su CVE asociado, su severidad y la versión recomendada para parchar.
    """
    # 1. Obtener la ruta al ejecutable de Trivy
    trivy_bin = obtener_ejecutable_trivy()
    
    # 2. Armar los argumentos de la línea de comandos
    # - fs: Modo de escaneo sobre el sistema de archivos local (filesystem)
    # --format json: Genera salida en formato JSON estructurado
    # --severity: Filtra por las severidades deseadas (LOW hasta CRITICAL)
    # --scanners vuln: Enfoca el análisis exclusivamente en vulnerabilidades de paquetes
    comando = [
        trivy_bin,
        "fs",
        "--format", "json",
        "--severity", severities,
        "--scanners", "vuln",
        target_path
    ]

    # 3. Ejecutar el comando en el sistema operativo mediante un subproceso
    try:
        res = subprocess.run(
            comando,
            capture_output=True,  # Captura la salida estándar y de errores
            text=True,            # Convierte los bytes leídos en strings UTF-8
            encoding="utf-8",
            check=False           # No interrumpe la ejecución si Trivy retorna código no-cero
        )
    except Exception as e:
        print(f"[-] Error al invocar Trivy: {e}")
        return []

    # 4. Limpieza de salida: Encontrar dónde comienza el JSON dentro del texto devuelto
    stdout = res.stdout.strip()
    idx_start = stdout.find("{")
    if idx_start == -1:
        # Si no hay llaves JSON, no se encontraron resultados o hubo un fallo
        return []

    # 5. Parsear el JSON a estructuras de Python
    try:
        raw_json = json.loads(stdout[idx_start:])
    except Exception as e:
        print(f"[-] Error parseando JSON de Trivy: {e}")
        return []

    vulnerabilidades: List[Dict[str, Any]] = []

    # 6. Procesar los resultados: Trivy agrupa los hallazgos en la clave 'Results'
    # Cada entrada en 'Results' representa un archivo manifiesto (ej. package.json o requirements.txt)
    for result_item in raw_json.get("Results", []):
        target_file = result_item.get("Target", "")
        vulns = result_item.get("Vulnerabilities", [])

        # Iterar sobre cada vulnerabilidad detectada en ese manifiesto
        for v in vulns:
            vulnerabilidades.append({
                "manifiesto": target_file,
                "paquete": v.get("PkgName", ""),
                "version_instalada": v.get("InstalledVersion", ""),
                "version_corregida": v.get("FixedVersion", "Sin parche oficial"),
                "cve_id": v.get("VulnerabilityID", ""),
                "severidad": v.get("Severity", "UNKNOWN"),
                "titulo": v.get("Title", ""),
                "descripcion": v.get("Description", ""),
                "enlaces": v.get("PrimaryURL", "")
            })

    return vulnerabilidades
