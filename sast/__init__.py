"""
Módulo SAST: Motor Híbrido de Seguridad (Semgrep SAST + Trivy SCA + Taint Tracker + Agente LLM APR)
"""

from .semgrep_scanner import scan_con_semgrep
from .trivy_scanner import scan_con_trivy
from .taint_tracker import (
    rastrear_flujo_hallazgo,
    enriquecer_hallazgos_con_flujo,
    encontrar_funcion_contenedora,
    buscar_llamadas_en_repositorio,
)
from .llm_client import (
    auditar_codigo,
    auditar_hallazgo_semgrep,
    auditar_paquete_contexto,
    auditar_hallazgo_trivy,
    ping_server,
    obtener_ngrok_url,
    AuditResultModel,
)
from .evaluator import (
    evaluar_hallazgos_ground_truth,
    generar_reporte_metricas,
)

__all__ = [
    "scan_con_semgrep",
    "scan_con_trivy",
    "rastrear_flujo_hallazgo",
    "enriquecer_hallazgos_con_flujo",
    "encontrar_funcion_contenedora",
    "buscar_llamadas_en_repositorio",
    "auditar_codigo",
    "auditar_hallazgo_semgrep",
    "auditar_paquete_contexto",
    "auditar_hallazgo_trivy",
    "ping_server",
    "obtener_ngrok_url",
    "AuditResultModel",
    "evaluar_hallazgos_ground_truth",
    "generar_reporte_metricas",
]
