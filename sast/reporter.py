"""
sast/reporter.py
=============================================================================
Generador de Reportes Comparativos y Dashboards Visuales de Seguridad
=============================================================================
Genera un informe visual interactivo (HTML con diseño moderno y modo oscuro)
y un informe tabular en Markdown que compara de forma transparente:
  1. Las 40 vulnerabilidades del Ground Truth: si Semgrep, Trivy y el Agente IA las detectaron.
  2. El ruido de Semgrep (falsos positivos): qué alertas no eran vulnerables y cómo respondió el Agente IA.
  3. Métricas de reducción de ruido, Precision, Recall y F1-Score.
"""

from __future__ import annotations
import json
import os
import html
from typing import Any, Dict, List, Optional
from .evaluator import coincide_con_ground_truth


def compilar_matriz_comparativa(
    ground_truth_list: List[Dict[str, Any]],
    hallazgos_semgrep_auditados: List[Dict[str, Any]],
    hallazgos_trivy: Optional[List[Dict[str, Any]]] = None,
    tolerancia_lineas: int = 15,
    modo: str = "hybrid"
) -> Dict[str, Any]:
    """
    Compila la matriz completa de evaluación cruzada entre:
    - Ground Truth (vulnerabilidades reales conocidas)
    - Semgrep (SAST) [o desacoplado en modo pure-llm]
    - Trivy (SCA)
    - Agente LLM (Triage IA / AST Taint Audit)
    """
    trivy_list = hallazgos_trivy or []

    # 1. Mapeo de hallazgos que coinciden con Ground Truth
    gt_matriz = []
    hallazgos_usados_ids = set()

    for gt in ground_truth_list:
        gt_id = gt["id"]
        # Buscar si algún hallazgo o función coincide con esta vulnerabilidad
        match_h = None
        for idx, h in enumerate(hallazgos_semgrep_auditados):
            if coincide_con_ground_truth(h, gt, tolerancia_lineas=tolerancia_lineas):
                match_h = h
                hallazgos_usados_ids.add(idx)
                break

        # Buscar si Trivy reportó algo en este repo (generalmente librerías)
        match_trivy = [t for t in trivy_list if t.get("repo") == gt.get("repo")]

        detectado_semgrep = match_h is not None if modo == "hybrid" else False
        detectado_trivy = len(match_trivy) > 0
        trivy_detalle = f"{len(match_trivy)} CVEs detectados" if detectado_trivy else "N/A (Código Fuente)"

        agente_auditado = False
        agente_estado = "NO_ALCANZADO"
        agente_explicacion = (
            "Función no alcanzada o no auditada en esta corrida."
            if modo == "pure-llm"
            else "No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA."
        )
        flujo_tipo = "INTRA_FILE"
        flujo_ruta = f"{gt.get('archivo')}:{gt.get('linea')}"
        snippet = ""

        if match_h:
            agente_auditado = True
            agente_estado = match_h.get("estado", "DESCONOCIDO")
            agente_explicacion = match_h.get("explicacion", "")
            flujo = match_h.get("flujo_inter_archivo", {})
            flujo_tipo = flujo.get("tipo_flujo", "INTRA_FILE")
            flujo_ruta = flujo.get("ruta_flujo", flujo_ruta)
            snippet = match_h.get("codigo", "") or match_h.get("fragmento_codigo", "")

        # Clasificación con respecto a Ground Truth
        if agente_estado == "VULNERABLE":
            clasificacion = "TP"  # Verdadero Positivo
        elif agente_estado == "SEGURO":
            clasificacion = "FN"  # Falso Negativo (el agente descartó una vuln real)
        else:
            clasificacion = "NO_DETECTADO_SAST" if modo == "hybrid" else "FN"

        semgrep_label = (
            match_h.get("mensaje", "") if modo == "hybrid" and match_h
            else ("Desacoplado (Ablation Study)" if modo == "pure-llm" else "")
        )

        gt_matriz.append({
            "id": gt_id,
            "repo": gt.get("repo", ""),
            "archivo": gt.get("archivo", ""),
            "linea": gt.get("linea", 0),
            "cwe_id": gt.get("cwe_id", ""),
            "owasp_categoria": gt.get("owasp_categoria", ""),
            "descripcion": gt.get("descripcion", ""),
            "detectado_semgrep": detectado_semgrep,
            "semgrep_regla": semgrep_label,
            "detectado_trivy": detectado_trivy,
            "trivy_detalle": trivy_detalle,
            "agente_auditado": agente_auditado,
            "agente_estado": agente_estado,
            "agente_explicacion": agente_explicacion,
            "flujo_tipo": flujo_tipo,
            "flujo_ruta": flujo_ruta,
            "clasificacion": clasificacion,
            "snippet": snippet
        })

    # 2. Mapeo de Ruido (Código seguro que NO está en Ground Truth)
    ruido_semgrep_matriz = []
    for idx, h in enumerate(hallazgos_semgrep_auditados):
        if idx in hallazgos_usados_ids:
            continue  # Ya fue asignado a un Ground Truth

        estado_ia = h.get("estado", "DESCONOCIDO")
        exp_ia = h.get("explicacion", "")
        flujo = h.get("flujo_inter_archivo", {})
        flujo_tipo = flujo.get("tipo_flujo", "INTRA_FILE")
        flujo_ruta = flujo.get("ruta_flujo", f"{h.get('archivo')}:{h.get('linea')}")
        snippet_h = h.get("codigo", "") or h.get("fragmento_codigo", "")
        regla_desc = h.get("mensaje") or h.get("nombre_funcion") or "Función de aplicación"

        if estado_ia == "SEGURO":
            clasificacion = "TN"  # Verdadero Negativo
        elif estado_ia == "VULNERABLE":
            clasificacion = "FP"  # Falso Positivo
        else:
            clasificacion = "NO_EVALUADO"

        ruido_semgrep_matriz.append({
            "repo": h.get("repo", ""),
            "archivo": h.get("archivo", ""),
            "linea": h.get("linea", 0),
            "semgrep_regla": regla_desc,
            "cwe": h.get("cwe_id") or h.get("cwe") or "Desconocido",
            "owasp": h.get("owasp_categoria") or h.get("owasp") or "Desconocido",
            "agente_estado": estado_ia,
            "agente_explicacion": exp_ia,
            "flujo_tipo": flujo_tipo,
            "flujo_ruta": flujo_ruta,
            "clasificacion": clasificacion,
            "snippet": snippet_h
        })

    # 3. Métricas cuantitativas globales
    tp = sum(1 for item in gt_matriz if item["clasificacion"] == "TP")
    fn = sum(1 for item in gt_matriz if item["clasificacion"] in ("FN", "NO_DETECTADO_SAST"))
    tn = sum(1 for item in ruido_semgrep_matriz if item["clasificacion"] == "TN")
    fp = sum(1 for item in ruido_semgrep_matriz if item["clasificacion"] == "FP")

    total_gt = len(ground_truth_list)
    semgrep_tp = sum(1 for item in gt_matriz if item["detectado_semgrep"])
    semgrep_ruido = len(ruido_semgrep_matriz)

    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    recall = (tp / total_gt * 100) if total_gt > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    
    # Tasa de reducción de falsos positivos lograda por el agente
    reduccion_ruido = (tn / semgrep_ruido * 100) if semgrep_ruido > 0 else 0.0

    metricas = {
        "total_ground_truth": total_gt,
        "semgrep_detectados": semgrep_tp,
        "semgrep_recall": round((semgrep_tp / total_gt * 100), 2) if total_gt > 0 else 0.0,
        "semgrep_total_ruido": semgrep_ruido,
        "agente_tp": tp,
        "agente_fn": fn,
        "agente_tn": tn,
        "agente_fp": fp,
        "precision": round(precision, 2),
        "recall": round(recall, 2),
        "f1_score": round(f1, 2),
        "reduccion_ruido_pct": round(reduccion_ruido, 2),
    }

    return {
        "metricas": metricas,
        "ground_truth_matriz": gt_matriz,
        "ruido_semgrep_matriz": ruido_semgrep_matriz,
        "trivy_hallazgos": hallazgos_trivy
    }


def generar_reporte_html(datos: Dict[str, Any], ruta_salida: str) -> None:
    """Genera un dashboard visual interactivo en HTML con diseño premium, modo oscuro y filtros."""
    m = datos["metricas"]
    gt_items = datos["ground_truth_matriz"]
    ruido_items = datos["ruido_semgrep_matriz"]

    # Serializar datos JSON para el buscador interactivo en JS
    datos_json = json.dumps(datos, ensure_ascii=False)

    html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard Comparativo SAST: Semgrep + Trivy + Agente IA</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-primary: #090d16;
      --bg-secondary: #0f172a;
      --bg-card: #141e33;
      --bg-card-hover: #1a2744;
      --border-color: #223254;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --accent-cyan: #06b6d4;
      --accent-blue: #3b82f6;
      --accent-green: #10b981;
      --accent-amber: #f59e0b;
      --accent-red: #ef4444;
      --accent-purple: #8b5cf6;
      --radius: 12px;
      --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.4);
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-main);
      line-height: 1.5;
      padding: 24px;
      min-height: 100vh;
    }}

    .container {{
      max-width: 1500px;
      margin: 0 auto;
    }}

    /* HEADER */
    header {{
      background: linear-gradient(135deg, rgba(30, 41, 59, 0.7) 0%, rgba(15, 23, 42, 0.9) 100%);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 32px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
      position: relative;
      overflow: hidden;
    }}

    header::before {{
      content: "";
      position: absolute;
      top: -50px;
      right: -50px;
      width: 250px;
      height: 250px;
      background: radial-gradient(circle, rgba(6, 182, 212, 0.15) 0%, transparent 70%);
      pointer-events: none;
    }}

    .badge-header {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(6, 182, 212, 0.15);
      color: var(--accent-cyan);
      border: 1px solid rgba(6, 182, 212, 0.3);
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 12px;
    }}

    h1 {{
      font-size: 2rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(to right, #f8fafc, #94a3b8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 8px;
    }}

    p.subtitle {{
      color: var(--text-muted);
      font-size: 0.95rem;
      max-width: 900px;
    }}

    /* KPI CARDS */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }}

    .kpi-card {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 20px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
      position: relative;
    }}

    .kpi-card:hover {{
      transform: translateY(-2px);
      border-color: var(--accent-cyan);
      box-shadow: 0 12px 24px -10px rgba(6, 182, 212, 0.25);
    }}

    .kpi-card .kpi-label {{
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      font-weight: 600;
      margin-bottom: 8px;
    }}

    .kpi-card .kpi-value {{
      font-size: 2.2rem;
      font-weight: 800;
      letter-spacing: -0.03em;
      color: #fff;
    }}

    .kpi-card .kpi-detail {{
      font-size: 0.78rem;
      color: var(--text-muted);
      margin-top: 6px;
    }}

    .kpi-green {{ border-left: 4px solid var(--accent-green); }}
    .kpi-blue {{ border-left: 4px solid var(--accent-blue); }}
    .kpi-cyan {{ border-left: 4px solid var(--accent-cyan); }}
    .kpi-amber {{ border-left: 4px solid var(--accent-amber); }}
    .kpi-purple {{ border-left: 4px solid var(--accent-purple); }}

    /* CONTROLS (TABS, SEARCH, FILTERS) */
    .controls-panel {{
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 16px;
      margin-bottom: 20px;
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      align-items: center;
      justify-content: space-between;
    }}

    .tab-group {{
      display: flex;
      background: var(--bg-primary);
      padding: 4px;
      border-radius: 8px;
      border: 1px solid var(--border-color);
    }}

    .tab-btn {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 8px 18px;
      border-radius: 6px;
      font-size: 0.88rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }}

    .tab-btn.active {{
      background: var(--bg-card);
      color: #fff;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.3);
      border: 1px solid var(--border-color);
    }}

    .search-group {{
      display: flex;
      gap: 12px;
      flex: 1;
      max-width: 500px;
    }}

    .search-input {{
      width: 100%;
      background: var(--bg-primary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 8px 14px;
      color: #fff;
      font-size: 0.88rem;
      outline: none;
      transition: border-color 0.2s;
    }}

    .search-input:focus {{
      border-color: var(--accent-cyan);
    }}

    /* TABLES */
    .table-container {{
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      overflow-x: auto;
      box-shadow: var(--shadow);
      margin-bottom: 30px;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.85rem;
    }}

    th {{
      background: #0b1120;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.72rem;
      letter-spacing: 0.05em;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border-color);
      white-space: nowrap;
    }}

    td {{
      padding: 14px 16px;
      border-bottom: 1px solid rgba(34, 50, 84, 0.6);
      vertical-align: top;
    }}

    tr:hover td {{
      background: rgba(20, 30, 51, 0.7);
    }}

    .code-font {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
    }}

    /* PILLS / STATUS BADGES */
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 600;
      white-space: nowrap;
    }}

    .badge-tp {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
    .badge-tn {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
    .badge-fp {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
    .badge-fn {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
    .badge-na {{ background: rgba(148, 163, 184, 0.1); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2); }}
    .badge-inter {{ background: rgba(139, 92, 246, 0.15); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.3); }}

    .explanation-box {{
      background: var(--bg-primary);
      border-radius: 6px;
      padding: 8px 10px;
      margin-top: 6px;
      color: #cbd5e1;
      font-size: 0.8rem;
      border-left: 3px solid var(--accent-cyan);
    }}

    /* DRAWER / CODE ACCORDION */
    details {{
      margin-top: 6px;
    }}

    summary {{
      color: var(--accent-cyan);
      cursor: pointer;
      font-size: 0.75rem;
      user-select: none;
    }}

    summary:hover {{
      text-decoration: underline;
    }}

    pre.snippet-code {{
      background: #020617;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 10px;
      margin-top: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.74rem;
      color: #e2e8f0;
      overflow-x: auto;
      max-height: 180px;
    }}

    /* COMPARISON SECTION */
    .comparison-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 30px;
    }}

    .comparison-box {{
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 24px;
    }}

    .comparison-box h3 {{
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 16px;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .metric-row {{
      display: flex;
      justify-content: space-between;
      padding: 10px 0;
      border-bottom: 1px solid rgba(34, 50, 84, 0.5);
      font-size: 0.88rem;
    }}

    .metric-row:last-child {{
      border-bottom: none;
    }}

    .metric-name {{
      color: var(--text-muted);
    }}

    .metric-val {{
      font-weight: 700;
      color: #fff;
    }}

    footer {{
      text-align: center;
      color: var(--text-muted);
      font-size: 0.8rem;
      padding: 20px;
      margin-top: 30px;
      border-top: 1px solid var(--border-color);
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge-header">🔬 Pipeline SAST Híbrido Multicapa</div>
      <h1>Dashboard de Seguridad y Evaluación del Agente IA</h1>
      <p class="subtitle">
        Contraste cuantitativo entre herramientas industriales de código estático (<strong>Semgrep SAST</strong>),
        análisis de composición de dependencias (<strong>Trivy SCA</strong>), rastreo de flujo inter-archivo (<strong>Taint Tracker</strong>)
        y triage semántico con <strong>LLM (Qwen2.5-Coder-7B)</strong> frente a 40 debilidades controladas.
      </p>
    </header>

    <!-- KPI STATS -->
    <div class="kpi-grid">
      <div class="kpi-card kpi-purple">
        <div class="kpi-label">Ground Truth (Reales)</div>
        <div class="kpi-value">{m['total_ground_truth']}</div>
        <div class="kpi-detail">Vulnerabilidades controladas inyectadas</div>
      </div>
      <div class="kpi-card kpi-amber">
        <div class="kpi-label">Detectadas por Semgrep</div>
        <div class="kpi-value">{m['semgrep_detectados']} / {m['total_ground_truth']}</div>
        <div class="kpi-detail">Sensibilidad Semgrep: {m['semgrep_recall']}%</div>
      </div>
      <div class="kpi-card kpi-green">
        <div class="kpi-label">Verificados por IA (TP)</div>
        <div class="kpi-value">{m['agente_tp']}</div>
        <div class="kpi-detail">Vulnerabilidades reales confirmadas</div>
      </div>
      <div class="kpi-card kpi-blue">
        <div class="kpi-label">Ruido Filtrado por IA (TN)</div>
        <div class="kpi-value">{m['agente_tn']} / {m['semgrep_total_ruido']}</div>
        <div class="kpi-detail">Reducción de Falsos Positivos: <strong>{m['reduccion_ruido_pct']}%</strong></div>
      </div>
      <div class="kpi-card kpi-cyan">
        <div class="kpi-label">Precisión del Agente</div>
        <div class="kpi-value">{m['precision']}%</div>
        <div class="kpi-detail">F1-Score: <strong>{m['f1_score']}%</strong> | FPR: <strong>{(100 - m['reduccion_ruido_pct']):.1f}%</strong></div>
      </div>
    </div>

    <!-- CONTROLS -->
    <div class="controls-panel">
      <div class="tab-group">
        <button class="tab-btn active" onclick="cambiarPestana('tab-gt')">🎯 Ground Truth ({len(gt_items)})</button>
        <button class="tab-btn" onclick="cambiarPestana('tab-ruido')">🧹 Ruido Semgrep ({len(ruido_items)})</button>
        <button class="tab-btn" onclick="cambiarPestana('tab-comparativa')">📈 Comparativa Global</button>
      </div>

      <div class="search-group">
        <input type="text" id="buscador" class="search-input" placeholder="🔍 Buscar por repositorio, CWE, archivo o palabra clave..." oninput="filtrarTablas()">
      </div>
    </div>

    <!-- TAB 1: GROUND TRUTH TABLE -->
    <div id="tab-gt" class="tab-content">
      <div class="table-container">
        <table id="tabla-gt">
          <thead>
            <tr>
              <th style="width: 50px;">ID</th>
              <th>Repositorio</th>
              <th>Archivo y Sumidero</th>
              <th>Taxonomía (CWE / OWASP)</th>
              <th>Semgrep (SAST)</th>
              <th>Trivy (SCA)</th>
              <th>Agente IA (Veredicto)</th>
              <th>Clasificación</th>
            </tr>
          </thead>
          <tbody>
"""

    for item in gt_items:
        # Semgrep status badge
        if item["detectado_semgrep"]:
            semgrep_badge = '<span class="badge badge-tp">🟢 DETECTADO</span>'
        else:
            semgrep_badge = '<span class="badge badge-na">⚪ NO DETECTADO</span>'

        # Trivy status badge
        if item["detectado_trivy"]:
            trivy_badge = f'<span class="badge badge-tp">🟢 {item["trivy_detalle"]}</span>'
        else:
            trivy_badge = '<span class="badge badge-na">⚪ N/A (Código)</span>'

        # Agente IA status badge
        if item["agente_estado"] == "VULNERABLE":
            ia_badge = '<span class="badge badge-tp">🛡️ VULNERABLE</span>'
        elif item["agente_estado"] == "SEGURO":
            ia_badge = '<span class="badge badge-fn">⚠️ SEGURO</span>'
        else:
            ia_badge = '<span class="badge badge-na">⚪ OMITIDO</span>'

        # Clasificación badge
        c = item["clasificacion"]
        if c == "TP":
            cl_badge = '<span class="badge badge-tp">✅ TP (Detectado)</span>'
        elif c == "FN":
            cl_badge = '<span class="badge badge-fn">❌ FN (Descartado)</span>'
        else:
            cl_badge = '<span class="badge badge-na">⚠️ Omitido por SAST</span>'

        flujo_badge = ""
        if item.get("flujo_tipo") == "INTER_FILE_FLOW":
            flujo_badge = f'<div style="margin-top:4px;"><span class="badge badge-inter">🔗 Flujo Inter-Archivo</span></div>'

        snippet_html = ""
        if item.get("snippet"):
            snippet_html = f"""
            <details>
              <summary>Ver fragmento de código auditado</summary>
              <pre class="snippet-code">{html.escape(item['snippet'])}</pre>
            </details>
            """

        html_content += f"""
            <tr class="gt-row" data-search="{html.escape(f"{item['repo']} {item['archivo']} {item['cwe_id']} {item['owasp_categoria']} {item['descripcion']} {item['clasificacion']}")}">
              <td class="code-font" style="font-weight: 700; color: var(--accent-cyan);">#{item['id']}</td>
              <td><strong>{html.escape(item['repo'])}</strong></td>
              <td>
                <div class="code-font">{html.escape(item['archivo'])}:{item['linea']}</div>
                {flujo_badge}
                <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 4px;">{html.escape(item['descripcion'])}</div>
                {snippet_html}
              </td>
              <td>
                <span class="badge badge-na code-font">{html.escape(item['cwe_id'])}</span>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">{html.escape(item['owasp_categoria'])}</div>
              </td>
              <td>{semgrep_badge}</td>
              <td>{trivy_badge}</td>
              <td>
                {ia_badge}
                <div class="explanation-box">{html.escape(item['agente_explicacion'])}</div>
              </td>
              <td>{cl_badge}</td>
            </tr>
"""

    html_content += """
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 2: SEMGREP NOISE TABLE -->
    <div id="tab-ruido" class="tab-content" style="display: none;">
      <div class="table-container">
        <table id="tabla-ruido">
          <thead>
            <tr>
              <th>Repositorio</th>
              <th>Archivo y Línea</th>
              <th>Alerta Reportada por Semgrep</th>
              <th>¿Era Vulnerable?</th>
              <th>Veredicto del Agente IA</th>
              <th>Resultado del Triage</th>
            </tr>
          </thead>
          <tbody>
"""

    for r in ruido_items:
        if r["clasificacion"] == "TN":
            res_badge = '<span class="badge badge-tn">🛡️ TN: Ruido Filtrado con Éxito</span>'
            ia_badge = '<span class="badge badge-tn">SEGURO</span>'
        elif r["clasificacion"] == "FP":
            res_badge = '<span class="badge badge-fp">⚠️ FP: Falsa Alarma Confirmada</span>'
            ia_badge = '<span class="badge badge-fp">VULNERABLE</span>'
        else:
            res_badge = '<span class="badge badge-na">⚪ Pendiente de Auditoría</span>'
            ia_badge = '<span class="badge badge-na">NO EVALUADO</span>'

        html_content += f"""
            <tr class="ruido-row" data-search="{html.escape(f"{r['repo']} {r['archivo']} {r['semgrep_regla']} {r['cwe']} {r['clasificacion']}")}">
              <td><strong>{html.escape(r['repo'])}</strong></td>
              <td class="code-font">{html.escape(r['archivo'])}:{r['linea']}</td>
              <td>
                <div style="font-size: 0.8rem; font-weight: 500;">{html.escape(r['semgrep_regla'][:120])}...</div>
                <div style="margin-top: 4px;">
                  <span class="badge badge-na code-font">{html.escape(r['cwe'])}</span>
                  <span class="badge badge-na" style="font-size: 0.7rem;">{html.escape(r['owasp'][:40])}</span>
                </div>
              </td>
              <td><span class="badge badge-fn">❌ NO (Código Seguro / Config)</span></td>
              <td>
                {ia_badge}
                <div class="explanation-box">{html.escape(r['agente_explicacion'])}</div>
              </td>
              <td>{res_badge}</td>
            </tr>
"""

    html_content += f"""
          </tbody>
        </table>
      </div>
    </div>

    <!-- TAB 3: GLOBAL COMPARISON -->
    <div id="tab-comparativa" class="tab-content" style="display: none;">
      <div class="comparison-grid">
        <div class="comparison-box">
          <h3>🔍 Semgrep Standalone (SAST Tradicional)</h3>
          <div class="metric-row">
            <span class="metric-name">Vulnerabilidades Reales Detectadas</span>
            <span class="metric-val">{m['semgrep_detectados']} / {m['total_ground_truth']} ({m['semgrep_recall']}%)</span>
          </div>
          <div class="metric-row">
            <span class="metric-name">Falsas Alarmas Generadas (Ruido)</span>
            <span class="metric-val" style="color: var(--accent-amber);">{m['semgrep_total_ruido']} alertas</span>
          </div>
          <div class="metric-row">
            <span class="metric-name">Razón Señal / Ruido</span>
            <span class="metric-val">{m['semgrep_detectados']}:{m['semgrep_total_ruido']} (1 vuln real cada {round(m['semgrep_total_ruido'] / max(1, m['semgrep_detectados']), 1)} alertas)</span>
          </div>
          <div class="metric-row">
            <span class="metric-name">Capacidad de Razonamiento de Contexto</span>
            <span class="metric-val" style="color: var(--accent-red);">No (Solo coincidencia sintáctica)</span>
          </div>
        </div>

        <div class="comparison-box">
          <h3>🤖 Pipeline Híbrido: Semgrep + Taint Tracker + Agente IA</h3>
          <div class="metric-row">
            <span class="metric-name">Verdaderos Positivos Confirmados (TP)</span>
            <span class="metric-val" style="color: var(--accent-green);">{m['agente_tp']}</span>
          </div>
          <div class="metric-row">
            <span class="metric-name">Ruido Eliminado Exitosamente (TN)</span>
            <span class="metric-val" style="color: var(--accent-cyan);">{m['agente_tn']} / {m['semgrep_total_ruido']} ({m['reduccion_ruido_pct']}%)</span>
          </div>
          <div class="metric-row">
            <span class="metric-name">Precisión del Sistema (Precision)</span>
            <span class="metric-val" style="color: var(--accent-cyan);">{m['precision']}%</span>
          </div>
          <div class="metric-row">
            <span class="metric-name">F1-Score</span>
            <span class="metric-val" style="color: var(--accent-green);">{m['f1_score']}%</span>
          </div>
        </div>
      </div>
    </div>

    <footer>
      Generado automáticamente por el Pipeline SAST Inteligente &bull; Antigravity IDE &bull; Deepmind Team
    </footer>
  </div>

  <script>
    function cambiarPestana(idTab) {{
      document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.getElementById(idTab).style.display = 'block';
      event.target.classList.add('active');
    }}

    function filtrarTablas() {{
      const query = document.getElementById('buscador').value.toLowerCase().trim();
      
      document.querySelectorAll('#tabla-gt tbody tr').forEach(row => {{
        const text = row.getAttribute('data-search') ? row.getAttribute('data-search').toLowerCase() : '';
        row.style.display = text.includes(query) ? '' : 'none';
      }});

      document.querySelectorAll('#tabla-ruido tbody tr').forEach(row => {{
        const text = row.getAttribute('data-search') ? row.getAttribute('data-search').toLowerCase() : '';
        row.style.display = text.includes(query) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>
"""

    with open(ruta_salida, "w", encoding="utf-8") as f:
        f.write(html_content)


def generar_reporte_markdown(datos: Dict[str, Any], ruta_salida: str) -> None:
    """Genera un informe completo en formato Markdown listo para GitHub o documentación de tesis."""
    m = datos["metricas"]
    gt_items = datos["ground_truth_matriz"]
    ruido_items = datos["ruido_semgrep_matriz"]

    md = []
    md.append("# 📊 Informe Comparativo de Seguridad: SAST + SCA + Agente IA\n")
    md.append("## Resumen Ejecutivo de Métricas\n")
    md.append(f"| Métrica | Valor | Descripción |")
    md.append(f"| :--- | :---: | :--- |")
    md.append(f"| **Ground Truth (Vulnerabilidades Reales)** | **{m['total_ground_truth']}** | Debilidades intencionales documentadas |")
    md.append(f"| **Detectadas por Semgrep** | **{m['semgrep_detectados']} / {m['total_ground_truth']}** | Recall de Semgrep: {m['semgrep_recall']}% |")
    md.append(f"| **Falsos Positivos de Semgrep (Ruido)** | **{m['semgrep_total_ruido']}** | Alertas en código no vulnerable |")
    md.append(f"| **Verdaderos Positivos Confirmados por IA (TP)** | **{m['agente_tp']}** | Vulnerabilidades reales verificadas |")
    md.append(f"| **Ruido Descartado por IA (TN)** | **{m['agente_tn']}** | Falsas alarmas filtradas con éxito |")
    md.append(f"| **Reducción de Ruido Lograda por IA** | **{m['reduccion_ruido_pct']}%** | Porcentaje de alertas irrelevantes eliminadas |")
    md.append(f"| **Precisión del Agente (Precision)** | **{m['precision']}%** | `TP / (TP + FP)` |")
    md.append(f"| **Sensibilidad Global (Recall)** | **{m['recall']}%** | `TP / Total Ground Truth` |")
    md.append(f"| **F1-Score** | **{m['f1_score']}%** | Balance armónico Precision / Recall |\n")

    md.append("## 1. Matriz de Vulnerabilidades del Ground Truth\n")
    md.append("| ID | Repo | Archivo:Línea | CWE | Semgrep? | Trivy? | Agente IA | Explicación |")
    md.append("| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |")

    for item in gt_items:
        s_icon = "✅ SÍ" if item["detectado_semgrep"] else "❌ NO"
        t_icon = f"✅ {item['trivy_detalle']}" if item["detectado_trivy"] else "⚪ N/A"
        ia_icon = f"🛡️ {item['agente_estado']}" if item["agente_auditado"] else "⚪ NO AUDITADO"
        exp = item["agente_explicacion"].replace("\n", " ").replace("|", "\\|")[:90] + "..."
        md.append(f"| #{item['id']} | `{item['repo']}` | `{item['archivo']}:{item['linea']}` | {item['cwe_id']} | {s_icon} | {t_icon} | {ia_icon} | {exp} |")

    md.append("\n## 2. Matriz de Ruido de Semgrep (Falsos Positivos Descartados vs Confirmados)\n")
    md.append("| Repo | Archivo:Línea | Alerta Semgrep | ¿Era Real? | Respuesta Agente IA | Triage |")
    md.append("| :--- | :--- | :--- | :---: | :---: | :--- |")

    for r in ruido_items[:50]:  # Mostrar los primeros 50 en markdown
        if r["clasificacion"] == "TN":
            triage = "🛡️ TN (Filtrado)"
        elif r["clasificacion"] == "FP":
            triage = "⚠️ FP (Falsa Alarma)"
        else:
            triage = "⚪ Pendiente"
        regla = r["semgrep_regla"].replace("\n", " ").replace("|", "\\|")[:60] + "..."
        md.append(f"| `{r['repo']}` | `{r['archivo']}:{r['linea']}` | {regla} | ❌ NO | **{r['agente_estado']}** | {triage} |")

    if len(ruido_items) > 50:
        md.append(f"\n*(... y {len(ruido_items) - 50} falsos positivos más filtrados en el dashboard HTML completo)*\n")

    with open(ruta_salida, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
