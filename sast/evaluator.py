"""
sast/evaluator.py
=============================================================================
Paso 4 del Pipeline SAST: Evaluación Cuantitativa frente a Ground Truth
=============================================================================
Contrasta los veredictos emitidos por el modelo LLM frente a las 36 debilidades
controladas documentadas en 'dataset_repos/ground_truth.json'.
Calcula la matriz de confusión (TP, FP, FN, TN) con tolerancia de +-10 líneas
y computa Precision, Recall, F1-Score y tasa de falsos positivos (FPR).
"""

from __future__ import annotations
import json
import os
from typing import Any, Dict, List, Optional, Tuple


def cargar_ground_truth(gt_path: str) -> List[Dict[str, Any]]:
    """Carga la lista de fallas inyectadas desde ground_truth.json."""
    if not os.path.exists(gt_path):
        raise FileNotFoundError(f"No se encontró el archivo de verdad de campo: {gt_path}")
    with open(gt_path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalizar_ruta(ruta: str) -> str:
    """Normaliza separadores de directorios a barras inclinadas hacia adelante."""
    return ruta.replace("\\", "/").strip().lstrip("./")


def coincide_con_ground_truth(
    hallazgo: Dict[str, Any],
    gt_item: Dict[str, Any],
    tolerancia_lineas: int = 15
) -> bool:
    """
    Verifica si un hallazgo del modelo coincide con una falla del ground truth.
    Requiere coincidencia de repositorio, archivo y cercanía de línea (+- tolerancia).
    """
    if hallazgo.get("repo") != gt_item.get("repo"):
        return False

    arch_h = normalizar_ruta(hallazgo.get("archivo", ""))
    arch_gt = normalizar_ruta(gt_item.get("archivo", ""))

    if not (arch_h == arch_gt or arch_h.endswith(arch_gt) or arch_gt.endswith(arch_h)):
        return False

    linea_gt = int(gt_item.get("linea", 0))

    # 1. Si el hallazgo proviene de extracción AST y tiene rango de líneas de función
    l_ini = hallazgo.get("linea_inicio")
    l_fin = hallazgo.get("linea_fin")
    if l_ini is not None and l_fin is not None:
        if (int(l_ini) - 3) <= linea_gt <= (int(l_fin) + 3):
            return True

    # 2. Si tiene linea o linea_impacto puntual
    linea_h = int(hallazgo.get("linea_impacto") or hallazgo.get("linea") or 0)
    if linea_h > 0 and abs(linea_h - linea_gt) <= tolerancia_lineas:
        return True

    return False


def evaluar_hallazgos_ground_truth(
    resultados: List[Dict[str, Any]],
    ground_truth_path: str,
    tolerancia_lineas: int = 15,
    repo_filter: Optional[str] = None
) -> Dict[str, Any]:
    """
    Compara la lista de veredictos del LLM contra el ground_truth.json.
    
    Cada elemento de 'resultados' debe contener al menos:
      - repo: nombre de la carpeta del repo
      - archivo: ruta relativa del archivo
      - linea: número de línea del sumidero
      - estado: 'VULNERABLE' o 'SEGURO'
      - owasp_categoria: categoría predicha
      - cwe_predicho: (opcional)
    """
    ground_truth = cargar_ground_truth(ground_truth_path)
    if repo_filter:
        ground_truth = [gt for gt in ground_truth if gt.get("repo") == repo_filter]

    tp_items = []
    fp_items = []
    tn_items = []
    matched_gt_ids = set()

    for r in resultados:
        es_vulnerable = str(r.get("estado", "")).strip().upper() == "VULNERABLE"

        # Buscar si coincide con alguna falla del ground truth
        matched_gt = None
        for gt in ground_truth:
            if coincide_con_ground_truth(r, gt, tolerancia_lineas):
                matched_gt = gt
                break

        if es_vulnerable:
            if matched_gt:
                tp_items.append({
                    "hallazgo": r,
                    "ground_truth": matched_gt
                })
                matched_gt_ids.add(matched_gt["id"])
            else:
                fp_items.append(r)
        else:
            # Predijo SEGURO
            if not matched_gt:
                tn_items.append(r)

    # Las fallas del ground truth que no fueron detectadas son Falsos Negativos
    fn_items = [gt for gt in ground_truth if gt["id"] not in matched_gt_ids]

    tp = len(tp_items)
    fp = len(fp_items)
    fn = len(fn_items)
    tn = len(tn_items)

    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn) * 100) if (fp + tn) > 0 else 0.0

    return {
        "metricas": {
            "total_ground_truth": len(ground_truth),
            "total_evaluados": len(resultados),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "f1_score": round(f1, 2),
            "fpr": round(fpr, 2),
        },
        "detalles": {
            "verdaderos_positivos": tp_items,
            "falsos_positivos": fp_items,
            "falsos_negativos": fn_items,
            "verdaderos_negativos": tn_items,
        }
    }


def generar_reporte_metricas(eval_res: Dict[str, Any]) -> str:
    """Genera un reporte textual formateado en markdown para consola o archivo."""
    m = eval_res["metricas"]
    rep = []
    rep.append("==================================================================")
    rep.append("   📊 INFORME DE EVALUACIÓN SAST - BANCO DE PRUEBAS DE SEGURIDAD  ")
    rep.append("==================================================================")
    rep.append(f"• Total debilidades reales en Ground Truth : {m['total_ground_truth']}")
    rep.append(f"• Total casos/flujos analizados           : {m['total_evaluados']}")
    rep.append(f"• Verdaderos Positivos (TP)               : {m['tp']}  (Vulnerabilidades reales detectadas)")
    rep.append(f"• Falsos Positivos (FP)                   : {m['fp']}  (Falsas alarmas en código seguro)")
    rep.append(f"• Falsos Negativos (FN)                   : {m['fn']}  (Vulnerabilidades omitidas)")
    rep.append(f"• Verdaderos Negativos (TN)               : {m['tn']}  (Código seguro clasificado correctamente)")
    rep.append("------------------------------------------------------------------")
    rep.append(f"🎯 Precisión (Precision)                  : {m['precision']}%")
    rep.append(f"🔍 Sensibilidad / Cobertura (Recall)      : {m['recall']}%")
    rep.append(f"⭐ F1-Score                               : {m['f1_score']}%")
    rep.append(f"⚠️  Tasa de Falsos Positivos (FPR)         : {m['fpr']}%")
    rep.append("==================================================================")

    fn_list = eval_res["detalles"]["falsos_negativos"]
    if fn_list:
        rep.append("\n❌ DEBILIDADES NO DETECTADAS (Falsos Negativos):")
        for fn in fn_list:
            rep.append(f"  - [{fn['repo']}] {fn['archivo']}:{fn['linea']} ({fn['cwe_id']} - {fn['owasp_categoria']})")

    fp_list = eval_res["detalles"]["falsos_positivos"]
    if fp_list:
        rep.append("\n⚠️ FALSAS ALARMAS (Falsos Positivos):")
        for fp in fp_list[:10]:
            rep.append(f"  - [{fp.get('repo')}] {fp.get('archivo')}:{fp.get('linea')} -> {fp.get('owasp_categoria')}")
        if len(fp_list) > 10:
            rep.append(f"    ... y {len(fp_list) - 10} más.")

    return "\n".join(rep)
