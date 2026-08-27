# LLM SAST & Automated Program Repair (APR)

Investigación y desarrollo de un agente basado en Modelos de Lenguaje compactos ($\le$ 14B) para **Análisis Estático de Seguridad de Software (SAST)**, estimación de impacto (**CVSS**) y **Reparación Automática de Vulnerabilidades (APR)**.

---

## 🎯 Objetivos del Proyecto

1. **Detección y Clasificación:** Identificar debilidades de código alineadas a **OWASP Top 10** y mapeadas al estándar **MITRE CWE** (ej. `CWE-89`, `CWE-79`, `CWE-22`, `CWE-798`).
2. **Estimación de Riesgo:** Iniciar vectores de ataque y calcular el puntaje base **CVSS v3.1** de forma automática.
3. **Reparación Automática (Patching):** Generar parches de código seguro y funcional manteniendo la lógica original.
4. **Ejecución Eficiente:** Evaluar modelos locales (como `Qwen2.5-Coder-7B`) en entornos accesibles (GPU T4) con salidas JSON estructuradas.

---

## 📊 Datasets y Benchmarks

Para el desarrollo y la evaluación formal del sistema se utilizan dos conjuntos de datos estructurados en formato CSV:

| Archivo | Rol en el Proyecto | Fuente | Referencia |
| :--- | :--- | :--- | :--- |
| `dev_benchmark.csv` | **Desarrollo y Calibración:** Ajuste de prompts, pruebas locales y validación de esquemas JSON. | [`s2e-lab/SecurityEval`](https://huggingface.co/datasets/s2e-lab/SecurityEval) | S2E Lab / Univ. of Notre Dame (2022) |
| `test_benchmark.csv` | **Evaluación Final:** Medición ciega de métricas (Precisión, Recall, MAE CVSS). | [`walledai/CyberSecEval`](https://huggingface.co/datasets/walledai/CyberSecEval) | Meta AI / Purple Llama (2023) |

### Estructura de los datos
Los archivos contienen las columnas: `id`, `cwe_id`, `lenguaje`, `codigo` y `es_vulnerable` (Ground Truth).

---

## 🏗️ Arquitectura y Flujo

```text
[ Código Fuente / Dataset ]
            │
            ▼
[ Agente SAST (Qwen2.5-Coder-7B) ] ──► (Inferencia determinista T=0.0)
            │
            ├──► Detección de Vulnerabilidad (VULNERABLE / SEGURO)
            ├──► Clasificación MITRE CWE
            ├──► Vector y Puntuación Base CVSS v3.1
            └──► Parche de Código Seguro (Diff / APR)