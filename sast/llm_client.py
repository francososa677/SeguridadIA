"""
sast/llm_client.py
=============================================================================
Paso 3 del Pipeline SAST: Orquestación e Inferencia con el Modelo LLM
=============================================================================
Gestiona la comunicación HTTP con el servidor remoto (Kaggle/Colab) a través del
túnel ngrok, formateo de prompts taxonómicos OWASP/CWE/CVSS, validación de esquemas
con Pydantic y bucle de autocorrección (Feedback Loop) ante respuestas defectuosas.
"""

from __future__ import annotations
import json
import os
import re
import time
from typing import Any, Dict, Optional
import requests
from pydantic import BaseModel, Field

# ==============================================================================
# CONFIGURACIÓN DEL ENTORNO Y TÚNEL NGROK
# ==============================================================================

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")


def obtener_ngrok_url() -> str:
    """Obtiene la URL del túnel ngrok desde variables de entorno o config.json."""
    if "NGROK_URL" in os.environ and os.environ["NGROK_URL"].strip():
        return os.environ["NGROK_URL"].strip()

    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                url = data.get("NGROK_URL", "").strip()
                if url:
                    return url
        except Exception:
            pass

    return "https://transmarginally-unrebuffed-else.ngrok-free.dev"


def ping_server(url: Optional[str] = None) -> Dict[str, Any]:
    """Comprueba la conectividad con el endpoint del servidor LLM."""
    target_url = url or obtener_ngrok_url()
    headers = {"ngrok-skip-browser-warning": "true"}
    start = time.time()
    try:
        res = requests.get(target_url, headers=headers, timeout=10)
        elapsed = round(time.time() - start, 2)
        return {
            "ok": res.status_code == 200,
            "status_code": res.status_code,
            "latency_seconds": elapsed,
            "url": target_url,
            "response": res.text[:200]
        }
    except requests.exceptions.Timeout:
        return {
            "ok": False,
            "error": "Timeout (Tiempo de espera agotado al conectar)",
            "url": target_url
        }
    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "url": target_url
        }


# ==============================================================================
# PROMPT DEL SISTEMA MINIMALISTA (TRIAGE DE VULNERABILIDAD: VULNERABLE / SEGURO)
# ==============================================================================

SYSTEM_PROMPT = """Sos un auditor senior de seguridad de código (SAST).
Tu única función es analizar el fragmento de código provisto y su contexto de invocación para determinar si existe una vulnerabilidad real y explotable o si se trata de un falso positivo.

Criterios de decisión:
- "VULNERABLE": Si el flujo de datos no está sanitizado, la entrada es controlada por el usuario o existe un camino de explotación comprobable.
- "SEGURO": Si el código tiene defensas adecuadas, la entrada es fija/constante, o la alerta es un falso positivo.

Responde ÚNICAMENTE con un objeto JSON válido con la siguiente estructura:
{
  "estado": "VULNERABLE", // o "SEGURO"
  "explicacion": "Explicación técnica concisa en 1 o 2 oraciones justificando tu veredicto."
}
"""

TAINT_AUDIT_SYSTEM_PROMPT = """Sos un auditor senior de seguridad de código y análisis de flujo de datos (Taint Analysis).
Tu tarea es auditar funciones individuales de código fuente para determinar si contienen vulnerabilidades de seguridad explotables (Ablation Study: Pure LLM).

Debes realizar un análisis de Taint en 3 pasos:
1. FUENTES (Sources): ¿La función recibe argumentos no confiables, variables de entorno, entradas de red o lecturas de archivos?
2. FLUJO Y SANITIZACIÓN: ¿Los datos fluyen hacia operaciones críticas sin validación sintáctica, sanitización o control de tipos/límites?
3. SUMIDEROS (Sinks): ¿Llegan a operaciones sensibles (ej: inyección de comandos o SQL, ejecución de código arbitrario eval/exec, deserialización insegura pickle, path traversal, desbordamiento de búfer, SSRF, generación débil de tokens criptográficos)?

Criterios de decisión:
- "VULNERABLE": Si existe un camino de explotación claro y no mitigado desde los argumentos/entradas hacia un sumidero crítico.
- "SEGURO": Si el código tiene defensas suficientes, la función es puramente auxiliar o no existe riesgo de explotación.

Responde ÚNICAMENTE con un objeto JSON válido con la siguiente estructura:
{
  "estado": "VULNERABLE", // o "SEGURO"
  "cwe_id": "CWE-XX",     // Identificador CWE estimado (o "N/A" si es seguro)
  "owasp_categoria": "A0X:2021-Nombre", // Categoría OWASP estimada (o "N/A")
  "linea_impacto": 44,    // Número de línea donde ocurre el sink dentro del archivo (o null)
  "explicacion": "Explicación técnica concisa en 1 o 2 oraciones justificando tu veredicto."
}
"""

# ==============================================================================
# MODELO PYDANTIC DE SALIDA
# ==============================================================================

class AuditResultModel(BaseModel):
    estado: str = Field(description="'VULNERABLE' o 'SEGURO'")
    explicacion: str = Field(default="", description="Breve explicación técnica")
    cwe_id: Optional[str] = Field(default="N/A", description="ID CWE")
    owasp_categoria: Optional[str] = Field(default="N/A", description="Categoría OWASP")
    linea_impacto: Optional[int] = Field(default=None, description="Línea donde ocurre el sink")
    codigo_parchado: Optional[str] = Field(default="", description="Código corregido opcional")
    owasp_id: Optional[str] = Field(default="N/A", description="ID OWASP")
    cvss_score: Optional[float] = Field(default=0.0, description="Puntaje CVSS")
    cvss_vector: Optional[str] = Field(default="N/A", description="Vector CVSS")


# ==============================================================================
# PARSEO ROBUSTO DE JSON Y REPARACIÓN
# ==============================================================================

def reparar_truncamiento(text: str) -> str:
    """Repara comillas o llaves abiertas si el modelo truncó la generación."""
    text = text.strip()
    if text.endswith('}'):
        return text

    if text.count('"') % 2 == 1:
        text += '"'
    if text.count('{') > text.count('}'):
        text += '}'
    return text


def extraer_json_robusto(text: str) -> dict:
    """Extrae y limpia JSON de la respuesta del LLM con múltiples fallbacks."""
    text = reparar_truncamiento(text).strip()

    # Intento 1: Parseo directo
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Intento 2: Limpieza de bloques markdown ```json ... ```
    cleaned = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    cleaned = re.sub(r"^```\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()

    try:
        return json.loads(cleaned, strict=False)
    except json.JSONDecodeError:
        pass

    # Intento 3: Buscar la subcadena entre la primera { y la última }
    start_idx = cleaned.find('{')
    end_idx = cleaned.rfind('}')
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        try:
            return json.loads(cleaned[start_idx:end_idx+1], strict=False)
        except json.JSONDecodeError:
            pass

    # Intento 4: Fallback con expresiones regulares flexibles
    try:
        res: Dict[str, Any] = {}
        # Detección del estado
        m_estado = re.search(r'"estado"\s*:\s*"(VULNERABLE|SEGURO)"', cleaned, flags=re.IGNORECASE)
        if m_estado:
            res["estado"] = m_estado.group(1).upper()
        elif re.search(r'\bVULNERABLE\b', cleaned, flags=re.IGNORECASE):
            res["estado"] = "VULNERABLE"
        elif re.search(r'\bSEGURO\b', cleaned, flags=re.IGNORECASE):
            res["estado"] = "SEGURO"

        # Detección de la explicación
        m_exp = re.search(r'"explicacion"\s*:\s*"(.*?)"(?=\s*[,}\n])', cleaned, flags=re.DOTALL)
        if m_exp:
            res["explicacion"] = m_exp.group(1).strip()
        else:
            res["explicacion"] = "Analizado por el agente SAST"

        # Detección de CWE, OWASP y línea de impacto
        m_cwe = re.search(r'"cwe_id"\s*:\s*"(.*?)"', cleaned, flags=re.IGNORECASE)
        res["cwe_id"] = m_cwe.group(1).strip() if m_cwe else "N/A"

        m_owasp = re.search(r'"owasp_categoria"\s*:\s*"(.*?)"', cleaned, flags=re.IGNORECASE)
        res["owasp_categoria"] = m_owasp.group(1).strip() if m_owasp else "N/A"

        m_lin = re.search(r'"linea_impacto"\s*:\s*(\d+)', cleaned)
        res["linea_impacto"] = int(m_lin.group(1)) if m_lin else None

        res["codigo_parchado"] = ""

        if "estado" in res:
            return res
    except Exception:
        pass

    return {"error": "JSON no válido"}


# ==============================================================================
# AUDITORÍA DIRECTA DE CÓDIGO Y DE PAQUETES DE CONTEXTO
# ==============================================================================

def invocar_llm_con_reintentos(messages: list, max_reintentos: int = 3) -> dict:
    """Envía mensajes al LLM con feedback loop autónomo en caso de formato erróneo."""
    endpoint = f"{obtener_ngrok_url()}/chat"
    headers = {"ngrok-skip-browser-warning": "true"}

    for intento in range(max_reintentos):
        try:
            resp = requests.post(endpoint, json={"messages": messages}, headers=headers, timeout=180)
            resp.raise_for_status()
            raw_text = resp.json().get("response", "")

            parsed = extraer_json_robusto(raw_text)
            if "error" not in parsed:
                try:
                    valid_obj = AuditResultModel(**parsed)
                    return valid_obj.model_dump()
                except Exception as ve:
                    parsed = {"error": f"Error de esquema Pydantic: {str(ve)}"}

            if intento < max_reintentos - 1:
                feedback = (
                    f"Tu respuesta previa no cumplió con el formato JSON estricto requerido:\n{raw_text}\n\n"
                    f"Error específico: {parsed.get('error')}\n"
                    "Por favor corregilo y devolvé ÚNICAMENTE el bloque JSON válido."
                )
                messages.append({"role": "user", "content": feedback})
            else:
                parsed["raw"] = raw_text
                return parsed

        except requests.exceptions.RequestException as e:
            if intento == max_reintentos - 1:
                return {"error": f"Error de conexión con el LLM: {str(e)}"}
            time.sleep(1)

    return {"error": "Se agotaron los reintentos"}


def auditar_codigo(codigo: str, lenguaje: str = "python") -> dict:
    """Audita un fragmento de código individual."""
    prompt_usuario = f"Lenguaje: {lenguaje}\n\nCódigo a auditar:\n```{lenguaje}\n{codigo}\n```"
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_usuario}
    ]
    return invocar_llm_con_reintentos(messages)


def auditar_paquete_contexto(paquete: dict) -> dict:
    """Audita un paquete de contexto generado por el Taint Tracker (flujo inter-archivo)."""
    repo = paquete.get("repo", "desconocido")
    categoria = paquete.get("categoria", "")
    sumidero = paquete.get("funcion_sumidero", "")
    variable = paquete.get("variable_rastreada", "")
    tipo_flujo = paquete.get("tipo_flujo", "")
    ruta_flujo = paquete.get("ruta_flujo", "")

    origen = paquete.get("modulo_origen_fuente", {})
    destino = paquete.get("modulo_destino_sumidero", {})

    prompt_usuario = f"""### CONTEXTO DE AUDITORÍA SAST INTER-MÓDULO:
- **Repositorio:** {repo}
- **Categoría Preliminar:** {categoria}
- **Sumidero Detectado:** {sumidero}
- **Variable Rastreada:** {variable}
- **Tipo de Flujo:** {tipo_flujo}
- **Ruta del Flujo:** {ruta_flujo}

---
#### MÓDULO ORIGEN / FUENTE (Archivo: {origen.get('archivo')}, Línea: {origen.get('linea')}):
```
{origen.get('fragmento_codigo', '')}
```

---
#### MÓDULO DESTINO / SUMIDERO (Archivo: {destino.get('archivo')}, Línea: {destino.get('linea')}):
```
{destino.get('fragmento_codigo', '')}
```

Determina si existe un flujo vulnerable explotable desde el origen hacia el sumidero y emite el veredicto formal JSON.
"""

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_usuario}
    ]
    return invocar_llm_con_reintentos(messages)


def auditar_hallazgo_semgrep(hallazgo: dict) -> dict:
    """Audita un hallazgo reportado por Semgrep para descartar falsos positivos y generar APR."""
    archivo = hallazgo.get("archivo", "archivo_desconocido")
    linea = hallazgo.get("linea", 1)
    mensaje = hallazgo.get("mensaje", "")
    cwe = hallazgo.get("cwe", "Desconocido")
    owasp = hallazgo.get("owasp", "Desconocido")
    codigo = hallazgo.get("fragmento_codigo", "")

    # Extraer contexto de flujo inter-archivo si fue analizado por el Taint Tracker
    flujo_extra = ""
    flujo = hallazgo.get("flujo_inter_archivo")
    if flujo:
        tipo_flujo = flujo.get("tipo_flujo", "INTRA_FILE_FLOW")
        ruta_flujo = flujo.get("ruta_flujo", "")
        origen = flujo.get("origen_principal")
        
        flujo_extra = f"""
---
#### ANÁLISIS DE FLUJO INTER-ARCHIVO (TAINT TRACKER):
- **Tipo de Flujo:** {tipo_flujo}
- **Ruta del Flujo:** {ruta_flujo}
"""
        if origen:
            flujo_extra += f"""- **Módulo Invocador (Call-Site / Origen):** {origen.get('archivo_origen')}:{origen.get('linea_origen')}
```
{origen.get('snippet_origen')}
```
"""

    prompt_usuario = f"""### ALERTA DE SEGURIDAD ESTÁTICA DETECTADA (SEMGREP):
- **Archivo:** {archivo} (Línea {linea})
- **Regla / Mensaje Semgrep:** {mensaje}
- **CWE Sugerido:** {cwe}
- **OWASP Sugerido:** {owasp}{flujo_extra}

---
#### FRAGMENTO DE CÓDIGO DEL SUMIDERO (SINK):
```
{codigo}
```

Analizá el código en su contexto:
1. Determiná si es una vulnerabilidad REAL y explotable o si se trata de un FALSO POSITIVO (por ejemplo si la entrada es constante, está sanitizada o no es controlable por el usuario).
2. Respondé en formato JSON con la clave "estado" ("VULNERABLE" o "SEGURO") y una breve "explicacion" técnica.
"""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_usuario}
    ]
    return invocar_llm_con_reintentos(messages)


def auditar_hallazgo_trivy(hallazgo: dict) -> dict:
    """Explica el impacto de un CVE de dependencia de Trivy y genera la recomendación de parche."""
    manifiesto = hallazgo.get("manifiesto", "")
    paquete = hallazgo.get("paquete", "")
    v_actual = hallazgo.get("version_instalada", "")
    v_fix = hallazgo.get("version_corregida", "")
    cve = hallazgo.get("cve_id", "")
    sev = hallazgo.get("severidad", "")
    titulo = hallazgo.get("titulo", "")
    desc = hallazgo.get("descripcion", "")

    prompt_usuario = f"""### VULNERABILIDAD EN DEPENDENCIA DETECTADA (TRIVY - SCA):
- **Manifiesto:** {manifiesto}
- **Librería / Paquete:** {paquete}
- **Versión Instalada:** {v_actual}
- **Versión con Parche (Fix):** {v_fix}
- **Identificador CVE:** {cve}
- **Severidad Oficial:** {sev}
- **Título / Resumen:** {titulo}
- **Descripción:** {desc}

Explicá en español conciso el impacto técnico de este CVE para la aplicación, qué tipo de ataque permitiría y proporcioná el cambio exacto que debe realizarse en el manifiesto ({manifiesto}) o el comando para actualizar la dependencia de forma segura.
"""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_usuario}
    ]
    return invocar_llm_con_reintentos(messages)


def auditar_funcion_ast(funcion_data: dict) -> dict:
    """
    Audita una función individual troceada por el extractor AST para el Ablation Study (Pure LLM).
    Aplica Taint Analysis guiado: Sources -> Flow/Sanitization -> Sinks.
    """
    repo = funcion_data.get("repo", "desconocido")
    archivo = funcion_data.get("archivo", "")
    nombre = funcion_data.get("nombre_funcion", "")
    l_ini = funcion_data.get("linea_inicio", 1)
    l_fin = funcion_data.get("linea_fin", 1)
    lenguaje = funcion_data.get("lenguaje", "python")
    codigo = funcion_data.get("codigo", "")

    prompt_usuario = f"""### AUDITORÍA ESTÁTICA BASADA EN AST (FUNCIÓN INDIVIDUAL):
- **Repositorio:** {repo}
- **Archivo:** {archivo} (Líneas {l_ini} a {l_fin})
- **Función / Método:** `{nombre}`
- **Lenguaje:** {lenguaje}

---
#### CÓDIGO FUENTE DE LA FUNCIÓN:
```{lenguaje}
{codigo}
```

Realizá el análisis guiado de Taint (Fuentes -> Flujo -> Sumidero):
1. ¿Los parámetros o entradas de la función pueden ser manipulados por un atacante (Sources)?
2. ¿Fluyen hacia operaciones críticas (Sinks) sin validación estricta ni sanitización?
3. Emití tu veredicto en formato JSON estricto con estado ("VULNERABLE" o "SEGURO"), cwe_id, owasp_categoria, linea_impacto y explicacion.
"""
    messages = [
        {"role": "system", "content": TAINT_AUDIT_SYSTEM_PROMPT},
        {"role": "user", "content": prompt_usuario}
    ]
    return invocar_llm_con_reintentos(messages)

