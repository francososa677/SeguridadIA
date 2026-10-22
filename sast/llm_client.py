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
# PROMPT DEL SISTEMA (OWASP Top 10 + CWE + CVSS v3.1 + APR)
# ==============================================================================

SYSTEM_PROMPT = """Sos un agente auditor senior especializado en Análisis Estático de Seguridad de Software (SAST) y Reparación Automática de Programas (APR), con dominio de estándares formales de la industria (OWASP Top 10:2021, MITRE CWE, CVSS v3.1).

Tu tarea consiste en auditar exhaustivamente el código provisto, determinar si introduce un riesgo de seguridad explotable, clasificarlo con rigor taxonómico y generar una remediación robusta.

---

### METODOLOGÍA DE AUDITORÍA:
1. **Identificación de Flujo:** Rastreá el flujo de datos desde orígenes (Sources) hacia operaciones críticas o sumideros de ejecución (Sinks).
2. **Evaluación de Mitigaciones:** Si existen controles defensivos válidos (validaciones de tipos, listas blancas, consultas preparadas, escape contextual), el código es SEGURO.
3. **Completitud:** Si el fragmento es una interfaz o firma sin llamadas a sumideros, decláralo SEGURO.
4. **Clasificación Estricta:** Si existe una debilidad real, asociala a su categoría fundamental de OWASP Top 10 (2021) o "Otros/General".
5. **Remediación (APR):** Reescribí el código corrigiendo la causa raíz y preservando la funcionalidad.

---

### TAXONOMÍA FORMAL: OWASP TOP 10 (2021):
1. **A01:2021 - Broken Access Control:** Path Traversal (CWE-22), bypass de autorización, CORS permisivo (CWE-942).
2. **A02:2021 - Cryptographic Failures:** Criptografía débil/rota (MD5/SHA1/DES, CWE-327), PRNG predecible (CWE-330, CWE-338), Timing Attacks (CWE-208).
3. **A03:2021 - Injection:** SQLi (CWE-89), OS Command Injection (CWE-78), Code Injection (CWE-94), XSS (CWE-79), CRLF/Header Injection (CWE-113), Format String (CWE-134).
4. **A04:2021 - Insecure Design:** DoS por recursión descontrolada (CWE-674), HTTP Request Smuggling (CWE-444), XML Entity Expansion/Bomb (CWE-776).
5. **A05:2021 - Security Misconfiguration:** Modo debug activo (CWE-215), permisos permisivos (CWE-732), cookie sin HttpOnly (CWE-1004).
6. **A06:2021 - Vulnerable Components / Memory Safety:** Buffer Overflow (CWE-120, CWE-121), Out-of-bounds Read (CWE-125), Double Free (CWE-415), NULL Pointer Dereference (CWE-476).
7. **A07:2021 - Identification and Authentication Failures:** Credenciales hardcodeadas (CWE-798), funciones críticas sin autenticar (CWE-306).
8. **A08:2021 - Software and Data Integrity Failures:** Deserialización insegura (pickle.loads, CWE-502), bypass de firma (algoritmo 'none', CWE-347).
9. **A09:2021 - Security Logging and Monitoring Failures:** Log Injection (CWE-117), secretos/tokens en logs (CWE-532).
10. **A10:2021 - Server-Side Request Forgery (SSRF):** Peticiones remotas sin validar rangos privados/loopback (CWE-918).
11. **Otros/General:** Otras debilidades no cubiertas por las categorías anteriores.
12. **Seguro:** Flujo sin caminos de explotación viables.

---

### FORMATO OBLIGATORIO DE RESPUESTA:
Respondé ÚNICAMENTE con un bloque JSON bien estructurado que cumpla con el siguiente esquema:
{
  "estado": "VULNERABLE", // o "SEGURO"
  "owasp_id": "A01",      // Uno de: "A01"..."A10", "Otros/General", o "Seguro"
  "owasp_categoria": "A01:2021-Broken Access Control", // Nombre estándar o "Seguro"
  "nombre_vulnerabilidad": "Nombre formal (ej: Path Traversal, SQL Injection, Ninguna)",
  "cvss_score": 7.5,      // Número de 0.0 a 10.0 (0.0 si es Seguro)
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // Vector CVSS v3.1 o "Ninguno"
  "explicacion": "Análisis técnico claro del flujo source-sink o justificación de por qué es seguro.",
  "codigo_parchado": "Código completo seguro preservando la funcionalidad"
}
"""

# ==============================================================================
# MODELO PYDANTIC DE SALIDA
# ==============================================================================

class AuditResultModel(BaseModel):
    estado: str = Field(description="'VULNERABLE' o 'SEGURO'")
    owasp_id: str = Field(description="ID de la categoría (ej: 'A01'...'A10', 'Otros/General', 'Seguro')")
    owasp_categoria: str = Field(description="Nombre largo oficial de la categoría OWASP o 'Seguro'")
    nombre_vulnerabilidad: str = Field(description="Nombre formal de la vulnerabilidad o 'Ninguna'")
    cvss_score: float = Field(description="Puntaje CVSS v3.1 de 0.0 a 10.0")
    cvss_vector: str = Field(description="Vector CVSS v3.1 o 'Ninguno'")
    explicacion: str = Field(description="Explicación técnica")
    codigo_parchado: str = Field(description="Código corregido o el mismo original si es seguro")


# ==============================================================================
# PARSEO ROBUSTO DE JSON Y REPARACIÓN
# ==============================================================================

def reparar_truncamiento(text: str) -> str:
    """Repara comillas o llaves abiertas si el modelo truncó la generación."""
    text = text.strip()
    if text.endswith('}'):
        return text

    triple_double_count = text.count('"""')
    triple_single_count = text.count("'''")
    if triple_double_count % 2 == 1:
        text += '\n"""\n}'
    elif triple_single_count % 2 == 1:
        text += "\n'''\n}"
    else:
        double_count = text.count('"')
        if double_count % 2 == 1:
            text += '\n"}'
        elif text.count('{') > text.count('}'):
            text += '\n}'
    return text


def extraer_json_robusto(text: str) -> dict:
    """Extrae y limpia JSON de la respuesta del LLM con múltiples fallbacks."""
    text = reparar_truncamiento(text).strip()

    def replacer_triple(match):
        key = match.group(1)
        content = match.group(3).replace('\\', '\\\\').replace('"', '\\"')
        return f'{key}: "{content}"'

    def replacer_simple(match):
        key = match.group(1)
        content = match.group(2).replace('\\', '\\\\').replace('"', '\\"')
        return f'{key}: "{content}"'

    if '"""' in text or "'''" in text:
        text = re.sub(r'("[a-zA-Z0-9_]+"):\s*("""|\'\'\')(.*?)\2(?=\s*[,}])', replacer_triple, text, flags=re.DOTALL)

    text = re.sub(r'("codigo_parchado"):\s*"(.*)"(?=\s*\})', replacer_simple, text, flags=re.DOTALL)
    text = re.sub(r'("explicacion"):\s*"(.*)"(?=\s*,\s*"codigo_parchado")', replacer_simple, text, flags=re.DOTALL)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    try:
        return json.loads(text, strict=False)
    except json.JSONDecodeError:
        pass

    cleaned = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    cleaned = re.sub(r"^```\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned).strip()

    try:
        return json.loads(cleaned, strict=False)
    except json.JSONDecodeError:
        pass

    start_idx = cleaned.find('{')
    end_idx = cleaned.rfind('}')
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        try:
            return json.loads(cleaned[start_idx:end_idx+1], strict=False)
        except json.JSONDecodeError:
            pass

    # Fallback con Regex
    try:
        res: Dict[str, Any] = {}
        for f in ["estado", "owasp_id", "owasp_categoria", "nombre_vulnerabilidad", "cvss_vector"]:
            m = re.search(rf'"{f}"\s*:\s*"(.*?)"(?=\s*[,}}])', cleaned, flags=re.DOTALL)
            if m:
                res[f] = m.group(1)

        score_m = re.search(r'"cvss_score"\s*:\s*([0-9.]+)', cleaned)
        res["cvss_score"] = float(score_m.group(1)) if score_m else 0.0

        exp_m = re.search(r'"explicacion"\s*:\s*"(.*?)"(?=\s*,\s*"codigo_parchado")', cleaned, flags=re.DOTALL)
        res["explicacion"] = exp_m.group(1) if exp_m else "Analizado por SAST"

        cp_m = re.search(r'"codigo_parchado"\s*:\s*(.*)', cleaned, flags=re.DOTALL)
        if cp_m:
            c_val = cp_m.group(1).strip().rstrip('}').strip().strip('"').strip("'")
            res["codigo_parchado"] = c_val
        else:
            res["codigo_parchado"] = ""

        required = ["estado", "owasp_id", "owasp_categoria", "nombre_vulnerabilidad", "cvss_score", "cvss_vector", "explicacion", "codigo_parchado"]
        if all(k in res for k in required):
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
2. Si es seguro, respondé con estado "SEGURO", cvss_score 0.0 y explicá por qué no es explotable.
3. Si es vulnerable, clasificá formalmente la taxonomía OWASP/CWE, calculá el CVSS v3.1 y generá el código parchado completo preservando la funcionalidad.
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
