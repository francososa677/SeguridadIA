import requests
import json
import re
import os
from typing import Optional
from pydantic import BaseModel, Field

# ==============================================================================
# CONFIGURACIÓN DEL ENTORNO Y NGROK
# ==============================================================================

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def obtener_ngrok_url():
    """
    Lee config.json para obtener la URL del túnel ngrok donde corre la API del LLM.
    Si el archivo no existe o falla la lectura, retorna una URL por defecto (fallback).
    Garantiza remover barras inclinadas al final para evitar errores //chat.
    """
    url = "https://jinx-dwindling-gloss.ngrok-free.dev"
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                url = json.load(f).get("NGROK_URL", url)
        except:
            pass
    return url.strip().rstrip("/")

NGROK_URL = obtener_ngrok_url()

# ==============================================================================
# PROMPT DEL SISTEMA (INSTRUCCIONES DE AUDITORÍA Y CONSERVADURISMO)
# ==============================================================================

SYSTEM_PROMPT = """Sos un auditor de seguridad de código. Tu única tarea es determinar si el siguiente código es VULNERABLE o SEGURO.

Respondé ÚNICAMENTE con un objeto JSON en este formato exacto:
{
  "estado": "VULNERABLE"
}
o
{
  "estado": "SEGURO"
}

No agregues ninguna explicación, ni puntuación CVSS, ni código corregido, ni clasificación OWASP, ni formato markdown adicional. Solo el objeto JSON con el campo "estado"."""

# ==============================================================================
# ESQUEMA DE VALIDACIÓN PYDANTIC
# ==============================================================================

class AuditResultModel(BaseModel):
    """
    Modelo Pydantic para la auditoría minimalista de detección binaria.
    Solo requiere el estado 'VULNERABLE' o 'SEGURO'. El resto de los campos son opcionales con valores predeterminados.
    """
    estado: str = Field(description="Debe ser 'VULNERABLE' o 'SEGURO'")
    owasp_id: Optional[str] = Field(default="No solicitado")
    owasp_categoria: Optional[str] = Field(default="No solicitado")
    nombre_vulnerabilidad: Optional[str] = Field(default="No solicitado")
    cvss_score: Optional[float] = Field(default=0.0)
    cvss_vector: Optional[str] = Field(default="Ninguno")
    explicacion: Optional[str] = Field(default="No solicitada")
    codigo_parchado: Optional[str] = Field(default="")

# ==============================================================================
# FUNCIONES DE REPARACIÓN Y PARSEO DE RESPUESTAS (ROBUSTEZ JSON)
# ==============================================================================

def reparar_truncamiento(text: str) -> str:
    """
    Detecta si la generación del JSON fue físicamente truncada (por ejemplo, porque
    el modelo alcanzó su límite máximo de tokens de salida) y añade el cierre 
    adecuado de comillas, bloques de texto y llaves para evitar un error de parseo JSON.
    """
    text = text.strip()
    # Si ya termina con la llave de cierre de JSON, asumimos que está cerrado y no requiere reparación.
    if text.endswith('}'):
        return text
        
    # Contamos la cantidad de delimitadores de texto multilínea (comillas triples)
    triple_double_count = text.count('"""')
    triple_single_count = text.count("'''")
    
    # Si hay una comilla triple de apertura que no tiene su correspondiente cierre,
    # la cerramos y cerramos el JSON.
    if triple_double_count % 2 == 1:
        text += '\n"""\n}'
    elif triple_single_count % 2 == 1:
        text += "\n'''\n}"
    else:
        # En caso contrario, verificamos las comillas dobles normales.
        double_count = text.count('"')
        if double_count % 2 == 1:
            text += '\n"}'
        else:
            # Si las comillas están balanceadas pero faltan llaves, agregamos la llave de cierre.
            if text.count('{') > text.count('}'):
                text += '\n}'
    return text

def extraer_json_robusto(text: str) -> dict:
    """
    Intenta extraer, limpiar y parsear el JSON de la respuesta del LLM.
    Implementa múltiples capas de fallbacks y correcciones con expresiones regulares 
    para lidiar con imperfecciones comunes del modelo (como salto de líneas no escapados,
    comillas internas sin escapar, bloques de código markdown, etc.).
    """
    # Paso 0: Reparar posibles truncamientos de tokens
    text = reparar_truncamiento(text)
    text = text.strip()
    
    # Replacer para reparar bloques de comillas triples (habituales cuando el LLM escribe código)
    # Convierte: "codigo_parchado": """ mi_codigo """  ===>  "codigo_parchado": "mi_codigo" (escapado)
    def replacer_triple(match):
        key = match.group(1)
        content = match.group(3)
        # Escapamos primero las barras invertidas para no romper secuencias de control en JSON (ej: \n, \t)
        # y luego las comillas dobles internas para no romper el string JSON.
        content_escaped = content.replace('\\', '\\\\').replace('"', '\\"')
        return f'{key}: "{content_escaped}"'
        
    # Replacer para reparar comillas dobles internas dentro de un string de JSON
    def replacer_simple(match):
        key = match.group(1)
        content = match.group(2)
        content_escaped = content.replace('\\', '\\\\').replace('"', '\\"')
        return f'{key}: "{content_escaped}"'

    has_triple_quotes = '"""' in text or "'''" in text
    
    # Aplicar expresiones regulares para corregir comillas triples o dobles mal formadas en los campos de texto
    if has_triple_quotes:
        text = re.sub(r'("[a-zA-Z0-9_]+"):\s*("""|\'\'\')(.*?)\2(?=\s*[,}])', replacer_triple, text, flags=re.DOTALL)
        
    if not has_triple_quotes:
        text = re.sub(r'("codigo_parchado"):\s*"(.*)"(?=\s*\})', replacer_simple, text, flags=re.DOTALL)
        
    text = re.sub(r'("explicacion"):\s*"(.*)"(?=\s*,\s*"codigo_parchado")', replacer_simple, text, flags=re.DOTALL)
    
    # Estrategia 1: Intentar parsear el JSON crudo directamente
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
        
    # Estrategia 2: Intentar parsear con strict=False (tolera tabulaciones y saltos de línea reales dentro de cadenas)
    try:
        return json.loads(text, strict=False)
    except json.JSONDecodeError:
        pass
        
    # Estrategia 3: Limpiar bloques markdown típicos de un LLM como ```json ... ``` y reintentar parsear
    cleaned = text
    cleaned = re.sub(r"^```json\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^```\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    cleaned = cleaned.strip()
    try:
        return json.loads(cleaned, strict=False)
    except json.JSONDecodeError:
        pass
        
    # Estrategia 4: Extraer la subcadena que se encuentra estrictamente entre la primera '{' y la última '}'
    start_idx = cleaned.find('{')
    end_idx = cleaned.rfind('}')
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        json_candidate = cleaned[start_idx:end_idx+1]
        try:
            return json.loads(json_candidate, strict=False)
        except json.JSONDecodeError:
            pass
            
    # Estrategia 5 (Fallback Extremo): Extraer campos uno por uno usando expresiones regulares
    # Útil si el JSON está muy destruido sintácticamente pero los datos requeridos siguen allí.
    try:
        resultado_regex = {}
        
        # Helper interno para extraer el contenido delimitado por comillas de un campo específico
        def get_field_regex(field_name, t):
            pattern = rf'"{field_name}"\s*:\s*"(.*?)"(?=\s*[,}}])'
            m = re.search(pattern, t, flags=re.DOTALL)
            if m:
                return m.group(1)
            return None
            
        # Extraer el valor flotante del CVSS Score
        score_m = re.search(r'"cvss_score"\s*:\s*([0-9.]+)', cleaned)
        resultado_regex["cvss_score"] = float(score_m.group(1)) if score_m else 0.0
        
        # Extraer campos de texto estándar
        for f in ["estado", "owasp_id", "owasp_categoria", "nombre_vulnerabilidad", "cvss_vector"]:
            val = get_field_regex(f, cleaned)
            if val is not None:
                resultado_regex[f] = val
                
        # Extraer la explicación (buscando hasta llegar al inicio de 'codigo_parchado')
        exp_m = re.search(r'"explicacion"\s*:\s*"(.*?)"(?=\s*,\s*"codigo_parchado")', cleaned, flags=re.DOTALL)
        if exp_m:
            resultado_regex["explicacion"] = exp_m.group(1)
        else:
            exp_m_fallback = re.search(r'"explicacion"\s*:\s*(.*?)(?=\s*,\s*"codigo_parchado")', cleaned, flags=re.DOTALL)
            if exp_m_fallback:
                resultado_regex["explicacion"] = exp_m_fallback.group(1).strip().strip('"').strip("'")
                
        # Extraer el código parchado (tomando todo lo que sigue al nombre del campo)
        cp_m = re.search(r'"codigo_parchado"\s*:\s*(.*)', cleaned, flags=re.DOTALL)
        if cp_m:
            cp_content = cp_m.group(1).strip()
            if cp_content.endswith("}"):
                cp_content = cp_content[:-1].strip()
                
            # Limpiar posibles comillas triples o simples que envuelven al código
            if cp_content.startswith('"""') and cp_content.endswith('"""'):
                cp_content = cp_content[3:-3]
            elif cp_content.startswith("'''") and cp_content.endswith("'''"):
                cp_content = cp_content[3:-3]
            elif cp_content.startswith('"') and cp_content.endswith('"'):
                cp_content = cp_content[1:-1]
            elif cp_content.startswith("'") and cp_content.endswith("'"):
                cp_content = cp_content[1:-1]
                
            resultado_regex["codigo_parchado"] = cp_content
            
        # Si logramos extraer al menos 'estado', lo aceptamos para la evaluación minimalista
        if "estado" in resultado_regex:
            return resultado_regex
    except Exception:
        pass

    # Fallback para respuestas minimalistas en texto plano
    text_upper = cleaned.upper()
    if "VULNERABLE" in text_upper and "SEGURO" not in text_upper:
        return {"estado": "VULNERABLE"}
    elif "SEGURO" in text_upper and "VULNERABLE" not in text_upper:
        return {"estado": "SEGURO"}
        
    # Si todo falla, retornamos un diccionario con el indicador de error
    return {"error": "JSON no válido"}

# ==============================================================================
# FUNCIÓN DE LLAMADA PRINCIPAL E ITERACIÓN CON FEEDBACK
# ==============================================================================

def auditar_codigo(codigo: str, lenguaje: str = "python") -> dict:
    """
    Envía una petición POST con el código a auditar al endpoint de chat expuesto en Colab.
    
    Implementa un bucle de reintentos con autorealimentación (feedback loop):
    Si el LLM devuelve una respuesta mal estructurada o JSON corrupto, se le envía de 
    regreso la salida fallida junto con el detalle del error de parseo o validación de Pydantic,
    exigiéndole que lo corrija de forma autónoma.
    """
    endpoint = f"{obtener_ngrok_url()}/chat"
    headers = {"ngrok-skip-browser-warning": "true"}
    
    prompt_usuario = f"Lenguaje: {lenguaje}\n\nCódigo:\n```{lenguaje}\n{codigo}\n```"
    
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_usuario}
    ]
    
    max_reintentos = 3
    for intento in range(max_reintentos):
        payload = {"messages": messages}
        try:
            # Petición HTTP al servidor de chat en Colab
            response = requests.post(endpoint, json=payload, headers=headers, timeout=180)
            response.raise_for_status()
            
            # Obtiene el texto crudo generado por el LLM
            raw_text = response.json().get("response", "")
            
            # 1. Realiza la limpieza sintáctica y parseo del JSON
            resultado = extraer_json_robusto(raw_text)
            
            if "error" not in resultado:
                # 2. Validación semántica y de tipos usando el modelo Pydantic
                try:
                    validated_model = AuditResultModel(**resultado)
                    return validated_model.model_dump()
                except Exception as ve:
                    # Si el JSON es válido pero sus campos no cumplen los requisitos de Pydantic
                    error_feedback = f"Error de estructura/tipos (Pydantic): {str(ve)}"
                    resultado = {"error": error_feedback}
            
            # Bloque de depuración por consola en caso de fallo de parseo o validación
            print("\n" + "!"*40)
            print(f"[DEBUG - FALLO DE PARSEO/VALIDACIÓN] (Intento {intento+1}/{max_reintentos})")
            print(f"Error: {resultado.get('error')}")
            print(f"Texto crudo devuelto por el modelo:\n{raw_text}")
            print("!"*40 + "\n")
            
            # Si aún nos quedan intentos disponibles, cargamos el error al historial de chat
            # para pedirle una autocorrección al modelo.
            if intento < max_reintentos - 1:
                # El servidor del modelo (por ejemplo, en Kaggle/Colab) puede validar estrictamente
                # que los roles de los mensajes sean exclusivamente 'user' o 'system', rechazando 'assistant'.
                # Por lo tanto, enviamos tanto la respuesta fallida previa como las instrucciones
                # combinadas en un único mensaje con rol 'user'.
                feedback_prompt = (
                    f"Tu respuesta anterior fue:\n{raw_text}\n\n"
                    "Esta respuesta anterior no era un JSON válido o no respetaba el esquema requerido por la validación de Pydantic.\n"
                    f"Detalle del error: {resultado.get('error')}\n\n"
                    "Por favor, corregí este error. Respondé ÚNICAMENTE con el bloque JSON completo, limpio y corregido, respetando estrictamente el esquema."
                )
                messages.append({"role": "user", "content": feedback_prompt})
                print(f"🔄 Reintentando auditoría enviando el error al modelo (Feedback Loop)...")
            else:
                # Si se agotaron los intentos y persiste el error, retorna lo que haya con la respuesta cruda.
                resultado["raw"] = raw_text
                return resultado
                
        except requests.exceptions.RequestException as e:
            print(f"\n[DEBUG - ERROR DE RED / HTTP] (Intento {intento+1}/{max_reintentos}): {str(e)}\n")
            if intento == max_reintentos - 1:
                return {"error": f"Falla de conexión: {str(e)}"}

# ==============================================================================
# PRUEBA DE HUMO (SMOKE TEST)
# ==============================================================================
if __name__ == "__main__":
    # Código vulnerable a SQL Injection para validar localmente el script
    codigo_prueba = """
def get_user_data(db, user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query).fetchall()
"""
    print("Enviando código de prueba a Colab...")
    resultado = auditar_codigo(codigo_prueba)
    print(json.dumps(resultado, indent=2, ensure_ascii=False))