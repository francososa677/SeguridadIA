import requests
import json
import re
import os
from pydantic import BaseModel, Field

# ==============================================================================
# CONFIGURACIÓN DEL ENTORNO Y NGROK
# ==============================================================================

# CONFIG_PATH: Ruta absoluta del archivo de configuración (config.json) en el mismo directorio.
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def obtener_ngrok_url():
    """
    Lee config.json para obtener la URL del túnel ngrok donde corre la API del LLM.
    Si el archivo no existe o falla la lectura, retorna una URL por defecto (fallback).
    """
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                # Retorna el valor de NGROK_URL del JSON; si no existe, usa la URL predeterminada.
                return json.load(f).get("NGROK_URL", "https://jinx-dwindling-gloss.ngrok-free.dev")
        except:
            pass
    return "https://jinx-dwindling-gloss.ngrok-free.dev"

# NGROK_URL: Almacena la URL final resuelta que se usará para realizar las peticiones HTTP al LLM.
NGROK_URL = obtener_ngrok_url()

# ==============================================================================
# PROMPT DEL SISTEMA (INSTRUCCIONES DE AUDITORÍA Y CONSERVADURISMO)
# ==============================================================================

# SYSTEM_PROMPT: Instrucciones detalladas de comportamiento que configuran al LLM para actuar como
# un motor SAST (Análisis Estático) y APR (Reparación Automática). Define las reglas para la
# clasificación de vulnerabilidades según el OWASP Top 10 y estrategias clave para evitar falsos positivos.
SYSTEM_PROMPT = """Sos un agente auditor experto en Análisis Estático de Seguridad de Software (SAST) y Reparación Automática (APR).
Tu tarea es auditar el fragmento de código provisto.

Seguí estos pasos:
1. Análisis de flujo: Localizá entradas no confiables (Sources) y sumideros de ejecución (Sinks).
2. Clasificación: Clasificá la vulnerabilidad según las categorías de OWASP Top 10 (2021) o determiná "Seguro" si no hay vulnerabilidad.
3. Estimación CVSS v3.1: Proporcioná el Base Score (0.0 a 10.0) y su vector base.
4. Reparación: Reescribí la función completa de forma segura manteniendo su funcionalidad original.

Las categorías de OWASP Top 10 válidas para clasificar son:
- A01:2021-Broken Access Control
- A02:2021-Cryptographic Failures
- A03:2021-Injection
- A04:2021-Insecure Design
- A05:2021-Security Misconfiguration
- A06:2021-Vulnerable and Outdated Components
- A07:2021-Identification and Authentication Failures
- A08:2021-Software and Data Integrity Failures
- A09:2021-Security Logging Failures
- A10:2021-Server-Side Request Forgery
- Otros/General (si es vulnerable pero no entra en las categorías anteriores)
- Seguro (si el código no tiene vulnerabilidades)

REGLAS CRÍTICAS PARA EVITAR FALSOS POSITIVOS Y ERRORES DE CLASIFICACIÓN:
1. REGLA DE CONSERVADURISMO: No declares un código como VULNERABLE a menos que exista un camino de ejecución claro, directo y no sanitizado desde una entrada controlada por el usuario (source) hasta una función o instrucción peligrosa (sink).
   - Si se utilizan consultas SQL preparadas (Prepared Statements) o consultas parametrizadas, el código es SEGURO contra SQL Injection. No declares inyección de SQL solo porque aparezcan las palabras clave "select", "insert", "update" o "delete".
   - Si las variables utilizadas en sumideros sensibles son constantes de texto, enteros definidos localmente o provienen de fuentes seguras/estáticas, el código es SEGURO.
   - Si no hay entrada del usuario (ej: una función helper interna que solo opera con datos duros), no asumas que la entrada es controlada por un atacante.

2. CRITERIO PARA "Otros/General":
   - Utilizá "Otros/General" para vulnerabilidades de bajo nivel o de sistema de memoria (como desbordamiento de búfer/buffer overflow, desbordamiento de pila/stack overflow, punteros nulos, memory leaks o problemas de concurrrencia en C/C++) que claramente comprometan la seguridad pero no formen parte del OWASP Top 10 Web estándar.
   - No clasifiques estas vulnerabilidades de sistema bajo "A03:2021-Injection" ni bajo "A08:2021-Software and Data Integrity Failures" a menos que haya una inyección de sintaxis estructurada real (ej: comando de consola u OS command injection).

REGLA ESTRICTA: Respondé EXCLUSIVAMENTE con un JSON válido con esta estructura:
{
  "estado": "VULNERABLE",  // o "SEGURO"
  "owasp_id": "A03",       // ID de la categoría (ej: "A01", "A02", ..., "Otros/General", "Seguro")
  "owasp_categoria": "A03:2021-Injection", // Nombre largo oficial o "Otros/General" o "Seguro"
  "nombre_vulnerabilidad": "Nombre formal", // ej. "SQL Injection" o "Ninguna"
  "cvss_score": 7.5,       // o 0.0 si es seguro
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // o "Ninguno"
  "explicacion": "Explicación técnica concisa",
  "codigo_parchado": "código corregido" // o el mismo código original si es seguro
}"""

# ==============================================================================
# ESQUEMA DE VALIDACIÓN PYDANTIC
# ==============================================================================

class AuditResultModel(BaseModel):
    """
    Modelo Pydantic para validar y estructurar la salida devuelta por el LLM.
    Define de forma estricta los campos requeridos y sus tipos de datos.
    Si la respuesta del LLM no tiene esta estructura exacta, la validación fallará.
    """
    estado: str = Field(description="Debe ser 'VULNERABLE' o 'SEGURO'")
    owasp_id: str = Field(description="ID de la categoría (ej: 'A01', 'A02', ..., 'Otros/General', 'Seguro')")
    owasp_categoria: str = Field(description="Nombre largo oficial de la categoría OWASP o 'Otros/General' o 'Seguro'")
    nombre_vulnerabilidad: str = Field(description="Nombre formal de la vulnerabilidad o 'Ninguna'")
    cvss_score: float = Field(description="Base Score CVSS v3.1 (0.0 a 10.0)")
    cvss_vector: str = Field(description="Vector base CVSS o 'Ninguno'")
    explicacion: str = Field(description="Explicación técnica concisa")
    codigo_parchado: str = Field(description="El código corregido completo o el mismo código original si es seguro")

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
            
        # Si logramos reconstruir satisfactoriamente todos los campos con regex, los retornamos
        required_fields = ["estado", "owasp_id", "owasp_categoria", "nombre_vulnerabilidad", "cvss_score", "cvss_vector", "explicacion", "codigo_parchado"]
        if all(k in resultado_regex for k in required_fields):
            return resultado_regex
    except Exception:
        pass
        
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
    # Cabecera para evitar la pantalla de advertencia intermedia de ngrok
    headers = {"ngrok-skip-browser-warning": "true"}
    
    # Prompt del usuario estructurando el código a analizar
    prompt_usuario = f"Lenguaje: {lenguaje}\n\nCódigo:\n```{lenguaje}\n{codigo}\n```"
    
    # Historial de mensajes inicial (System prompt + código)
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