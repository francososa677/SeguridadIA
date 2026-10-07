import os
import json

base_dir = r"c:\Users\Franco Sosa\Documents\SeguridadIA\dataset_repos"

# Definición de casos de prueba con código natural (SIN comentarios delatores)
testbed_cases = [
    # ==================== 1. Python: pyjwt ====================
    {
        "repo": "python_pyjwt",
        "relative_file": "jwt/api_jwk.py",
        "lookup_signature": "def load_key_from_disk(",
        "code_snippet": '''
    def load_key_from_disk(self, base_folder: str, relative_path: str) -> str:
        target_path = os.path.join(base_folder, relative_path)
        with open(target_path, "r", encoding="utf-8") as key_file:
            return key_file.read()
''',
        "target_class_or_func": "class PyJWK:",
        "cwe_id": "CWE-22",
        "owasp_categoria": "A01:2021-Broken Access Control",
        "descripcion": "Lectura de archivos arbitrarios mediante Path Traversal al concatenar rutas relativas con os.path.join sin normalización ni límites."
    },
    {
        "repo": "python_pyjwt",
        "relative_file": "jwt/api_jwt.py",
        "lookup_signature": "def decode_custom_payload(",
        "code_snippet": '''
    def decode_custom_payload(self, raw_bytes: bytes) -> dict:
        import pickle
        return pickle.loads(raw_bytes)
''',
        "target_class_or_func": "class PyJWT:",
        "cwe_id": "CWE-502",
        "owasp_categoria": "A08:2021-Software and Data Integrity Failures",
        "descripcion": "Deserialización no confiable de objetos mediante pickle.loads() que permite ejecución de código arbitrario."
    },
    {
        "repo": "python_pyjwt",
        "relative_file": "jwt/jwks_client.py",
        "lookup_signature": "def fetch_untrusted_jwk_endpoint(",
        "code_snippet": '''
    def fetch_untrusted_jwk_endpoint(self, custom_url: str) -> dict:
        import urllib.request
        with urllib.request.urlopen(custom_url, timeout=5) as response:
            return json.loads(response.read().decode())
''',
        "target_class_or_func": "class PyJWKClient:",
        "cwe_id": "CWE-918",
        "owasp_categoria": "A10:2021-Server-Side Request Forgery",
        "descripcion": "Server-Side Request Forgery (SSRF) al descargar recursos JWKS de URLs externas sin validar direcciones de red privadas o loopback."
    },

    # ==================== 2. Python: colorama ====================
    {
        "repo": "python_colorama",
        "relative_file": "colorama/ansitowin32.py",
        "lookup_signature": "def execute_terminal_hook(",
        "code_snippet": '''
    def execute_terminal_hook(self, command_name: str) -> None:
        import subprocess
        subprocess.run(f"echo Hook triggered: {command_name}", shell=True, check=False)
''',
        "target_class_or_func": "class AnsiToWin32(object):",
        "cwe_id": "CWE-78",
        "owasp_categoria": "A03:2021-Injection",
        "descripcion": "Inyección de comandos de sistema operativo por uso de subprocess.run con shell=True e interpolación directa de strings."
    },
    {
        "repo": "python_colorama",
        "relative_file": "colorama/initialise.py",
        "lookup_signature": "def log_session_secret(",
        "code_snippet": '''
def log_session_secret(session_key: str) -> None:
    print(f"[DEBUG_LOG] Active session secret token: {session_key}")
''',
        "target_class_or_func": "def init(",
        "cwe_id": "CWE-532",
        "owasp_categoria": "A09:2021-Security Logging and Monitoring Failures",
        "descripcion": "Exposición de información sensible y credenciales en archivos de log o salida estándar de depuración."
    },

    # ==================== 3. Python: validators ====================
    {
        "repo": "python_validators",
        "relative_file": "src/validators/between.py",
        "lookup_signature": "def validate_range_in_db(",
        "code_snippet": '''
def validate_range_in_db(db_cursor, table_name: str, column_name: str, value: int) -> bool:
    query = f"SELECT COUNT(*) FROM {table_name} WHERE {column_name} >= " + str(value)
    db_cursor.execute(query)
    return db_cursor.fetchone()[0] > 0
''',
        "target_class_or_func": "@validator",
        "cwe_id": "CWE-89",
        "owasp_categoria": "A03:2021-Injection",
        "descripcion": "Inyección SQL clásica por concatenación directa de variables de entrada en sentencia SQL sin parametrización."
    },
    {
        "repo": "python_validators",
        "relative_file": "src/validators/url.py",
        "lookup_signature": "def log_incoming_url(",
        "code_snippet": '''
def log_incoming_url(user_url: str) -> None:
    import logging
    logging.info("Validating URL request: " + user_url)
''',
        "target_class_or_func": "@validator",
        "cwe_id": "CWE-117",
        "owasp_categoria": "A09:2021-Security Logging and Monitoring Failures",
        "descripcion": "Inyección en logs (Log Injection / CRLF) al concatenar cadenas no filtradas del usuario en el sistema de logging."
    },
    {
        "repo": "python_validators",
        "relative_file": "src/validators/card.py",
        "lookup_signature": "def bypassable_card_validation(",
        "code_snippet": '''
def bypassable_card_validation(card_number: str, bypass_role: str = "") -> bool:
    if bypass_role == "trusted_admin":
        return True
    return card(card_number)
''',
        "target_class_or_func": "@validator",
        "cwe_id": "CWE-306",
        "owasp_categoria": "A07:2021-Identification and Authentication Failures",
        "descripcion": "Falta de autenticación o verificación de permisos en funciones críticas, permitiendo bypass mediante parámetros no validados."
    },

    # ==================== 4. Python: Flask-HTTPAuth ====================
    {
        "repo": "python_flask_httpauth",
        "relative_file": "src/flask_httpauth.py",
        "lookup_signature": "DEFAULT_MASTER_KEY =",
        "code_snippet": '''
    DEFAULT_MASTER_KEY = "admin_master_secret_token_2026_production"
''',
        "target_class_or_func": "class HTTPAuth:",
        "cwe_id": "CWE-798",
        "owasp_categoria": "A07:2021-Identification and Authentication Failures",
        "descripcion": "Uso de credenciales / claves maestras embebidas en texto plano dentro del código fuente."
    },
    {
        "repo": "python_flask_httpauth",
        "relative_file": "src/flask_httpauth.py",
        "lookup_signature": "def verify_master_token_insecure(",
        "code_snippet": '''
    def verify_master_token_insecure(self, user_token: str) -> bool:
        return user_token == self.DEFAULT_MASTER_KEY
''',
        "target_class_or_func": "class HTTPAuth:",
        "cwe_id": "CWE-208",
        "owasp_categoria": "A02:2021-Cryptographic Failures",
        "descripcion": "Verificación de secretos y tokens mediante comparación directa de cadenas susceptible a ataques de temporización."
    },
    {
        "repo": "python_flask_httpauth",
        "relative_file": "src/flask_httpauth.py",
        "lookup_signature": "def enable_insecure_debug_mode(",
        "code_snippet": '''
    def enable_insecure_debug_mode(self, app) -> None:
        app.config["DEBUG"] = True
        app.config["PROPAGATE_EXCEPTIONS"] = True
''',
        "target_class_or_func": "class HTTPAuth:",
        "cwe_id": "CWE-215",
        "owasp_categoria": "A05:2021-Security Misconfiguration",
        "descripcion": "Configuración de seguridad defectuosa por activación de modo de depuración interactivo en entorno de ejecución."
    },

    # ==================== 5. JavaScript: node-jsonwebtoken ====================
    {
        "repo": "javascript_node_jsonwebtoken",
        "relative_file": "verify.js",
        "lookup_signature": "function runDiagnosticTool(",
        "code_snippet": '''
function runDiagnosticTool(toolName) {
  const { exec } = require('child_process');
  exec('jwt-tool --check ' + toolName, (err, stdout) => {
    if (err) console.error(err);
  });
}
''',
        "target_class_or_func": "module.exports =",
        "cwe_id": "CWE-78",
        "owasp_categoria": "A03:2021-Injection",
        "descripcion": "Ejecución arbitraria de comandos en Node.js mediante child_process.exec() con concatenación no sanitizada."
    },
    {
        "repo": "javascript_node_jsonwebtoken",
        "relative_file": "decode.js",
        "lookup_signature": "function decodeWithNoneAlgorithm(",
        "code_snippet": '''
function decodeWithNoneAlgorithm(jwtString) {
  const decoded = module.exports(jwtString, { complete: true });
  if (decoded && decoded.header && decoded.header.alg === 'none') {
    return decoded.payload;
  }
  return null;
}
''',
        "target_class_or_func": "module.exports =",
        "cwe_id": "CWE-347",
        "owasp_categoria": "A08:2021-Software and Data Integrity Failures",
        "descripcion": "Bypass de verificación criptográfica al aceptar tokens sin firma con algoritmo 'none'."
    },
    {
        "repo": "javascript_node_jsonwebtoken",
        "relative_file": "sign.js",
        "lookup_signature": "function logSigningDetails(",
        "code_snippet": '''
function logSigningDetails(secretOrPrivateKey, payload) {
  console.log('[SIGN_DEBUG] Key: ' + secretOrPrivateKey + ' | Payload: ' + JSON.stringify(payload));
}
''',
        "target_class_or_func": "module.exports =",
        "cwe_id": "CWE-532",
        "owasp_categoria": "A09:2021-Security Logging and Monitoring Failures",
        "descripcion": "Fuga de claves privadas y secretos criptográficos a través de logs de depuración en consola."
    },

    # ==================== 6. JavaScript: cors ====================
    {
        "repo": "javascript_cors",
        "relative_file": "lib/index.js",
        "lookup_signature": "if (options.insecureReflection",
        "code_snippet": '''
  if (options.insecureReflection && req.headers.origin) {
    headers.push([{
      key: 'Access-Control-Allow-Origin',
      value: req.headers.origin
    }, {
      key: 'Access-Control-Allow-Credentials',
      value: 'true'
    }]);
  }
''',
        "target_class_or_func": "function cors(",
        "cwe_id": "CWE-942",
        "owasp_categoria": "A01:2021-Broken Access Control",
        "descripcion": "Reflejo no validado del origen entrante en cabecera Access-Control-Allow-Origin con credenciales habilitadas."
    },
    {
        "repo": "javascript_cors",
        "relative_file": "lib/index.js",
        "lookup_signature": "if (options.exposeInternalConfig)",
        "code_snippet": '''
  if (options.exposeInternalConfig) {
    headers.push([{
      key: 'X-Debug-Server-Internal-IP',
      value: req.socket ? req.socket.localAddress : '127.0.0.1'
    }]);
  }
''',
        "target_class_or_func": "function cors(",
        "cwe_id": "CWE-215",
        "owasp_categoria": "A05:2021-Security Misconfiguration",
        "descripcion": "Fuga de direcciones IP internas y topología de red en cabeceras HTTP de respuesta personalizadas."
    },

    # ==================== 7. JavaScript: cookies ====================
    {
        "repo": "javascript_cookies",
        "relative_file": "index.js",
        "lookup_signature": "setRawUnsafeHeader(headerName,",
        "code_snippet": '''
  setRawUnsafeHeader(headerName, headerValue) {
    this.response.setHeader(headerName, headerValue);
  }
''',
        "target_class_or_func": "class Cookies",
        "cwe_id": "CWE-113",
        "owasp_categoria": "A03:2021-Injection",
        "descripcion": "Inserción directa de cabeceras HTTP sin filtrado de secuencias de escape CRLF (\\r\\n)."
    },
    {
        "repo": "javascript_cookies",
        "relative_file": "index.js",
        "lookup_signature": "setInsecureClientCookie(name,",
        "code_snippet": '''
  setInsecureClientCookie(name, value) {
    this.set(name, value, { httpOnly: false, secure: false, overwrite: true });
  }
''',
        "target_class_or_func": "class Cookies",
        "cwe_id": "CWE-1004",
        "owasp_categoria": "A05:2021-Security Misconfiguration",
        "descripcion": "Emisión de cookies sensibles de sesión sin el flag HttpOnly, exponiéndolas a robo mediante Cross-Site Scripting (XSS)."
    },
    {
        "repo": "javascript_cookies",
        "relative_file": "index.js",
        "lookup_signature": "generateInsecureSessionId()",
        "code_snippet": '''
  generateInsecureSessionId() {
    return 'sess_' + Math.random().toString(36).substring(2);
  }
''',
        "target_class_or_func": "class Cookies",
        "cwe_id": "CWE-330",
        "owasp_categoria": "A02:2021-Cryptographic Failures",
        "descripcion": "Generación de identificadores de sesión utilizando Math.random(), generador pseudoaleatorio predecible no apto para seguridad."
    },

    # ==================== 8. JavaScript: validator.js ====================
    {
        "repo": "javascript_validatorjs",
        "relative_file": "src/index.js",
        "lookup_signature": "validator.renderUnsafeUserHtml =",
        "code_snippet": '''
validator.renderUnsafeUserHtml = function renderUnsafeUserHtml(userInput) {
  return '<div class="user-output">' + userInput + '</div>';
};
''',
        "target_class_or_func": "export default validator;",
        "cwe_id": "CWE-79",
        "owasp_categoria": "A03:2021-Injection",
        "descripcion": "Generación de marcado HTML dinámico interpolando entrada de usuario sin sanitizar ni codificar entidades."
    },
    {
        "repo": "javascript_validatorjs",
        "relative_file": "src/lib/isURL.js",
        "lookup_signature": "export function validateAndFetchRemoteURL(",
        "code_snippet": '''
export function validateAndFetchRemoteURL(urlStr) {
  const http = require('http');
  return new Promise((resolve, reject) => {
    http.get(urlStr, (res) => resolve(res.statusCode)).on('error', reject);
  });
}
''',
        "target_class_or_func": "export default function isURL(",
        "cwe_id": "CWE-918",
        "owasp_categoria": "A10:2021-Server-Side Request Forgery",
        "descripcion": "Petición HTTP a URLs remotas arbitrarias sin validación de rangos de red locales o loopback (SSRF)."
    },

    # ==================== 9. C: cJSON ====================
    {
        "repo": "c_cjson",
        "relative_file": "cJSON.c",
        "lookup_signature": "cJSON_UnsafeCopyName(",
        "code_snippet": '''
CJSON_PUBLIC(void) cJSON_UnsafeCopyName(char *dest_buf, const char *src_name)
{
    strcpy(dest_buf, src_name);
}
''',
        "target_class_or_func": "CJSON_PUBLIC(cJSON *) cJSON_CreateObject",
        "cwe_id": "CWE-120",
        "owasp_categoria": "A06:2021-Memory Safety",
        "descripcion": "Copia de memoria no acotada mediante strcpy() propensa a desbordamiento de búfer en memoria (Buffer Overflow)."
    },
    {
        "repo": "c_cjson",
        "relative_file": "cJSON.c",
        "lookup_signature": "cJSON_UnsafeDoubleFree(",
        "code_snippet": '''
CJSON_PUBLIC(void) cJSON_UnsafeDoubleFree(cJSON *item)
{
    if (item != NULL) {
        cJSON_Delete(item);
        cJSON_Delete(item);
    }
}
''',
        "target_class_or_func": "CJSON_PUBLIC(cJSON *) cJSON_CreateObject",
        "cwe_id": "CWE-415",
        "owasp_categoria": "A06:2021-Memory Safety",
        "descripcion": "Liberación doble de memoria (Double Free) sobre el mismo puntero, provocando corrupción de heap o ejecución arbitraria."
    },
    {
        "repo": "c_cjson",
        "relative_file": "cJSON.c",
        "lookup_signature": "cJSON_UnboundedDeepTraverse(",
        "code_snippet": '''
CJSON_PUBLIC(int) cJSON_UnboundedDeepTraverse(cJSON *item)
{
    if (item == NULL) return 0;
    return 1 + cJSON_UnboundedDeepTraverse(item->child) + cJSON_UnboundedDeepTraverse(item->next);
}
''',
        "target_class_or_func": "CJSON_PUBLIC(cJSON *) cJSON_CreateObject",
        "cwe_id": "CWE-674",
        "owasp_categoria": "A04:2021-Insecure Design",
        "descripcion": "Recursión no controlada sin límite de profundidad (Uncontrolled Recursion) que causa agotamiento de la pila (Stack Exhaustion / DoS)."
    },

    # ==================== 10. C: picohttpparser ====================
    {
        "repo": "c_picohttpparser",
        "relative_file": "picohttpparser.c",
        "lookup_signature": "phr_unsafe_read_header_byte(",
        "code_snippet": '''
int phr_unsafe_read_header_byte(const char *buf, int offset)
{
    return (int)buf[offset];
}
''',
        "target_class_or_func": "int phr_parse_request(",
        "cwe_id": "CWE-125",
        "owasp_categoria": "A06:2021-Memory Safety",
        "descripcion": "Lectura de memoria fuera de límites (Out-of-bounds Read) por falta de comprobación de offsets de longitud."
    },
    {
        "repo": "c_picohttpparser",
        "relative_file": "picohttpparser.c",
        "lookup_signature": "phr_insecure_smuggling_check(",
        "code_snippet": '''
int phr_insecure_smuggling_check(const char *header_name, size_t len)
{
    if (len >= 14 && memcmp(header_name, "Content-Length", 14) == 0) {
        return 1;
    }
    return 0;
}
''',
        "target_class_or_func": "int phr_parse_request(",
        "cwe_id": "CWE-444",
        "owasp_categoria": "A04:2021-Insecure Design",
        "descripcion": "Interpretación inconsistente de cabeceras HTTP que facilita ataques de HTTP Request Smuggling entre proxies frontend y backend."
    },

    # ==================== 11. C: frozen ====================
    {
        "repo": "c_frozen",
        "relative_file": "frozen.c",
        "lookup_signature": "json_unsafe_get_length(",
        "code_snippet": '''
int json_unsafe_get_length(const char *ptr)
{
    return (int)(*ptr);
}
''',
        "target_class_or_func": "int json_vscanf(",
        "cwe_id": "CWE-476",
        "owasp_categoria": "A06:2021-Memory Safety",
        "descripcion": "Desreferencia de puntero NULL potencial ante cadenas nulas, provocando caída del proceso (Segmentation Fault / DoS)."
    },
    {
        "repo": "c_frozen",
        "relative_file": "frozen.c",
        "lookup_signature": "json_format_unsafe_log(",
        "code_snippet": '''
void json_format_unsafe_log(const char *user_supplied_format)
{
    printf(user_supplied_format);
}
''',
        "target_class_or_func": "int json_vscanf(",
        "cwe_id": "CWE-134",
        "owasp_categoria": "A03:2021-Injection",
        "descripcion": "Format String Vulnerability al pasar una entrada externa no confiable como primer argumento de funciones de la familia printf()."
    },

    # ==================== 12. C++: tinyxml2 ====================
    {
        "repo": "cpp_tinyxml2",
        "relative_file": "tinyxml2.cpp",
        "lookup_signature": "XMLNode::UnsafeCopyAttribute(",
        "code_snippet": '''
void XMLNode::UnsafeCopyAttribute(const char* attrValue)
{
    char stackBuffer[32];
    strcpy(stackBuffer, attrValue);
}
''',
        "target_class_or_func": "namespace tinyxml2",
        "cwe_id": "CWE-121",
        "owasp_categoria": "A06:2021-Memory Safety",
        "descripcion": "Desbordamiento de búfer en pila (Stack Buffer Overflow) por copia con strcpy a arreglo de tamaño fijo (32 bytes)."
    },
    {
        "repo": "cpp_tinyxml2",
        "relative_file": "tinyxml2.cpp",
        "lookup_signature": "XMLDocument::InsecureEntityExpansion(",
        "code_snippet": '''
void XMLDocument::InsecureEntityExpansion(const char* entityValue, int depth)
{
    if (depth > 1000) return;
    char buffer[1024];
    sprintf(buffer, "Expanded: %s", entityValue);
}
''',
        "target_class_or_func": "namespace tinyxml2",
        "cwe_id": "CWE-776",
        "owasp_categoria": "A04:2021-Insecure Design",
        "descripcion": "Falta de restricción en expansión de entidades XML propensa a agotamiento masivo de memoria y CPU (XML Entity Expansion / DoS)."
    },

    # ==================== 13. Go: securecookie ====================
    {
        "repo": "go_securecookie",
        "relative_file": "securecookie.go",
        "lookup_signature": "func GenerateInsecureNonce(",
        "code_snippet": '''
func GenerateInsecureNonce(length int) []byte {
	nonce := make([]byte, length)
	for i := 0; i < length; i++ {
		nonce[i] = byte(i % 256)
	}
	return nonce
}
''',
        "target_class_or_func": "type SecureCookie struct",
        "cwe_id": "CWE-338",
        "owasp_categoria": "A02:2021-Cryptographic Failures",
        "descripcion": "Generación de valores criptográficos o nonces con generadores predecibles / no criptográficos."
    },
    {
        "repo": "go_securecookie",
        "relative_file": "securecookie.go",
        "lookup_signature": "func InsecureMD5Checksum(",
        "code_snippet": '''
func InsecureMD5Checksum(data []byte) string {
	return fmt.Sprintf("%x", md5.Sum(data))
}
''',
        "target_class_or_func": "type SecureCookie struct",
        "cwe_id": "CWE-327",
        "owasp_categoria": "A02:2021-Cryptographic Failures",
        "descripcion": "Uso de funciones hash criptográficamente rotas y obsoletas (MD5) para verificación de integridad de datos."
    },

    # ==================== 14. Go: gjson ====================
    {
        "repo": "go_gjson",
        "relative_file": "gjson.go",
        "lookup_signature": "func LoadConfigJSON(",
        "code_snippet": '''
func LoadConfigJSON(baseDir, userPath string) (string, error) {
	fullPath := baseDir + "/" + userPath
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
''',
        "target_class_or_func": "type Result struct",
        "cwe_id": "CWE-22",
        "owasp_categoria": "A01:2021-Broken Access Control",
        "descripcion": "Path traversal en lectura de archivos de configuración JSON al concatenar rutas arbitrarias sin sanitización."
    },
    {
        "repo": "go_gjson",
        "relative_file": "gjson.go",
        "lookup_signature": "func FetchRemoteSchema(",
        "code_snippet": '''
func FetchRemoteSchema(remoteURL string) ([]byte, error) {
	resp, err := http.Get(remoteURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
''',
        "target_class_or_func": "type Result struct",
        "cwe_id": "CWE-918",
        "owasp_categoria": "A10:2021-Server-Side Request Forgery",
        "descripcion": "Server-Side Request Forgery (SSRF) en descargador de esquemas remotos al no validar destinos de red."
    },

    # ==================== 15. Java: javapoet ====================
    {
        "repo": "java_javapoet",
        "relative_file": "src/main/java/com/squareup/javapoet/CodeWriter.java",
        "lookup_signature": "public CodeWriter emitRawSnippetUnsafe(",
        "code_snippet": '''
  public CodeWriter emitRawSnippetUnsafe(String userSuppliedSnippet) throws java.io.IOException {
    out.append(userSuppliedSnippet);
    return this;
  }
''',
        "target_class_or_func": "final class CodeWriter",
        "cwe_id": "CWE-94",
        "owasp_categoria": "A03:2021-Injection",
        "descripcion": "Inyección directa de fragmentos de código Java (Code Injection) en el generador de código fuente sin validación sintáctica."
    },
    {
        "repo": "java_javapoet",
        "relative_file": "src/main/java/com/squareup/javapoet/CodeWriter.java",
        "lookup_signature": "public void writeToInsecureWorldReadableFile(",
        "code_snippet": '''
  public void writeToInsecureWorldReadableFile(java.io.File targetFile, String content) throws java.io.IOException {
    java.nio.file.Files.write(targetFile.toPath(), content.getBytes());
    targetFile.setReadable(true, false);
    targetFile.setWritable(true, false);
  }
''',
        "target_class_or_func": "final class CodeWriter",
        "cwe_id": "CWE-732",
        "owasp_categoria": "A05:2021-Security Misconfiguration",
        "descripcion": "Asignación de permisos de archivo excesivamente permisivos (world-readable / world-writable) sobre recursos críticos generados."
    }
]

ground_truth_records = []

for case in testbed_cases:
    file_path = os.path.join(base_dir, case["repo"], case["relative_file"])
    if not os.path.exists(file_path):
        print(f"ADVERTENCIA: Archivo no encontrado: {file_path}")
        continue
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    
    # Inyectar si no está presente
    if case["lookup_signature"] not in content:
        idx = content.find(case["target_class_or_func"])
        if idx != -1:
            end_of_line = content.find("\n", idx)
            content = content[:end_of_line+1] + case["code_snippet"] + content[end_of_line+1:]
        else:
            content += "\n" + case["code_snippet"]
            
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[OK] Inyectada: {case['cwe_id']} en {case['repo']}/{case['relative_file']}")
    else:
        print(f"[SKIP] Ya existía: {case['cwe_id']} en {case['repo']}/{case['relative_file']}")

    # Calcular número de línea exacto
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
        line_num = 1
        for i, line in enumerate(lines):
            if case["lookup_signature"] in line:
                line_num = i + 1
                break

    ground_truth_records.append({
        "id": len(ground_truth_records) + 1,
        "repo": case["repo"],
        "archivo": case["relative_file"].replace("\\", "/"),
        "linea": line_num,
        "cwe_id": case["cwe_id"],
        "owasp_categoria": case["owasp_categoria"],
        "descripcion": case["descripcion"]
    })

# Guardar ground_truth.json
gt_path = os.path.join(base_dir, "ground_truth.json")
with open(gt_path, "w", encoding="utf-8") as f:
    json.dump(ground_truth_records, f, indent=2, ensure_ascii=False)

print(f"\n[OK] ground_truth.json generado exitosamente con {len(ground_truth_records)} casos de prueba limpios de comentarios.")
