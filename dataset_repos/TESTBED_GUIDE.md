# Guía del Banco de Pruebas SAST (Testbed Dataset Guide)

Este directorio contiene un **banco de pruebas sintético** compuesto por 15 repositorios de código abierto reales, multimodulares y funcionales, sobre los cuales se han introducido **40 debilidades de seguridad controladas** (incluyendo casos de flujo inter-archivo) que abarcan las 10 categorías del estándar **OWASP Top 10 (2021)** y debilidades críticas de memoria de **MITRE CWE**.

---

## 🎯 Objetivo de Evaluación
Evaluar la capacidad de detección, precisión y tasa de falsos positivos de analizadores estáticos de seguridad (SAST), rastreadores de flujo inter-archivo (Taint Tracking) y agentes de IA (e.g. LLMs de 7B/8B parámetros) al recorrer bases de código completas con dependencias y llamadas inter-módulo.

---

## 📊 Matriz de Verdad de Campo (Ground Truth - 40 Casos)

El archivo [`ground_truth.json`](file:///c:/Users/Franco%20Sosa/Documents/SeguridadIA/dataset_repos/ground_truth.json) contiene la especificación exacta de cada falla para contrastación automática.

| ID | Repositorio | Archivo | Línea | CWE ID | Categoría OWASP Top 10 | Resumen de la Falla |
|:---:|:---|:---|:---:|:---:|:---|:---|
| **1** | `python_pyjwt` | `jwt/api_jwk.py` | 21 | **CWE-22** | A01:2021-Broken Access Control | Path Traversal en `load_key_from_disk` sin sanitizar rutas relativas. |
| **2** | `python_pyjwt` | `jwt/api_jwt.py` | 44 | **CWE-502** | A08:2021-Software & Data Integrity | Deserialización no segura de objetos mediante `pickle.loads()`. |
| **3** | `python_pyjwt` | `jwt/jwks_client.py` | 36 | **CWE-918** | A10:2021-Server-Side Request Forgery | SSRF en descarga de JWKS sin filtrado de redes locales/privadas. |
| **4** | `python_colorama` | `colorama/ansitowin32.py` | 280 | **CWE-78** | A03:2021-Injection | Command Injection vía `subprocess.run(..., shell=True)`. |
| **5** | `python_colorama` | `colorama/initialise.py` | 35 | **CWE-532** | A09:2021-Security Logging & Monitoring | Fuga de secretos/tokens de sesión en texto claro en logs. |
| **6** | `python_validators` | `src/validators/between.py` | 16 | **CWE-89** | A03:2021-Injection | SQL Injection por concatenación directa de parámetros en consulta. |
| **7** | `python_validators` | `src/validators/url.py` | 165 | **CWE-117** | A09:2021-Security Logging & Monitoring | Log Injection / CRLF en logs al registrar URLs entrantes. |
| **8** | `python_validators` | `src/validators/card.py` | 12 | **CWE-306** | A07:2021-Auth Failures | Bypass de validación crítica por parámetro de rol no autenticado. |
| **9** | `python_flask_httpauth` | `src/flask_httpauth.py` | 19 | **CWE-798** | A07:2021-Auth Failures | Clave maestra secreta embebida en texto plano (`DEFAULT_MASTER_KEY`). |
| **10** | `python_flask_httpauth` | `src/flask_httpauth.py` | 19 | **CWE-208** | A02:2021-Crypto Failures | Comparación de tokens vulnerable a Timing Attacks. |
| **11** | `python_flask_httpauth` | `src/flask_httpauth.py` | 19 | **CWE-215** | A05:2021-Security Misconfiguration | Activación forzada de modo de depuración interactivo (`DEBUG=True`). |
| **12** | `javascript_node_jsonwebtoken` | `verify.js` | 23 | **CWE-78** | A03:2021-Injection | Command Injection en Node.js vía `child_process.exec()`. |
| **13** | `javascript_node_jsonwebtoken` | `decode.js` | 5 | **CWE-347** | A08:2021-Software & Data Integrity | Bypass de verificación criptográfica aceptando algoritmo `'none'`. |
| **14** | `javascript_node_jsonwebtoken` | `sign.js` | 88 | **CWE-532** | A09:2021-Security Logging & Monitoring | Exposición de claves privadas en logs de depuración. |
| **15** | `javascript_cors` | `lib/index.js` | 161 | **CWE-942** | A01:2021-Broken Access Control | Reflejo inseguro de cabecera `Origin` con `credentials: true`. |
| **16** | `javascript_cors` | `lib/index.js` | 161 | **CWE-215** | A05:2021-Security Misconfiguration | Exposición de IP interna de servidor en cabeceras de respuesta. |
| **17** | `javascript_cookies` | `index.js` | 313 | **CWE-113** | A03:2021-Injection | CRLF / Header Injection al escribir cabeceras HTTP sin sanitizar `\r\n`. |
| **18** | `javascript_cookies` | `index.js` | 319 | **CWE-1004** | A05:2021-Security Misconfiguration | Emisión de cookies de sesión sin el flag `HttpOnly`. |
| **19** | `javascript_cookies` | `index.js` | 325 | **CWE-330** | A02:2021-Crypto Failures | Identificadores de sesión generados con `Math.random()`. |
| **20** | `javascript_validatorjs` | `src/index.js` | 253 | **CWE-79** | A03:2021-Injection | Reflected XSS en generación dinámica de marcado HTML. |
| **21** | `javascript_validatorjs` | `src/lib/isURL.js` | 58 | **CWE-918** | A10:2021-Server-Side Request Forgery | SSRF en función de descarga remota sin validar red local. |
| **22** | `c_cjson` | `cJSON.c` | 1 | **CWE-120** | A06:2021-Memory Safety | Buffer Overflow por copia no acotada con `strcpy`. |
| **23** | `c_cjson` | `cJSON.c` | 1 | **CWE-415** | A06:2021-Memory Safety | Double Free por liberación duplicada de punteros de memoria. |
| **24** | `c_cjson` | `cJSON.c` | 1 | **CWE-674** | A04:2021-Insecure Design | Recursión no controlada sin límite de profundidad (Stack Overflow DoS). |
| **25** | `c_picohttpparser` | `picohttpparser.c` | 1 | **CWE-125** | A06:2021-Memory Safety | Out-of-bounds Read por indexación directa sin comprobar límites. |
| **26** | `c_picohttpparser` | `picohttpparser.c` | 1 | **CWE-444** | A04:2021-Insecure Design | HTTP Request Smuggling por parsing permisivo de cabeceras. |
| **27** | `c_frozen` | `frozen.c` | 1 | **CWE-476** | A06:2021-Memory Safety | NULL Pointer Dereference por falta de chequeo previo de puntero. |
| **28** | `c_frozen` | `frozen.c` | 1 | **CWE-134** | A03:2021-Injection | Format String Vulnerability por pasar entrada directa a `printf`. |
| **29** | `cpp_tinyxml2` | `tinyxml2.cpp` | 128 | **CWE-121** | A06:2021-Memory Safety | Stack Buffer Overflow por copia a buffer fijo de 32 bytes. |
| **30** | `cpp_tinyxml2` | `tinyxml2.cpp` | 128 | **CWE-776** | A04:2021-Insecure Design | XML Entity Expansion (XML Bomb) por expansión no restringida. |
| **31** | `go_securecookie` | `securecookie.go` | 157 | **CWE-338** | A02:2021-Crypto Failures | Uso de generador pseudoaleatorio predecible para nonces. |
| **32** | `go_securecookie` | `securecookie.go` | 157 | **CWE-327** | A02:2021-Crypto Failures | Algoritmo hash criptográficamente roto (MD5) sin sal. |
| **33** | `go_gjson` | `gjson.go` | 68 | **CWE-22** | A01:2021-Broken Access Control | Path Traversal en lectura de archivos de configuración. |
| **34** | `go_gjson` | `gjson.go` | 68 | **CWE-918** | A10:2021-Server-Side Request Forgery | SSRF en descargador de esquemas remotos sin validación de red. |
| **35** | `java_javapoet` | `.../CodeWriter.java` | 46 | **CWE-94** | A03:2021-Injection | Code Injection directo en generación de fuentes Java. |
| **36** | `java_javapoet` | `.../CodeWriter.java` | 46 | **CWE-732** | A05:2021-Security Misconfiguration | Asignación de permisos de archivo world-readable/world-writable. |
| **37** | `python_pyjwt` | `jwt/utils.py` | 153 | **CWE-78** | A03:2021-Injection | Command Injection inter-archivo (`api_jwk.py:sync_remote_key_backup` -> `utils.py:execute_system_backup`). |
| **38** | `python_colorama` | `colorama/winterm.py` | 202 | **CWE-78** | A03:2021-Injection | Command Injection inter-archivo (`initialise.py:backup_console_session` -> `winterm.py:execute_terminal_backup`). |
| **39** | `python_validators` | `src/validators/utils.py` | 108 | **CWE-502** | A08:2021-Software & Data Integrity | Insecure Deserialization inter-archivo (`url.py:import_url_validation_profile` -> `utils.py:load_custom_regex_rule`). |
| **40** | `javascript_node_jsonwebtoken` | `decode.js` | 42 | **CWE-94** | A03:2021-Injection | Code Injection inter-archivo (`verify.js:verifyWithCustomPlugin` -> `decode.js:executePluginHook`). |

---

## 🌐 Cobertura por Categoría OWASP Top 10 (2021)

| Categoría OWASP Top 10 | Casos Incluidos | CWEs Cubiertos |
| :--- | :---: | :--- |
| **A01:2021 - Broken Access Control** | 4 | CWE-22, CWE-942 |
| **A02:2021 - Cryptographic Failures** | 5 | CWE-208, CWE-327, CWE-330, CWE-338 |
| **A03:2021 - Injection** | 11 | CWE-78, CWE-79, CWE-89, CWE-94, CWE-113, CWE-134 |
| **A04:2021 - Insecure Design** | 4 | CWE-444, CWE-674, CWE-776 |
| **A05:2021 - Security Misconfiguration** | 5 | CWE-215, CWE-732, CWE-1004 |
| **A06:2021 - Vulnerable Components / Memory Safety** | 5 | CWE-120, CWE-121, CWE-125, CWE-415, CWE-476 |
| **A07:2021 - Identification & Auth Failures** | 3 | CWE-306, CWE-798 |
| **A08:2021 - Software & Data Integrity Failures** | 3 | CWE-347, CWE-502 |
| **A09:2021 - Security Logging & Monitoring Failures** | 3 | CWE-117, CWE-532 |
| **A10:2021 - Server-Side Request Forgery (SSRF)** | 3 | CWE-918 |
| **TOTAL** | **40** | **23 tipos de CWE únicos (4 inter-archivo)** |

---

## 📈 Metodología para el Cálculo de Métricas y Matriz de Confusión

Para contrastar automáticamente los hallazgos de un agente SAST frente al archivo [`ground_truth.json`](file:///c:/Users/Franco%20Sosa/Documents/SeguridadIA/dataset_repos/ground_truth.json):

### 1. Definición de Estados
* **Verdadero Positivo (TP - True Positive):** El modelo detecta una debilidad en el archivo correcto y coincide en el CWE / categoría esperada (margen de tolerancia de $\pm 10$ líneas).
* **Falso Positivo (FP - False Positive):** El modelo reporta una vulnerabilidad en código limpio o inventa una falla inexistente.
* **Falso Negativo (FN - False Negative):** El modelo no reporta una debilidad listada en `ground_truth.json`.
* **Verdadero Negativo (TN - True Negative):** Módulos o funciones libres de fallas clasificadas correctamente como seguras.

### 2. Métricas de Rendimiento
$$\text{Precision} = \frac{TP}{TP + FP}$$

$$\text{Recall (Sensibilidad)} = \frac{TP}{TP + FN}$$

$$F_1\text{-Score} = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$
