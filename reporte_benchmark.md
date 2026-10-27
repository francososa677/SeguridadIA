# 📊 Informe Comparativo de Seguridad: SAST + SCA + Agente IA

## Resumen Ejecutivo de Métricas

| Métrica | Valor | Descripción |
| :--- | :---: | :--- |
| **Ground Truth (Vulnerabilidades Reales)** | **40** | Debilidades intencionales documentadas |
| **Detectadas por Semgrep** | **13 / 40** | Recall de Semgrep: 32.5% |
| **Falsos Positivos de Semgrep (Ruido)** | **145** | Alertas en código no vulnerable |
| **Verdaderos Positivos Confirmados por IA (TP)** | **10** | Vulnerabilidades reales verificadas |
| **Ruido Descartado por IA (TN)** | **110** | Falsas alarmas filtradas con éxito |
| **Reducción de Ruido Lograda por IA** | **75.86%** | Porcentaje de alertas irrelevantes eliminadas |
| **Precisión del Agente (Precision)** | **27.03%** | `TP / (TP + FP)` |
| **Sensibilidad Global (Recall)** | **25.0%** | `TP / Total Ground Truth` |
| **F1-Score** | **25.97%** | Balance armónico Precision / Recall |

## 1. Matriz de Vulnerabilidades del Ground Truth

| ID | Repo | Archivo:Línea | CWE | Semgrep? | Trivy? | Agente IA | Explicación |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| #1 | `python_pyjwt` | `jwt/api_jwk.py:21` | CWE-22 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #2 | `python_pyjwt` | `jwt/api_jwt.py:44` | CWE-502 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | El método `decode_custom_payload` utiliza `pickle.loads` para deserializar datos recibidos... |
| #3 | `python_pyjwt` | `jwt/jwks_client.py:36` | CWE-918 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | El método `fetch_untrusted_jwk_endpoint` acepta una entrada `custom_url` que es utilizada ... |
| #4 | `python_colorama` | `colorama/ansitowin32.py:280` | CWE-78 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | El uso de `subprocess.run` con `shell=True` permite que el comando sea ejecutado mediante ... |
| #5 | `python_colorama` | `colorama/initialise.py:35` | CWE-532 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #6 | `python_validators` | `src/validators/between.py:16` | CWE-89 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | El código concatena directamente la entrada del usuario (`value`) dentro de una consulta S... |
| #7 | `python_validators` | `src/validators/url.py:165` | CWE-117 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #8 | `python_validators` | `src/validators/card.py:12` | CWE-306 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #9 | `python_flask_httpauth` | `src/flask_httpauth.py:19` | CWE-798 | ✅ SÍ | ⚪ N/A | 🛡️ SEGURO | La variable 'DEBUG' está configurada como verdadera dentro de un método que no recibe ning... |
| #10 | `python_flask_httpauth` | `src/flask_httpauth.py:19` | CWE-208 | ✅ SÍ | ⚪ N/A | 🛡️ SEGURO | La variable 'DEBUG' está configurada como verdadera dentro de un método que no recibe ning... |
| #11 | `python_flask_httpauth` | `src/flask_httpauth.py:19` | CWE-215 | ✅ SÍ | ⚪ N/A | 🛡️ SEGURO | La variable 'DEBUG' está configurada como verdadera dentro de un método que no recibe ning... |
| #12 | `javascript_node_jsonwebtoken` | `verify.js:23` | CWE-78 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | La función `runDiagnosticTool` ejecuta un comando externo utilizando `exec`, lo que podría... |
| #13 | `javascript_node_jsonwebtoken` | `decode.js:5` | CWE-347 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #14 | `javascript_node_jsonwebtoken` | `sign.js:88` | CWE-532 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #15 | `javascript_cors` | `lib/index.js:161` | CWE-942 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #16 | `javascript_cors` | `lib/index.js:161` | CWE-215 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #17 | `javascript_cookies` | `index.js:313` | CWE-113 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #18 | `javascript_cookies` | `index.js:318` | CWE-1004 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #19 | `javascript_cookies` | `index.js:323` | CWE-330 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #20 | `javascript_validatorjs` | `src/index.js:253` | CWE-79 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #21 | `javascript_validatorjs` | `src/lib/isURL.js:58` | CWE-918 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | El código utiliza 'http.get' para realizar solicitudes a URLs proporcionadas por el usuari... |
| #22 | `c_cjson` | `cJSON.c:2562` | CWE-120 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #23 | `c_cjson` | `cJSON.c:2562` | CWE-415 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #24 | `c_cjson` | `cJSON.c:2562` | CWE-674 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #25 | `c_picohttpparser` | `picohttpparser.c:411` | CWE-125 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #26 | `c_picohttpparser` | `picohttpparser.c:411` | CWE-444 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #27 | `c_frozen` | `frozen.c:1070` | CWE-476 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #28 | `c_frozen` | `frozen.c:1070` | CWE-134 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #29 | `cpp_tinyxml2` | `tinyxml2.cpp:128` | CWE-121 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #30 | `cpp_tinyxml2` | `tinyxml2.cpp:128` | CWE-776 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #31 | `go_securecookie` | `securecookie.go:157` | CWE-338 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #32 | `go_securecookie` | `securecookie.go:157` | CWE-327 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #33 | `go_gjson` | `gjson.go:68` | CWE-22 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #34 | `go_gjson` | `gjson.go:68` | CWE-918 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #35 | `java_javapoet` | `src/main/java/com/squareup/javapoet/CodeWriter.java:46` | CWE-94 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #36 | `java_javapoet` | `src/main/java/com/squareup/javapoet/CodeWriter.java:46` | CWE-732 | ❌ NO | ⚪ N/A | ⚪ NO AUDITADO | No fue detectado por Semgrep, por lo tanto no llegó a ser auditado por el Agente IA.... |
| #37 | `python_pyjwt` | `jwt/utils.py:153` | CWE-78 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | El uso de 'subprocess.run' con 'shell=True' permite la inyección de comandos, lo que puede... |
| #38 | `python_colorama` | `colorama/winterm.py:202` | CWE-78 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | El uso de `subprocess.run` con `shell=True` permite la inyección de comandos, lo que puede... |
| #39 | `python_validators` | `src/validators/utils.py:108` | CWE-502 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | El código utiliza `pickle.loads` para deserializar datos que provienen de `profile_data`. ... |
| #40 | `javascript_node_jsonwebtoken` | `decode.js:42` | CWE-94 | ✅ SÍ | ⚪ N/A | 🛡️ VULNERABLE | El uso de `eval()` en la función `executePluginHook` permite la ejecución dinámica de códi... |

## 2. Matriz de Ruido de Semgrep (Falsos Positivos Descartados vs Confirmados)

| Repo | Archivo:Línea | Alerta Semgrep | ¿Era Real? | Respuesta Agente IA | Triage |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `c_cjson` | `c_cjson/.github/workflows/CI.yml:30` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `c_cjson` | `c_cjson/.github/workflows/CI.yml:76` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `c_cjson` | `c_cjson/.github/workflows/ci-fuzz.yml:8` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `c_cjson` | `c_cjson/.github/workflows/ci-fuzz.yml:13` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `c_cjson` | `c_cjson/.github/workflows/ci-fuzz.yml:19` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `c_picohttpparser` | `c_picohttpparser/.github/workflows/ci.yml:20` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `c_picohttpparser` | `c_picohttpparser/.github/workflows/release-reltest.yml:19` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `c_picohttpparser` | `c_picohttpparser/.github/workflows/release.yml:19` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `c_picohttpparser` | `c_picohttpparser/misc/release.rb:18` | Detected non-static command inside IO.popen. Audit the input... | ❌ NO | **VULNERABLE** | ⚠️ FP (Falsa Alarma) |
| `c_picohttpparser` | `c_picohttpparser/misc/release.rb:21` | Detected non-static command inside system. Audit the input t... | ❌ NO | **VULNERABLE** | ⚠️ FP (Falsa Alarma) |
| `c_picohttpparser` | `c_picohttpparser/misc/release.rb:38` | Detected non-static command inside system. Audit the input t... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/.github/workflows/test.yml:34` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/.github/workflows/test.yml:35` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/.github/workflows/test.yml:36` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/.github/workflows/test.yml:37` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_comment.html:227` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_comment.html:228` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_declaration.html:229` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_declaration.html:230` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_document.html:289` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_document.html:290` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_element.html:437` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_element.html:438` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_node.html:241` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_node.html:242` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_text.html:237` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_text.html:238` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_unknown.html:228` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/classtinyxml2_1_1_x_m_l_unknown.html:229` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/dynsections.js:83` | RegExp() called with a `id` function argument, this might al... | ❌ NO | **ERROR** | ⚪ Pendiente |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/index.html:81` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/index.html:86` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/index.html:106` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/index.html:209` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/index.html:224` | This link points to a plaintext HTTP URL. Prefer an encrypte... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/jquery.js:2` | RegExp() called with a `e` function argument, this might all... | ❌ NO | **ERROR** | ⚪ Pendiente |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/jquery.js:2` | Possibility of prototype polluting function detected. By add... | ❌ NO | **ERROR** | ⚪ Pendiente |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/jquery.js:2` | Possibility of prototype polluting function detected. By add... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `cpp_tinyxml2` | `cpp_tinyxml2/docs/jquery.js:34` | Detected the use of eval(). eval() can be dangerous if used ... | ❌ NO | **ERROR** | ⚪ Pendiente |
| `go_gjson` | `go_gjson/.github/workflows/go.yml:17` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `go_gjson` | `go_gjson/.github/workflows/go.yml:22` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `go_gjson` | `go_gjson/.github/workflows/go.yml:25` | A `run:` step pipes the output of `curl` or `wget` directly ... | ❌ NO | **VULNERABLE** | ⚠️ FP (Falsa Alarma) |
| `go_securecookie` | `go_securecookie/.github/workflows/issues.yml:18` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `go_securecookie` | `go_securecookie/.github/workflows/security.yml:20` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `go_securecookie` | `go_securecookie/.github/workflows/security.yml:23` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `go_securecookie` | `go_securecookie/.github/workflows/security.yml:29` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `go_securecookie` | `go_securecookie/.github/workflows/security.yml:34` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `go_securecookie` | `go_securecookie/.github/workflows/test.yml:21` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `go_securecookie` | `go_securecookie/.github/workflows/test.yml:24` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |
| `go_securecookie` | `go_securecookie/.github/workflows/test.yml:33` | GitHub Actions step uses a mutable tag or branch reference. ... | ❌ NO | **SEGURO** | 🛡️ TN (Filtrado) |

*(... y 95 falsos positivos más filtrados en el dashboard HTML completo)*
