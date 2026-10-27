# 📊 Informe Comparativo de Seguridad: SAST + SCA + Agente IA

## Resumen Ejecutivo de Métricas

| Métrica | Valor | Descripción |
| :--- | :---: | :--- |
| **Ground Truth (Vulnerabilidades Reales)** | **4** | Debilidades intencionales documentadas |
| **Detectadas por Semgrep** | **0 / 4** | Recall de Semgrep: 0.0% |
| **Falsos Positivos de Semgrep (Ruido)** | **99** | Alertas en código no vulnerable |
| **Verdaderos Positivos Confirmados por IA (TP)** | **0** | Vulnerabilidades reales verificadas |
| **Ruido Descartado por IA (TN)** | **94** | Falsas alarmas filtradas con éxito |
| **Reducción de Ruido Lograda por IA** | **0.0%** | Porcentaje de alertas irrelevantes eliminadas |
| **Precisión del Agente (Precision)** | **0.0%** | `TP / (TP + FP)` |
| **Sensibilidad Global (Recall)** | **0.0%** | `TP / Total Ground Truth` |
| **F1-Score** | **0.0%** | Balance armónico Precision / Recall |

## 1. Matriz de Vulnerabilidades del Ground Truth

| ID | Repo | Archivo:Línea | CWE | Semgrep? | Trivy? | Agente IA | Explicación |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| #1 | `python_pyjwt` | `jwt/api_jwk.py:21` | CWE-22 | ❌ NO | ⚪ N/A | 🛡️ NO_EVALUADO | Omitido por límite de ejecución... |
| #2 | `python_pyjwt` | `jwt/api_jwt.py:44` | CWE-502 | ❌ NO | ⚪ N/A | 🛡️ NO_EVALUADO | Omitido por límite de ejecución... |
| #3 | `python_pyjwt` | `jwt/jwks_client.py:36` | CWE-918 | ❌ NO | ⚪ N/A | 🛡️ NO_EVALUADO | Omitido por límite de ejecución... |
| #37 | `python_pyjwt` | `jwt/utils.py:153` | CWE-78 | ❌ NO | ⚪ N/A | 🛡️ NO_EVALUADO | Omitido por límite de ejecución... |

## 2. Matriz de Ruido de Semgrep (Falsos Positivos Descartados vs Confirmados)

| Repo | Archivo:Línea | Alerta Semgrep | ¿Era Real? | Respuesta Agente IA | Triage |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `python_pyjwt` | `jwt/algorithms.py:142` | get_default_algorithms... | ❌ NO | **ERROR** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:184` | Algorithm.compute_hash_digest... | ❌ NO | **ERROR** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:206` | Algorithm.check_crypto_key_type... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:258` | Algorithm.to_jwk... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:290` | NoneAlgorithm.prepare_key... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:328` | HMACAlgorithm._is_der_key... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:346` | HMACAlgorithm.prepare_key... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:451` | HMACAlgorithm.to_jwk... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:463` | HMACAlgorithm.from_jwk... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:482` | HMACAlgorithm.check_key_length... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:521` | RSAAlgorithm.check_key_length... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:530` | RSAAlgorithm.prepare_key... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:572` | RSAAlgorithm.to_jwk... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:611` | RSAAlgorithm.from_jwk... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:682` | RSAAlgorithm.sign... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:686` | RSAAlgorithm.verify... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:708` | ECAlgorithm.__init__... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:716` | ECAlgorithm._validate_curve... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:727` | ECAlgorithm.prepare_key... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:760` | ECAlgorithm.sign... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:765` | ECAlgorithm.verify... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:791` | ECAlgorithm.to_jwk... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:835` | ECAlgorithm.from_jwk... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:913` | RSAPSSAlgorithm.sign... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:924` | RSAPSSAlgorithm.verify... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:961` | OKPAlgorithm.prepare_key... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:983` | OKPAlgorithm.sign... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:997` | OKPAlgorithm.verify... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:1032` | OKPAlgorithm.to_jwk... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/algorithms.py:1079` | OKPAlgorithm.from_jwk... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:26` | PyJWK.sync_remote_key_backup... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:32` | PyJWK.__init__... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:102` | PyJWK.from_dict... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:114` | PyJWK.from_json... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:128` | PyJWK.key_type... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:136` | PyJWK.key_id... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:144` | PyJWK.public_key_use... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:153` | PyJWKSet.__init__... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:180` | PyJWKSet.from_dict... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:185` | PyJWKSet.from_json... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:189` | PyJWKSet.__getitem__... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jwk.py:200` | PyJWTSetWithTimestamp.__init__... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jws.py:39` | PyJWS.__init__... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jws.py:62` | PyJWS.register_algorithm... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jws.py:79` | PyJWS.unregister_algorithm... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jws.py:94` | PyJWS.get_algorithms... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jws.py:102` | PyJWS.get_algorithm_by_name... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jws.py:123` | PyJWS.encode... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jws.py:222` | PyJWS.decode_complete... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |
| `python_pyjwt` | `jwt/api_jws.py:293` | PyJWS.decode... | ❌ NO | **NO_EVALUADO** | ⚪ Pendiente |

*(... y 49 falsos positivos más filtrados en el dashboard HTML completo)*
