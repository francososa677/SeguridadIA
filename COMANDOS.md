# 📖 Manual de Comandos CLI (`main.py`)

Este manual describe el funcionamiento detallado de todos los comandos disponibles en [`main.py`](file:///c:/Users/Franco%20Sosa/Documents/SeguridadIA/main.py), la interfaz de línea de comandos (CLI) de la plataforma híbrida **Semgrep + Trivy + Taint Tracker + Agente LLM**.

---

## 📋 Resumen de Comandos

| Comando | Motor / Etapa | Propósito Principal |
| :--- | :---: | :--- |
| [`ping`](#1-comando-ping) | Diagnóstico | Verifica conectividad y latencia con el servidor LLM (Colab/ngrok). |
| [`scan-code`](#2-comando-scan-code) | **Semgrep (SAST)** | Escaneo estático permisivo de código fuente (C, Python, JS, Go, Java). |
| [`trace`](#3-comando-trace) | **Taint Tracker** | Rastreo de flujos inter-archivo (Call-Sites) hacia los sumideros (Sinks). |
| [`scan-deps`](#4-comando-scan-deps) | **Trivy (SCA)** | Escaneo de dependencias y manifiestos buscando vulnerabilidades conocidas (CVEs). |
| [`audit`](#5-comando-audit) | **Pipeline Integral** | Auditoría completa: SAST + Taint Tracker + SCA + Triage IA y parches APR. |
| [`evaluate`](#6-comando-evaluate) | **Métricas / Benchmark** | Evaluación masiva y cálculo de Matriz de Confusión frente a `ground_truth.json`. |

---

## 1. Comando `ping`

Comprueba el estado del túnel ngrok y verifica que el servidor de inferencia del LLM (en Google Colab o Kaggle) esté activo y respondiendo.

### Sintaxis
```bash
python main.py ping [--url URL]
```

### Argumentos y Opciones
* `--url` *(Opcional)*: URL específica del túnel de ngrok. Si se omite, usa la configurada en [`config.json`](file:///c:/Users/Franco%20Sosa/Documents/SeguridadIA/config.json).

### Ejemplos
```bash
python main.py ping
```

### Salida esperada
```text
[*] Comprobando conexión con el servidor LLM en: https://mi-túnel.ngrok-free.dev ...
✅ CONEXIÓN EXITOSA (Latencia: 0.42s)
Respuesta del servidor: {"status": "ok", "model": "Qwen2.5-Coder-7B"}
```

---

## 2. Comando `scan-code`

Ejecuta **Semgrep** en modo permisivo (`p/security-audit` por defecto) para detectar rápidamente funciones peligrosas y flujos sospechosos en el código.

### Sintaxis
```bash
python main.py scan-code [path] [--config CONFIG] [--trace] [--limit N] [--out ARCHIVO_JSON]
```

### Argumentos y Opciones
* `path` *(Opcional)*: Ruta de archivo o repositorio a escanear. Por defecto: `dataset_repos/`.
* `--config` *(Opcional)*: Conjunto de reglas de Semgrep. Por defecto: `p/security-audit` (modo radar permisivo). También podés usar `auto` o `p/default`.
* `--trace` *(Opcional)*: Activa el análisis de flujo inter-archivo para enriquecer cada hallazgo con su invocador.
* `--limit` *(Opcional)*: Límite de hallazgos a mostrar en consola. Por defecto: `15`.
* `--out` *(Opcional)*: Archivo JSON donde exportar la lista completa de hallazgos.

### Ejemplos
```bash
# Escaneo de un repositorio específico
python main.py scan-code dataset_repos/python_colorama

# Escaneo con rastreo inter-archivo activado
python main.py scan-code dataset_repos/python_colorama --trace

# Escanear y exportar a JSON
python main.py scan-code dataset_repos/python_colorama --out hallazgos_colorama.json
```

---

## 3. Comando `trace`

Ejecuta el **Rastreador de Flujo de Datos Inter-Archivo (Taint Tracker)**:
1. Detecta los puntos sumideros (*Sinks*) en el código.
2. Identifica la función que los contiene y sus parámetros.
3. Busca en todos los demás archivos del repositorio quién invoca a esa función (*Call-Sites*).
4. Muestra si el flujo es **Inter-Archivo** (proviene de otro módulo) o **Intra-Archivo** (local).

### Sintaxis
```bash
python main.py trace [path] [--limit N] [--out ARCHIVO_JSON]
```

### Argumentos y Opciones
* `path` *(Opcional)*: Ruta de archivo o repositorio a rastrear. Por defecto: `dataset_repos/`.
* `--limit` *(Opcional)*: Límite de flujos a mostrar en pantalla. Por defecto: `15`.
* `--out` *(Opcional)*: Archivo JSON donde exportar el grafo completo de flujos.

### Ejemplos
```bash
# Rastrear flujos en un repositorio
python main.py trace dataset_repos/python_pyjwt

# Rastrear y exportar a JSON
python main.py trace dataset_repos/python_pyjwt --out flujos_pyjwt.json
```

---

## 4. Comando `scan-deps`

Ejecuta **Trivy** sobre el sistema de archivos buscando vulnerabilidades conocidas (CVEs) en los manifiestos de librerías (`requirements.txt`, `package.json`, `go.mod`, etc.).

### Sintaxis
```bash
python main.py scan-deps [path] [--limit N] [--out ARCHIVO_JSON]
```

### Argumentos y Opciones
* `path` *(Opcional)*: Carpeta a escanear. Por defecto: `dataset_repos/`.
* `--limit` *(Opcional)*: Límite de dependencias a listar en pantalla. Por defecto: `15`.
* `--out` *(Opcional)*: Archivo JSON donde exportar los CVEs detectados.

### Ejemplos
```bash
# Escanear dependencias de un repositorio
python main.py scan-deps dataset_repos/python_flask_httpauth

# Escanear todo el proyecto y exportar a JSON
python main.py scan-deps . --out dependencias_vulnerables.json
```

---

## 5. Comando `audit`

El comando central de la plataforma:
1. Ejecuta **Semgrep** sobre el código fuente (SAST).
2. Ejecuta el **Taint Tracker** para conectar invocadores inter-archivo (*Call-Sites*) con sumideros.
3. Ejecuta **Trivy** sobre las dependencias (SCA).
4. Envía a tu **Agente LLM** el contexto completo (invocador + sumidero).
5. El LLM razona si es un falso positivo o real, calcula **CVSS v3.1** y **genera el parche de código seguro (APR)**.

### Sintaxis
```bash
python main.py audit <path> [--limit N] [--out ARCHIVO_JSON]
```

### Argumentos y Opciones
* `<path>` *(Obligatorio)*: Ruta del archivo o repositorio a auditar.
* `--limit` *(Opcional)*: Número máximo de hallazgos a consultar al modelo. Por defecto: `5`.
* `--out` *(Opcional)*: Archivo JSON donde guardar el informe completo con veredictos y parches.

### Ejemplos
```bash
# Auditar un repositorio limitando a los primeros 3 casos
python main.py audit dataset_repos/python_colorama --limit 3

# Auditar y guardar el reporte completo
python main.py audit dataset_repos/python_pyjwt --out reporte_auditoria.json
```

---

## 6. Comando `evaluate`

Evalúa científicamente la precisión de la plataforma contrastando las predicciones de **Semgrep + Taint Tracker + LLM** contra las 40 debilidades documentadas en [`ground_truth.json`](file:///c:/Users/Franco%20Sosa/Documents/SeguridadIA/dataset_repos/ground_truth.json).

### Sintaxis
```bash
python main.py evaluate [--repo REPO] [--limit N] [--out ARCHIVO_JSON]
```

### Argumentos y Opciones
* `--repo` *(Opcional)*: Nombre de la carpeta de un repositorio específico de `dataset_repos/` (ej. `python_colorama`, `c_cjson`). Si se omite, evalúa todos.
* `--limit` *(Opcional)*: Límite de casos a evaluar.
* `--out` *(Opcional)*: Archivo JSON donde guardar el informe detallado de evaluación.

### Ejemplos
```bash
# Evaluar un repositorio en particular
python main.py evaluate --repo python_colorama

# Evaluar 5 casos y exportar informe
python main.py evaluate --limit 5 --out evaluacion_parcial.json
```
