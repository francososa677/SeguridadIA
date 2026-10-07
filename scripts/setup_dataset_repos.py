import os
import subprocess
import shutil
import json

base_dir = r"c:\Users\Franco Sosa\Documents\SeguridadIA\dataset_repos"
os.makedirs(base_dir, exist_ok=True)

repos = [
    # Python (4)
    {
        "name": "pyjwt",
        "language": "Python",
        "subfolder": "python_pyjwt",
        "url": "https://github.com/jpadilla/pyjwt.git",
        "description": "Librería en Python para codificación, decodificación y verificación criptográfica de JSON Web Tokens (RFC 7519)."
    },
    {
        "name": "colorama",
        "language": "Python",
        "subfolder": "python_colorama",
        "url": "https://github.com/tartley/colorama.git",
        "description": "Librería modular para renderizado de texto coloreado y gestión de secuencias de escape ANSI en consola multiplataforma."
    },
    {
        "name": "validators",
        "language": "Python",
        "subfolder": "python_validators",
        "url": "https://github.com/python-validators/validators.git",
        "description": "Librería modular de validación y sanitización de datos (URLs, correos, dominios, inputs)."
    },
    {
        "name": "Flask-HTTPAuth",
        "language": "Python",
        "subfolder": "python_flask_httpauth",
        "url": "https://github.com/miguelgrinberg/Flask-HTTPAuth.git",
        "description": "Extensión modular de Flask para autenticación HTTP básica, digest y por token."
    },
    # JavaScript / TypeScript (4)
    {
        "name": "node-jsonwebtoken",
        "language": "JavaScript",
        "subfolder": "javascript_node_jsonwebtoken",
        "url": "https://github.com/auth0/node-jsonwebtoken.git",
        "description": "Módulo de Node.js de Auth0 para firma, verificación y parseo de tokens JWT."
    },
    {
        "name": "cors",
        "language": "JavaScript",
        "subfolder": "javascript_cors",
        "url": "https://github.com/expressjs/cors.git",
        "description": "Middleware modular de Express/Connect para gestión y configuración de cabeceras Cross-Origin Resource Sharing."
    },
    {
        "name": "cookies",
        "language": "JavaScript",
        "subfolder": "javascript_cookies",
        "url": "https://github.com/pillarjs/cookies.git",
        "description": "Módulo de gestión, firma criptográfica y verificación de cookies HTTP para servidores Node.js."
    },
    {
        "name": "validator.js",
        "language": "JavaScript",
        "subfolder": "javascript_validatorjs",
        "url": "https://github.com/validatorjs/validator.js.git",
        "description": "Librería de sanitización y validación de strings e inputs para Node.js y navegador."
    },
    # C / C++ (4)
    {
        "name": "cJSON",
        "language": "C",
        "subfolder": "c_cjson",
        "url": "https://github.com/DaveGamble/cJSON.git",
        "description": "Parser y serializador ultraliviano de JSON en ANSI C con manipulación dinámica de memoria."
    },
    {
        "name": "picohttpparser",
        "language": "C",
        "subfolder": "c_picohttpparser",
        "url": "https://github.com/h2o/picohttpparser.git",
        "description": "Parser HTTP/1.x de alto rendimiento en C para peticiones, cabeceras y chunks."
    },
    {
        "name": "frozen",
        "language": "C",
        "subfolder": "c_frozen",
        "url": "https://github.com/cesanta/frozen.git",
        "description": "Parser y generador de JSON diseñado para sistemas embebidos y seguridad de memoria en C/C++."
    },
    {
        "name": "tinyxml2",
        "language": "C++",
        "subfolder": "cpp_tinyxml2",
        "url": "https://github.com/leethomason/tinyxml2.git",
        "description": "Parser DOM XML estructurado, modular y eficiente en C++ para integración directa en proyectos."
    },
    # Go / Java (3)
    {
        "name": "securecookie",
        "language": "Go",
        "subfolder": "go_securecookie",
        "url": "https://github.com/gorilla/securecookie.git",
        "description": "Paquete en Go para codificación, firma HMAC y cifrado simétrico autenticado de cookies."
    },
    {
        "name": "gjson",
        "language": "Go",
        "subfolder": "go_gjson",
        "url": "https://github.com/tidwall/gjson.git",
        "description": "Librería en Go para parseo, extracción y navegación rápida de valores JSON."
    },
    {
        "name": "javapoet",
        "language": "Java",
        "subfolder": "java_javapoet",
        "url": "https://github.com/square/javapoet.git",
        "description": "Librería modular de Square en Java para modelado de clases y generación de código fuente Java."
    }
]

metadata_output = []

def remove_readonly(func, path, excinfo):
    import stat
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass

for r in repos:
    target_path = os.path.join(base_dir, r["subfolder"])
    if os.path.exists(target_path):
        shutil.rmtree(target_path, onerror=remove_readonly)
    
    print(f"Clonando {r['name']} ({r['language']}) en {r['subfolder']}...")
    cmd = ["git", "clone", "--depth", "1", r["url"], target_path]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"ERROR clonando {r['name']}: {res.stderr}")
    else:
        git_dir = os.path.join(target_path, ".git")
        if os.path.exists(git_dir):
            if os.name == "nt":
                subprocess.run(["cmd", "/c", f'rmdir /s /q "{git_dir}"'], capture_output=True)
            else:
                shutil.rmtree(git_dir, ignore_errors=True)
        
        # Conteo de archivos de código fuente
        source_exts = {".py", ".js", ".ts", ".c", ".cpp", ".h", ".hpp", ".go", ".java"}
        src_files = []
        for root, dirs, files in os.walk(target_path):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in source_exts:
                    src_files.append(os.path.relpath(os.path.join(root, f), target_path))
                    
        print(f"-> OK: {len(src_files)} archivos de código fuente.")
        
        metadata_output.append({
            "nombre": r["name"],
            "lenguaje": r["language"],
            "carpeta": r["subfolder"],
            "url": r["url"],
            "archivos_codigo_fuente": len(src_files),
            "descripcion": r["description"]
        })

meta_path = os.path.join(base_dir, "metadata.json")
with open(meta_path, "w", encoding="utf-8") as f:
    json.dump(metadata_output, f, indent=2, ensure_ascii=False)

print(f"\n¡Listo! metadata.json generado exitosamente con {len(metadata_output)} repositorios.")
