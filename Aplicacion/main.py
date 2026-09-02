import sys
import os
import json
import re
import time
import uuid
import threading
import pandas as pd
import requests
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from pydantic import BaseModel

# Add parent dir to system path so we can import llm.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from llm import auditar_codigo, obtener_ngrok_url, SYSTEM_PROMPT

app = FastAPI(title="SAST & APR Experiment Dashboard")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Workspace directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
APP_DIR = os.path.join(BASE_DIR, "Aplicacion")
RESULTADOS_DIR = os.path.join(APP_DIR, "resultados")
PRUEBAS_JSON_PATH = os.path.join(APP_DIR, "pruebas.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

# Ensure folders exist
os.makedirs(RESULTADOS_DIR, exist_ok=True)
os.makedirs(DATASETS_DIR, exist_ok=True)

# Global dictionary to hold real-time progress and logs
active_runs = {}

# Pydantic models
class ConfigUpdate(BaseModel):
    NGROK_URL: str

class PruebaCreate(BaseModel):
    nombre: str
    descripcion: str
    dataset: str

class PruebaUpdate(BaseModel):
    nombre: str
    descripcion: str

# Helper functions to read/write pruebas.json
def _raw_read_pruebas():
    if not os.path.exists(PRUEBAS_JSON_PATH):
        return []
    try:
        with open(PRUEBAS_JSON_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return []

def write_pruebas(pruebas):
    with open(PRUEBAS_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(pruebas, f, indent=2, ensure_ascii=False)

def sync_pruebas_from_results():
    pruebas = _raw_read_pruebas()
    existing_files = {p.get("resultados_file") for p in pruebas if p.get("resultados_file")}
    
    changed = False
    if os.path.exists(RESULTADOS_DIR):
        for fname in os.listdir(RESULTADOS_DIR):
            if fname.endswith(".csv") and fname not in existing_files:
                fpath = os.path.join(RESULTADOS_DIR, fname)
                try:
                    df = pd.read_csv(fpath)
                    total_casos = len(df)
                    if total_casos == 0:
                        continue
                    
                    acc_det = round(df["acierto_deteccion"].mean() * 100, 2) if "acierto_deteccion" in df.columns else 0.0
                    acc_clas = round(df["acierto_clasificacion"].mean() * 100, 2) if "acierto_clasificacion" in df.columns else 0.0
                    tiempo_prom = round(df["tiempo_segundos"].mean(), 2) if "tiempo_segundos" in df.columns else 0.0
                    
                    if fname.startswith("resultados_prueba_"):
                        parts = fname.replace("resultados_prueba_", "").replace(".csv", "").split("_", 1)
                        p_id = f"prueba_{parts[0]}" if not parts[0].startswith("prueba_") else parts[0]
                        p_name = parts[1].replace("_", " ") if len(parts) > 1 else parts[0]
                    else:
                        p_id = f"prueba_{int(os.path.getmtime(fpath))}"
                        p_name = fname.replace(".csv", "").replace("_", " ")
                    
                    status = "completed" if total_casos >= 300 else "canceled"
                    
                    nueva = {
                        "id": p_id,
                        "nombre": p_name,
                        "descripcion": f"Prueba recuperada desde {fname}",
                        "dataset": "dev_balanced_benchmark2.csv",
                        "fecha_creacion": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(fpath))),
                        "status": status,
                        "resultados_file": fname,
                        "precision_deteccion": acc_det,
                        "precision_clasificacion": acc_clas,
                        "total_casos": 300 if total_casos >= 300 else total_casos,
                        "casos_analizados": total_casos,
                        "tiempo_promedio": tiempo_prom,
                        "system_prompt": SYSTEM_PROMPT,
                        "ultimo_indice_analizado": total_casos - 1
                    }
                    pruebas.append(nueva)
                    changed = True
                except Exception as e:
                    print(f"Error sincronizando {fname}: {e}")
                    
    if changed:
        write_pruebas(pruebas)

def read_pruebas():
    sync_pruebas_from_results()
    return _raw_read_pruebas()

def sanitize_filename(name: str) -> str:
    import unicodedata
    name = unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('ascii')
    name = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)
    name = re.sub(r'_+', '_', name)
    return name.strip('_')

def cleanup_stuck_pruebas():
    pruebas = _raw_read_pruebas()
    changed = False
    for p in pruebas:
        if p["status"] == "running":
            p["status"] = "canceled"
            changed = True
        if "system_prompt" not in p:
            p["system_prompt"] = SYSTEM_PROMPT
            changed = True
        if "ultimo_indice_analizado" not in p:
            casos = p.get("casos_analizados")
            if casos is not None and casos > 0:
                p["ultimo_indice_analizado"] = casos - 1
            else:
                p["ultimo_indice_analizado"] = -1
            changed = True
    if changed:
        write_pruebas(pruebas)

cleanup_stuck_pruebas()
sync_pruebas_from_results()



def update_prueba_status(prueba_id, status, precision_det=None, precision_clas=None, resultados_file=None, total_casos=None, casos_analizados=None, tiempo_promedio=None, ultimo_indice_analizado=None):
    pruebas = read_pruebas()
    for p in pruebas:
        if p["id"] == prueba_id:
            p["status"] = status
            if precision_det is not None:
                p["precision_deteccion"] = precision_det
            if precision_clas is not None:
                p["precision_clasificacion"] = precision_clas
            if resultados_file is not None:
                p["resultados_file"] = resultados_file
            if total_casos is not None:
                p["total_casos"] = total_casos
            if casos_analizados is not None:
                p["casos_analizados"] = casos_analizados
            if tiempo_promedio is not None:
                p["tiempo_promedio"] = tiempo_promedio
            if ultimo_indice_analizado is not None:
                p["ultimo_indice_analizado"] = ultimo_indice_analizado
            break
    write_pruebas(pruebas)

# Background task for running the benchmark
def run_benchmark_task(prueba_id: str, dataset_filename: str, output_filename: str, start_idx: int = 0):
    state = active_runs[prueba_id]
    dataset_path = os.path.join(DATASETS_DIR, dataset_filename)
    output_path = os.path.join(RESULTADOS_DIR, output_filename)
    
    try:
        df = pd.read_csv(dataset_path)
        total_rows = len(df)
        if total_rows == 0:
            raise ValueError("El archivo dataset está vacío.")
        state["total_casos"] = total_rows
        update_prueba_status(prueba_id, "running", total_casos=total_rows)
    except Exception as e:
        state["status"] = "failed"
        state["logs"].append(f"❌ Error al leer el dataset: {str(e)}")
        update_prueba_status(prueba_id, "failed")
        return

    resultados = []
    if start_idx > 0 and os.path.exists(output_path):
        try:
            df_old = pd.read_csv(output_path)
            resultados = df_old.fillna("").to_dict(orient="records")
            state["logs"].append(f"🔄 Reanudando desde registro índice {start_idx} (cargados {len(resultados)} resultados previos)...")
        except Exception as e:
            state["logs"].append(f"⚠️ No se pudieron cargar resultados previos: {str(e)}. Se empezará de cero.")
            resultados = []
            start_idx = 0

    state["logs"].append(f"ℹ️ Iniciando auditoría de {total_rows} casos (empezando en índice {start_idx})...")
    
    for idx, fila in df.iterrows():
        # Skip rows before start_idx
        if idx < start_idx:
            continue
            
        # Check for cancel request
        if state["cancel_flag"]:
            state["logs"].append("⚠️ Cancelación solicitada por el usuario.")
            break
            
        id_muestra = fila['id']
        cwe_real = str(fila['cwe_id']).strip()
        owasp_real = str(fila['categoria_owasp']).strip()
        es_vulnerable_real = bool(fila['es_vulnerable'])
        codigo = fila['codigo']
        lenguaje = str(fila.get('lenguaje', 'python'))
        
        state["logs"].append(f"🔍 [{idx+1}/{total_rows}] Auditando ID: {id_muestra}...")
        
        inicio = time.time()
        try:
            prediccion = auditar_codigo(codigo, lenguaje)
        except Exception as e:
            prediccion = {"error": f"Excepción interna: {str(e)}"}
            
        duracion = round(time.time() - inicio, 2)
        
        # Check if error returned
        if "error" in prediccion:
            state["logs"].append(f"   -> ❌ Falló: {prediccion.get('error')}")
            estado_predicho = "ERROR"
            owasp_predicho = "ERROR"
            owasp_id_predicho = "ERROR"
        else:
            estado_predicho = str(prediccion.get("estado", "ERROR")).strip().upper()
            owasp_predicho = str(prediccion.get("owasp_categoria", "ERROR")).strip()
            owasp_id_predicho = str(prediccion.get("owasp_id", "ERROR")).strip()
            log_label = estado_predicho if owasp_predicho == "No solicitado" else owasp_predicho
            state["logs"].append(f"   -> ✅ Completado: {log_label} ({duracion}s)")
            
        acierto_deteccion = (es_vulnerable_real and estado_predicho == "VULNERABLE") or (not es_vulnerable_real and estado_predicho == "SEGURO")
        acierto_clasificacion = owasp_real.upper() == owasp_predicho.upper()
        
        # Deduplicate records just in case
        resultados = [r for r in resultados if r["id"] != id_muestra]
        
        resultados.append({
            "id": id_muestra,
            "lenguaje": lenguaje,
            "cwe_ground_truth": cwe_real,
            "owasp_ground_truth": owasp_real,
            "owasp_id_predicho": owasp_id_predicho,
            "owasp_categoria_predicho": owasp_predicho,
            "acierto_deteccion": acierto_deteccion,
            "acierto_clasificacion": acierto_clasificacion,
            "estado_predicho": prediccion.get("estado") if "error" not in prediccion else "ERROR",
            "cvss_score": prediccion.get("cvss_score") if "error" not in prediccion else 0.0,
            "cvss_vector": prediccion.get("cvss_vector") if "error" not in prediccion else "Ninguno",
            "explicacion": prediccion.get("explicacion") if "error" not in prediccion else f"Error: {prediccion.get('error')}",
            "codigo_original": codigo,
            "codigo_parchado": codigo if estado_predicho == "SEGURO" else (prediccion.get("codigo_parchado") if "error" not in prediccion else ""),
            "tiempo_segundos": duracion
        })
        
        # Write CSV immediately for crash resilience!
        try:
            pd.DataFrame(resultados).to_csv(output_path, index=False)
        except Exception as e:
            state["logs"].append(f"⚠️ Error al guardar CSV temporal: {str(e)}")
            
        # Update progress and pruebas.json
        state["progress"] = round(((idx + 1) / total_rows) * 100, 2)
        state["casos_analizados"] = len(resultados)
        
        # Compute temporary metrics
        df_temp = pd.DataFrame(resultados)
        precision_det_temp = round(df_temp['acierto_deteccion'].mean() * 100, 2)
        precision_clas_temp = round(df_temp['acierto_clasificacion'].mean() * 100, 2)
        tiempo_prom_temp = round(df_temp['tiempo_segundos'].mean(), 2) if 'tiempo_segundos' in df_temp.columns else 0.0
        
        update_prueba_status(
            prueba_id,
            status="running",
            precision_det=precision_det_temp,
            precision_clas=precision_clas_temp,
            resultados_file=output_filename,
            total_casos=total_rows,
            casos_analizados=len(resultados),
            tiempo_promedio=tiempo_prom_temp,
            ultimo_indice_analizado=idx
        )
        
        time.sleep(0.3)

    # Save final results
    if resultados:
        df_resultados = pd.DataFrame(resultados)
        df_resultados.to_csv(output_path, index=False)
        precision_det = round(df_resultados['acierto_deteccion'].mean() * 100, 2)
        precision_clas = round(df_resultados['acierto_clasificacion'].mean() * 100, 2)
        tiempo_prom = round(df_resultados['tiempo_segundos'].mean(), 2) if 'tiempo_segundos' in df_resultados.columns else 0.0
        
        final_status = "canceled" if state["cancel_flag"] else "completed"
        state["status"] = final_status
        state["logs"].append(f"💾 Resultados guardados en resultados/{output_filename}")
        state["logs"].append(f"📊 Métricas finales -> Detección: {precision_det}%, Clasificación: {precision_clas}%")
        
        last_idx = -1 if final_status == "completed" else idx
        
        update_prueba_status(
            prueba_id,
            status=final_status,
            precision_det=precision_det,
            precision_clas=precision_clas,
            resultados_file=output_filename,
            total_casos=total_rows,
            casos_analizados=len(resultados),
            tiempo_promedio=tiempo_prom,
            ultimo_indice_analizado=last_idx
        )
    else:
        state["status"] = "failed"
        state["logs"].append("❌ No se generó ningún resultado.")
        update_prueba_status(prueba_id, "failed", total_casos=total_rows, casos_analizados=0, ultimo_indice_analizado=-1)

# Endpoints
@app.get("/api/config")
def get_config():
    return {"NGROK_URL": obtener_ngrok_url()}

@app.post("/api/config")
def update_config(config: ConfigUpdate):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({"NGROK_URL": config.NGROK_URL}, f, indent=2)
        return {"status": "ok", "NGROK_URL": config.NGROK_URL}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"No se pudo guardar la configuración: {str(e)}")

@app.get("/api/ping")
def test_ping():
    ngrok_url = obtener_ngrok_url()
    try:
        start = time.time()
        res = requests.get(ngrok_url, timeout=8)
        elapsed = round(time.time() - start, 2)
        if res.status_code == 200:
            try:
                info = res.json()
            except:
                info = {"status": "online", "detail": "Respuesta no es JSON válida"}
            return {"connected": True, "elapsed": elapsed, "info": info}
        else:
            return {"connected": False, "elapsed": elapsed, "detail": f"Código {res.status_code}"}
    except Exception as e:
        return {"connected": False, "detail": str(e)}

@app.get("/api/datasets")
def list_datasets():
    if not os.path.exists(DATASETS_DIR):
        return []
    files = [f for f in os.listdir(DATASETS_DIR) if f.endswith(".csv")]
    return sorted(files)

@app.get("/api/pruebas")
def list_pruebas():
    sync_pruebas_from_results()
    pruebas = read_pruebas()
    updated = False
    for p in pruebas:
        if p.get("total_casos") is None or p.get("casos_analizados") is None or "tiempo_promedio" not in p:
            res_file = p.get("resultados_file")
            has_loaded_df = False
            df_res = None
            
            if res_file:
                res_path = os.path.join(RESULTADOS_DIR, res_file)
                if os.path.exists(res_path):
                    try:
                        df_res = pd.read_csv(res_path)
                        has_loaded_df = True
                    except Exception:
                        pass
            
            if p.get("total_casos") is None or p.get("casos_analizados") is None:
                if has_loaded_df and df_res is not None:
                    count = len(df_res)
                    p["total_casos"] = count
                    p["casos_analizados"] = count
                    updated = True
                else:
                    dataset = p.get("dataset")
                    if dataset:
                        ds_path = os.path.join(DATASETS_DIR, dataset)
                        if os.path.exists(ds_path):
                            try:
                                df_ds = pd.read_csv(ds_path)
                                p["total_casos"] = len(df_ds)
                                p["casos_analizados"] = len(df_ds) if p.get("status") == "completed" else 0
                                updated = True
                            except Exception:
                                pass
                                
            if "tiempo_promedio" not in p or p.get("tiempo_promedio") is None:
                if has_loaded_df and df_res is not None and 'tiempo_segundos' in df_res.columns:
                    p["tiempo_promedio"] = round(df_res['tiempo_segundos'].mean(), 2)
                    updated = True
                else:
                    p["tiempo_promedio"] = None
                    updated = True
    if updated:
        write_pruebas(pruebas)
    return pruebas

@app.post("/api/pruebas")
def create_prueba(p: PruebaCreate, background_tasks: BackgroundTasks):
    dataset_path = os.path.join(DATASETS_DIR, p.dataset)
    if not os.path.exists(dataset_path):
        raise HTTPException(status_code=400, detail=f"El dataset {p.dataset} no existe.")
        
    pruebas = read_pruebas()
    
    # Generate unique ID
    prueba_id = f"prueba_{int(time.time())}"
    
    sanitized_name = sanitize_filename(p.nombre)
    output_filename = f"resultados_{prueba_id}_{sanitized_name}.csv" if sanitized_name else f"resultados_{prueba_id}.csv"

    nueva_prueba = {
        "id": prueba_id,
        "nombre": p.nombre,
        "descripcion": p.descripcion,
        "dataset": p.dataset,
        "fecha_creacion": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "running",
        "resultados_file": output_filename,
        "precision_deteccion": None,
        "precision_clasificacion": None,
        "total_casos": None,
        "casos_analizados": None,
        "tiempo_promedio": None,
        "system_prompt": SYSTEM_PROMPT,
        "ultimo_indice_analizado": -1
    }
    
    pruebas.append(nueva_prueba)
    write_pruebas(pruebas)
    
    # Initialize active run state
    active_runs[prueba_id] = {
        "progress": 0.0,
        "logs": [],
        "status": "running",
        "cancel_flag": False,
        "total_casos": 0,
        "casos_analizados": 0
    }
    
    background_tasks.add_task(run_benchmark_task, prueba_id, p.dataset, output_filename)
    
    return nueva_prueba

@app.get("/api/pruebas/{prueba_id}/status")
def get_prueba_status(prueba_id: str):
    if prueba_id in active_runs:
        return active_runs[prueba_id]
        
    # If not in active_runs but exists in list, return complete status
    pruebas = read_pruebas()
    for p in pruebas:
        if p["id"] == prueba_id:
            return {
                "progress": 100.0 if p["status"] == "completed" else 0.0,
                "logs": [f"ℹ️ Estado de la prueba: {p['status']}"],
                "status": p["status"],
                "cancel_flag": False
            }
            
    raise HTTPException(status_code=404, detail="Prueba no encontrada.")

@app.post("/api/pruebas/{prueba_id}/cancel")
def cancel_prueba(prueba_id: str):
    if prueba_id in active_runs:
        active_runs[prueba_id]["cancel_flag"] = True
        return {"status": "cancellation_requested"}
        
    raise HTTPException(status_code=404, detail="La prueba no está corriendo o no existe.")

@app.get("/api/pruebas/{prueba_id}/resultados")
def get_prueba_resultados(prueba_id: str):
    pruebas = read_pruebas()
    resultados_file = None
    for p in pruebas:
        if p["id"] == prueba_id:
            resultados_file = p["resultados_file"]
            break
            
    if not resultados_file:
        raise HTTPException(status_code=404, detail="Resultados no disponibles para esta prueba.")
        
    path = os.path.join(RESULTADOS_DIR, resultados_file)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="El archivo de resultados físico no existe.")
        
    try:
        df = pd.read_csv(path)
        # Replace NaN to empty string for safety
        df = df.fillna("")
        return df.to_dict(orient="records")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al leer resultados: {str(e)}")

@app.put("/api/pruebas/{prueba_id}/descripcion")
def update_prueba(prueba_id: str, data: PruebaUpdate):
    pruebas = read_pruebas()
    for p in pruebas:
        if p["id"] == prueba_id:
            old_name = p.get("nombre", "")
            old_filename = p.get("resultados_file")
            
            p["nombre"] = data.nombre
            p["descripcion"] = data.descripcion
            
            # If name changed, rename the CSV file
            if old_name != data.nombre:
                sanitized_new = sanitize_filename(data.nombre)
                new_filename = f"resultados_{prueba_id}_{sanitized_new}.csv" if sanitized_new else f"resultados_{prueba_id}.csv"
                
                if old_filename and old_filename != new_filename:
                    old_path = os.path.join(RESULTADOS_DIR, old_filename)
                    new_path = os.path.join(RESULTADOS_DIR, new_filename)
                    if os.path.exists(old_path):
                        try:
                            os.rename(old_path, new_path)
                        except:
                            pass
                    p["resultados_file"] = new_filename
                    
            write_pruebas(pruebas)
            return {
                "status": "success", 
                "nombre": p["nombre"], 
                "descripcion": p["descripcion"],
                "resultados_file": p.get("resultados_file")
            }
    raise HTTPException(status_code=404, detail="Prueba no encontrada")

@app.delete("/api/pruebas/{prueba_id}")
def delete_prueba(prueba_id: str):
    pruebas = read_pruebas()
    resultados_file = None
    nueva_lista = []
    found = False
    
    for p in pruebas:
        if p["id"] == prueba_id:
            resultados_file = p["resultados_file"]
            found = True
        else:
            nueva_lista.append(p)
            
    if not found:
        raise HTTPException(status_code=404, detail="Prueba no encontrada.")
        
    write_pruebas(nueva_lista)
    
    # Delete results file if exists
    if resultados_file:
        path = os.path.join(RESULTADOS_DIR, resultados_file)
        if os.path.exists(path):
            try:
                os.remove(path)
            except:
                pass
                
    # Clean up active runs cache
    if prueba_id in active_runs:
        del active_runs[prueba_id]
        
    return {"status": "ok"}

@app.post("/api/pruebas/{prueba_id}/resume")
def resume_prueba(prueba_id: str, background_tasks: BackgroundTasks):
    pruebas = read_pruebas()
    target_prueba = None
    for p in pruebas:
        if p["id"] == prueba_id:
            target_prueba = p
            break
            
    if not target_prueba:
        raise HTTPException(status_code=404, detail="Prueba no encontrada")
        
    if target_prueba["status"] == "running":
        raise HTTPException(status_code=400, detail="La prueba ya está en ejecución")
        
    dataset_path = os.path.join(DATASETS_DIR, target_prueba["dataset"])
    if not os.path.exists(dataset_path):
        raise HTTPException(status_code=400, detail=f"El dataset {target_prueba['dataset']} no existe.")

    # Get index to start from
    last_idx = target_prueba.get("ultimo_indice_analizado", -1)
    start_idx = last_idx + 1 if last_idx >= 0 else 0
    
    # Update status to running
    target_prueba["status"] = "running"
    write_pruebas(pruebas)
    
    # Initialize active run state
    active_runs[prueba_id] = {
        "progress": round((start_idx / target_prueba.get("total_casos", 1)) * 100, 2) if target_prueba.get("total_casos") else 0.0,
        "logs": [f"🔄 Reanudando ejecución de prueba en segundo plano desde el índice {start_idx}..."],
        "status": "running",
        "cancel_flag": False,
        "total_casos": target_prueba.get("total_casos", 0),
        "casos_analizados": target_prueba.get("casos_analizados", 0)
    }
    
    output_filename = target_prueba["resultados_file"] or f"resultados_{prueba_id}.csv"
    background_tasks.add_task(run_benchmark_task, prueba_id, target_prueba["dataset"], output_filename, start_idx)
    return {"status": "success", "message": f"Prueba reanudada en índice {start_idx}"}

# Serve static frontend files
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")

@app.get("/")
def read_index():
    return RedirectResponse(url="/static/index.html")
