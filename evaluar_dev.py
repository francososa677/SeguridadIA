import pandas as pd
import json
import time
from llm import auditar_codigo

# ==============================================================================
# PROCESAMIENTO Y EVALUACIÓN DEL DATASET DE PRUEBAS (BENCHMARK)
# ==============================================================================

def ejecutar_benchmark(archivo_entrada, archivo_salida):
    """
    Carga un archivo CSV que contiene un conjunto de prueba (benchmark) de código seguro y vulnerable,
    envía cada caso al agente de análisis (LLM), evalúa la precisión del veredicto y escribe 
    las métricas detalladas en un nuevo archivo CSV de salida.
    
    Parámetros:
      - archivo_entrada: Ruta del CSV origen con las columnas 'id', 'cwe_id', 'categoria_owasp', 'es_vulnerable', 'codigo', 'lenguaje'.
      - archivo_salida: Ruta del CSV destino donde se escribirán los veredictos y explicaciones del LLM.
    """
    print(f"Leyendo casos desde: {archivo_entrada} ...")
    # Cargar el dataset usando pandas
    df = pd.read_csv(archivo_entrada)
    total_filas = len(df)
    
    # Lista donde iremos acumulando los resultados de cada análisis
    resultados = []
    print(f"Iniciando evaluación de {total_filas} casos con Qwen2.5-Coder...\n")
    
    try:
        # iterrows() nos permite recorrer fila por fila el DataFrame de pandas
        for idx, fila in df.iterrows():
            id_muestra = fila['id']
            cwe_real = str(fila['cwe_id']).strip()
            owasp_real = str(fila['categoria_owasp']).strip()
            es_vulnerable_real = bool(fila['es_vulnerable'])
            codigo = fila['codigo']
            # Obtener lenguaje (usa 'python' por defecto si la columna no existe en el CSV)
            lenguaje = str(fila.get('lenguaje', 'python'))
            
            print(f"[{idx+1}/{total_filas}] Auditando ID: {id_muestra} (Ground Truth OWASP: {owasp_real})...")
            
            # Medir el tiempo que demora el LLM en responder la consulta
            inicio = time.time()
            # Llamamos a la función auditar_codigo de llm.py, que maneja el envío HTTP y la validación
            prediccion = auditar_codigo(codigo, lenguaje)
            duracion = round(time.time() - inicio, 2)
            
            # Normalizar los datos devueltos por el LLM
            estado_predicho = str(prediccion.get("estado", "ERROR")).strip().upper()
            owasp_predicho = str(prediccion.get("owasp_categoria", "ERROR")).strip()
            owasp_id_predicho = str(prediccion.get("owasp_id", "ERROR")).strip()
            
            # ------------------------------------------------------------------
            # CÁLCULO DE ACIERTOS (Métricas de Confusión)
            # ------------------------------------------------------------------
            #
            # Acierto de Detección (Vulnerable vs Seguro):
            # Es verdadero (True) si el código es realmente vulnerable y el LLM predice "VULNERABLE",
            # o si el código es realmente seguro y el LLM predice "SEGURO".
            acierto_deteccion = (es_vulnerable_real and estado_predicho == "VULNERABLE") or (not es_vulnerable_real and estado_predicho == "SEGURO")
            
            # Acierto de Clasificación (Categoría OWASP exacta):
            # Es verdadero (True) si la categoría OWASP real (Ground Truth) coincide
            # textualmente con la categoría que predijo el LLM.
            acierto_clasificacion = owasp_real.upper() == owasp_predicho.upper()
            
            # Imprimir resultado en consola del caso evaluado en tiempo real
            print(f"   -> Predicción: {owasp_predicho} | Acierto Det: {'✅' if acierto_deteccion else '❌'} | Acierto Clas: {'✅' if acierto_clasificacion else '❌'} ({duracion}s)")
            
            # Acumular toda la información en la lista de resultados para guardarla luego
            resultados.append({
                "id": id_muestra,
                "lenguaje": lenguaje,
                "cwe_ground_truth": cwe_real,
                "owasp_ground_truth": owasp_real,
                "owasp_id_predicho": owasp_id_predicho,
                "owasp_categoria_predicho": owasp_predicho,
                "acierto_deteccion": acierto_deteccion,
                "acierto_clasificacion": acierto_clasificacion,
                "estado_predicho": prediccion.get("estado"),
                "cvss_score": prediccion.get("cvss_score"),
                "cvss_vector": prediccion.get("cvss_vector"),
                "explicacion": prediccion.get("explicacion"),
                "codigo_original": codigo,
                "codigo_parchado": prediccion.get("codigo_parchado"),
                "tiempo_segundos": duracion
            })
            
            # Pequeña pausa para no saturar el servidor del modelo y permitir interrupciones limpias
            time.sleep(0.3)
            
    finally:
        # El bloque 'finally' asegura que, incluso si el script es cancelado por el usuario (Ctrl+C)
        # o arroja un error inesperado a la mitad, guardaremos los datos que hayamos logrado procesar.
        if resultados:
            # Crear un DataFrame con todos los casos procesados
            df_resultados = pd.DataFrame(resultados)
            # Guardar como archivo CSV
            df_resultados.to_csv(archivo_salida, index=False)
            
            # Calcular promedios generales de precisión
            precision_det = df_resultados['acierto_deteccion'].mean() * 100
            precision_clas = df_resultados['acierto_clasificacion'].mean() * 100
            
            # Imprimir informe resumido por consola
            print("\n" + "="*50)
            print(f"Progreso guardado ({len(resultados)}/{total_filas} casos).")
            print(f"Resultados guardados en: {archivo_salida}")
            print(f"Precisión de DETECCIÓN: {precision_det:.2f}%")
            print(f"Precisión de CLASIFICACIÓN OWASP: {precision_clas:.2f}%")
            print("="*50)
        else:
            print("\nNo se recolectaron resultados para guardar.")

# ==============================================================================
# EJECUCIÓN DEL SCRIPT
# ==============================================================================
if __name__ == "__main__":
    # Configuración por defecto: lee 'dev_benchmark.csv' y guarda como 'resultados_dev.csv'
    ejecutar_benchmark("dev_benchmark.csv", "resultados_dev.csv")