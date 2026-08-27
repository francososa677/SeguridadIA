import requests
import time

NGROK_URL = "https://jinx-dwindling-gloss.ngrok-free.dev"

def test_ping():
    print(f"Probando conexión con: {NGROK_URL} ...")
    start = time.time()
    try:
        # Petición GET rápida al endpoint base
        res = requests.get(NGROK_URL, timeout=10)
        elapsed = round(time.time() - start, 2)
        
        if res.status_code == 200:
            print(f"✅ CONEXIÓN EXITOSA ({elapsed}s)")
            print(f"Respuesta del servidor: {res.json()}")
        else:
            print(f"⚠️ Servidor respondió con código: {res.status_code}")
            print(res.text)
    except requests.exceptions.Timeout:
        print("❌ ERROR: Tiempo de espera agotado (Timeout). Verificá que la celda de Uvicorn en Colab siga en ejecución.")
    except requests.exceptions.RequestException as e:
        print(f"❌ ERROR de red: {e}")

if __name__ == "__main__":
    test_ping()