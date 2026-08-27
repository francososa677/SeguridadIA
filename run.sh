#!/bin/bash
echo "🚀 Iniciando la aplicación web de auditoría SAST..."
echo "👉 Abre tu navegador en: http://127.0.0.1:8000"
.venv/bin/uvicorn Aplicacion.main:app --host 127.0.0.1 --port 8000 --reload
