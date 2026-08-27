import pandas as pd
import numpy as np

# Load the results CSV
csv_path = "Aplicacion/resultados/Primer_prueba_con_nuevo_data_set.csv"
df = pd.read_csv(csv_path)

# Overall numbers
total = len(df)
det_ok = df['acierto_deteccion'].sum()
clas_ok = df['acierto_clasificacion'].sum()

# Confusion Matrix
tp = len(df[(df['owasp_ground_truth'] != 'Seguro') & (df['estado_predicho'] == 'VULNERABLE')])
fn = len(df[(df['owasp_ground_truth'] != 'Seguro') & (df['estado_predicho'] == 'SEGURO')])
fp = len(df[(df['owasp_ground_truth'] == 'Seguro') & (df['estado_predicho'] == 'VULNERABLE')])
tn = len(df[(df['owasp_ground_truth'] == 'Seguro') & (df['estado_predicho'] == 'SEGURO')])

precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
fpr = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0
fnr = (fn / (fn + tp)) * 100 if (fn + tp) > 0 else 0

# Print to generate report content
print("## Resumen General de Métricas")
print(f"- **Total de casos analizados**: {total}")
print(f"- **Acierto en Detección (Vulnerable vs Seguro)**: {det_ok / total * 100:.2f}% ({det_ok}/{total})")
print(f"- **Acierto en Clasificación OWASP**: {clas_ok / total * 100:.2f}% ({clas_ok}/{total})")
print(f"- **Precisión (Precision)**: {precision:.2f}%")
print(f"- **Sensibilidad / Cobertura (Recall)**: {recall:.2f}%")
print(f"- **F1-Score**: {f1:.2f}%")
print(f"- **Tasa de Falsos Positivos (FPR / Falsas Alarmas)**: {fpr:.2f}% ({fp}/{fp + tn})")
print(f"- **Tasa de Falsos Negativos (FNR / Omisiones)**: {fnr:.2f}% ({fn}/{fn + tp})")

print("\n## Rendimiento por Lenguaje")
languages = df['lenguaje'].unique()
for lang in sorted(languages):
    ldf = df[df['lenguaje'] == lang]
    ltotal = len(ldf)
    ldet = ldf['acierto_deteccion'].mean() * 100
    lclas = ldf['acierto_clasificacion'].mean() * 100
    
    ltp = len(ldf[(ldf['owasp_ground_truth'] != 'Seguro') & (ldf['estado_predicho'] == 'VULNERABLE')])
    lfn = len(ldf[(ldf['owasp_ground_truth'] != 'Seguro') & (ldf['estado_predicho'] == 'SEGURO')])
    lfp = len(ldf[(ldf['owasp_ground_truth'] == 'Seguro') & (ldf['estado_predicho'] == 'VULNERABLE')])
    ltn = len(ldf[(ldf['owasp_ground_truth'] == 'Seguro') & (ldf['estado_predicho'] == 'SEGURO')])
    
    lfpr = (lfp / (lfp + ltn)) * 100 if (lfp + ltn) > 0 else 0
    lfnr = (lfn / (lfn + ltp)) * 100 if (lfn + ltp) > 0 else 0
    
    print(f"### {lang.upper()}")
    print(f"- **Casos totales**: {ltotal}")
    print(f"- **Acierto Detección**: {ldet:.2f}%")
    print(f"- **Acierto Clasificación**: {lclas:.2f}%")
    print(f"- **Falsos Positivos (FPR)**: {lfpr:.2f}% ({lfp}/{lfp + ltn})")
    print(f"- **Falsos Negativos (FNR)**: {lfnr:.2f}% ({lfn}/{lfn + ltp})")

print("\n## Análisis de Errores Críticos")
print("### 1. Falsos Positivos: Código seguro clasificado como vulnerable")
fp_cases = df[(df['owasp_ground_truth'] == 'Seguro') & (df['estado_predicho'] == 'VULNERABLE')]
print(fp_cases.groupby('owasp_categoria_predicho').size().nlargest(5))

print("\n### 2. Clasificaciones erróneas más comunes (Ground Truth -> Predicho)")
misclass = df[(df['owasp_ground_truth'] != df['owasp_categoria_predicho'])]
print(misclass.groupby(['owasp_ground_truth', 'owasp_categoria_predicho']).size().nlargest(8))
