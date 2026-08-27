import os
import re
import random
import pandas as pd
from datasets import load_dataset

# Configuration
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "datasets")
os.makedirs(OUTPUT_DIR, exist_ok=True)

LANGUAGES = ["python", "javascript", "java", "c++", "c", "go", "php", "ruby"]

# Target configuration for 300 balanced cases (150 safe / 150 vulnerable)
# 6 languages with 19 safe & 19 vuln = 228
# 2 languages with 18 safe & 18 vuln = 72
# Total: 300
LANG_CONFIG = {
    "python": {"safe": 19, "vuln": 19},
    "javascript": {"safe": 19, "vuln": 19},
    "java": {"safe": 19, "vuln": 19},
    "c++": {"safe": 19, "vuln": 19},
    "c": {"safe": 19, "vuln": 19},
    "go": {"safe": 19, "vuln": 19},
    "php": {"safe": 18, "vuln": 18},
    "ruby": {"safe": 18, "vuln": 18}
}

# Mapping common CWEs to OWASP Top 10 (2021)
CWE_TO_OWASP = {
    # A01:2021-Broken Access Control
    "CWE-22": "A01:2021-Broken Access Control",
    "CWE-23": "A01:2021-Broken Access Control",
    "CWE-284": "A01:2021-Broken Access Control",
    "CWE-285": "A01:2021-Broken Access Control",
    "CWE-287": "A01:2021-Broken Access Control",
    "CWE-306": "A01:2021-Broken Access Control",
    "CWE-352": "A01:2021-Broken Access Control",
    "CWE-425": "A01:2021-Broken Access Control",
    "CWE-639": "A01:2021-Broken Access Control",
    "CWE-862": "A01:2021-Broken Access Control",
    "CWE-863": "A01:2021-Broken Access Control",
    # A02:2021-Cryptographic Failures
    "CWE-259": "A02:2021-Cryptographic Failures",
    "CWE-311": "A02:2021-Cryptographic Failures",
    "CWE-312": "A02:2021-Cryptographic Failures",
    "CWE-319": "A02:2021-Cryptographic Failures",
    "CWE-326": "A02:2021-Cryptographic Failures",
    "CWE-327": "A02:2021-Cryptographic Failures",
    "CWE-328": "A02:2021-Cryptographic Failures",
    "CWE-330": "A02:2021-Cryptographic Failures",
    "CWE-338": "A02:2021-Cryptographic Failures",
    "CWE-347": "A02:2021-Cryptographic Failures",
    "CWE-522": "A02:2021-Cryptographic Failures",
    "CWE-916": "A02:2021-Cryptographic Failures",
    # A03:2021-Injection
    "CWE-74": "A03:2021-Injection",
    "CWE-77": "A03:2021-Injection",
    "CWE-78": "A03:2021-Injection",
    "CWE-79": "A03:2021-Injection",
    "CWE-89": "A03:2021-Injection",
    "CWE-94": "A03:2021-Injection",
    "CWE-917": "A03:2021-Injection",
    # A05:2021-Security Misconfiguration
    "CWE-276": "A05:2021-Security Misconfiguration",
    "CWE-732": "A05:2021-Security Misconfiguration",
    # A07:2021-Identification and Authentication Failures
    "CWE-798": "A07:2021-Identification and Authentication Failures",
    # A08:2021-Software and Data Integrity Failures
    "CWE-353": "A08:2021-Software and Data Integrity Failures",
    "CWE-354": "A08:2021-Software and Data Integrity Failures",
    "CWE-494": "A08:2021-Software and Data Integrity Failures",
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
    "CWE-829": "A08:2021-Software and Data Integrity Failures",
    # A09:2021-Security Logging Failures
    "CWE-209": "A09:2021-Security Logging Failures",
    "CWE-532": "A09:2021-Security Logging Failures",
    # A10:2021-Server-Side Request Forgery
    "CWE-918": "A10:2021-Server-Side Request Forgery",
}

def clean_code(code_str):
    if not isinstance(code_str, str):
        return ""
    code_str = code_str.strip()
    if code_str.startswith("```"):
        first_line_end = code_str.find("\n")
        if first_line_end != -1:
            code_str = code_str[first_line_end+1:]
        if code_str.endswith("```"):
            code_str = code_str[:-3]
    return code_str.strip()

def map_cwe_to_owasp(cwe_id):
    if not isinstance(cwe_id, str):
        return "Otros/General"
    cwe_id = cwe_id.upper().strip()
    return CWE_TO_OWASP.get(cwe_id, "Otros/General")

def map_description_to_cwe_and_owasp(description):
    desc_lower = description.lower() if isinstance(description, str) else ""
    if "sql injection" in desc_lower or "sql-injection" in desc_lower:
        return "CWE-89", "A03:2021-Injection", "SQL Injection"
    elif "command injection" in desc_lower:
        return "CWE-78", "A03:2021-Injection", "OS Command Injection"
    elif "deserialization" in desc_lower:
        return "CWE-502", "A08:2021-Software and Data Integrity Failures", "Deserialization of Untrusted Data"
    elif "cryptographic" in desc_lower or "hash" in desc_lower or "random" in desc_lower or "prng" in desc_lower:
        return "CWE-338", "A02:2021-Cryptographic Failures", "Cryptographically Weak PRNG"
    elif "buffer overflow" in desc_lower or "memory management" in desc_lower:
        return "CWE-120", "Otros/General", "Buffer Overflow"
    elif "xss" in desc_lower or "cross-site scripting" in desc_lower:
        return "CWE-79", "A03:2021-Injection", "Cross-Site Scripting"
    elif "hard-coded" in desc_lower or "credential" in desc_lower or "password" in desc_lower:
        return "CWE-798", "A07:2021-Identification and Authentication Failures", "Hard-coded Credentials"
    elif "path traversal" in desc_lower or "directory traversal" in desc_lower:
        return "CWE-22", "A01:2021-Broken Access Control", "Path Traversal"
    return "CWE-Other", "Otros/General", "General Vulnerability"

def main():
    print("Loading datasets in memory...")

    # 1. Load DPO dataset
    print("Loading CyberNative/Code_Vulnerability_Security_DPO...")
    dpo_dataset = load_dataset("CyberNative/Code_Vulnerability_Security_DPO")
    df_dpo = pd.DataFrame(dpo_dataset['train'])
    df_dpo["lang"] = df_dpo["lang"].str.lower()

    # 2. Load CVEfixes dataset (solo se usa para el lenguaje C en este script)
    print("Loading hitoshura25/cvefixes...")
    cvefixes_dataset = load_dataset("hitoshura25/cvefixes")
    df_cve = pd.DataFrame(cvefixes_dataset['train'])
    df_cve["language"] = df_cve["language"].str.lower()

    # Nos quedamos solo con las filas de "c" antes de limpiar, para no
    # procesar innecesariamente los otros lenguajes de CVEfixes
    # (ya que ahora solo generamos DEV y los otros 7 lenguajes salen del DPO dataset)
    df_c_cve = df_cve[df_cve["language"] == "c"].copy()

    # Liberamos el dataframe grande de CVEfixes, ya no lo necesitamos completo
    del df_cve

    # Clean CVEfixes (C): asegurar que las columnas de código sean string y no estén vacías
    df_c_cve = df_c_cve[df_c_cve["vulnerable_code"].notna() & df_c_cve["fixed_code"].notna()].copy()
    df_c_cve["vulnerable_code"] = df_c_cve["vulnerable_code"].apply(clean_code)
    df_c_cve["fixed_code"] = df_c_cve["fixed_code"].apply(clean_code)
    df_c_cve = df_c_cve[(df_c_cve["vulnerable_code"] != "") & (df_c_cve["fixed_code"] != "")].copy()

    # Shuffle
    df_c_cve = df_c_cve.sample(frac=1, random_state=42).reset_index(drop=True)

    # Solo necesitamos 19 safe y 19 vuln para DEV (ya no generamos TEST en este script)
    dev_c_safe = df_c_cve.iloc[:19]
    dev_c_vuln = df_c_cve.iloc[19:38]

    # Verify we have enough C samples (ahora solo se necesitan 38, no 76)
    if len(df_c_cve) < 38:
        raise ValueError(f"Not enough valid C samples in CVEfixes: got {len(df_c_cve)}, need 38.")

    dev_records = []
    # test_records = []  # No se usa en este script (solo generamos DEV)

    # --- BUILD DEV DATASET (DPO for 7 languages, CVEfixes for C) ---
    print("\nBuilding validation (DEV) dataset...")
    # Add C samples first
    for _, row in dev_c_safe.iterrows():
        dev_records.append({
            "id": f"dev_safe_c_{len(dev_records)}",
            "cwe_id": "Seguro",
            "nombre_vulnerabilidad": "Ninguna",
            "categoria_owasp": "Seguro",
            "lenguaje": "c",
            "codigo": row["fixed_code"],
            "es_vulnerable": False
        })
    for _, row in dev_c_vuln.iterrows():
        cwe_id = row["cwe_id"] if pd.notna(row["cwe_id"]) else "CWE-Other"
        cwe_name = row["cwe_name"] if pd.notna(row["cwe_name"]) else "General Vulnerability"
        owasp = map_cwe_to_owasp(cwe_id)
        dev_records.append({
            "id": f"dev_vuln_c_{len(dev_records)}",
            "cwe_id": cwe_id,
            "nombre_vulnerabilidad": cwe_name,
            "categoria_owasp": owasp,
            "lenguaje": "c",
            "codigo": row["vulnerable_code"],
            "es_vulnerable": True
        })

    # Process other 7 languages from DPO
    for lang, config in LANG_CONFIG.items():
        if lang == "c":
            continue

        lang_dpo = df_dpo[df_dpo["lang"] == lang].sample(frac=1, random_state=42).reset_index(drop=True)
        half = len(lang_dpo) // 2
        safe_source = lang_dpo.iloc[:half]
        vuln_source = lang_dpo.iloc[half:]

        # Take safe samples
        safe_samples = safe_source.head(config["safe"])
        for _, row in safe_samples.iterrows():
            dev_records.append({
                "id": f"dev_safe_{lang}_{len(dev_records)}",
                "cwe_id": "Seguro",
                "nombre_vulnerabilidad": "Ninguna",
                "categoria_owasp": "Seguro",
                "lenguaje": lang,
                "codigo": clean_code(row["chosen"]),
                "es_vulnerable": False
            })

        # Take vuln samples
        vuln_samples = vuln_source.head(config["vuln"])
        for _, row in vuln_samples.iterrows():
            cwe, owasp, name = map_description_to_cwe_and_owasp(row["vulnerability"])
            dev_records.append({
                "id": f"dev_vuln_{lang}_{len(dev_records)}",
                "cwe_id": cwe,
                "nombre_vulnerabilidad": name,
                "categoria_owasp": owasp,
                "lenguaje": lang,
                "codigo": clean_code(row["rejected"]),
                "es_vulnerable": True
            })

    # --- BUILD TEST DATASET (All 8 languages from CVEfixes) ---
    # Comentado: este script ahora solo genera el dataset DEV.
    # Si en el futuro se necesita regenerar TEST, hay que volver a cargar
    # df_cve completo (los otros 7 lenguajes) y descomentar este bloque.
    #
    # print("Building evaluation (TEST) dataset...")
    # # Add C samples first
    # for _, row in test_c_safe.iterrows():
    #     test_records.append({
    #         "id": f"test_safe_c_{len(test_records)}",
    #         "cwe_id": "Seguro",
    #         "nombre_vulnerabilidad": "Ninguna",
    #         "categoria_owasp": "Seguro",
    #         "lenguaje": "c",
    #         "codigo": row["fixed_code"],
    #         "es_vulnerable": False
    #     })
    # for _, row in test_c_vuln.iterrows():
    #     cwe_id = row["cwe_id"] if pd.notna(row["cwe_id"]) else "CWE-Other"
    #     cwe_name = row["cwe_name"] if pd.notna(row["cwe_name"]) else "General Vulnerability"
    #     owasp = map_cwe_to_owasp(cwe_id)
    #     test_records.append({
    #         "id": f"test_vuln_c_{len(test_records)}",
    #         "cwe_id": cwe_id,
    #         "nombre_vulnerabilidad": cwe_name,
    #         "categoria_owasp": owasp,
    #         "lenguaje": "c",
    #         "codigo": row["vulnerable_code"],
    #         "es_vulnerable": True
    #     })
    #
    # # Process other 7 languages from CVEfixes
    # for lang, config in LANG_CONFIG.items():
    #     if lang == "c":
    #         continue
    #
    #     lang_cve = df_cve[df_cve["language"] == lang].sample(frac=1, random_state=42).reset_index(drop=True)
    #     half = len(lang_cve) // 2
    #     safe_source = lang_cve.iloc[:half]
    #     vuln_source = lang_cve.iloc[half:]
    #
    #     # Take safe samples
    #     safe_samples = safe_source.head(config["safe"])
    #     for _, row in safe_samples.iterrows():
    #         test_records.append({
    #             "id": f"test_safe_{lang}_{len(test_records)}",
    #             "cwe_id": "Seguro",
    #             "nombre_vulnerabilidad": "Ninguna",
    #             "categoria_owasp": "Seguro",
    #             "lenguaje": lang,
    #             "codigo": row["fixed_code"],
    #             "es_vulnerable": False
    #         })
    #
    #     # Take vuln samples
    #     vuln_samples = vuln_source.head(config["vuln"])
    #     for _, row in vuln_samples.iterrows():
    #         cwe_id = row["cwe_id"] if pd.notna(row["cwe_id"]) else "CWE-Other"
    #         cwe_name = row["cwe_name"] if pd.notna(row["cwe_name"]) else "General Vulnerability"
    #         owasp = map_cwe_to_owasp(cwe_id)
    #         test_records.append({
    #             "id": f"test_vuln_{lang}_{len(test_records)}",
    #             "cwe_id": cwe_id,
    #             "nombre_vulnerabilidad": cwe_name,
    #             "categoria_owasp": owasp,
    #             "lenguaje": lang,
    #             "codigo": row["vulnerable_code"],
    #             "es_vulnerable": True
    #         })

    # Shuffle and save DEV dataset
    dev_df = pd.DataFrame(dev_records)
    dev_df = dev_df.sample(frac=1, random_state=42).reset_index(drop=True)
    dev_path = os.path.join(OUTPUT_DIR, "dev_balanced_benchmark.csv")
    dev_df.to_csv(dev_path, index=False)
    print(f"Saved {len(dev_df)} records to {dev_path} (Safe: {len(dev_df[dev_df['es_vulnerable'] == False])}, Vulnerable: {len(dev_df[dev_df['es_vulnerable'] == True])})")

    # Shuffle and save TEST dataset
    # Comentado junto con la construcción de test_records
    # test_df = pd.DataFrame(test_records)
    # test_df = test_df.sample(frac=1, random_state=42).reset_index(drop=True)
    # test_path = os.path.join(OUTPUT_DIR, "test_balanced_benchmark.csv")
    # test_df.to_csv(test_path, index=False)
    # print(f"Saved {len(test_df)} records to {test_path} (Safe: {len(test_df[test_df['es_vulnerable'] == False])}, Vulnerable: {len(test_df[test_df['es_vulnerable'] == True])})")

    print("\nDEV dataset processed successfully and verified!")

if __name__ == "__main__":
    main()