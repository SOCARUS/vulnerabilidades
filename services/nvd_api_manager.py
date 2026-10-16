import sqlite3
import requests
import time
import csv
from datetime import datetime

DB_FILE = "vulnerabilities.db"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def init_metadata_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cve_metadata (
        cve TEXT PRIMARY KEY,
        cvss_score REAL,
        exploitability_score REAL,
        impact_score REAL,
        severity TEXT,
        attack_vector TEXT,
        attack_complexity TEXT,
        privileges_required TEXT,
        user_interaction TEXT,
        last_modified TEXT,
        cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

def get_cve_info_v2(cve_id, api_key=None, retries=3):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Verificar en caché primero
    cur.execute("SELECT * FROM cve_metadata WHERE cve = ?", (cve_id,))
    row = cur.fetchone()
    if row:
        cols = [d[0] for d in cur.description]
        conn.close()
        return dict(zip(cols, row))

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "cveId": cve_id
    }

    # Control de velocidad: 6s sin key, 1s con key
    delay = 1 if api_key else 6

    for attempt in range(retries):
        try:
            resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    conn.close()
                    return None

                vuln = vulns[0]
                cve_item = vuln.get("cve")
                last_mod = vuln.get("lastModified")

                metrics = cve_item.get("metrics", {})
                cvss_v3 = None
                exploitability = None
                impact = None
                severity = None
                av = ac = pr = ui = None

                # cvssMetricV31 → preferido
                if "cvssMetricV31" in metrics:
                    m = metrics["cvssMetricV31"][0]
                    cvss_v3 = m.get("cvssData", {}).get("baseScore")
                    severity = m.get("cvssData", {}).get("baseSeverity")
                    exploitability = m.get("exploitabilityScore")
                    impact = m.get("impactScore")
                    av = m.get("cvssData", {}).get("attackVector")
                    ac = m.get("cvssData", {}).get("attackComplexity")
                    pr = m.get("cvssData", {}).get("privilegesRequired")
                    ui = m.get("cvssData", {}).get("userInteraction")

                # Fallback a cvssMetricV3
                elif "cvssMetricV3" in metrics:
                    m = metrics["cvssMetricV3"][0]
                    cvss_v3 = m.get("cvssData", {}).get("baseScore")
                    severity = m.get("cvssData", {}).get("baseSeverity")
                    exploitability = m.get("exploitabilityScore")
                    impact = m.get("impactScore")
                    av = m.get("cvssData", {}).get("attackVector")
                    ac = m.get("cvssData", {}).get("attackComplexity")
                    pr = m.get("cvssData", {}).get("privilegesRequired")
                    ui = m.get("cvssData", {}).get("userInteraction")

                cve_info = {
                    "cve": cve_id,
                    "cvss_score": cvss_v3,
                    "exploitability_score": exploitability,
                    "impact_score": impact,
                    "severity": severity,
                    "attack_vector": av,
                    "attack_complexity": ac,
                    "privileges_required": pr,
                    "user_interaction": ui,
                    "last_modified": last_mod
                }

                cur.execute("""
                    INSERT OR REPLACE INTO cve_metadata
                    (cve, cvss_score, exploitability_score, impact_score, severity,
                     attack_vector, attack_complexity, privileges_required,
                     user_interaction, last_modified)
                    VALUES (:cve, :cvss_score, :exploitability_score, :impact_score, :severity,
                            :attack_vector, :attack_complexity, :privileges_required,
                            :user_interaction, :last_modified)
                """, cve_info)
                conn.commit()
                conn.close()

                # Respetar rate limit
                time.sleep(delay)
                return cve_info
            else:
                print(f"⚠️ Error {resp.status_code} al consultar {cve_id}")
        except Exception as e:
            print(f"❌ Excepción: {e}, intento {attempt+1}/{retries}")
        time.sleep(delay)

    conn.close()
    return None

def export_to_csv(output_path=None):
    """
    Exporta todos los registros de la tabla cve_metadata a un archivo CSV.
    
    Args:
        output_path: Ruta del archivo CSV. Si no se especifica, se genera 
                     automáticamente con la fecha actual.
    
    Returns:
        str: Ruta del archivo CSV generado, o None si no hay registros.
    """
    if output_path is None:
        output_path = f"cve_metadata_{datetime.now().strftime('%Y-%m-%d')}.csv"
    
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM cve_metadata")
    rows = cur.fetchall()
    
    if not rows:
        print("No hay registros en la base de datos.")
        conn.close()
        return None
    
    columns = [description[0] for description in cur.description]
    conn.close()
    
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(columns)
        writer.writerows(rows)
    
    print(f"✅ Exportados {len(rows)} registros a '{output_path}'")
    return output_path

if __name__ == "__main__":
    init_metadata_db()
    test_cve = "CVE-2021-44228"
    info = get_cve_info_v2(test_cve)
    if info:
        print(f"Información para {test_cve}: {info}")
    else:
        print(f"No se encontró información para {test_cve}")