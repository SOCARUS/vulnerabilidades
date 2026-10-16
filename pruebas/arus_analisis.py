from datetime import datetime
import pandas as pd
import glob
import os

fecha = datetime.now().strftime("%Y-%m-%d")
input_dir = f"/logs/arus/{fecha}/json/"
output_dir = f"./output/arus/{fecha}/cleaned/" # 📂 carpeta donde guardar archivos limpios
os.makedirs(output_dir, exist_ok=True)

summary = []

def get_agent_id(agent):
    if isinstance(agent, dict):
        return agent.get("id")
    return None

def get_package_name(pkg):
    if isinstance(pkg, dict):
        return pkg.get("name")
    return None

def get_package_version(pkg):
    if isinstance(pkg, dict):
        return pkg.get("version")
    return None

def get_vuln_cve(vuln):
    if isinstance(vuln, dict):
        return vuln.get("cve")
    if isinstance(vuln, list) and len(vuln) > 0:
        first = vuln[0]
        if isinstance(first, dict):
            return first.get("cve")
        return first
    return None



for file in glob.glob(f"{input_dir}/*.jsonl"):
    print(f"Procesando {file} ...")

    try:
        # Cargar como NDJSON (1 evento por línea)
        df = pd.read_json(file, lines=True)

        total = len(df)

        # Extraer campos anidados
        if "agent" in df.columns:
            df["agent_id"] = df["agent"].apply(get_agent_id)

        if "package" in df.columns:
            df["package_name"] = df["package"].apply(get_package_name)
            df["package_version"] = df["package"].apply(get_package_version)

        if "vulnerability" in df.columns:
            df["vuln_cve"] = df["vulnerability"].apply(get_vuln_cve)

        # Quitar duplicados
        df_unique = df.drop_duplicates(subset=["agent_id", "package_name", "vuln_cve", "package_version"])

        total_unique = len(df_unique)
        removed = total - total_unique

        # Guardar limpio
        out_file = os.path.join(output_dir, os.path.basename(file).replace(".json", "_clean.json"))
        df_unique.to_json(out_file, orient="records", lines=True)

        print(f"  Total: {total:,} | Sin duplicados: {total_unique:,} | Eliminados: {removed:,}")

        summary.append({
            "file": os.path.basename(file),
            "total": total,
            "unique": total_unique,
            "removed": removed
        })

    except Exception as e:
        print(f"Error procesando {file}: {e}")

# Guardar resumen
if summary:
    df_sum = pd.DataFrame(summary)
    df_sum.to_csv(os.path.join(output_dir, "summary.csv"), index=False)
    print("\n✅ Resumen guardado en summary.csv")
else:
    print("⚠️ No se procesó ningún archivo.")
