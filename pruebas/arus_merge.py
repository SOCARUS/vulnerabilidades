from datetime import datetime
import pandas as pd
import glob
import os
import json


fecha = datetime.now().strftime("%Y-%m-%d")

# Carpeta donde están los archivos limpios
input_folder = f"./output/arus/{fecha}/cleaned/"
output_file = f"./output/arus/{fecha}/merged/merged_cleaned_{fecha}.jsonl"

# Crear carpeta de salida si no existe
os.makedirs(os.path.dirname(output_file), exist_ok=True)

# Buscar todos los archivos JSONL
files = glob.glob(os.path.join(input_folder, "*.jsonl"))

print(f"Encontrados {len(files)} archivos para procesar.")

dfs = []

for file in files:
    try:
        # Cargar JSONL manualmente
        with open(file, "r") as f:
            data = [json.loads(line) for line in f]

        # Aplanar estructuras anidadas
        df = pd.json_normalize(data)

        dfs.append(df)
        print(f"Procesado: {file}, {len(df)} eventos")
    except Exception as e:
        print(f"Error en {file}: {e}")

if dfs:
    big_df = pd.concat(dfs, ignore_index=True)

    # Verificamos qué columnas existen realmente
    print("Columnas detectadas:", big_df.columns.tolist())

    # Intentar quitar duplicados
    subset_cols = ["agent.id", "package.name", "vulnerability.cve", "package.version"]
    subset_cols = [c for c in subset_cols if c in big_df.columns]

    if subset_cols:
        before = len(big_df)
        big_df = big_df.drop_duplicates(subset=subset_cols)
        after = len(big_df)
        print(f"Eventos combinados: {before}, después de quitar duplicados: {after}")
    else:
        print("⚠️ No se encontraron las columnas esperadas para eliminar duplicados. Guardando todo igualmente.")

    # Guardar en JSONL siempre
    big_df.to_json(output_file, orient="records", lines=True, force_ascii=False)
    print(f"✅ Archivo final guardado en: {output_file}")
else:
    print("❌ No se procesó ningún archivo.")