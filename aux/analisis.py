import glob
import os

def obtener_csvs_output():
    base_folder = "./output/arus/"
    # Buscar todos los archivos CSV dentro de cualquier subcarpeta
    pattern = os.path.join(base_folder, "*", "*.csv")
    csv_files = glob.glob(pattern)

    print(f"Encontrados {len(csv_files)} archivos CSV:")
    for file in csv_files:
        print(" -", file)

    return csv_files

# Ejemplo de uso
archivos = obtener_csvs_output()
print(archivos.sort())
print(archivos[0])