import json
import os

import pandas as pd
from datetime import datetime
from helper.queries.vulnerabilidades import reporte_arturo_calle, check_directory
from helper.procesadores.vulnerabilidades import normalizacion_json
from helper.graficas.vulnerabilidades import graficar_vulnerabilidades
from helper.correos.vulnerabilidades_arturo_calle import leer_y_enviar_correo


# status = "Active"
status = ["Solved", "Active"]

for i in status:
    #Generar el reporte desde opensearch
    reporte_arturo_calle(status=i)

    #Validar si se generó el archivo y pasarlo a un dataframe
    fecha = datetime.now().strftime("%Y-%m-%d")
    directorio = f"./output/arturo_calle/{fecha}/json/vulnerabilidades_{i}.json"
    if os.path.exists(directorio):
        df = normalizacion_json(directorio)
        df = df.reset_index(drop=True)
        directorio = f"./output/arturo_calle/{fecha}"
        check_directory(directorio)
        estado = "activas" if i=="Active" else "resueltas"
        output = f"{directorio}/vulnerabilidades_{estado}.csv"
        df.to_csv(output, encoding="utf-8")
        graficar_vulnerabilidades(df, directorio=f"./output/arturo_calle/{fecha}/", status=i)
        # leer_y_enviar_correo(fecha=fecha)
    else:
        print("Valide si el archivo se generó correctamente")