import json
import os

import pandas as pd
from datetime import datetime
from helper.queries.vulnerabilidades import reporte_sura, check_directory
from helper.procesadores.vulnerabilidades import normalizacion_json
from helper.graficas.vulnerabilidades import graficar_vulnerabilidades
from helper.correos.vulnerabilidades_sura import leer_y_enviar_correo

with open('./input/agentes.json', 'r') as f:
    #load json
    agents = json.loads(f.read())

sura = agents['sura']['agents']

# status = "Active"
status = ["Solved", "Active"]

try:
    for i in status:
        #Generar el reporte desde opensearch
        fecha = datetime.now().strftime("%Y-%m-%d")
        reporte_sura(agentes=sura, status=i)

        #Validar si se generó el archivo y pasarlo a un dataframe
        directorio = f"./output/sura/{fecha}/json/vulnerabilidades_sura_{i}.json"

        if os.path.exists(directorio):
            df = normalizacion_json(directorio)
            df = df.reset_index(drop=True)
            directorio = f"./output/sura/{fecha}"
            # check_directory(directorio)
            estado = "activas" if i=="Active" else "resueltas"
            output = f"{directorio}/vulnerabilidades_sura_{estado}.csv"
            df.to_csv(output, encoding="utf-8")
            graficar_vulnerabilidades(df, directorio=f"./output/sura/{fecha}/", status=i)
        else:
            print("Valide si el archivo se generó correctamente")



    #TODO: mover la logica a otra parte
    rutas_generadas=[
                    f"./output/sura/{fecha}/vulnerabilidades_sura_activas.csv",
                    f"./output/sura/{fecha}/vulnerabilidades_sura_resueltas.csv",
                    f"./output/sura/{fecha}/vulnerabilidades_activas.png",
                    f"./output/sura/{fecha}/vulnerabilidades_resueltas.png"
                    ]
    flag = True
    for ruta in rutas_generadas:
        if not os.path.exists(ruta):
            flag = False
            print(f"El archivo {ruta} no se ha generado correctamente.")
            raise FileNotFoundError(f"El archivo {ruta} no se ha generado correctamente.")
    if flag:
        print("Todos los archivos se han generado correctamente.")
        correos = ["juan.vargas@arus.com.co", "jorge.vallejo@arus.com.co", "andres.ortiz@arus.com.co", "aldemar.posada@arus.com.co", "david.mesa@arus.com.co", "juan.restrepom@arus.com.co"]
        # correos = ["juan.vargas@arus.com.co"]
        leer_y_enviar_correo(fecha=fecha, correos=correos)
    else:
        print("Algunos archivos no se han generado correctamente, por favor revise los logs.")
except Exception as e:
    print(f"Error al generar el reporte para el estado {i}: {e}")