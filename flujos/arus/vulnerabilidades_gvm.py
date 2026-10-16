from services.nvd_api_manager import get_cve_info_v2, init_metadata_db
from flujos.arus.vulnerabilidades import load_cisa_data
from datetime import datetime
from services.conexion import client
import glob
import json
import os
import pandas as pd
import requests
import re
import shutil
import tarfile


fecha = datetime.now().strftime("%Y-%m-%d")


def reporte_vulnerabilidades_gvm():
    # --- Configuración ---
    INDEX = "wazuh-alerts-4.x-2025.*"
    SCROLL_SIZE = 10_000       # docs por petición a OpenSearch
    SCROLL_TTL = "2m"          # tiempo de vida del scroll
    OUTPUT_PREFIX = f"./output/arus/{fecha}/gvm/"  # prefijo de los archivos de salida

    if not os.path.exists(OUTPUT_PREFIX):
        os.makedirs(OUTPUT_PREFIX)
        print(f"Directorio '{OUTPUT_PREFIX}' creado.")

    # {"terms": {"vulnerability.severity": ["Critical", "High", "Medium"]}}
    query = {
    "size": 5,
    "query": {"bool": {
        "must": [
        {"range": {"timestamp": {"gte": "now-60d","lte": "now"}}},
        {"term": {"rule.id": {"value": "100200"}}},
        {"exists": {"field": "data.event.solution"}}
        ],
        "must_not": [
        {"terms": {"data.event.threat": ["Log", "(sin amenaza)"]}}
        ]
        }
    }
    }

    # --- Scroll inicial ---
    page = client.search(
    index=INDEX,
    body=query,
    scroll=SCROLL_TTL,
    size=SCROLL_SIZE
    )

    sid = page["_scroll_id"]
    scroll_size = len(page["hits"]["hits"])

    # --- Variables de control ---
    file_name = f"{OUTPUT_PREFIX}reporte_gvm.jsonl"
    f = open(file_name, "w+", encoding="utf-8")
    print(f"Iniciando exportación a {file_name}...")
    # print(scroll_size)
    # count=0
    # while count < 5:
    while scroll_size > 0:
        # print(len(page["hits"]["hits"]))
        for doc in page["hits"]["hits"]:
            f.write(json.dumps(doc["_source"]) + "\n")
            # count+=1
        # Pedir siguiente página
        page = client.scroll(scroll_id=sid, scroll=SCROLL_TTL)
        sid = page["_scroll_id"]
        scroll_size = len(page["hits"]["hits"])
    # Cerrar último archivo
    f.close()

    print(f"Exportación completada, último archivo: {file_name}")
    
    reporte = f"./output/arus/{fecha}/gvm/reporte_gvm.jsonl"
    # Cargar JSONL manualmente
    with open(reporte, "r") as f:
        data = [json.loads(line) for line in f]

    # Aplanar estructuras anidadas
    df = pd.json_normalize(data)
    print(df)
    print(df.columns)
    # reporte = f"./muestra.jsonl"
    # Guardar en JSONL siempre
    df.to_json(reporte, orient="records", lines=True, force_ascii=False)
    print(f"Normalizacion y aplanamiento de archivo json: {reporte}")


def analisis_vulnerabilidades_gvm():
    # reporte = f"./output/arus/{fecha}/gvm/reporte_gvm.jsonl"
    reporte = f"./output/arus/{fecha}/gvm/reporte_gvm.jsonl"
    # Cargar JSONL manualmente
    with open(reporte, 'r', encoding='utf-8') as f:
        data = [json.loads(line) for line in f]


    with open(f"./input/info_agentes_arus.json") as f:
        agents_file = json.load(f)

    # Crear diccionario con info de agentes (clave = id)
    agents_info = {
        item["ip"]: {
            "os": item.get("os", "Unknown"),
            "group": item.get("group", "Uknown"),
            "ip": item.get("ip", ["Unknown"])  # tomar la primera IP o 'Unknown'
        }  # usamos .get("os") para evitar KeyError
        for item in agents_file["data"]["affected_items"]
        if "id" in item  # solo procesar si tienen un id
    }
    # 🔹 Descargar feed de CISA KEV
    # cisa_dict = load_cisa_data()
    def is_array(variable):
        try:
            len(variable)
            return True
        except TypeError:
            return False
    def get_vuln_cve(vuln):
        if isinstance(vuln, dict):
            return vuln.get("cves")
        if isinstance(vuln, list) and len(vuln) > 0:
            first = vuln[0]
            if isinstance(first, dict):
                return first.get("cves")
            return first
        return None

    # 🔹 Descargar feed de CISA KEV
    cisa_dict = load_cisa_data()
    arr = []
    for item in data:
        host_ip = item.get('data.event.host', '')
        info = agents_info.get(host_ip,"No encontrado"),
        # cve =
        
        arr.append({
            'Servidor_ID': item.get('data.event.host', ''),
            'Activo_Afectado': item.get('agent.name', ''),
            'Direccion_IP': item.get('data.event.host', ''),
            'Tecnologia_Afectada': item.get('data.event.name', ''),
            'Tipo_Solucion': item.get('data.event.tag_solution_type', ''),
            'Version_Tecnologia_Afectada': item.get('package.version', ''),
            'Tipo_Activo': "Servidores",
            'CVE_ID': item.get('data.event.cves', ''),
            'Link_Referencia': item.get('vulnerability.reference', ''),
            'Fecha_Deteccion': item.get('vulnerability.detected_at', ''),
            'Fecha_Exposicion': item.get('vulnerability.published_at', ''),
            'Fecha_Parche': "N/A",
            'Clasifiacion_CVSS': item.get('data.event.cvss_base', ''),
            'CVSS_Version': item.get('data.event.tag_cvss_base_vector', ''),
            'Severidad': item.get('data.event.severity', ''),
            "Proyecto_Negocio": "Uknown" if is_array(info) else info[0]["group"][0], # obtener grupo o 'Unknown' si no existe
            "Familia_SO": "Uknown" if is_array(info) else info[0]["os"]["name"], # obtener grupo o 'Unknown' si no existe
            "Version_SO": "Uknown" if is_array(info) else info[0]["os"]["version"],
            "Fuente_Deteccion": "GVM Scanner",
            "Estado": "active",
            'Vulnerabilidad_Con_Exploit': str(item.get('vulnerability.cisa_kve_info', {})).replace(",","|")
        })
    # Guardar en JSONL siempre
    df = pd.DataFrame(arr)
    # print(df["vuln_cve"])
    # if "cves" in df.columns:
    #     df["vuln_cve"] = df["CVE_ID"].apply(get_vuln_cve)
    
    # print(df["CVE_ID"])
    df["CVE_ID"] = df["CVE_ID"].apply(
    lambda x: x[0] if isinstance(x, list) and len(x) > 0 else x
    )

        # Filas donde el CVE está vacío o es lista vacía
    sin_cve = df[df["CVE_ID"].apply(lambda x: isinstance(x, list) and len(x) == 0 or pd.isna(x))]

    print(f"Total de filas sin CVE: {len(sin_cve)}")
    print(sin_cve.head())
    sin_cve.to_csv('./sin_cve.csv')
    # print(df["CVE_ID"])
    # extra = df["CVE_ID"].apply(get_cve_info_v2).apply(pd.Series)
    # df = pd.concat([df, extra], axis=1)

    df.to_csv(f"./output/arus/{fecha}/gvm/reporte_gvm.csv")
    

            # "Responsable_Remediacion": "Equipo Microsoft" if info[0]["group"][0]== "ARUS-SERVERS-WINDOWS" else "Equipo Linux" , # obtener grupo o 'Unknown' si ,