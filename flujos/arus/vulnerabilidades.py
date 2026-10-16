
from services.nvd_api_manager import get_cve_info_v2, init_metadata_db
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


def reporte_vulnerabilidades_arus():
    # --- Configuración ---
    index_name = "wazuh-states-vulnerabilities-wazuh_cluster"
    CHUNK_FILE_SIZE = 200_000  # puedes poner 500_000 si quieres
    OUTPUT_PREFIX = f"/logs/arus/{fecha}/json/vulns_export"  # prefijo de los archivos de salida

    if not os.path.exists(OUTPUT_PREFIX):
        os.makedirs(OUTPUT_PREFIX)
        print(f"Directorio '{OUTPUT_PREFIX}' creado.")

    # arus = ['451', '452', '453', '454', '455', '456', '457', '458', '459', '460', '461', '462', '463', '464', '465', '466', '467', '468', '469', '470', '471', '472', '473', '474', '475', '476', '477', '478', '479', '480', '481', '482', '483', '484', '485', '486', '487', '488', '489', '490', '491', '492', '493', '494', '495', '496', '497', '498', '499', '500', '501', '502', '503', '504', '505', '506', '507', '508', '509', '510', '511', '512', '513', '514', '515', '516', '518', '519', '520', '521', '522', '523', '524', '525', '526', '527', '528', '529', '530', '531', '532', '533', '534', '535', '536', '537', '538', '539', '540', '541', '542', '543', '544', '545', '546', '547', '548', '549', '550', '551', '552', '553', '554', '555', '556', '557', '558', '559', '560', '561', '562', '563', '564', '565', '566', '567', '568', '569', '570', '571', '572', '573', '574', '575', '576', '577', '578', '579', '580', '581', '582', '583', '584', '585', '586', '587', '588', '589', '590', '591', '592', '593', '594', '595', '596', '597', '598','061', '062', '063', '064', '109', '110', '111', '112', '113', '114', '115', '116', '117', '118', '119', '120', '121', '122', '123', '124', '125', '126', '381', '382', '383', '384', '385', '386', '387', '388', '389', '390', '391', '392', '393', '394', '395', '396', '397', '398', '399', '400', '401', '402', '403', '404', '406', '407', '408', '411', '414', '415', '416', '417', '418', '419', '420', '421', '422', '423', '424', '425', '426', '427', '428', '429', '430', '431', '432', '433', '434', '435', '436', '437', '438', '439', '440', '441', '442', '443', '444', '446', '447', '448']
    arus = ['451',  '452',  '453',  '454',  '455',  '456',  '457',  '458',  '459',  '460',  '461',  '462',  '464',  '465',  '466',  '467',  '468',  '469',  '470',  '471',  '472',  '473',  '474',  '476',  '477',  '478',  '480',  '481',  '482',  '483',  '485',  '486',  '487',  '488',  '489',  '490',  '491',  '492',  '493',  '494',  '495',  '496',  '497',  '498',  '499',  '500',  '501',  '502',  '503',  '504',  '505',  '506',  '507',  '508',  '509',  '510',  '511',  '512',  '513',  '514',  '515',  '516',  '518',  '519',  '520',  '521',  '522',  '523',  '524',  '527',  '528',  '529',  '530',  '531',  '532',  '533',  '534',  '535',  '536',  '537',  '538',  '539',  '540',  '541',  '542',  '543',  '544',  '545',  '546',  '547',  '548',  '549',  '550',  '551',  '552',  '553',  '554',  '555',  '556',  '557',  '558',  '559',  '560',  '562',  '563',  '564',  '565',  '566',  '567',  '568',  '569',  '570',  '571',  '572',  '573',  '574',  '575',  '576',  '577',  '578',  '579',  '580',  '581',  '582',  '583',  '584',  '585',  '586',  '587',  '588',  '589',  '590',  '592',  '593',  '594',  '595',  '596',  '597',  '598',  '603',  '604',  '609',  '610',  '613',  '614',  '617',  '618',  '621',  '622',  '623',  '624',  '626',  '627',  '628',  '631',  '632',  '061',  '062',  '063',  '064',  '109',  '110',  '111',  '112',  '113',  '114',  '115',  '116',  '117',  '118',  '119',  '120',  '121',  '122',  '123',  '124',  '125',  '126',  '381',  '382',  '383',  '384',  '385',  '386',  '387',  '388',  '389',  '390',  '391',  '392',  '393',  '394',  '395',  '396',  '397',  '398',  '399',  '400',  '401',  '402',  '403',  '404',  '406',  '407',  '408',  '411',  '414',  '416',  '417',  '418',  '419',  '421',  '422',  '423',  '424',  '425',  '426',  '427',  '428',  '429',  '430',  '431',  '432',  '433',  '434',  '435',  '436',  '437',  '438',  '439',  '440',  '441', '442',  '443',  '444',  '446',  '447',  '448',  '601',  '602',  '638']


    # --- Query ---
    query={
        "size":10000,
        "query": {
            "bool": {
                "should": [
                    {"terms": {"agent.id": arus}}
                 ],
                 "minimum_should_match": 1
                } },
         "sort": [
            {"timestamp":{"order":"desc","unmapped_type":"boolean"}},
            {"_id": "asc"} # Crucial para la consistencia
        ]
    }

    response = client.search(body=query, index=index_name)
    hits = response['hits']['hits']


    # --- Variables de control ---
    file_index = 1
    doc_counter = 0
    file_name = f"{OUTPUT_PREFIX}_{file_index}.jsonl"
    f = open(file_name, "w", encoding="utf-8")
    while hits:
        for doc in response["hits"]["hits"]:
            f.write(json.dumps(doc["_source"]) + "\n")
            doc_counter += 1

            # Cuando llega al límite, cerrar archivo y abrir uno nuevo
            if doc_counter >= CHUNK_FILE_SIZE:
                f.close()
                print(f"Archivo {file_name} terminado con {doc_counter} docs")

                # Resetear contadores
                file_index += 1
                doc_counter = 0
                file_name = f"{OUTPUT_PREFIX}_{file_index}.jsonl"
                f = open(file_name, "w", encoding="utf-8")
                print(f"Continuando exportación en {file_name}...")
        # all_results.extend(hits)
        
        # Obtener los valores de ordenación del último elemento de la página actual
        last_hit_sort = hits[-1]['sort']
        
        # 2. Configurar la siguiente página usando search_after
        query["search_after"] = last_hit_sort
        
        # Ejecutar la siguiente consulta
        response = client.search(body=query, index=index_name)
        hits = response['hits']['hits']

    # Cerrar último archivo
    f.close()
    print(f"Exportación completada, último archivo: {file_name}")


def analisis_vulnerabilidades_arus():
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
            return vuln.get("id")
        if isinstance(vuln, list) and len(vuln) > 0:
            first = vuln[0]
            if isinstance(first, dict):
                return first.get("id")
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
            df_unique = df.drop_duplicates(subset=["agent_id", "vuln_cve"])

            total_unique = len(df_unique)
            removed = total - total_unique

            # Guardar limpio
            out_file = os.path.join(output_dir, os.path.basename(file).replace(".json", "_clean.json"))
            df_unique.to_json(out_file, orient="records", lines=True)
                    

            #TODO: Centralizar eliminacion de archivos        
            # # 🔥 Eliminar carpeta original solo si se guardó correctamente
            # try:
            #     shutil.rmtree(input_dir)
            #     print(f"🗑️ Carpeta original eliminada: {input_dir}")
            # except Exception as e:
            #     print(f"⚠️ No se pudo eliminar la carpeta {input_dir}: {e}")


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


def merge_vulnerabilidades_arus():
    # Carpeta donde están los archivos limpios
    input_folder = f"./output/arus/{fecha}/cleaned/"
    output_file = f"./output/arus/{fecha}/merged/merged_cleaned.jsonl"

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
        subset_cols = ["agent.id", "vulnerability.id"]
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
        # big_df.to_csv('merge.csv')
        
        # print(f"✅ Archivo final guardado en: {output_file}")
    else:
        print("❌ No se procesó ningún archivo.")



def enriquecimiento_reporte_arus():
    # Aquí iría la lógica para enriquecer el reporte, si es necesario

    with open(f'./output/arus/{fecha}/merged/merged_cleaned.jsonl', 'r', encoding='utf-8') as f:
        data = [json.loads(line) for line in f]

    with open(f"./input/info_agentes_arus.json") as f:
        agents_file = json.load(f)

    # Crear diccionario con info de agentes (clave = id)
    agents_info = {
        item["id"]: {
            "os": item.get("os", "Unknown"),
            "group": item.get("group", "Uknown"),
            "ip": item.get("ip", ["Unknown"])  # tomar la primera IP o 'Unknown'
        }  # usamos .get("os") para evitar KeyError
        for item in agents_file["data"]["affected_items"]
        if "id" in item  # solo procesar si tienen un id
    }

    arr = []
    for item in data:
        agent_id = item.get('agent_id', '')
        info = agents_info.get(agent_id,"No encontrado"),
        arr.append({
            'Servidor_ID': item.get('agent_id', ''),
            'Activo_Afectado': item.get('agent.name', ''),
            'Direccion_IP': info[0]["ip"] if info[0]["ip"]!= None else "No se encontró",
            'Tecnologia_Afectada': item.get('package.name', ''),
            'Version_Tecnologia_Afectada': item.get('package.version', ''),
            'Tipo_Activo': "Servidores",
            'CVE_ID': item.get('vulnerability.id', ''),
            'Link_Referencia': item.get('vulnerability.reference', ''),
            'Fecha_Deteccion': item.get('vulnerability.detected_at', ''),
            'Fecha_Exposicion': item.get('vulnerability.published_at', ''),
            'Fecha_Parche': "N/A",
            'Clasifiacion_CVSS': item.get('vulnerability.score.base', ''),
            'CVSS_Version': item.get('vulnerability.score.version', ''),
            'Severidad': item.get('vulnerability.severity', ''),
            "Proyecto_Negocio": info[0]["group"][0], # obtener grupo o 'Unknown' si no existe
            "Familia_SO": info[0]["os"]["name"], # obtener grupo o 'Unknown' si no existe
            "Version_SO": info[0]["os"]["version"],
            "Fuente_Deteccion": item.get('vulnerability.scanner.source', ''),
            "Responsable_Remediacion": "Equipo Microsoft" if info[0]["group"][0]== "ARUS-SERVERS-WINDOWS" else "Equipo Linux" , # obtener grupo o 'Unknown' si ,
            "Estado": "active",
            'Vulnerabilidad_Con_Exploit': str(item.get('vulnerability.cisa_kve_info', {})).replace(",","|"),
        })
    df = pd.DataFrame(arr)
    print(len(df))
    # extra = df["CVE_ID"].apply(get_cve_info_v2).apply(pd.Series)
    # df = pd.concat([df, extra], axis=1)
    # print(len(df))
    
    fecha_archivo = fecha.replace('-','_')
    input_dir = f'./output/arus/vulnerabilidades_arus_{fecha_archivo}'
    df.to_csv(f'{input_dir}.csv', index=False)
    #export to json
    df.to_json(f'{input_dir}.json', orient='records', lines=True)


#limpiar rutas utilizadas para el reporte
def eliminar_archivos_temporales():
    #Analisis de vulnerabilidades ARUS
    #🔥 Eliminar carpeta original solo si se guardó correctamente
    analisis_vulnerabilidades_dir = f"/logs/arus/{fecha}"
    try:
        shutil.rmtree(analisis_vulnerabilidades_dir)
        print(f"🗑️ Carpeta original eliminada: {analisis_vulnerabilidades_dir}")
    except Exception as e:
        print(f"⚠️ No se pudo eliminar la carpeta {analisis_vulnerabilidades_dir}: {e}")

    #Merged
    # Eliminar directorios temporale de cleaned
    cleaned_dir = f"./output/arus/{fecha}/cleaned"
    try:
        shutil.rmtree(cleaned_dir)
        print(f"🗑️ Carpeta original eliminada: {cleaned_dir}")
    except Exception as e:
        print(f"⚠️ No se pudo eliminar la carpeta {cleaned_dir}: {e}")
    
    
    merged_dir = f"./output/arus/{fecha}/merged"
    try:
        shutil.rmtree(merged_dir)
        print(f"🗑️ Carpeta original eliminada: {merged_dir}")
    except Exception as e:
        print(f"⚠️ No se pudo eliminar la carpeta {merged_dir}: {e}")


def check_dataframe_kev(df):
    resp = requests.get("https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv", verify=False)
    with open('cisa_kev.csv', 'w+', encoding="utf-8") as f:
        f.write(str(resp.text))
        
    #Se cargan los datos a un dataframe
    kev = pd.read_csv('cisa_kev.csv')
    kev = kev.rename(columns={'cveID': 'CVE_ID'})

    #Se valida si    
    df["VulnerabilidadConExploit"] = df["CVE_ID"].isin(kev["CVE_ID"])
    return df

#Backlog vulnerabilidades y parchadoS
def backlog_y_vulnerabilidades_resueltas():
    # --- CONFIGURACIÓN ---
    CARPETA_REPORTES = "./output/arus/"   # carpeta con archivos tipo: descubiertas_vulnerabilidades_2025_10_08.csv
    BACKLOG_FILE = "backlog_vulnerabilidades.csv"
    NOMBRE_REPORTE_GLOBE = ".csv"  # archivos csv en la carpeta

    # --- FUNCIONES ---
    def parse_date_from_filename(fname):
        """Extrae una fecha del nombre de archivo y la normaliza a YYYY-MM-DD.
        Soporta formatos: YYYY_MM_DD, YYYY-MM-DD, YYYYMMDD
        Devuelve None si no encuentra."""
        patterns = [
            r'(\d{4}[_-]\d{2}[_-]\d{2})',  # 2025_10_08 or 2025-10-08
            r'(\d{8})'  # 20251008
        ]
        for p in patterns:
            m = re.search(p, fname)
            if m:
                s = m.group(1)
                # normalizar
                if '_' in s:
                    return s.replace('_', '-')
                if '-' in s:
                    return s
                if len(s) == 8:
                    return f"{s[0:4]}-{s[4:6]}-{s[6:8]}"
        return None

    def agregar_vuln_id(df):
        """Crea un identificador único para cada vulnerabilidad"""
        df["Servidor_ID"] = df["Servidor_ID"].astype(str)
        df["vuln_id"] = (
            df["Servidor_ID"] + "_" +
            df["CVE_ID"].astype(str) + "_" +
            df["Direccion_IP"].astype(str) + "_" 
        )
        return df

    def cargar_reporte(path):
        df = pd.read_csv(path, dtype=str, low_memory=False).fillna("")  # tratar todo como str para evitar errores
        df = agregar_vuln_id(df)
        return df

    def listar_archivos_ordenados(carpeta):
        archivos = []
        for f in os.listdir(carpeta):
            if f.lower().endswith(".csv"):
                fecha = parse_date_from_filename(f)
                if fecha:
                    archivos.append((fecha, os.path.join(carpeta, f)))
        archivos.sort(key=lambda x: x[0])  # orden por fecha (YYYY-MM-DD)
        return archivos
    
    
    # Cargar el archivo con la informacion de los agentes(Grupo y SO)
    with open("./input/info_agentes_arus.json") as f:
        agents_file = json.load(f)

    # Crear diccionario de información de agentes
    # agents_info = {
    #     item["id"]: {
    #         "os": item.get("os", {"name": "Unknown", "version": "Unknown"}),
    #         "group": item.get("group", ["Unknown"]),
    #         "ip": item.get("ip", ["Unknown"])
    #     }
    #     for item in agents_file["data"]["affected_items"]
    #     if "id" in item
    # }
    
    def ultima_fecha_procesada(backlog_df):
        """Determina la última fecha que fue procesada basándose en Archivo_detectado / Archivo_resuelto.
        Devuelve fecha en formato YYYY-MM-DD o None."""
        fechas = []
        # columnas que contienen nombres de archivo; extraer fecha de esos nombres
        for col in ["Archivo_detectado", "Archivo_resuelto"]:
            if col in backlog_df.columns:
                for fname in backlog_df[col].dropna().unique():
                    if fname == "":
                        continue
                    fecha = parse_date_from_filename(str(fname))
                    if fecha:
                        fechas.append(fecha)
        if fechas:
            return max(fechas)
        # fallback: usar Fecha_detectado / Fecha_Parche si existen
        for col in ["Fecha_detectado", "Fecha_Parche"]:
            if col in backlog_df.columns:
                vals = backlog_df[col].dropna().astype(str)
                vals = vals[vals != ""]
                if not vals.empty:
                    try:
                        # asumir ya están en YYYY-MM-DD
                        return max(vals)
                    except Exception:
                        pass
        return None

    # --- MAIN ---
    reportes = listar_archivos_ordenados(CARPETA_REPORTES)
    if not reportes:
        raise FileNotFoundError(f"No se encontraron archivos CSV con fecha en {CARPETA_REPORTES}")

    # Si no existe backlog, crear con el archivo más antiguo
    if not os.path.exists(BACKLOG_FILE):
        fecha0, archivo0 = reportes[0]
        df0 = cargar_reporte(archivo0)
        df0["Estado"] = "Abierta"
        df0["Fecha_detectado"] = fecha0
        df0["Archivo_detectado"] = os.path.basename(archivo0)
        df0["Fecha_Parche"] = ""
        df0["Archivo_resuelto"] = ""
        df0.to_csv(BACKLOG_FILE, index=False)
        backlog = df0
        print(f"Backlog inicial creado con {len(backlog)} vulnerabilidades del archivo {archivo0} (fecha {fecha0})")
    else:
        backlog = pd.read_csv(BACKLOG_FILE, dtype=str).fillna("")
        backlog = agregar_vuln_id(backlog)
        print(f"Backlog cargado con {len(backlog)} filas.")

    # Determinar última fecha procesada para evitar reprocesar
    last_date = ultima_fecha_procesada(backlog)
    if last_date:
        print(f"Última fecha procesada detectada en backlog: {last_date}")
    else:
        # si no se detecta, asumimos que backlog cubre hasta la fecha mínima de sus detectados
        if "Fecha_detectado" in backlog.columns:
            vals = backlog["Fecha_detectado"][backlog["Fecha_detectado"] != ""]
            if not vals.empty:
                last_date = vals.max()
                print(f"Última fecha detectada usada como referencia: {last_date}")

    # Construir lista de archivos a procesar: solo aquellos con fecha > last_date (o todos si last_date is None)
    if last_date:
        pendientes = [(d,p) for (d,p) in reportes if d > last_date]
    else:
        # si no hay last_date y backlog existía, mejor procesar todos en orden (backlog evitará duplicados)
        pendientes = reportes

    if not pendientes:
        print("No hay archivos nuevos para procesar.")
    else:
        print(f"Archivos a procesar: {len(pendientes)}")

    # Inicializar variables para el caso en que no haya archivos pendientes
    descubiertas = pd.DataFrame()
    cerradas_ids = set()

    for fecha_actual, ruta_actual in pendientes:
        fecha_actual = str(fecha_actual).replace('-','_')
        nombre_reporte = os.path.basename(ruta_actual)
        df_actual = cargar_reporte(ruta_actual)
        ids_actuales = set(df_actual["vuln_id"])
        ids_backlog = set(backlog["vuln_id"])

        # --- Descubiertas: IDs que están en el reporte actual y no en backlog histórico ---
        nuevas_ids = ids_actuales - ids_backlog
        descubiertas = df_actual[df_actual["vuln_id"].isin(nuevas_ids)].copy()
        if not descubiertas.empty:
            descubiertas["Estado"] = "Abierta"
            descubiertas["Fecha_detectado"] = fecha_actual
            descubiertas["Archivo_detectado"] = nombre_reporte
            descubiertas["Fecha_Parche"] = ""
            descubiertas["Archivo_resuelto"] = ""
            
            # Eliminar columnas duplicadas para evitar errores de compatibilidad en el backlog
            backlog = backlog.loc[:, ~backlog.columns.duplicated()]
            descubiertas = descubiertas.loc[:, ~descubiertas.columns.duplicated()]

            backlog = pd.concat([backlog, descubiertas], ignore_index=True)
            out_desc = os.path.join(CARPETA_REPORTES+fecha, f"descubiertas_{fecha_actual}.csv")
            descubiertas.to_csv(out_desc, index=False)
            print(f"{fecha_actual}: {len(descubiertas)} descubiertas -> {out_desc}")

        # --- Resueltas: IDs que estaban Abiertas en backlog y ya no aparecen en el reporte actual ---
        if "Estado" not in backlog.columns:
            backlog["Estado"] = "Abierta"
        abiertas_ids = set(backlog.loc[backlog["Estado"] == "Abierta", "vuln_id"])
        cerradas_ids = abiertas_ids - ids_actuales
        if cerradas_ids:
            mask = backlog["vuln_id"].isin(cerradas_ids) & (backlog["Estado"] == "Abierta")
            backlog.loc[mask, "Estado"] = "Cerrada"
            backlog.loc[mask, "Fecha_Parche"] = fecha_actual
            backlog.loc[mask, "Archivo_resuelto"] = nombre_reporte
            resueltas = backlog[mask].copy()
            out_res = os.path.join(CARPETA_REPORTES+fecha, f"resueltas_{fecha_actual}.csv")
            resueltas.to_csv(out_res, index=False)
            print(f"{fecha_actual}: {len(resueltas)} resueltas -> {out_res}")

        #Mover el campo Link_Referencia al final ya que es muy largo.
        columna = backlog.pop('Link_Referencia')
        backlog['Link_Referencia'] = columna

        def to_bool_exploit(x):
            if str(x) == "{}":
                return False
            else:
                return True

        backlog["Vulnerabilidad_Con_Exploit"] = backlog["Vulnerabilidad_Con_Exploit"].apply(to_bool_exploit)


        def replace_date(x):
            x = str(x).replace("_","-")
            return x

        backlog["Fecha_detectado"] = backlog["Fecha_detectado"].apply(replace_date)

        
        # Intentar quitar duplicados
        subset_cols = ["Servidor_ID", "Tecnologia_Afectada", "CVE_ID", "Version_Tecnologia_Afectada"]
        subset_cols = [c for c in subset_cols if c in backlog.columns]

        if subset_cols:
            before = len(backlog)
            backlog = backlog.drop_duplicates(subset=subset_cols)
            after = len(backlog)
            print(f"Eventos combinados: {before}, después de quitar duplicados: {after}")
        else:
            print("⚠️ No se encontraron las columnas esperadas para eliminar duplicados. Guardando todo igualmente.")


        backlog = check_dataframe_kev(backlog)
        # Persistir backlog después de cada archivo procesado
        
        #Excluir ips del backlog
        ips_excluir = [
            "10.0.0.146",
            "10.0.1.249"
        ]
        backlog = backlog[~backlog["Direccion_IP"].isin(ips_excluir)]

        backlog.to_csv(BACKLOG_FILE, index=False)

    output_dir = f'./output/arus/{fecha}/'
    fecha_archivo = fecha.replace('-','_')
    tar_path = os.path.join(output_dir, f"vulnerabilidades_arus_{fecha_archivo}.tar.gz")

    if not descubiertas.empty and len(cerradas_ids)>0:
        print("Condicional 1 activado")
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(BACKLOG_FILE,
                    arcname=BACKLOG_FILE)
            tar.add(os.path.join(output_dir, f"descubiertas_{fecha_archivo}.csv"),
                    arcname=f"descubiertas_{fecha_archivo}.csv")
            tar.add(os.path.join(output_dir, f"resueltas_{fecha_archivo}.csv"),
                    arcname=f"resueltas_{fecha_archivo}.csv")

    elif descubiertas.empty and len(cerradas_ids)==0:
        print("Condicional 2 activado")
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(BACKLOG_FILE,
                    arcname=BACKLOG_FILE)
    elif not descubiertas.empty and len(cerradas_ids)==0:
        print("Condicional 3 activado")
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(BACKLOG_FILE,
                    arcname=BACKLOG_FILE)
            tar.add(os.path.join(output_dir, f"descubiertas_{fecha_archivo}.csv"),
                arcname=f"descubiertas_{fecha_archivo}.csv")
    elif descubiertas.empty and len(cerradas_ids)>0:
        print("Condicional 4 activado")
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(BACKLOG_FILE,
                    arcname=BACKLOG_FILE)
            tar.add(os.path.join(output_dir, f"resueltas_{fecha_archivo}.csv"),
                    arcname=f"resueltas_{fecha_archivo}.csv")

    print(f"\nProceso finalizado. Backlog contiene {len(backlog)} filas totales.")



def procesamiento_vulnerabilidades():
    output_dir = f'./output/arus/{fecha}/'
    fecha_archivo = fecha.replace('-','_')
    archivo = os.path.join(output_dir, f"vulnerabilidades_arus_{fecha_archivo}.tar.gz")
    df = pd.read_csv(archivo)
    print(df.head())