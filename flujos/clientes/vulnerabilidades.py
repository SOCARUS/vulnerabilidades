
from datetime import datetime
from services.conexion import client
import glob
import json
import os
import pandas as pd
import sqlite3


fecha = datetime.now().strftime("%Y-%m-%d")

def reporte_vulnerabilidades(agentes, cliente):
    # --- Configuración ---
    index_name = "wazuh-states-vulnerabilities-wazuh_cluster"
    CHUNK_FILE_SIZE = 200_000  # puedes poner 500_000 si quieres
    OUTPUT_PREFIX = f"./clientes/vulnerabilidades/{cliente}"  # prefijo de los archivos de salida

    if not os.path.exists(OUTPUT_PREFIX):
        os.makedirs(OUTPUT_PREFIX)
        print(f"Directorio '{OUTPUT_PREFIX}' creado.")

    # --- Query ---
    query={
        "size":10000,
        "query": {
            "bool": {
                "should": [
                    {"terms": {"agent.id": agentes}}
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
    file_name = f"{OUTPUT_PREFIX}/{cliente}_{file_index}.jsonl"
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
    print(f"Exportación completada, archivo: {file_name}")

    with open(file_name, "r") as f:
        data = [json.loads(line) for line in f]

    # Aplanar estructuras anidadas
    df = pd.json_normalize(data)

    # Normalizar columnas de estado y fechas para que se exporten como en la base de datos
    status_candidates = [
        "status",
        "data.vulnerability.status",
        "vulnerability.status",
        "data.vulnerability.state",
        "vulnerability.state",
    ]
    status_col = next((col for col in status_candidates if col in df.columns), None)
    if status_col is not None:
        df["status"] = df[status_col].astype(str).str.strip()
        df["status"] = df["status"].replace({
            "active": "Active",
            "resolved": "Solved",
            "solved": "Solved",
            "active;": "Active",
            "resolved;": "Solved",
            "": "Active",
        })
    else:
        df["status"] = "Active"

    for source, target in {
        "vulnerability.detected_at": "fecha_detectado",
        "data.vulnerability.detected_at": "fecha_detectado",
        "vulnerability.resolved_at": "fecha_resuelta",
        "data.vulnerability.resolved_at": "fecha_resuelta",
        "vulnerability.last_seen": "last_seen_at",
        "data.vulnerability.last_seen": "last_seen_at",
    }.items():
        if source in df.columns and target not in df.columns:
            df[target] = df[source]

    if "fecha_detectado" not in df.columns:
        df["fecha_detectado"] = ""
    if "fecha_resuelta" not in df.columns:
        df["fecha_resuelta"] = ""
    if "last_seen_at" not in df.columns:
        df["last_seen_at"] = ""

    # Intentar quitar duplicados
    subset_cols = ["agent.id","package.name","package.version","vulnerability.id"]
    subset_cols = [c for c in subset_cols if c in df.columns]

    if subset_cols:
        before = len(df)
        df = df.drop_duplicates(subset=subset_cols)
        after = len(df)
        print(f"Eventos combinados: {before}, después de quitar duplicados: {after}")
    else:
        print("⚠️ No se encontraron las columnas esperadas para eliminar duplicados. Guardando todo igualmente.")

    columns_to_export = [
        "agent.id",
        "agent.name",
        "host.os.name",
        "package.name",
        "package.version",
        "vulnerability.id",
        "vulnerability.classification",
        "vulnerability.detected_at",
        "fecha_detectado",
        "vulnerability.severity",
        "vulnerability.score.base",
        "package.installed",
        "status",
        "fecha_resuelta",
        "last_seen_at",
    ]
    columns_to_export = [col for col in columns_to_export if col in df.columns]

    df[columns_to_export].to_csv(f"{OUTPUT_PREFIX}/vulnerabilidades_{cliente}.csv", index=False)

def reporte_backlog_vulnerabilidades(cliente):
    
    conn = sqlite3.connect(f'./backlog_db/{cliente}.sqlite3')
    conn.row_factory = sqlite3.Row

    query = """
        SELECT
            agent_name,
            host_os_name,
            package_name,
            package_version,
            vulnerability_id,
            vulnerability_classification,
            vulnerability_severity,
            vulnerability_score_base,
            package_installed,
            status,
            fecha_detectado,
            fecha_resuelta,
            last_seen_at
        FROM vulnerabilities
        WHERE 1 = 1
    """
    rows = conn.execute(query).fetchall()
    conn.close()

    resultado = [dict(row) for row in rows]

    df = pd.DataFrame(resultado)

    print(df.head())
    df.to_csv('prueba_prebel.csv')