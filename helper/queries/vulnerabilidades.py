from services.conexion import client, client_ac


from datetime import datetime
import json
import os
import requests
 

fecha = datetime.now().strftime("%Y-%m-%d")

def reporte_sura(agentes, status, max_reintentos=3, fecha=fecha):
    directorio = f"./output/sura/{fecha}/json/"
    check_directory(directorio)
    output = f"{directorio}vulnerabilidades_sura_{status}.json"
    print(os.path.exists(output))
    if os.path.exists(output):
        print("Existe")
        return
    else:
        print("No existe")
        reintentos = 0
        while reintentos < max_reintentos:
            try:
                resp = client.search(
                    index="wazuh-alerts-4.x*",
                    scroll="10m",  # mantener el contexto abierto por 2 minutos
                    request_timeout=120,
                    size=1000,
                    body={
                        "query": {
                            "bool": {
                                "must": [
                                    {"match": {"rule.groups": "vulnerability-detector"}},
                                    {"range": {"timestamp": {"gte": "now-90d", "lte": "now"}}},
                                    {"terms": {"agent.id": agentes}},
                                    {"term": {"data.vulnerability.status": status}}
                                ]
                            }
                        }
                    }
                )
                scroll_id = resp['_scroll_id']
                all_hits = resp['hits']['hits']
                while True:
                    resp = client.scroll(scroll_id=scroll_id, scroll="5m")
                    hits = resp['hits']['hits']
                    if not hits:
                        break
                    all_hits.extend(hits)
                print(f"Total documentos: {len(all_hits)}")
                with open(output, 'w') as f:
                    json.dump(all_hits, f, indent=2)
                break  # Éxito, salir del bucle
            except Exception as e:
                reintentos += 1
                print(f"Error en intento {reintentos}: {e}")
                if reintentos >= max_reintentos:
                    print("Se alcanzó el número máximo de reintentos. Abortando.")
                    raise



def reporte_arturo_calle( status, max_reintentos=3, fecha=fecha):
    directorio = f"./output/arturo_calle/{fecha}/json"
    os.makedirs(directorio, exist_ok=True)
    output = f"{directorio}/vulnerabilidades_{status}.json"
    reintentos = 0
    while reintentos < max_reintentos:
        try:
            resp = client_ac.search(
                index="wazuh-alerts-4.x*",
                scroll="10m",  # mantener el contexto abierto por 2 minutos
                request_timeout=120,
                size=1000,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"match": {"rule.groups": "vulnerability-detector"}},
                                {"range": {"timestamp": {"gte": "now-60d", "lte": "now"}}},
                                {"term": {"data.vulnerability.status": status}}
                            ]
                        }
                    }
                }
            )
            scroll_id = resp['_scroll_id']
            all_hits = resp['hits']['hits']
            while True:
                resp = client_ac.scroll(scroll_id=scroll_id, scroll="5m")
                hits = resp['hits']['hits']
                if not hits:
                    break
                all_hits.extend(hits)
            print(f"Total documentos: {len(all_hits)}")
            with open(output, 'w') as f:
                json.dump(all_hits, f, indent=2)
            break  # Éxito, salir del bucle
        except Exception as e:
            reintentos += 1
            print(f"Error en intento {reintentos}: {e}")
            if reintentos >= max_reintentos:
                print("Se alcanzó el número máximo de reintentos. Abortando.")
                raise


def reporte_arus(agentes, max_reintentos=3, fecha=fecha):
    directorio = f"./output/arus/{fecha}/json/"
    check_directory(directorio)
    output = f"{directorio}vulnerabilidades_arus.json"
    if os.path.exists(output):
        print("Existe")
        with open(output, "r") as f:
            all_hits = json.load(f)

        # 🔹 Descargar feed de CISA KEV
        CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(CISA_URL)
        response.raise_for_status()
        cisa_data = response.json()
        cisa_dict = {entry["cveID"]: entry for entry in cisa_data.get("vulnerabilities", [])}

        # 🔹 Enriquecer cada entrada
        for entry in all_hits:
            cve = entry.get("_source", {}).get("data", {}).get("vulnerability", {}).get("cve")
            if cve and cve in cisa_dict:
                entry["_source"]["data"]["vulnerability"]["cisa_kve_info"] = cisa_dict[cve]

        # 🔹 Guardar archivo enriquecido
        with open(output, 'w') as f:
            json.dump(all_hits, f, indent=2)

        # 🔹 Permisos: lectura/escritura solo para arusadm
        os.chmod(output, 0o600)

        print(f"Archivo enriquecido guardado en: {output}")
    else:
        print("No existe")
        reintentos = 0
        print("reintentos", reintentos)
        while reintentos < max_reintentos:
            try:
                resp = client.search(
                    index="wazuh-alerts-4.x*",
                    scroll="10m",
                    request_timeout=120,
                    size=1000,
                    body={
                        "query": {
                            "bool": {
                                "must": [
                                    {"match": {"rule.groups": "vulnerability-detector"}},
                                    {"range": {"timestamp": {"gte": "now-90d", "lte": "now"}}},
                                    {"terms": {"agent.id": agentes}},
                                ]
                            }
                        }
                    }
                )
                scroll_id = resp['_scroll_id']
                all_hits = resp['hits']['hits']
                while True:
                    resp = client.scroll(scroll_id=scroll_id, scroll="5m")
                    hits = resp['hits']['hits']
                    if not hits:
                        break
                    all_hits.extend(hits)
 
                print(f"Total documentos: {len(all_hits)}")
 
                # 🔹 Descargar feed de CISA KEV
                CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                response = requests.get(CISA_URL)
                response.raise_for_status()
                cisa_data = response.json()
                cisa_dict = {entry["cveID"]: entry for entry in cisa_data.get("vulnerabilities", [])}
 
                # 🔹 Enriquecer cada entrada
                for entry in all_hits:
                    cve = entry.get("_source", {}).get("data", {}).get("vulnerability", {}).get("cve")
                    if cve and cve in cisa_dict:
                        entry["_source"]["data"]["vulnerability"]["cisa_kve_info"] = cisa_dict[cve]
 
                # 🔹 Guardar archivo enriquecido
                with open(output, 'w') as f:
                    json.dump(all_hits, f, indent=2)
 
                # 🔹 Permisos: lectura/escritura solo para arusadm
                os.chmod(output, 0o600)
 
                print(f"Archivo enriquecido guardado en: {output}")
                break  # Éxito, salir del bucle
 
            except Exception as e:
                reintentos += 1
                print(f"Error en intento {reintentos}: {e}")
                if reintentos >= max_reintentos:
                    print("Se alcanzó el número máximo de reintentos. Abortando.")
                    raise


def reporte_arus_v2(agentes, max_reintentos=3,nombre="titulo", fecha=fecha):
    directorio = f"./output/arus/{fecha}/json/"
    check_directory(directorio)
    output = f"{directorio}vulnerabilidades_arus_{nombre}.json"
    if os.path.exists(output):
        print("Existe")
        with open(output, "r") as f:
            all_hits = json.load(f)

        # 🔹 Descargar feed de CISA KEV
        # CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        # response = requests.get(CISA_URL)
        # response.raise_for_status()
        # cisa_data = response.json()
        # cisa_dict = {entry["cveID"]: entry for entry in cisa_data.get("vulnerabilities", [])}

        # # 🔹 Enriquecer cada entrada
        # for entry in all_hits:
        #     cve = entry.get("_source", {}).get("data", {}).get("vulnerability", {}).get("cve")
        #     if cve and cve in cisa_dict:
        #         entry["_source"]["data"]["vulnerability"]["cisa_kve_info"] = cisa_dict[cve]

        # 🔹 Guardar archivo enriquecido
        with open(output, 'w') as f:
            json.dump(all_hits, f, indent=2)

        # 🔹 Permisos: lectura/escritura solo para arusadm
        os.chmod(output, 0o600)

        print(f"Archivo enriquecido guardado en: {output}")
    else:
        print("No existe")
        reintentos = 0
        print("reintentos", reintentos)
        while reintentos < max_reintentos:
            try:
                resp = client.search(
                    index="wazuh-states-vulnerabilities-wazuh_cluster",
                    scroll="10m",
                    request_timeout=120,
                    size=1000,
                    body={
                        "query": {
                            "bool": {
                                "must": [
                                    {"terms": {"agent.id": agentes}}
                                ]
                            }
                        }
                    }
                )
                scroll_id = resp['_scroll_id']
                all_hits = resp['hits']['hits']
                while True:
                    resp = client.scroll(scroll_id=scroll_id, scroll="5m")
                    hits = resp['hits']['hits']
                    if not hits:
                        break
                    all_hits.extend(hits)
 
                print(f"Total documentos: {len(all_hits)}")
 
                # 🔹 Descargar feed de CISA KEV
                # CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                # response = requests.get(CISA_URL)
                # response.raise_for_status()
                # cisa_data = response.json()
                # cisa_dict = {entry["cveID"]: entry for entry in cisa_data.get("vulnerabilities", [])}
 
                # # 🔹 Enriquecer cada entrada
                # for entry in all_hits:
                #     cve = entry.get("_source", {}).get("data", {}).get("vulnerability", {}).get("cve")
                #     if cve and cve in cisa_dict:
                #         entry["_source"]["data"]["vulnerability"]["cisa_kve_info"] = cisa_dict[cve]
 
                # 🔹 Guardar archivo enriquecido
                with open(output, 'w') as f:
                    json.dump(all_hits, f, indent=2)
 
                # 🔹 Permisos: lectura/escritura solo para arusadm
                os.chmod(output, 0o600)
 
                print(f"Archivo enriquecido guardado en: {output}")
                break  # Éxito, salir del bucle
 
            except Exception as e:
                reintentos += 1
                print(f"Error en intento {reintentos}: {e}")
                if reintentos >= max_reintentos:
                    print("Se alcanzó el número máximo de reintentos. Abortando.")
                    raise



def check_directory(directorio):
    if not os.path.exists(directorio):
        os.makedirs(directorio)
        print(f"Directorio '{directorio}' creado.")