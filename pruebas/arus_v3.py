from services.conexion import client


import json
import os
from datetime import datetime


fecha = datetime.now().strftime("%Y-%m-%d")

# --- Configuración ---
INDEX = "wazuh-states-vulnerabilities-wazuh_cluster"
CHUNK_FILE_SIZE = 200_000  # puedes poner 500_000 si quieres
SCROLL_SIZE = 10_000       # docs por petición a OpenSearch
SCROLL_TTL = "2m"          # tiempo de vida del scroll
OUTPUT_PREFIX = f"/logs/arus/{fecha}/json/vulns_export"  # prefijo de los archivos de salida

if not os.path.exists(OUTPUT_PREFIX):
    os.makedirs(OUTPUT_PREFIX)
    print(f"Directorio '{OUTPUT_PREFIX}' creado.")
# --- Cliente ---
# client = OpenSearch(
#     hosts=[{"host": HOST, "port": PORT}],
#     http_auth=(USER, PASS),
#     use_ssl=True,
#     verify_certs=False
# )

arus = ['451', '452', '453', '454', '455', '456', '457', '458', '459', '460', '461', '462', '463', '464', '465', '466', '467', '468', '469', '470', '471', '472', '473', '474', '475', '476', '477', '478', '479', '480', '481', '482', '483', '484', '485', '486', '487', '488', '489', '490', '491', '492', '493', '494', '495', '496', '497', '498', '499', '500', '501', '502', '503', '504', '505', '506', '507', '508', '509', '510', '511', '512', '513', '514', '515', '516', '518', '519', '520', '521', '522', '523', '524', '525', '526', '527', '528', '529', '530', '531', '532', '533', '534', '535', '536', '537', '538', '539', '540', '541', '542', '543', '544', '545', '546', '547', '548', '549', '550', '551', '552', '553', '554', '555', '556', '557', '558', '559', '560', '561', '562', '563', '564', '565', '566', '567', '568', '569', '570', '571', '572', '573', '574', '575', '576', '577', '578', '579', '580', '581', '582', '583', '584', '585', '586', '587', '588', '589', '590', '591', '592', '593', '594', '595', '596', '597', '598','061', '062', '063', '064', '109', '110', '111', '112', '113', '114', '115', '116', '117', '118', '119', '120', '121', '122', '123', '124', '125', '126', '381', '382', '383', '384', '385', '386', '387', '388', '389', '390', '391', '392', '393', '394', '395', '396', '397', '398', '399', '400', '401', '402', '403', '404', '406', '407', '408', '411', '414', '415', '416', '417', '418', '419', '420', '421', '422', '423', '424', '425', '426', '427', '428', '429', '430', '431', '432', '433', '434', '435', '436', '437', '438', '439', '440', '441', '442', '443', '444', '446', '447', '448']
# linux=["451", "452", "453", "454", "455", "456", "457", "458", "459", "460", "461", "462", "463", "464", "465", "466", "467", "468", "469", "470", "471", "472", "473", "474", "475", "476", "477", "478", "479", "480", "481", "482", "483", "484", "485", "486", "487", "488", "489", "490", "491", "492", "493", "494", "495", "496", "497", "499", "500", "501", "502", "503", "504", "505", "506", "507", "508", "509", "510", "511"]
# windows=["061", "062", "063", "064", "109", "110", "111", "112", "113", "114", "115", "116", "117", "118", "119", "120", "121", "122", "123", "124", "125", "126", "381", "382", "383", "384", "385", "386", "387", "388", "389", "390", "391", "392", "393", "394", "395", "396", "397", "398", "399", "400", "401", "402", "403", "404", "406", "407", "408", "411", "414", "415", "416", "417", "418", "419", "420", "421", "422", "423", "424", "425", "426", "427", "428", "429", "430", "431", "432", "433", "434", "435", "436", "437", "438", "439", "440", "441", "442", "443", "444", "446", "447", "448",]


# --- Query ---
# {"terms": {"vulnerability.severity": ["Critical", "High", "Medium"]}}
query = {
        "query": {
            "bool": {
                "must": [
                    {"terms": {"agent.id": arus}}
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
file_index = 1
doc_counter = 0
file_name = f"{OUTPUT_PREFIX}_{file_index}.jsonl"
f = open(file_name, "w", encoding="utf-8")

print(f"Iniciando exportación a {file_name}...")

while scroll_size > 0:
    for doc in page["hits"]["hits"]:
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

    # Pedir siguiente página
    page = client.scroll(scroll_id=sid, scroll=SCROLL_TTL)
    sid = page["_scroll_id"]
    scroll_size = len(page["hits"]["hits"])

# Cerrar último archivo
f.close()
print(f"Exportación completada, último archivo: {file_name}")
