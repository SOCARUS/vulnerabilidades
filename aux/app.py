from conexion import client
from sura.vulnerabilidades import vulnerabilidades_sura
import json
from datetime import datetime

datetime_format = "%Y_%m_%dT%H_%M"

now = datetime.now().strftime(datetime_format)

with open('agentes.json', 'r') as f:
    #load json
    agents = json.loads(f.read())

sura = agents['sura']['agents']
print(sura)

status = "Active"
# status = "Active"
resp = client.search(
    index="wazuh-alerts-4.x*",
    scroll="10m",  # mantener el contexto abierto por 2 minutos
    request_timeout=70,
    size=1000,
    body={
        "query": {
            "bool": {
                "must": [
                {
                "match": {
                    "rule.groups": "vulnerability-detector"
                }
                },
                {
                    "range": {
                    "timestamp": {
                        "gte": "now-120d",
                        "lte": "now"
                    }
                    }
                },
                {
                    "terms": {
                    "agent.id": sura
                    }
                },
                {
                    "term": {
                        "data.vulnerability.status": status
                    }
                }
                ]
            }
            }
    })

scroll_id = resp['_scroll_id']
all_hits = resp['hits']['hits']

while True:
    resp = client.scroll(scroll_id=scroll_id, scroll="5m")
    hits = resp['hits']['hits']
    if not hits:
        break
    all_hits.extend(hits)

print(f"Total documentos: {len(all_hits)}")
with open(f'vulnerabilidades_sura_{status}_{now}.json', 'w') as f:
    json.dump(all_hits, f, indent=2)
