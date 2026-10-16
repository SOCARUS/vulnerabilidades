import json
import requests
import os
import stat

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

response = requests.get(CISA_URL)
response.raise_for_status()
cisa_data = response.json()

cisa_dict = {entry["cveID"]: entry for entry in cisa_data.get("vulnerabilities", [])}

with open("/home/arusadm/dev/vulnerabilidades/output/arus/2025-08-28/json/vulnerabilidades_arus.json", "r") as f:
    wazuh_data = json.load(f)

def enrich_entry(entry):
    cve = entry.get("_source", {}).get("data", {}).get("vulnerability", {}).get("cve")
    if cve and cve in cisa_dict:
        entry["_source"]["data"]["vulnerability"]["cisa_kve_info"] = cisa_dict[cve]
    return entry

if isinstance(wazuh_data, list):
    wazuh_data = [enrich_entry(entry) for entry in wazuh_data]
else:
    wazuh_data = enrich_entry(wazuh_data)

output_file = "/home/arusadm/dev/vulnerabilidades/output/arus/2025-08-28/json/vulnerabilidades_arus_enriquecido.json"
with open(output_file, "w") as f:
    json.dump(wazuh_data, f, indent=2)

os.chmod(output_file, stat.S_IRUSR | stat.S_IWUSR)

print(f"Archivo enriquecido guardado en: {output_file} con permisos 600 (rw-------)")
