import pandas as pd

# Cargar los CSV o Excel
wazuh = pd.read_csv("wazuh_vulns.csv")
gvm = pd.read_csv("gvm_vulns.csv")

# Normalizar nombres de columnas (para evitar fallos en el merge)
wazuh.columns = wazuh.columns.str.strip().str.lower()
gvm.columns = gvm.columns.str.strip().str.lower()


print(wazuh.columns)
print(gvm.columns)

# Claves de unión
# keys = ['cve_id', 'package_name', 'package_version', 'ip']

# merged = pd.merge(gvm, wazuh, on=keys, how='outer', suffixes=('_gvm', '_wazuh'))