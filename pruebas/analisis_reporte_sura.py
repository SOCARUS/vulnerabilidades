import json

import matplotlib.pyplot as plt
import pandas as pd

with open('./output/vulnerabilidades_sura_Active_2025_07_15T10_43.json', 'r') as f:
    vulnerabilidades = json.loads(f.read())

# Convertir a DataFrame para facilitar el análisis
df = pd.json_normalize(vulnerabilidades)
df['timestamp'] = pd.to_datetime(df['_source.timestamp'])

# seleccionar las columnas relevantes
df = df[[
    '_source.timestamp',
    '_source.agent.name',
    '_source.agent.id',
    '_source.data.vulnerability.package.name',
    '_source.data.vulnerability.package.version',
    '_source.data.vulnerability.cve',
    '_source.data.vulnerability.status',
    '_source.data.vulnerability.severity',
    '_source.data.vulnerability.published',
    '_source.data.vulnerability.title',
    '_source.data.vulnerability.status',
    '_source.rule.description',
    '_source.data.vulnerability.reference',
    ]]

df = df.rename(columns={
    '_source.timestamp': 'timestamp',
    '_source.agent.name': 'agent_name',
    '_source.agent.id': 'agent_id',
    '_source.data.vulnerability.package.name': 'package_name',
    '_source.data.vulnerability.package.version': 'package_version',
    '_source.data.vulnerability.cve': 'cve',
    '_source.data.vulnerability.status': 'status',
    '_source.data.vulnerability.severity': 'severity',
    '_source.data.vulnerability.published': 'published',
    '_source.data.vulnerability.title': 'title',
    '_source.rule.description': 'description',
    '_source.data.vulnerability.reference': 'reference'
})

# Convertir la columna 'timestamp' a datetime
df['timestamp'] = pd.to_datetime(df['timestamp'])


# Agrupar por agente y contar vulnerabilidades
vulnerabilidades_por_agente = df.groupby('agent_name').size().reset_index(name='count')
# Mostrar las vulnerabilidades por agente
print("Vulnerabilidades por agente:")
print(vulnerabilidades_por_agente)
# Agrupar por severidad y contar vulnerabilidades
vulnerabilidades_por_severidad = df.groupby('package_name').size().reset_index(name='count')


#mostrar vulnerabilidades por dia y por severidad
print("Vulnerabilidades por severidad:")

vulnerabilidades_por_dia = df.groupby(df['timestamp'].dt.date).size().reset_index(name='count')

#Graficar vulnerabilidades por dia
plt.figure(figsize=(12, 6))
plt.plot(vulnerabilidades_por_dia['timestamp'], vulnerabilidades_por_dia['count'], marker='o')
plt.title('Vulnerabilidades por día')
plt.xlabel('Fecha')
plt.ylabel('Número de vulnerabilidades')
plt.xticks(rotation=45)
plt.grid()
plt.tight_layout()
plt.show()

#Agrupar y graficar vulnerabilidades por severidad y por dia
vulnerabilidades_por_severidad = df.groupby(['package_name', 'severity']).size().reset_index(name='count')
print("Vulnerabilidades por severidad:")
print(vulnerabilidades_por_severidad)
# Graficar vulnerabilidades por severidad
plt.figure(figsize=(12, 6))
vulnerabilidades_por_severidad.pivot(index='package_name', columns='severity', values='count').plot(kind='bar', stacked=True)

plt.title('Vulnerabilidades por severidad')
plt.xlabel('Paquete')
plt.ylabel('Número de vulnerabilidades')
plt.xticks(rotation=45)
plt.legend(title='Severidad')
plt.tight_layout()
plt.savefig('vulnerabilidades_por_severidad.png')
plt.show()

print(f"Total vulnerabilidades: {len(vulnerabilidades)}")

# print(vulnerabilidades[0]['_source']['data']['vulnerability']['status'])
