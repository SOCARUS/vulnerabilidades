import json
import pandas as pd

def normalizacion_json(directorio):
    with open(directorio, 'r') as f:
        vulnerabilidades = json.loads(f.read())

        # Convertir a DataFrame para facilitar el análisis
        df = pd.json_normalize(vulnerabilidades)

        df = df.drop_duplicates(subset=['_source.agent.name', '_source.data.vulnerability.cve'])

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

        # Preparar columnas de fecha
        df['fecha'] = df['timestamp'].dt.date

        #Extraer el mes en texto
        df['mes'] = df['timestamp'].dt.strftime('%B')

        df['hora'] = df['timestamp'].dt.hour

        df['timestamp'] = df['timestamp'].dt.strftime('%d/%m/%Y %I:%M %p')



        return df