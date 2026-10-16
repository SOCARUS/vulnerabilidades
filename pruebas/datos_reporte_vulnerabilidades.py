import pandas as pd


status = 'activas'  # or 'resueltas'
df = pd.read_csv(f'./output/reporte_vulnerabilidades_sura_{status}.csv', parse_dates=['timestamp'])
df_resueltas = pd.read_csv(f'./output/reporte_vulnerabilidades_sura_resueltas.csv', parse_dates=['timestamp'])

print(df.head())

paquetes = df['package_name'].value_counts().head(10)
severidad = df['severity'].value_counts().head(10)
agent_name = df['agent_name'].value_counts().head(10)
cve = df['cve'].value_counts().head(10)
reference = df['reference'].value_counts().head(10)
# paquete_cve = df.groupby(['package_name','cve']).size().reset_index(name='count').sort_values(by='count', ascending=False).head(10)

conteo = df.groupby(['agent_name', 'severity']).size().unstack(fill_value=0).head(10)

vulnerabilidades_criticas_y_altas = df[df['severity'].isin(['Critical', 'High'])]
agentes = vulnerabilidades_criticas_y_altas['agent_name'].value_counts().head(10)
vulnerabilidades_criticas = df[df['severity'].isin(['Critical'])]
paquetes_criticos = vulnerabilidades_criticas['package_name'].value_counts().head(10)

#Top de agentes con vulnerabilidades críticas y altas:
print(agentes)
#Vulnerabilidades por severidad:
print(severidad)
#Paquetes más afectados:
print(paquetes)
#Top de paquetes con vulnerabilidades críticas:
print(paquetes_criticos)
paquetes_y_descripcion = df.groupby(['package_name', 'description']).size().reset_index(name='cantidad')
# paquetes_y_descripcion.to_csv(f'./output/paquetes_y_descripcion_{status}.csv', index=False)

print(len(df))
print(len(df_resueltas))