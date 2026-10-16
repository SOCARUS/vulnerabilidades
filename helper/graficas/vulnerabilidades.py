import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from helper.queries.vulnerabilidades import check_directory

# Estilo bonito
sns.set_theme(style="whitegrid")


def graficar_vulnerabilidades(df, directorio, status):
    # Preparar columnas de fecha
    meses_orden = [
        'January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'
    ]
    df['mes'] = pd.Categorical(df['mes'], categories=meses_orden, ordered=True)
    
    # Agrupaciones
    por_mes_severidad = df.groupby(['mes', 'severity']).size().unstack(fill_value=0)
    por_mes_severidad_filtrado = por_mes_severidad[por_mes_severidad.sum(axis=1) > 0]
    
    #Top 10 severidades
    por_severidad = df['severity'].value_counts()
    
    #top agentes
    top_agentes = df['agent_name'].value_counts().head(10)
    por_hora = df['hora'].value_counts().sort_index()
    por_tipo = df['package_name'].value_counts()

    # Crear figura del dashboard
    fig, axs = plt.subplots(2, 2, figsize=(16, 10))
    estado = "activas" if status=="Active" else "resueltas"
    fig.suptitle(f'Dashboard de vulnerabilidades {estado}', fontsize=16)

    # Gráfico 1: Vulnerabilidades por día y severidad (barra apilada)
    por_mes_severidad_filtrado.plot(kind='bar', stacked=True, ax=axs[0, 0], colormap='viridis')
    axs[0, 0].set_title('Por día y severidad')
    axs[0, 0].set_xlabel('Fecha')
    axs[0, 0].set_ylabel('Cantidad')
    axs[0, 0].tick_params(axis='x', rotation=45)

    # Gráfico 2: Total por severidad (barra horizontal)
    por_severidad.iloc[::-1].plot(kind='barh', ax=axs[0, 1], color='tomato')
    axs[0, 1].set_title('Conteo por severidad')
    axs[0, 1].set_xlabel('Cantidad')
    axs[0, 1].set_ylabel('severity')

    # Gráfico 3: Distribución por hora del día (línea)
    top_agentes.iloc[::-1].plot(kind='barh', ax=axs[1, 0], color='purple')
    axs[1, 0].set_title('Top  10 de agentes')
    axs[1, 0].set_xlabel('Cantidad')
    axs[1, 0].set_ylabel('Agente')

    # axs[1, 0].plot(por_hora.index, por_hora.values, marker='o', color='purple')
    # axs[1, 0].set_title('Eventos por hora del día')
    # axs[1, 0].set_xlabel('Hora')
    # axs[1, 0].set_ylabel('Cantidad')
    # axs[1, 0].set_xticks(range(0, 24))

    # Gráfico 4: Vulnerabilidades por tipo (torta)
    umbral = 0.05  # 5%
    total = por_tipo.sum()
    por_tipo_filtrado = por_tipo[por_tipo / total >= umbral]
    otros = por_tipo[por_tipo / total < umbral].sum()

    if otros > 0:
        por_tipo_filtrado['Otros'] = otros

    axs[1, 1].pie(
    por_tipo_filtrado,
    labels=por_tipo_filtrado.index,
    autopct='%1.1f%%',
    startangle=140,
    colors=sns.color_palette('pastel'),
    labeldistance=1.1
    )

    axs[1, 1].set_title('Distribución por tipo')




    plt.tight_layout(rect=[0, 0, 1, 0.95])
    check_directory(directorio)
    status = "activas" if status=="Active" else "resueltas"
    output = f"{directorio}vulnerabilidades_{status}.png"
    plt.savefig(output, dpi=300)