import pandas as pd
from datetime import datetime

from services.send_email import send_email

fecha = datetime.now().strftime("%Y-%m-%d")


def leer_y_enviar_correo(fecha=fecha, correos=["juan.vargas@arus.com.co"] ):
    df = pd.read_csv(f'./output/arturo_calle/{fecha}/vulnerabilidades_activas.csv', parse_dates=['timestamp'])
    df_resueltas = pd.read_csv(f'./output/{fecha}/vulnerabilidades_resueltas.csv', parse_dates=['timestamp'])

    paquetes = df['package_name'].value_counts().head(10)
    cve = df['cve'].value_counts().head(10)
    reference = df['reference'].value_counts().head(10)
    # paquete_cve = df.groupby(['package_name','cve']).size().reset_index(name='count').sort_values(by='count', ascending=False).head(10)

    conteo = df.groupby(['agent_name', 'severity']).size().unstack(fill_value=0).head(10)

    vulnerabilidades_criticas_y_altas = df[df['severity'].isin(['Critical', 'High'])]
    vulnerabilidades_criticas = df[df['severity'].isin(['Critical'])]
    conteo = vulnerabilidades_criticas.groupby(['package_name', 'description']).size().unstack(fill_value=0).head(10)


    #Severidad
    severidad = df['severity'].value_counts().head(10)
    severidad = severidad.reset_index()
    severidad.columns = ['Severidad', 'count']
    #Agentes 
    agent_name = df['agent_name'].value_counts().head(10)
    agent_name = agent_name.reset_index()
    agent_name.columns = ['Agentes', 'count']
    #Agentes  con vulnerabilidades criticas
    agentes_vulnerabilidades_criticas = vulnerabilidades_criticas['agent_name'].value_counts().head(10)
    agentes_vulnerabilidades_criticas = agentes_vulnerabilidades_criticas.reset_index()
    agentes_vulnerabilidades_criticas.columns = ['Agentes', 'count']
    #Paquetes con vulnerabilidades criticas
    paquetes_criticos = vulnerabilidades_criticas['package_name'].value_counts().head(10)
    paquetes_criticos = paquetes_criticos.reset_index()
    paquetes_criticos.columns = ['Paquetes', 'count']


            # ["juan.vargas@arus.com.co", "jorge.vallejo@arus.com.co", "andres.ortiz@arus.com.co", "aldemar.posada@arus.com.co", "david.mesa@arus.com.co", "juan.restrepom@arus.com.co"],
    send_email(
            correos,
            "Reporte de vulnerabilidades - Arturo Calle",
            email_message=f"""


            <h2>Analisis vulnerabilidades</h2>
            
            Buenas tardes,
            <br>
            <p>
            Se comparte el detalle de las vulnerabilidades de Arturo Calle actualmene junto con un pequeño analisis:
            </p>
            <br>
            <p>
            <strong>Actualmente tenemos: </strong>{len(df)} vulnerabilidades activas
            </p>
            <br>

            <strong>Y en los ultimos 90 días se han resuelto: </strong> {len(df_resueltas)} vulnerabilidades
            <br>

            <h3>Vulnerabilidades por severidad:</h3>

            {severidad.to_html(index=False)}

            <h3>Agentes con mas vulnerabilidades - General:</h3>

            {agent_name.to_html(index=False)}

            <h3>Agentes con mas vulnerabilidades criticas:</h3>

            {agentes_vulnerabilidades_criticas.to_html(index=False)}

            <h3>Paquetes con vulnerabilidades criticas:</h3>

            {paquetes_criticos.to_html(index=False)}


            <br>
            Cualquier informacion adicional que requieran, quedamos atentos

            """,
            attachment_location=[
                f"./output/{fecha}/vulnerabilidades_activas.csv",
                f"./output/{fecha}/vulnerabilidades_resueltas.csv",
                f"./output/{fecha}/vulnerabilidades_activas.png",
                f"./output/{fecha}/vulnerabilidades_resueltas.png"
                ],
            )