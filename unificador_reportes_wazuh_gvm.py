import pandas as pd
from datetime import datetime
from services.send_email import send_email
import os
import tarfile

date_str = datetime.now().strftime("%Y_%m_%d")


def unificar_reporte_wazuh_gvm():

    wazuh = pd.read_csv('./backlog_vulnerabilidades.csv')
    gvm = pd.read_csv(f'./integraciones/gvm/{date_str}/backlog_vulnerabilidades_gvm.csv')

    #Limpiar columnas que estén duplicadas con un 1 al final del nombre
    wazuh = wazuh.loc[:, ~wazuh.columns.str.endswith('.1')]
    wazuh.columns

    #Renombrar
    gvm = gvm.rename(columns={"Estado_Actual":"Estado"})

    print(len(wazuh))
    print(len(gvm))

    #Marcar el campo Fuente_Deteccion
    wazuh['Fuente_Deteccion'] = 'WAZUH'
    gvm['Fuente_Deteccion'] = 'GVM'

    #Concatenar ambos reportes
    df_total = pd.concat([wazuh, gvm], ignore_index=True)

    # Combinar fuentes
    fuentes = (
        df_total
        .groupby(["Direccion_IP", "CVE_ID", "Estado"])["Fuente_Deteccion"]
        .apply(lambda x: ", ".join(sorted(set(x))))
        .reset_index()
    )

    # Quitar duplicados conservando la primera fila completa
    df_base = df_total.drop_duplicates(subset=["Direccion_IP", "CVE_ID"])

    # Reemplazar columna fuente_deteccion por la combinada
    df_final = df_base.drop(columns=["Fuente_Deteccion"]).merge(
        fuentes,
        on=["Direccion_IP", "CVE_ID", "Estado"],
        how="left"
    )

    df_final = (
        df_total
        .groupby(["Direccion_IP", "CVE_ID"], as_index=False)
        .agg({
            **{col: "first" for col in df_total.columns if col not in ["Direccion_IP", "CVE_ID"]},
            "Fuente_Deteccion": lambda x: ", ".join(sorted(set(x)))
        })
    )
    nombre_archivo = f'vulnerabilidades_wazuh_gvm.csv'
    df_final.to_csv(nombre_archivo)

    output_dir = f'./output/arus/reporte_unificado/{date_str}/'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Directorio '{output_dir}' creado.")
    tar_path = os.path.join(output_dir, f"vulnerabilidades_wazuh_gvm_{date_str}.tar.gz")

    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(nombre_archivo,
                arcname=nombre_archivo)


    print('RESUMEN FINAL\n')
    print(f'Tamaño DataFrame: {len(df_final)}' )
    print(df_final.columns)
    print(f'Estado vulnerabilidades parchadas: {df_final["Estado"].value_counts()}')
    print(f'Estado fuente deteccion: {df_final["Fuente_Deteccion"].value_counts()}')
    print('COLUMNAS\n')


if __name__ == "__main__":
    unificar_reporte_wazuh_gvm()
    send_email(
    ["juan.vargas@arus.com.co", "juan.londono@arus.com.co", "cristian.gaviria@henkia.com"],
    "Reporte unificado de vulnerabilidades ARUS - GVM y WAZUH",
    f"""Se adjunta el reporte de vulnerabilidades de ARUS en formato csv.
        <br>
        <br>
        Cualquier información adicional que requieran, quedamos atentos.
    """,
    [f'./output/arus/reporte_unificado/{date_str}/vulnerabilidades_wazuh_gvm_{date_str}.tar.gz'],
)