from flujos.arus.vulnerabilidades_v3 import reporte_vulnerabilidades_arus, analisis_vulnerabilidades_arus, merge_vulnerabilidades_arus, enriquecimiento_reporte_arus, eliminar_archivos_temporales, backlog_y_vulnerabilidades_resueltas, procesamiento_vulnerabilidades, fecha 
from services.send_email import send_email

if __name__ == "__main__":
    # reporte_vulnerabilidades_arus()
    # analisis_vulnerabilidades_arus()
    # merge_vulnerabilidades_arus()
    # enriquecimiento_reporte_arus()
    backlog_y_vulnerabilidades_resueltas()
    #reporte_vulnerabilidades_gvm()
    # procesamiento_vulnerabilidades()
    fecha_archivo = fecha.replace('-','_')
    # ["juan.vargas@arus.com.co"],
    send_email(
        ["juan.vargas@arus.com.co"],
        "Reporte de vulnerabilidades ARUS Debug",
        f"""Se adjunta el reporte de vulnerabilidades de ARUS para su analisis.
            <br>
            <br>
            Cualquier información adicional que requieran, quedamos atentos.
        """,
        [f"./output/arus/{fecha}/vulnerabilidades_arus_{fecha_archivo}.tar.gz"],
    )
    # #Limpiar archivos temporales del /output y /logs/arus/
    # eliminar_archivos_temporales()
    print("Proceso de vulnerabilidades ARUS completado.")
