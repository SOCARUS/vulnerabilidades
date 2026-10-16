from flujos.arus.vulnerabilidades_gvm import  reporte_vulnerabilidades_gvm, analisis_vulnerabilidades_gvm, fecha 
import pandas as pd
from services.send_email import send_email
import json

if __name__ == "__main__":
    # reporte_vulnerabilidades_gvm()
    analisis_vulnerabilidades_gvm()
    # df = pd.read_json(f"./output/arus/{fecha}/gvm/reporte_gvm.jsonl", lines=True)
    # f.close()
    # total = len(df)
    # reporte_gvm()