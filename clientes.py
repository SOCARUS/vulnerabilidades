import json
import os
import tarfile
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from flujos.clientes.vulnerabilidades import reporte_vulnerabilidades
from services.backlog_vulnerabilidades_sqlite import upsert_report
from services.send_email import send_email


CLIENTES_ORDER = ["stf", "prebel", "personalsoft"]
WAIT_SECONDS_BETWEEN_CLIENTS = 30
MAX_CSV_BYTES_TO_SEND = 5 * 1024 * 1024  # 5 MB


def tablero_vuln(df, TOP_N=10, output_path=None):
    """Genera un dashboard por cliente con los principales equipos y vulnerabilidades."""
    df = df.copy()
    rename_map = {}
    for source, target in {
        "agent.name": "equipo",
        "package.name": "vulnerabilidad",
        "vulnerability.severity": "severidad",
    }.items():
        if source in df.columns:
            rename_map[source] = target
    if rename_map:
        df.rename(columns=rename_map, inplace=True)

    if "equipo" not in df.columns or "vulnerabilidad" not in df.columns:
        raise ValueError("El DataFrame debe incluir 'agent.name' y 'package.name'.")

    if output_path is None:
        output_path = Path("./output/tablero_vulnerabilidades.png")
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if df.empty:
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle("Tablero de Control: Sin datos disponibles", fontsize=16, fontweight="bold")
        for ax in axes.flat:
            ax.text(0.5, 0.5, "Sin datos", ha="center", va="center")
            ax.set_axis_off()
        fig.tight_layout()
        fig.savefig(output_path, dpi=300, bbox_inches="tight")
        plt.close(fig)
        return str(output_path)

    top_equipos_vulns = (
        df.groupby("equipo")["vulnerabilidad"]
        .nunique()
        .sort_values(ascending=False)
        .head(TOP_N)
    )

    top_vulns_equipos = (
        df.groupby("vulnerabilidad")["equipo"]
        .nunique()
        .sort_values(ascending=False)
        .head(TOP_N)
        .sort_values(ascending=True)
    )

    df_top = df[
        df["equipo"].isin(top_equipos_vulns.index)
        & df["vulnerabilidad"].isin(top_vulns_equipos.index)
    ]

    if not top_equipos_vulns.empty and not top_vulns_equipos.empty:
        matriz_top = (
            df_top.groupby(["equipo", "vulnerabilidad"])
            .size()
            .unstack(fill_value=0)
            .reindex(index=top_equipos_vulns.index, columns=top_vulns_equipos.index)
        )
    else:
        matriz_top = pd.DataFrame(index=top_equipos_vulns.index, columns=top_vulns_equipos.index, dtype=int).fillna(0)

    fig, axes = plt.subplots(nrows=2, ncols=2, figsize=(14, 10))
    fig.suptitle(
        f"Tablero de Control: Top {TOP_N} Hallazgos Críticos",
        fontsize=16,
        fontweight="bold",
    )

    axes[0, 0].bar(
        top_equipos_vulns.index,
        top_equipos_vulns.values,
        color="#2b5c8f",
        edgecolor="black",
    )
    axes[0, 0].set_title(f"Top {TOP_N} Equipos con Más CVEs Únicos", fontweight="bold")
    axes[0, 0].set_ylabel("Cant. CVEs Distintos")
    axes[0, 0].tick_params(axis="x", rotation=30)

    axes[0, 1].barh(
        top_vulns_equipos.index,
        top_vulns_equipos.values,
        color="#d95f02",
        edgecolor="black",
    )
    axes[0, 1].set_title(f"Top {TOP_N} Vulnerabilidades Más Propagadas", fontweight="bold")
    axes[0, 1].set_xlabel("Cant. Equipos Únicos Afectados")

    if "severidad" in df.columns:
        equipos_por_sev = df.groupby("severidad")["equipo"].nunique().sort_values(ascending=False)
        axes[1, 0].bar(
            equipos_por_sev.index,
            equipos_por_sev.values,
            color="#7570b3",
            edgecolor="black",
        )
        axes[1, 0].set_title("Equipos Únicos por Severidad", fontweight="bold")
        axes[1, 0].set_ylabel("Cant. Equipos")
    else:
        axes[1, 0].text(0.5, 0.5, "Sin severidad", ha="center", va="center")
        axes[1, 0].set_axis_off()

    if not matriz_top.empty:
        im = axes[1, 1].imshow(matriz_top.values, cmap="YlOrRd", aspect="auto")
        axes[1, 1].set_xticks(range(len(matriz_top.columns)))
        axes[1, 1].set_yticks(range(len(matriz_top.index)))
        axes[1, 1].set_xticklabels(matriz_top.columns, rotation=45, ha="right")
        axes[1, 1].set_yticklabels(matriz_top.index)
        axes[1, 1].set_title("Cruce Top Equipos vs Top Vulnerabilidades", fontweight="bold")
        fig.colorbar(im, ax=axes[1, 1], fraction=0.046, pad=0.04)
    else:
        axes[1, 1].text(0.5, 0.5, "Sin cruces", ha="center", va="center")
        axes[1, 1].set_axis_off()

    fig.tight_layout()
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return str(output_path)

def analisis_vulnerabilidades(df: pd.DataFrame, cliente: str) -> dict[str, Path]:
    """Genera dos CSVs con el análisis por equipo y paquetes vulnerables."""
    path = Path("./clientes/vulnerabilidades") / cliente
    path.mkdir(parents=True, exist_ok=True)

    resultados = {}

    if "agent.name" in df.columns and "package.name" in df.columns:
        vulnerabilidades_agrupadas_por_equipo = (
            df.groupby("agent.name")["package.name"]
            .value_counts()
            .reset_index(name="Count")
        )
        agrupadas_path = path / f"vulnerabilidades_agrupadas_por_equipo_{cliente}.csv"
        vulnerabilidades_agrupadas_por_equipo.to_csv(agrupadas_path, index=False)
        resultados["agrupadas_por_equipo"] = agrupadas_path

        paquetes_por_equipo = (
            df.groupby("agent.name")["package.name"]
            .nunique()
            .sort_values(ascending=False)
        )
        conteo_path = path / f"agentes_con_mas_paquetes_vulnerables_{cliente}.csv"
        paquetes_por_equipo.to_csv(conteo_path)
        resultados["paquetes_por_equipo"] = conteo_path
    else:
        mensaje = pd.DataFrame({"alerta": ["Faltan columnas 'agent.name' o 'package.name'"]})
        agrupadas_path = path / f"vulnerabilidades_agrupadas_por_equipo_{cliente}.csv"
        mensaje.to_csv(agrupadas_path, index=False)
        resultados["agrupadas_por_equipo"] = agrupadas_path

        conteo_path = path / f"agentes_con_mas_paquetes_vulnerables_{cliente}.csv"
        pd.DataFrame({"agente": [], "cantidad_paquetes": []}).to_csv(conteo_path, index=False)
        resultados["paquetes_por_equipo"] = conteo_path

    return resultados


def generar_resumen_cliente(cliente: str) -> pd.DataFrame:
    output_dir = Path("./clientes/vulnerabilidades") / cliente
    output_dir.mkdir(parents=True, exist_ok=True)

    csv_path = output_dir / f"vulnerabilidades_{cliente}.csv"
    resumen_path = output_dir / f"resumen_{cliente}.csv"

    if not csv_path.exists():
        resumen = pd.DataFrame([
            {
                "cliente": cliente,
                "fecha_ejecucion": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
                "estado": "sin_datos",
                "total_vulnerabilidades": 0,
                "agentes_unicos": 0,
                "criticas": 0,
                "altas": 0,
                "medias": 0,
                "bajas": 0,
                "desconocidas": 0,
                "archivo": str(csv_path),
            }
        ])
        resumen.to_csv(resumen_path, index=False)
        return resumen

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    df = df.fillna("")

    severidad = df["vulnerability.severity"].astype(str).str.lower().str.strip()
    resumen = pd.DataFrame([
        {
            "cliente": cliente,
            "fecha_ejecucion": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
            "estado": "ok",
            "total_vulnerabilidades": int(len(df)),
            "agentes_unicos": df["agent.id"].nunique() if "agent.id" in df.columns else 0,
            "criticas": int((severidad == "critical").sum()),
            "altas": int((severidad == "high").sum()),
            "medias": int((severidad == "medium").sum()),
            "bajas": int((severidad == "low").sum()),
            "desconocidas": int((~severidad.isin(["critical", "high", "medium", "low"]) & (severidad != "")).sum()),
            "archivo": str(csv_path),
        }
    ])

    resumen.to_csv(resumen_path, index=False)
    return resumen


def preparar_adjunto_csv(csv_path: Path, cliente: str | None = None) -> Path:
    csv_path = Path(csv_path)

    if not csv_path.exists():
        raise FileNotFoundError(f"No existe el CSV para adjuntar: {csv_path}")

    archivos = [csv_path]
    if cliente:
        archivos.extend(
            [
                csv_path.parent / f"vulnerabilidades_agrupadas_por_equipo_{cliente}.csv",
                csv_path.parent / f"agentes_con_mas_paquetes_vulnerables_{cliente}.csv",
            ]
        )
        archivos = [archivo for archivo in archivos if archivo.exists()]

    if len(archivos) == 1 and csv_path.stat().st_size <= MAX_CSV_BYTES_TO_SEND:
        return csv_path

    tar_path = csv_path.parent / f"analisis_{cliente}.tar.gz" if cliente else csv_path.with_suffix(".tar.gz")
    with tarfile.open(tar_path, "w:gz") as tar:
        for archivo in archivos:
            tar.add(archivo, arcname=archivo.name)

    print(f"Archivos comprimidos en {tar_path}")
    return tar_path


def build_email_message(cliente: str, resumen_df: pd.DataFrame) -> str:
    resumen_html = resumen_df.to_html(index=False, border=0, classes="table table-bordered")
    return f"""
        <h3>Resumen de vulnerabilidades - {cliente}</h3>
        <p>El reporte fue generado el {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}.</p>
        <p>Se adjunta el archivo CSV del cliente en formato normal o comprimido si supera el límite, junto con el tablero de vulnerabilidades del cliente.</p>
        {resumen_html}
    """


def actualizar_backlog_cliente(cliente: str, csv_path: Path) -> None:
    """Actualiza el backlog a partir del CSV generado para un cliente."""
    if not csv_path.exists():
        raise FileNotFoundError(f"No existe el CSV para actualizar el backlog: {csv_path}")

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    if df.empty:
        print(f"[{cliente}] El CSV está vacío; no se actualiza el backlog.")
        return

    upsert_report(cliente, df, db_dir="./backlog_db")


if __name__ == "__main__":
    with open("./clientes/agentes/clientes.json", encoding="utf-8") as f:
        clientes_config = json.loads(f.read())

    for cliente in CLIENTES_ORDER:
        config = clientes_config.get(cliente)
        if not config:
            print(f"Cliente '{cliente}' no existe en clientes.json, omitiendo.")
            continue

        agentes = config.get("agentes", [])
        destinatarios = config.get("destinatarios", [])

        if not destinatarios:
            print(f"Cliente '{cliente}' no tiene destinatarios configurados; se omite el envío.")
            continue

        print(f"\n==== Ejecutando cliente: {cliente} ====")
        reporte_vulnerabilidades(agentes=agentes, cliente=cliente)
        resumen = generar_resumen_cliente(cliente)

        csv_path = Path("./clientes/vulnerabilidades") / cliente / f"vulnerabilidades_{cliente}.csv"
        tablero_path = Path("./clientes/vulnerabilidades") / cliente / f"tablero_{cliente}.png"

        if csv_path.exists():
            df_cliente = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
            actualizar_backlog_cliente(cliente, csv_path)
            analisis_vulnerabilidades(df_cliente, cliente)
            tablero_vuln(df_cliente, TOP_N=10, output_path=tablero_path)
        else:
            print(f"No existe {csv_path}; no se generará tablero ni análisis para {cliente}.")

        attachment_path = preparar_adjunto_csv(csv_path, cliente)
        attachments = [str(attachment_path)]

        html_message = build_email_message(cliente, resumen)
        if tablero_path.exists():
            html_message = html_message + f'<div style="margin-top:20px;"><img src="cid:tablero_cliente" alt="Tablero de vulnerabilidades" style="width:100%; max-width:1100px; border:1px solid #ddd;" /></div>'

            # ["juan.vargas@henkia.com"],
        send_email(
            destinatarios,
            f"Reporte de vulnerabilidades - {cliente}",
            html_message,
            attachments,
            imagen=str(tablero_path) if tablero_path.exists() else '',
        )

        if cliente != CLIENTES_ORDER[-1]:
            print(f"Esperando {WAIT_SECONDS_BETWEEN_CLIENTS} segundos antes del siguiente cliente...")
            time.sleep(WAIT_SECONDS_BETWEEN_CLIENTS)

    print("\nProcesamiento completado para todos los clientes configurados.")
