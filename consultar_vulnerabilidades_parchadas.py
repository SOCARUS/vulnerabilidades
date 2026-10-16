#!/usr/bin/env python3
"""Consulta vulnerabilidades resueltas o parchadas por cliente."""

import argparse
import csv
import sqlite3
from pathlib import Path


# python consultar_vulnerabilidades_parchadas.py
# python consultar_vulnerabilidades_parchadas.py --cliente personalsoft
# python consultar_vulnerabilidades_parchadas.py --cliente personalsoft --status resolved --desde 2026-10-01 --hasta 2026-10-07
# python consultar_vulnerabilidades_parchadas.py --output ./resultado_vulnerabilidades.csv

DEFAULT_DB_DIR = Path("./backlog_db")


def get_db_files(db_dir: Path):
    """Devuelve las bases SQLite disponibles en el directorio."""
    if not db_dir.exists():
        raise FileNotFoundError(f"No existe el directorio de bases: {db_dir}")

    files = sorted(db_dir.glob("*.sqlite3"))
    if not files:
        raise FileNotFoundError(f"No se encontraron bases SQLite en {db_dir}")
    return files


def query_vulnerabilities(db_path: Path, client: str, status: str, since: str, until: str):
    """Obtiene las vulnerabilidades que cumplen los filtros."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    query = """
        SELECT
            agent_name,
            host_os_name,
            package_name,
            package_version,
            vulnerability_id,
            vulnerability_classification,
            vulnerability_severity,
            vulnerability_score_base,
            package_installed,
            status,
            fecha_detectado,
            fecha_resuelta,
            last_seen_at
        FROM vulnerabilities
        WHERE 1 = 1
    """
    params = []

    if status:
        query += " AND status = ?"
        params.append(status)

    if since:
        query += " AND fecha_resuelta >= ?"
        params.append(since)

    if until:
        query += " AND fecha_resuelta <= ?"
        params.append(f"{until}T23:59:59")

    query += " ORDER BY fecha_resuelta DESC, package_name, vulnerability_id"

    rows = conn.execute(query, params).fetchall()
    conn.close()

    return [dict(row) for row in rows]


def print_report(client_name: str, rows):
    """Imprime un reporte legible por consola."""
    print(f"\nCliente: {client_name}")
    print(f"Total de vulnerabilidades: {len(rows)}")

    if not rows:
        print("No se encontraron registros con los filtros seleccionados.")
        return

    headers = [
        "Agente",
        "Host",
        "Paquete",
        "Versión",
        "CVE",
        "Clasificación",
        "Severidad",
        "Score",
        "Instalado",
        "Fecha detección",
        "Fecha resolución",
    ]

    values = [
        [
            row["agent_name"],
            row["host_os_name"],
            row["package_name"],
            row["package_version"],
            row["vulnerability_id"],
            row["vulnerability_classification"],
            row["vulnerability_severity"],
            row["vulnerability_score_base"],
            row["package_installed"],
            row["fecha_detectado"],
            row["fecha_resuelta"],
        ]
        for row in rows
    ]

    widths = [len(header) for header in headers]
    for value_row in values:
        for index, value in enumerate(value_row):
            widths[index] = max(widths[index], len(str(value)))

    def fmt(row):
        return " | ".join(str(value).ljust(widths[index]) for index, value in enumerate(row))

    print(fmt(headers))
    print("-+-".join("-" * width for width in widths))
    for value_row in values:
        print(fmt(value_row))


def export_csv(rows, path: Path, client_name: str):
    """Exporta las vulnerabilidades a un archivo CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "cliente",
                "agent_name",
                "host_os_name",
                "package_name",
                "package_version",
                "vulnerability_id",
                "vulnerability_classification",
                "vulnerability_severity",
                "vulnerability_score_base",
                "package_installed",
                "status",
                "fecha_detectado",
                "fecha_resuelta",
                "last_seen_at",
            ],
        )
        writer.writeheader()
        for row in rows:
            row_with_client = {"cliente": client_name, **row}
            writer.writerow(row_with_client)

    print(f"\nArchivo CSV exportado: {path}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Consulta vulnerabilidades resueltas o parchadas por cliente desde SQLite."
    )
    parser.add_argument("--db-dir", type=Path, default=DEFAULT_DB_DIR, help="Directorio con las bases SQLite.")
    parser.add_argument("--cliente", help="Filtrar por un cliente concreto (nombre de la base sin .sqlite3).")
    parser.add_argument(
        "--status",
        default="resolved",
        choices=["active", "resolved"],
        help="Estado de la vulnerabilidad. Por defecto: resolved.",
    )
    parser.add_argument("--desde", help="Fecha de resolución inicial en formato YYYY-MM-DD.")
    parser.add_argument("--hasta", help="Fecha de resolución final en formato YYYY-MM-DD.")
    parser.add_argument("--output", type=Path, help="Ruta CSV donde exportar los resultados.")
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        db_files = get_db_files(args.db_dir)
    except FileNotFoundError as exc:
        raise SystemExit(str(exc))

    selected_files = []
    for db_file in db_files:
        client_name = db_file.stem
        if args.cliente and client_name != args.cliente:
            continue
        selected_files.append((client_name, db_file))

    if not selected_files:
        raise SystemExit(f"No se encontraron bases para el cliente '{args.cliente}'.")

    all_rows = []
    for client_name, db_file in selected_files:
        rows = query_vulnerabilities(db_file, client_name, args.status, args.desde, args.hasta)
        all_rows.extend({"cliente": client_name, **row} for row in rows)
        print_report(client_name, rows)

    if args.output:
        export_csv(all_rows, args.output, "")

    print(f"\nTotal de clientes consultados: {len(selected_files)}")
    print(f"Total de registros encontrados: {len(all_rows)}")


if __name__ == "__main__":
    main()
