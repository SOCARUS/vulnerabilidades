#!/usr/bin/env python3
"""Cruza el reporte actual de Wazuh con el backlog SQLite por cliente.

Compara los registros usando exactamente los mismos criterios que `compute_unique_id`:
agent.id, package.name, package.version y vulnerability.id.
"""

import argparse
import csv
import hashlib
import sqlite3
from pathlib import Path


DEFAULT_DB_DIR = Path("./backlog_db")
DEFAULT_REPORT_DIR = Path("./clientes/vulnerabilidades")


def normalize_value(value):
    return "" if value is None else str(value).strip()


def normalize_status(value):
    value = normalize_value(value).lower()
    if value in {"resolved", "solved"}:
        return "resolved"
    return "active"


def compute_key(row):
    raw = "|".join(
        normalize_value(row.get(column, ""))
        for column in [
            "agent.id",
            "package.name",
            "package.version",
            "vulnerability.id",
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def read_csv_report(csv_path):
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    if not rows:
        return []

    normalized = []
    for row in rows:
        key = compute_key(row)
        normalized.append(
            {
                "vuln_key": key,
                "agent_id": normalize_value(row.get("agent.id", "")),
                "agent_name": normalize_value(row.get("agent.name", "")),
                "host_os_name": normalize_value(row.get("host.os.name", "")),
                "package_name": normalize_value(row.get("package.name", "")),
                "package_version": normalize_value(row.get("package.version", "")),
                "vulnerability_id": normalize_value(row.get("vulnerability.id", "")),
                "classification": normalize_value(row.get("vulnerability.classification", "")),
                "status": normalize_status(row.get("status", "")),
                "fecha_detectado": normalize_value(row.get("fecha_detectado", "")),
                "fecha_resuelta": normalize_value(row.get("fecha_resuelta", "")),
                "last_seen_at": normalize_value(row.get("last_seen_at", "")),
            }
        )
    return normalized


def read_database_status(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT
            vuln_key,
            agent_id,
            agent_name,
            host_os_name,
            package_name,
            package_version,
            vulnerability_id,
            vulnerability_classification,
            status,
            fecha_detectado,
            fecha_resuelta,
            last_seen_at
        FROM vulnerabilities
        """
    ).fetchall()
    conn.close()

    return [dict(row) for row in rows]


def select_clients(db_dir, client_name):
    if client_name:
        db_path = db_dir / f"{client_name}.sqlite3"
        if not db_path.exists():
            raise FileNotFoundError(f"No existe la base SQLite: {db_path}")
        return [(client_name, db_path)]

    return [(path.stem, path) for path in sorted(db_dir.glob("*.sqlite3"))]


def findings_for_client(client_name, report_rows, db_rows):
    db_by_key = {row["vuln_key"]: row for row in db_rows}
    report_by_key = {row["vuln_key"]: row for row in report_rows}

    matched = []
    missing_from_report = []
    status_mismatch = []

    for key, db_row in db_by_key.items():
        report_row = report_by_key.get(key)
        if report_row is None:
            missing_from_report.append(
                {
                    "cliente": client_name,
                    "agent_id": db_row["agent_id"],
                    "agent_name": db_row["agent_name"],
                    "package_name": db_row["package_name"],
                    "package_version": db_row["package_version"],
                    "vulnerability_id": db_row["vulnerability_id"],
                    "db_status": db_row["status"],
                    "db_fecha_resuelta": db_row["fecha_resuelta"],
                    "motivo": "ausente_en_reporte_actual",
                }
            )
            continue

        db_status = normalize_status(db_row["status"])
        report_status = report_row["status"]
        if db_status != report_status:
            status_mismatch.append(
                {
                    "cliente": client_name,
                    "agent_id": db_row["agent_id"],
                    "agent_name": db_row["agent_name"],
                    "package_name": db_row["package_name"],
                    "package_version": db_row["package_version"],
                    "vulnerability_id": db_row["vulnerability_id"],
                    "db_status": db_status,
                    "report_status": report_status,
                    "db_fecha_resuelta": db_row["fecha_resuelta"],
                    "report_fecha_resuelta": report_row["fecha_resuelta"],
                    "motivo": "estado_distinto",
                }
            )
        else:
            matched.append(
                {
                    "cliente": client_name,
                    "agent_id": db_row["agent_id"],
                    "agent_name": db_row["agent_name"],
                    "package_name": db_row["package_name"],
                    "package_version": db_row["package_version"],
                    "vulnerability_id": db_row["vulnerability_id"],
                    "db_status": db_status,
                    "report_status": report_status,
                    "motivo": "coincide",
                }
            )

    return matched, missing_from_report, status_mismatch


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(client_name, matched, missing, mismatches):
    print(f"\nCliente: {client_name}")
    print(f"  Coinciden: {len(matched)}")
    print(f"  Ausentes en reporte: {len(missing)}")
    print(f"  Estado distinto: {len(mismatches)}")

    if missing:
        print("  Ejemplos ausentes:")
        for row in missing[:5]:
            print(f"    - {row['agent_id']} | {row['package_name']} | {row['package_version']} | {row['vulnerability_id']} | {row['db_status']} | {row['db_fecha_resuelta']}")

    if mismatches:
        print("  Ejemplos con estado distinto:")
        for row in mismatches[:5]:
            print(f"    - {row['agent_id']} | {row['package_name']} | {row['package_version']} | {row['vulnerability_id']} | BD={row['db_status']} | Wazuh={row['report_status']}")


def parse_args():
    parser = argparse.ArgumentParser(description="Cruza el CSV actual de Wazuh contra el backlog SQLite.")
    parser.add_argument("--cliente", help="Cliente concreto, sin la extensión .sqlite3.")
    parser.add_argument("--db-dir", type=Path, default=DEFAULT_DB_DIR)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--output", type=Path, help="Ruta CSV para guardar todos los resultados del cruce.")
    return parser.parse_args()


def main():
    args = parse_args()

    all_matched = []
    all_missing = []
    all_mismatches = []

    for client_name, db_path in select_clients(args.db_dir, args.cliente):
        csv_path = args.report_dir / client_name / f"vulnerabilidades_{client_name}.csv"
        if not csv_path.exists():
            raise FileNotFoundError(f"No existe el reporte actual: {csv_path}")

        report_rows = read_csv_report(csv_path)
        db_rows = read_database_status(db_path)
        matched, missing, mismatches = findings_for_client(client_name, report_rows, db_rows)

        all_matched.extend(matched)
        all_missing.extend(missing)
        all_mismatches.extend(mismatches)
        print_summary(client_name, matched, missing, mismatches)

    if args.output:
        write_csv(
            args.output,
            all_missing + all_mismatches,
            [
                "cliente",
                "agent_id",
                "agent_name",
                "package_name",
                "package_version",
                "vulnerability_id",
                "db_status",
                "report_status",
                "db_fecha_resuelta",
                "report_fecha_resuelta",
                "motivo",
            ],
        )
        print(f"\nArchivo de resultados: {args.output}")

    print(f"\nTotal coincidencias: {len(all_matched)}")
    print(f"Total ausentes: {len(all_missing)}")
    print(f"Total estados distintos: {len(all_mismatches)}")


if __name__ == "__main__":
    main()
