#!/usr/bin/env python3
"""Cruza los reportes Wazuh actuales con los backlogs SQLite por agente, CVE y paquete."""

import argparse
import csv
import hashlib
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path


DEFAULT_DB_DIR = Path("./backlog_db")
DEFAULT_REPORTS_DIR = Path("./clientes/vulnerabilidades")
DEFAULT_OUTPUT = Path("./output/validacion_cruce_vulnerabilidades.csv")


REPORT_FIELDS = ("agent.name", "vulnerability.id", "package.name")


def normalized_key(values):
    parts = tuple(str(value or "").strip() for value in values)
    if not all(parts):
        return None
    return parts


def composite_hash(key):
    return hashlib.sha256("|".join(key).encode("utf-8")).hexdigest()


def read_database(db_path):
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities)")}
        composite_column = "composite_key" if "composite_key" in columns else "NULL"
        return conn.execute(
            f"SELECT vuln_key, {composite_column}, agent_name, vulnerability_id, "
            "package_name, package_version, status FROM vulnerabilities"
        ).fetchall()


def read_report(report_path):
    with report_path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        missing = [field for field in REPORT_FIELDS if field not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"Faltan columnas en {report_path}: {', '.join(missing)}")
        return list(reader)


def compare_client(client, db_path, report_path):
    db_rows = read_database(db_path)
    report_rows = read_report(report_path)

    database_by_key = defaultdict(list)
    report_by_key = Counter()
    invalid_db_rows = 0
    invalid_report_rows = 0

    for stored_key, composite_key, agent_name, vulnerability_id, package_name, package_version, status in db_rows:
        key = normalized_key((agent_name, vulnerability_id, package_name))
        if key is None:
            invalid_db_rows += 1
            continue
        database_by_key[key].append(
            {
                "stored_key": stored_key,
                "composite_key": composite_key,
                "package_version": package_version or "",
                "status": status or "",
            }
        )

    for row in report_rows:
        key = normalized_key(row.get(field, "") for field in REPORT_FIELDS)
        if key is None:
            invalid_report_rows += 1
            continue
        report_by_key[key] += 1

    db_keys = set(database_by_key)
    report_keys = set(report_by_key)
    both = db_keys & report_keys
    database_only = db_keys - report_keys
    report_only = report_keys - db_keys
    database_collisions = sum(len(rows) - 1 for rows in database_by_key.values() if len(rows) > 1)
    report_duplicates = sum(count - 1 for count in report_by_key.values() if count > 1)
    composite_key_matches = sum(
        item["composite_key"] == composite_hash(key)
        for key, records in database_by_key.items()
        for item in records
    )

    result_rows = []
    for key in sorted(db_keys | report_keys):
        db_records = database_by_key.get(key, [])
        report_count = report_by_key.get(key, 0)
        if db_records and report_count:
            comparison = "in_both"
        elif db_records:
            comparison = "database_only_candidate_resolved"
        else:
            comparison = "report_only_candidate_new"

        result_rows.append(
            {
                "cliente": client,
                "agent.name": key[0],
                "vulnerability.id": key[1],
                "package.name": key[2],
                "comparison": comparison,
                "database_rows": len(db_records),
                "report_rows": report_count,
                "database_statuses": ",".join(sorted({item["status"] for item in db_records})),
                "database_package_versions": ",".join(sorted({item["package_version"] for item in db_records})),
                "stored_vuln_keys": ",".join(item["stored_key"] for item in db_records),
                "stored_composite_keys": ",".join(item["composite_key"] or "" for item in db_records),
                "expected_composite_vuln_key": composite_hash(key),
                "stored_key_matches_expected": all(
                    item["composite_key"] == composite_hash(key) for item in db_records
                ) if db_records else "",
            }
        )

    summary = {
        "client": client,
        "db_rows": len(db_rows),
        "report_rows": len(report_rows),
        "db_unique_keys": len(db_keys),
        "report_unique_keys": len(report_keys),
        "in_both": len(both),
        "database_only": len(database_only),
        "report_only": len(report_only),
        "database_collision_rows": database_collisions,
        "report_duplicate_rows": report_duplicates,
        "stored_keys_matching_new_composite": composite_key_matches,
        "invalid_db_rows": invalid_db_rows,
        "invalid_report_rows": invalid_report_rows,
    }
    return summary, result_rows


def main():
    parser = argparse.ArgumentParser(
        description="Compara cada backlog SQLite con el CSV Wazuh usando agent.name + vulnerability.id + package.name."
    )
    parser.add_argument("--cliente", help="Limita el cruce a un cliente (nombre de la base).")
    parser.add_argument("--db-dir", type=Path, default=DEFAULT_DB_DIR)
    parser.add_argument("--reports-dir", type=Path, default=DEFAULT_REPORTS_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if not args.db_dir.exists():
        raise SystemExit(f"No existe el directorio de bases: {args.db_dir}")

    db_files = sorted(args.db_dir.glob("*.sqlite3"))
    if args.cliente:
        db_files = [path for path in db_files if path.stem == args.cliente]
    if not db_files:
        raise SystemExit("No se encontraron bases para los filtros seleccionados.")

    summaries = []
    all_rows = []
    for db_path in db_files:
        client = db_path.stem
        report_path = args.reports_dir / client / f"vulnerabilidades_{client}.csv"
        if not report_path.exists():
            print(f"{client}: no se encontró el reporte {report_path}; se omite.")
            continue

        summary, rows = compare_client(client, db_path, report_path)
        summaries.append(summary)
        all_rows.extend(rows)
        print(
            f"{client}: DB={summary['db_rows']} ({summary['db_unique_keys']} claves), "
            f"Wazuh={summary['report_rows']} ({summary['report_unique_keys']} claves); "
            f"en ambos={summary['in_both']}, solo DB={summary['database_only']}, "
            f"solo Wazuh={summary['report_only']}, colisiones DB={summary['database_collision_rows']}, "
            f"claves guardadas iguales al hash nuevo={summary['stored_keys_matching_new_composite']}"
        )
        if summary["invalid_db_rows"] or summary["invalid_report_rows"]:
            print(
                f"  Filas sin alguno de los tres campos: DB={summary['invalid_db_rows']}, "
                f"Wazuh={summary['invalid_report_rows']}"
            )

    if not summaries:
        raise SystemExit("No había reportes para cruzar.")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "cliente",
        "agent.name",
        "vulnerability.id",
        "package.name",
        "comparison",
        "database_rows",
        "report_rows",
        "database_statuses",
        "database_package_versions",
        "stored_vuln_keys",
        "stored_composite_keys",
        "expected_composite_vuln_key",
        "stored_key_matches_expected",
    ]
    with args.output.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"Detalle por clave exportado a: {args.output}")


if __name__ == "__main__":
    main()
