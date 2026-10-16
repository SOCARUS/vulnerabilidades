import argparse
import hashlib
import os
import sqlite3
from datetime import datetime

import pandas as pd


COLUMNS = [
    "agent.id",
    "agent.name",
    "host.os.name",
    "package.name",
    "package.version",
    "vulnerability.id",
    "vulnerability.classification",
    "vulnerability.detected_at",
    "vulnerability.severity",
    "vulnerability.score.base",
    "package.installed",
]

UNIQUE_KEY_COLUMNS = [
    "agent.name",
    "vulnerability.id",
    "package.name",
]

ROW_KEY_COLUMNS = [
    "agent.id",
    "package.name",
    "package.version",
    "vulnerability.id",
]


def today_iso() -> str:
    return datetime.today().strftime("%Y-%m-%d")


def normalize_value(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


def normalize_date(value: object) -> str:
    value = normalize_value(value)
    if not value:
        return ""

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return value


def compute_unique_id(row: dict) -> str:
    raw = "|".join(normalize_value(row.get(col, "")) for col in UNIQUE_KEY_COLUMNS)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_row_id(row: dict) -> str:
    raw = "|".join(normalize_value(row.get(col, "")) for col in ROW_KEY_COLUMNS)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def get_db_path(client: str, db_dir: str = "./backlog_db") -> str:
    os.makedirs(db_dir, exist_ok=True)
    return os.path.join(db_dir, f"{client}.sqlite3")


def ensure_db(client: str, db_dir: str = "./backlog_db") -> sqlite3.Connection:
    db_path = get_db_path(client, db_dir)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vuln_key TEXT PRIMARY KEY,
            composite_key TEXT,
            agent_id TEXT,
            agent_name TEXT,
            host_os_name TEXT,
            package_name TEXT,
            package_version TEXT,
            vulnerability_id TEXT,
            vulnerability_classification TEXT,
            vulnerability_detected_at TEXT,
            vulnerability_severity TEXT,
            vulnerability_score_base TEXT,
            package_installed TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            fecha_detectado TEXT,
            fecha_resuelta TEXT,
            created_at TEXT,
            updated_at TEXT,
            last_seen_at TEXT
        )
        """
    )

    columns = {row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities)")}
    if "composite_key" not in columns:
        conn.execute("ALTER TABLE vulnerabilities ADD COLUMN composite_key TEXT")

    rows = conn.execute(
        """
        SELECT vuln_key, agent_name, vulnerability_id, package_name,
               fecha_detectado, fecha_resuelta, vulnerability_detected_at, composite_key
        FROM vulnerabilities
          WHERE composite_key IS NULL
              OR length(COALESCE(fecha_detectado, '')) > 10
              OR length(COALESCE(fecha_resuelta, '')) > 10
              OR length(COALESCE(vulnerability_detected_at, '')) > 10
        """
    ).fetchall()

    for (vuln_key, agent_name, vulnerability_id, package_name,
         fecha_detectado, fecha_resuelta, vulnerability_detected_at, composite_key) in rows:
        expected_key = compute_unique_id({
            "agent.name": agent_name,
            "vulnerability.id": vulnerability_id,
            "package.name": package_name,
        })
        conn.execute(
            """
            UPDATE vulnerabilities
            SET composite_key = ?,
                fecha_detectado = ?,
                fecha_resuelta = ?,
                vulnerability_detected_at = ?,
                updated_at = COALESCE(updated_at, ?)
            WHERE vuln_key = ?
            """,
            (
                expected_key,
                normalize_date(fecha_detectado),
                normalize_date(fecha_resuelta),
                normalize_date(vulnerability_detected_at),
                today_iso(),
                vuln_key,
            ),
        )

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_composite_key "
        "ON vulnerabilities(composite_key)"
    )
    conn.execute(
        "UPDATE vulnerabilities SET status = 'resolved' WHERE status = 're09'"
    )
    conn.commit()
    return conn


def normalize_status(value: object) -> str:
    status = normalize_value(value).lower()
    if status in {"resolved", "solved"}:
        return "resolved"
    return "active"


def prepare_report(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    df = df.copy()

    for col in COLUMNS:
        if col not in df.columns:
            df[col] = ""

    df["_status"] = df["status"].apply(normalize_status) if "status" in df.columns else "active"
    df["_fecha_resuelta"] = df["fecha_resuelta"].apply(normalize_date) if "fecha_resuelta" in df.columns else ""
    df["_vuln_key"] = df.apply(lambda row: compute_unique_id(row.to_dict()), axis=1)
    df["_record_key"] = df.apply(lambda row: compute_row_id(row.to_dict()), axis=1)
    return df


def upsert_report(client: str, report_df: pd.DataFrame, db_dir: str = "./backlog_db"):
    if report_df is None or report_df.empty:
        print(f"[{client}] no hay registros para procesar.")
        return

    today = today_iso()
    report_df = prepare_report(report_df)
    conn = ensure_db(client, db_dir)
    cur = conn.cursor()

    current_keys = set(report_df["_vuln_key"].tolist())

    # 1) Vulnerabilidades que ya no aparecen: pasar a resolved
    active_rows = cur.execute(
        "SELECT DISTINCT composite_key FROM vulnerabilities "
        "WHERE status = 'active' AND composite_key IS NOT NULL"
    ).fetchall()
    active_keys = {row[0] for row in active_rows}

    for key in sorted(active_keys - current_keys):
        cur.execute(
            """
            UPDATE vulnerabilities
            SET status = 'resolved',
                fecha_resuelta = ?,
                updated_at = ?,
                last_seen_at = ?
            WHERE composite_key = ? AND status = 'active'
            """,
            (today, today, today, key),
        )

    status_by_key = {}
    resolution_date_by_key = {}
    for _, row in report_df.iterrows():
        row_dict = row.to_dict()
        key = row_dict["_vuln_key"]
        row_status = row_dict.get("_status", "active")
        if key not in status_by_key or row_status == "active":
            status_by_key[key] = row_status
        row_resolution_date = normalize_date(row_dict.get("_fecha_resuelta", ""))
        if row_resolution_date:
            resolution_date_by_key[key] = row_resolution_date

    for key, status in status_by_key.items():
        cur.execute(
            """
            UPDATE vulnerabilities
            SET status = ?,
                fecha_resuelta = ?,
                updated_at = ?,
                last_seen_at = ?
            WHERE composite_key = ?
            """,
            (
                status,
                None if status == "active" else resolution_date_by_key.get(key) or today,
                today,
                today,
                key,
            ),
        )

    # 2) Insertar o actualizar vulnerabilidades del reporte actual
    for _, row in report_df.iterrows():
        row_dict = row.to_dict()
        vuln_key = row_dict["_vuln_key"]
        record_key = row_dict["_record_key"]
        status = row_dict.get("_status", "active")
        fecha_resuelta = normalize_date(row_dict.get("_fecha_resuelta", ""))
        agent_id = normalize_value(row_dict.get("agent.id", ""))
        agent_name = normalize_value(row_dict.get("agent.name", ""))
        host_os_name = normalize_value(row_dict.get("host.os.name", ""))
        package_name = normalize_value(row_dict.get("package.name", ""))
        package_version = normalize_value(row_dict.get("package.version", ""))
        vulnerability_id = normalize_value(row_dict.get("vulnerability.id", ""))
        vulnerability_classification = normalize_value(row_dict.get("vulnerability.classification", ""))
        vulnerability_detected_at = normalize_date(row_dict.get("vulnerability.detected_at", "")) or today
        vulnerability_severity = normalize_value(row_dict.get("vulnerability.severity", ""))
        vulnerability_score_base = normalize_value(row_dict.get("vulnerability.score.base", ""))
        package_installed = normalize_value(row_dict.get("package.installed", ""))

        existing = cur.execute(
            "SELECT vuln_key, status, fecha_detectado FROM vulnerabilities WHERE vuln_key = ?",
            (record_key,),
        ).fetchone()

        if existing:
            cur.execute(
                """
                UPDATE vulnerabilities
                SET agent_id = ?,
                    agent_name = ?,
                    host_os_name = ?,
                    package_name = ?,
                    package_version = ?,
                    vulnerability_id = ?,
                    vulnerability_classification = ?,
                    vulnerability_detected_at = ?,
                    vulnerability_severity = ?,
                    vulnerability_score_base = ?,
                    package_installed = ?,
                    composite_key = ?,
                    status = ?,
                    fecha_resuelta = ?,
                    updated_at = ?,
                    last_seen_at = ?
                WHERE vuln_key = ?
                """,
                (
                    agent_id,
                    agent_name,
                    host_os_name,
                    package_name,
                    package_version,
                    vulnerability_id,
                    vulnerability_classification,
                    vulnerability_detected_at,
                    vulnerability_severity,
                    vulnerability_score_base,
                    package_installed,
                    vuln_key,
                    status,
                    None if status == "active" else fecha_resuelta or today,
                    today,
                    today,
                    record_key,
                ),
            )
        else:
            cur.execute(
                """
                INSERT INTO vulnerabilities (
                    vuln_key,
                    composite_key,
                    agent_id,
                    agent_name,
                    host_os_name,
                    package_name,
                    package_version,
                    vulnerability_id,
                    vulnerability_classification,
                    vulnerability_detected_at,
                    vulnerability_severity,
                    vulnerability_score_base,
                    package_installed,
                    status,
                    fecha_detectado,
                    fecha_resuelta,
                    created_at,
                    updated_at,
                    last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_key,
                    vuln_key,
                    agent_id,
                    agent_name,
                    host_os_name,
                    package_name,
                    package_version,
                    vulnerability_id,
                    vulnerability_classification,
                    vulnerability_detected_at,
                    vulnerability_severity,
                    vulnerability_score_base,
                    package_installed,
                    status,
                    vulnerability_detected_at or today,
                    None if status == "active" else fecha_resuelta or today,
                    today,
                    today,
                    today,
                ),
            )

    conn.commit()
    conn.close()
    print(f"[{client}] backlog actualizado correctamente en {get_db_path(client, db_dir)}")


def load_report(csv_path: str) -> pd.DataFrame:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"No existe el archivo: {csv_path}")

    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    return df


def main():
    parser = argparse.ArgumentParser(description="Actualiza el backlog de vulnerabilidades por cliente en SQLite.")
    parser.add_argument("--cliente", required=True, help="Nombre del cliente para crear/actualizar su base de datos")
    parser.add_argument("--csv", required=True, help="Ruta del CSV exportado con las vulnerabilidades del cliente")
    parser.add_argument("--db-dir", default="./backlog_db", help="Directorio donde se guardarán las bases SQLite")
    args = parser.parse_args()

    df = load_report(args.csv)
    upsert_report(args.cliente, df, args.db_dir)


if __name__ == "__main__":
    main()
