import sqlite3
from datetime import datetime

DB_FILE = "vulnerabilidades.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilidades (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        servidor TEXT,
        paquete TEXT,
        version TEXT,
        cve TEXT,
        estado TEXT,
        fecha_detectado TEXT,
        fecha_resuelto TEXT
    )
    """)
    conn.commit()
    conn.close()

def update_lookup(current_vulns):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    today = datetime.today().strftime("%Y-%m-%d")

    # Crear clave única
    def key(v):
        return (v["servidor"], v["paquete"], v["version"], v["cve"])

    # Obtener vulnerabilidades activas de la DB
    c.execute("SELECT servidor, paquete, version, cve FROM vulnerabilidades WHERE estado = 'activo'")
    active_keys = {tuple(row) for row in c.fetchall()}

    current_keys = {key(v) for v in current_vulns}

    # Marcar nuevas vulnerabilidades
    for v in current_vulns:
        if key(v) not in active_keys:
            c.execute("""
                INSERT INTO vulnerabilidades (servidor, paquete, version, cve, estado, fecha_detectado, fecha_resuelto)
                VALUES (?, ?, ?, ?, 'activo', ?, NULL)
            """, (v["servidor"], v["paquete"], v["version"], v["cve"], today))

    # Marcar resueltas
    resolved = active_keys - current_keys
    for r in resolved:
        c.execute("""
            UPDATE vulnerabilidades
            SET estado = 'resuelta', fecha_resuelto = ?
            WHERE servidor = ? AND paquete = ? AND version = ? AND cve = ? AND estado = 'activo'
        """, (today, r[0], r[1], r[2], r[3]))

    conn.commit()
    conn.close()

# Ejemplo de uso
if __name__ == "__main__":
    init_db()

    # Simulación: vulnerabilidades reportadas hoy
    current_report = [
        {"servidor": "srv1", "paquete": "openssl", "version": "1.1.1", "cve": "CVE-2023-1234"},
        {"servidor": "srv2", "paquete": "nginx", "version": "1.21", "cve": "CVE-2024-5678"},
    ]
    update_lookup(current_report)
