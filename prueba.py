from consultar_vulnerabilidades_parchadas import query_vulnerabilities
import sqlite3
import pandas as pd


conn = sqlite3.connect('./backlog_db/prebel.sqlite3')
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


# query += " ORDER BY fecha_resuelta DESC, package_name, vulnerability_id"
# query = """
#     SELECT
#         status
#     FROM vulnerabilities
#     WHERE status = 'resolved';
# """
rows = conn.execute(query).fetchall()
conn.close()

resultado = [dict(row) for row in rows]

df = pd.DataFrame(resultado)

print(df.head())
print(len(df))
# df.to_csv('prueba_prebel.csv')