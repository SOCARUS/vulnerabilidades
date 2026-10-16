from pathlib import Path

import pandas as pd

from clientes import tablero_vuln


def test_tablero_vuln_creates_png(tmp_path):
    df = pd.DataFrame(
        {
            "agent.name": ["eq1", "eq1", "eq2", "eq3", "eq3", "eq4"],
            "package.name": ["CVE-1", "CVE-2", "CVE-1", "CVE-3", "CVE-1", "CVE-4"],
            "vulnerability.severity": ["critical", "high", "critical", "medium", "low", "critical"],
        }
    )

    output = tmp_path / "tablero_cliente.png"
    result = tablero_vuln(df, TOP_N=3, output_path=str(output))

    assert result == str(output)
    assert output.exists()
    assert output.stat().st_size > 0
