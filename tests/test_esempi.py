import json
import subprocess
import sys
from pathlib import Path
import pytest

ESEMPI_DIR = Path(__file__).parent.parent / "esempi"
CASI_IPTABLES = sorted(p for p in ESEMPI_DIR.glob("iptables-*") if p.is_dir())


@pytest.mark.parametrize("caso_dir", CASI_IPTABLES, ids=lambda p: p.name)
def test_esempio_iptables(caso_dir: Path):
    regole_file = caso_dir / "regole.txt"
    zone_file = caso_dir / "zone.yml"
    atteso_file = caso_dir / "atteso.json"

    cmd = [sys.executable, "analizza.py", "--formato", "iptables", str(regole_file), "--output", "json"]
    if zone_file.exists():
        cmd.extend(["--zone", str(zone_file)])

    proc = subprocess.run(cmd, capture_output=True, text=True)
    atteso = json.loads(atteso_file.read_text(encoding="utf-8"))
    ottenuto = json.loads(proc.stdout)

    assert ottenuto == atteso
    assert proc.returncode == (1 if atteso["problemi"] else 0)
