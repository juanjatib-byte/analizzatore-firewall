import subprocess
import sys
import pytest
from analizzatore.lettori.fortigate import check_f6_inutilizzati, parse_fortigate
from analizzatore.lettori.iptables import parse_iptables


def test_fortigate_gruppi_nidificati():
    conf = """
config firewall address
    edit "HostA"
        set subnet 10.1.1.1 255.255.255.255
    next
end
config firewall addrgrp
    edit "SubGrp"
        set member "HostA"
    next
    edit "MainGrp"
        set member "SubGrp"
    next
end
config firewall policy
    edit 1
        set srcaddr "MainGrp"
        set dstaddr "all"
        set action accept
        set service "HTTPS"
    next
end
"""
    regole, oggetti, _ = parse_fortigate(conf)
    assert len(regole) == 1
    assert str(regole[0].src_ips[0]) == "10.1.1.1/32"
    assert check_f6_inutilizzati(oggetti) == []


def test_fortigate_f6_oggetto_inutilizzato():
    conf = """
config firewall address
    edit "Orfano"
        set subnet 10.9.9.9 255.255.255.255
    next
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set service "ALL"
    next
end
"""
    _, oggetti, _ = parse_fortigate(conf)
    res = check_f6_inutilizzati(oggetti)
    assert len(res) == 1
    assert res[0].code == "F6"
    assert "Orfano" in res[0].description



def test_fortigate_policy_disabilitata_ignorata():
    conf = """
config firewall policy
    edit 1
        set status disable
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
    regole, _, _ = parse_fortigate(conf)
    assert regole == []


def test_fortigate_formato_non_valido():
    with pytest.raises(ValueError):
        parse_fortigate("questo non è un file fortigate")


def test_iptables_formato_non_valido():
    with pytest.raises(ValueError):
        parse_iptables("testo casuale senza tabella filter")


def test_iptables_avviso_opzione_sconosciuta():
    txt = "*filter\n:INPUT DROP [0:0]\n-A INPUT -m limit --limit 10/min -j ACCEPT\nCOMMIT\n"
    _, _, avvisi = parse_iptables(txt)
    assert len(avvisi) >= 1


def test_cli_exit_code_2_file_inesistente():
    proc = subprocess.run(
        [sys.executable, "analizza.py", "--formato", "iptables", "non_esiste.txt"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2


def test_cli_output_markdown():
    proc = subprocess.run(
        [sys.executable, "analizza.py", "--formato", "fortigate", "esempi/fortigate-01/config.conf", "--output", "md"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "# Report Analisi Firewall" in proc.stdout

def test_iptables_catena_personalizzata_eredita_condizioni_salto():
    from analizzatore.controlli import check_f5_servizi_pericolosi

    txt = """
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:INTERNI - [0:0]
-A FORWARD -s 10.0.0.0/8 -j INTERNI
-A INTERNI -p tcp --dport 3389 -j ACCEPT
COMMIT
"""
    regole, _, _ = parse_iptables(txt)
    assert len(regole) == 1
    assert str(regole[0].src_ips[0]) == "10.0.0.0/8"
    assert check_f5_servizi_pericolosi(regole) == []

def test_iptables_catena_personalizzata_interseca_porte_salto():
    from analizzatore.controlli import check_f5_servizi_pericolosi

    txt = """
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:ADMIN - [0:0]
-A FORWARD -i eth0 -p tcp --dport 1:1024 -j ADMIN
-A ADMIN -p tcp --dport 22 -j ACCEPT
COMMIT
"""
    regole, _, _ = parse_iptables(txt)
    assert len(regole) == 1
    
    r = regole[0]
    assert str(r.src_ips[0]) == "0.0.0.0/0"
    assert len(r.dst_ports) == 1
    assert r.dst_ports[0].start == 22
    assert r.dst_ports[0].end == 22

    problemi = check_f5_servizi_pericolosi(regole)
    assert len(problemi) == 1
    p = problemi[0]
    assert "SSH (22)" in p.description
    assert "FTP" not in p.description
    assert "Telnet" not in p.description
