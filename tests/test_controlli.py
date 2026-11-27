from ipaddress import IPv4Network as Rete
from analizzatore.modello import PortRange, Rule
from analizzatore.controlli import (
    check_f1_oscurate,
    check_f2_conflitto,
    check_f3_ridondante,
    check_f4_permissive,
    check_f5_servizi_pericolosi,
    check_f7_default_open,
)



def test_f1_detecta_regla_oscurata():
    r1 = Rule(id="1", line_num=5, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.0.0.0/8")], protocol="tcp", dst_ports=[PortRange(443, 443)])
    r2 = Rule(id="2", line_num=9, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.1.2.3/32")], protocol="tcp", dst_ports=[PortRange(443, 443)])
    res = check_f1_oscurate([r1, r2])
    assert len(res) == 1
    assert res[0].code == "F1"
    assert res[0].line_num == 9
    assert res[0].caused_by == [5]


def test_f1_no_salta_si_accion_es_opuesta():
    r1 = Rule(id="1", line_num=3, chain="FORWARD", action="DROP", src_ips=[Rete("10.0.0.0/8")])
    r2 = Rule(id="2", line_num=7, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.1.1.1/32")])
    assert check_f1_oscurate([r1, r2]) == []


def test_f4_detecta_any_any():
    r = Rule(id="1", line_num=4, chain="FORWARD", action="ACCEPT")
    res = check_f4_permissive([r])
    assert len(res) == 1
    assert res[0].code == "F4"


def test_f4_detecta_interfaz_externa_a_interna():
    r = Rule(id="1", line_num=6, chain="FORWARD", action="ACCEPT", in_iface="eth0", out_iface="eth1")
    res = check_f4_permissive([r], untrusted_ifaces=["eth0"], trusted_ifaces=["eth1"])
    assert len(res) == 1
    assert res[0].code == "F4"


def test_f7_detecta_politica_accept_sin_cierre():
    res = check_f7_default_open([], {"FORWARD": ("ACCEPT", 3)})
    assert len(res) == 1
    assert res[0].code == "F7"
    assert res[0].line_num == 3


def test_f7_ok_con_regla_final_drop():
    cierre = Rule(id="1", line_num=10, chain="FORWARD", action="DROP")
    res = check_f7_default_open([cierre], {"FORWARD": ("ACCEPT", 3)})
    assert res == []

def test_f2_detecta_conflicto():
    r1 = Rule(id="1", line_num=4, chain="FORWARD", action="DROP", src_ips=[Rete("10.0.0.0/8")], protocol="tcp", dst_ports=[PortRange(22, 22)])
    r2 = Rule(id="2", line_num=8, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.1.2.3/32")], protocol="tcp", dst_ports=[PortRange(22, 22)])
    res = check_f2_conflitto([r1, r2])
    assert len(res) == 1
    p = res[0]
    assert p.code == "F2"
    assert p.line_num == 8
    assert p.caused_by == list([4])


def test_f2_no_salta_si_misma_accion():
    r1 = Rule(id="1", line_num=4, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.0.0.0/8")])
    r2 = Rule(id="2", line_num=8, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.1.2.3/32")])
    assert check_f2_conflitto([r1, r2]) == []


def test_f3_detecta_regla_redundante_sin_bloqueo_en_medio():
    r1 = Rule(id="1", line_num=3, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.1.2.3/32")], protocol="tcp", dst_ports=[PortRange(80, 80)])
    r2 = Rule(id="2", line_num=7, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.0.0.0/8")], protocol="tcp", dst_ports=[PortRange(80, 80)])
    res = check_f3_ridondante([r1, r2])
    assert len(res) == 1
    p = res[0]
    assert p.code == "F3"
    assert p.line_num == 3
    assert p.caused_by == list([7])


def test_f3_no_salta_si_hay_drop_en_medio():
    r1 = Rule(id="1", line_num=3, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.1.2.3/32")])
    r_drop = Rule(id="2", line_num=5, chain="FORWARD", action="DROP", src_ips=[Rete("10.0.0.0/8")])
    r2 = Rule(id="3", line_num=7, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.0.0.0/8")])
    assert check_f3_ridondante([r1, r_drop, r2]) == []


def test_f5_detecta_rdp_expuesto_desde_internet():
    r = Rule(id="1", line_num=6, chain="FORWARD", action="ACCEPT", protocol="tcp", dst_ports=[PortRange(3389, 3389)])
    res = check_f5_servizi_pericolosi([r])
    assert len(res) == 1
    p = res[0]
    assert p.code == "F5"
    assert "RDP" in p.description


def test_f5_no_salta_si_origen_es_red_interna():
    r = Rule(id="1", line_num=6, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.0.0.0/8")], protocol="tcp", dst_ports=[PortRange(3389, 3389)])
    assert check_f5_servizi_pericolosi([r]) == []

def test_f4_ignora_loopback():
    r = Rule(id="1", line_num=5, chain="INPUT", action="ACCEPT", in_iface="lo")
    assert check_f4_permissive([r]) == []


def test_f4_ignora_established_related():
    r = Rule(id="1", line_num=6, chain="INPUT", action="ACCEPT", is_established=True)
    assert check_f4_permissive([r]) == []
