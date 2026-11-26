from ipaddress import IPv4Network as Rete
from analizzatore.modello import PortRange, Rule
from analizzatore.controlli import check_f1_oscurate, check_f4_permissive, check_f7_default_open


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
