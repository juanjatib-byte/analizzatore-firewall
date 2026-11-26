from ipaddress import IPv4Network as Rete
from analizzatore.modello import PortRange, Rule
from analizzatore.confronto import are_ports_covered, is_protocol_covered, is_rule_covered


def test_puerto_unico_en_rango():
    assert are_ports_covered([PortRange(80, 80)], [PortRange(1, 1024)])


def test_puerto_fuera_de_rango():
    assert not are_ports_covered([PortRange(8080, 8080)], [PortRange(1, 1024)])


def test_lista_puertos_cubierta():
    assert are_ports_covered([PortRange(80, 80), PortRange(443, 443)], [PortRange(1, 1024)])


def test_protocolo_all_cubre_tcp():
    assert is_protocol_covered("tcp", "all")


def test_protocolo_distinto_no_cubre():
    assert not is_protocol_covered("udp", "tcp")


def test_regla_con_negacion_no_cubre():
    r_arriba = Rule(id="1", line_num=1, chain="FORWARD", action="ACCEPT", negate_src=True)
    r_abajo = Rule(id="2", line_num=2, chain="FORWARD", action="ACCEPT", src_ips=[Rete("10.1.0.0/16")])
    assert not is_rule_covered(r_abajo, r_arriba)
