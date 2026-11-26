import shlex
from dataclasses import dataclass
from ipaddress import IPv4Network

from analizzatore.modello import ANY_IP, ANY_PORT, PortRange, Problem, Rule


@dataclass
class FortiObject:
    name: str
    kind: str       # "address" | "addrgrp" | "service" | "service_group"
    line_num: int
    used: bool = False


def _parse_forti_ports(port_spec: str) -> list[PortRange]:
    """Convierte '80', '8000-8010' o '80 443' de FortiGate en list[PortRange]."""
    ranges: list[PortRange] = []
    for token in port_spec.split():
        # FortiGate a veces escribe '8080:80' (dst:src) -> nos quedamos con el puerto destino
        dst_part = token.split(":")[0]
        if "-" in dst_part:
            lo, hi = dst_part.split("-", 1)
            ranges.append(PortRange(int(lo), int(hi)))
        else:
            p = int(dst_part)
            ranges.append(PortRange(p, p))
    return ranges


def parse_fortigate(text: str) -> tuple[list[Rule], list[FortiObject], list[str]]:
    """Lee una configuración FortiOS (`show full-configuration`) y devuelve:
    1. Lista de objetos Rule ordenados según la evaluación del firewall.
    2. Lista de FortiObject definidos (para detectar F6 si used=False).
    3. Lista de avisos globales.
    """
    lines = text.splitlines()
    if "config firewall" not in text:
        raise ValueError("Il file non sembra una configurazione FortiGate valida")

    addresses: dict[str, list[IPv4Network]] = {"all": list(ANY_IP)}
    addr_groups: dict[str, list[str]] = {}
    services: dict[str, tuple[str, list[PortRange]]] = {
        "ALL": ("all", list(ANY_PORT)),
        "ALL_TCP": ("tcp", list(ANY_PORT)),
        "ALL_UDP": ("udp", list(ANY_PORT)),
        "ALL_ICMP": ("icmp", list(ANY_PORT)),
        "HTTP": ("tcp", [PortRange(80, 80)]),
        "HTTPS": ("tcp", [PortRange(443, 443)]),
        "SSH": ("tcp", [PortRange(22, 22)]),
        "TELNET": ("tcp", [PortRange(23, 23)]),
        "RDP": ("tcp", [PortRange(3389, 3389)]),
        "SMB": ("tcp", [PortRange(445, 445)]),
        "DNS": ("udp", [PortRange(53, 53)]),
        "PING": ("icmp", list(ANY_PORT)),
    }
    service_groups: dict[str, list[str]] = {}

    defined_objects: dict[tuple[str, str], FortiObject] = {}
    raw_policies: list[dict] = []
    global_warnings: list[str] = []

    section: str | None = None
    current: dict | None = None

    for line_num, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("config firewall "):
            section = line[len("config firewall "):].strip()
            current = None
            continue

        if line == "end":
            section = None
            current = None
            continue

        if not section:
            continue

        if line.startswith("edit "):
            tokens = shlex.split(line)
            name = tokens[1] if len(tokens) > 1 else ""
            current = {"name": name, "line_num": line_num}
            continue

        if line == "next" and current is not None:
            name = current["name"]
            l_num = current["line_num"]

            if section == "address":
                if name != "all":
                    defined_objects[("addr", name)] = FortiObject(name, "address", l_num)
                if "subnet" in current:
                    ip, mask = current["subnet"]
                    addresses[name] = [IPv4Network(f"{ip}/{mask}", strict=False)]
                else:
                    addresses[name] = list(ANY_IP)
                    if current.get("type") not in (None, "ipmask"):
                        global_warnings.append(f"Riga {l_num}: tipo address '{current.get('type')}' non interpretato")

            elif section == "addrgrp":
                defined_objects[("addr", name)] = FortiObject(name, "addrgrp", l_num)
                addr_groups[name] = current.get("member", [])

            elif section == "service custom":
                if name not in services:
                    defined_objects[("svc", name)] = FortiObject(name, "service", l_num)
                proto = "all"
                ports = list(ANY_PORT)
                if "tcp-portrange" in current:
                    proto = "tcp"
                    ports = _parse_forti_ports(current["tcp-portrange"])
                elif "udp-portrange" in current:
                    proto = "udp"
                    ports = _parse_forti_ports(current["udp-portrange"])
                elif current.get("protocol", "").upper() == "ICMP":
                    proto = "icmp"
                services[name] = (proto, ports)

            elif section == "service group":
                defined_objects[("svc", name)] = FortiObject(name, "service_group", l_num)
                service_groups[name] = current.get("member", [])

            elif section == "policy":
                raw_policies.append(current)

            current = None
            continue

        if current is not None and line.startswith("set "):
            tokens = shlex.split(line)
            if len(tokens) >= 3:
                key = tokens[1]
                vals = tokens[2:]
                if key == "subnet" and len(vals) >= 2:
                    current["subnet"] = (vals[0], vals[1])
                elif key in ("tcp-portrange", "udp-portrange"):
                    current[key] = " ".join(vals)
                elif key in ("member", "srcaddr", "dstaddr", "service", "srcintf", "dstintf"):
                    current[key] = vals
                else:
                    current[key] = vals[0]

    # Funciones auxiliares para resolver grupos anidados y marcar objetos usados (F6)
    def resolve_addr(name: str, visited: set[str]) -> list[IPv4Network]:
        if ("addr", name) in defined_objects:
            defined_objects[("addr", name)].used = True
        if name in visited:
            return []
        if name in addresses:
            return addresses[name]
        if name in addr_groups:
            res: list[IPv4Network] = []
            for m in addr_groups[name]:
                res.extend(resolve_addr(m, visited | {name}))
            return res or list(ANY_IP)
        global_warnings.append(f"Indirizzo FortiGate '{name}' non definito")
        return list(ANY_IP)

    def resolve_svc(name: str, visited: set[str]) -> list[tuple[str, list[PortRange]]]:
        if ("svc", name) in defined_objects:
            defined_objects[("svc", name)].used = True
        if name in visited:
            return []
        if name in services:
            return [services[name]]
        if name in service_groups:
            res: list[tuple[str, list[PortRange]]] = []
            for m in service_groups[name]:
                res.extend(resolve_svc(m, visited | {name}))
            return res or [("all", list(ANY_PORT))]
        global_warnings.append(f"Servizio FortiGate '{name}' non definito")
        return [("all", list(ANY_PORT))]

    # Convertir cada policy en uno o más objetos Rule (uno por protocolo si el servicio mezcla TCP y UDP)
    final_rules: list[Rule] = []
    for idx, pol in enumerate(raw_policies, start=1):
        if pol.get("status", "enable").lower() == "disable":
            continue

        raw_action = pol.get("action", "deny").lower()
        action = "ACCEPT" if raw_action == "accept" else "DROP"

        src_nets: list[IPv4Network] = []
        for s in pol.get("srcaddr", ["all"]):
            src_nets.extend(resolve_addr(s, set()))

        dst_nets: list[IPv4Network] = []
        for d in pol.get("dstaddr", ["all"]):
            dst_nets.extend(resolve_addr(d, set()))

        in_if = pol.get("srcintf", ["any"])[0]
        out_if = pol.get("dstintf", ["any"])[0]

        # Agrupar puertos por protocolo
        proto_ports: dict[str, list[PortRange]] = {}
        for svc_name in pol.get("service", ["ALL"]):
            for proto, pranges in resolve_svc(svc_name, set()):
                proto_ports.setdefault(proto, []).extend(pranges)

        for proto, pranges in proto_ports.items():
            final_rules.append(Rule(
                id=pol["name"],
                line_num=pol["line_num"],
                chain="policy",
                action=action,
                src_ips=src_nets or list(ANY_IP),
                dst_ips=dst_nets or list(ANY_IP),
                protocol=proto,
                dst_ports=pranges or list(ANY_PORT),
                in_iface=in_if,
                out_iface=out_if,
            ))

    return final_rules, list(defined_objects.values()), global_warnings


def check_f6_inutilizzati(objects: list[FortiObject]) -> list[Problem]:
    """F6: Objetos definidos en FortiGate pero nunca referenciados en ninguna policy."""
    problemi = []
    for obj in objects:
        if not obj.used:
            problemi.append(Problem(
                code="F6",
                severity="bassa",
                line_num=obj.line_num,
                description=f"Oggetto FortiGate '{obj.name}' ({obj.kind}) definito ma mai utilizzato",
            ))
    return problemi
