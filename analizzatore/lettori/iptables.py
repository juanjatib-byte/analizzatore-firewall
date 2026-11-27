import shlex
from ipaddress import IPv4Network

from analizzatore.modello import ANY_IP, ANY_PORT, PortRange, Rule


def _parse_ports(port_str: str) -> list[PortRange]:
    """Convierte '80', '80:443' o '80,443' en una lista de PortRange."""
    result = []
    for part in port_str.split(","):
        if ":" in part:
            start, end = part.split(":", 1)
            result.append(PortRange(int(start), int(end)))
        else:
            p = int(part)
            result.append(PortRange(p, p))
    return result


def _intersect_nets(parent: list[IPv4Network], child: list[IPv4Network]) -> list[IPv4Network]:
    """Combina las redes del salto con las de la subcadena (quedándose con la más específica)."""
    if parent == ANY_IP:
        return list(child)
    if child == ANY_IP:
        return list(parent)
    res = []
    for p in parent:
        for c in child:
            if c.subnet_of(p):
                res.append(c)
            elif p.subnet_of(c):
                res.append(p)
    return res

def _intersect_ports(parent: list[PortRange], child: list[PortRange]) -> list[PortRange]:
    """Calcula la intersección real entre los puertos del salto y los de la subcadena."""
    if parent == ANY_PORT:
        return list(child)
    if child == ANY_PORT:
        return list(parent)
    res: list[PortRange] = []
    for p in parent:
        for c in child:
            lo = max(p.start, c.start)
            hi = min(p.end, c.end)
            if lo <= hi:
                res.append(PortRange(lo, hi))
    return res


def parse_iptables(text: str) -> tuple[list[Rule], dict[str, tuple[str, int]], list[str]]:
    """Lee el texto de iptables-save y devuelve:
    1. Lista de reglas en orden de evaluación (heredando filtros en saltos a cadenas).
    2. Políticas por defecto {'INPUT': ('DROP', 2), ...}.
    3. Lista de avisos globales.
    """
    lines = text.splitlines()
    in_filter = False
    has_filter_table = False

    default_policies: dict[str, tuple[str, int]] = {}
    custom_chains: set[str] = set()
    raw_rules: dict[str, list[tuple[int, str]]] = {"INPUT": [], "FORWARD": [], "OUTPUT": []}
    global_warnings: list[str] = []

    for line_num, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("*"):
            in_filter = (line == "*filter")
            if in_filter:
                has_filter_table = True
            continue

        if not in_filter:
            continue

        if line == "COMMIT":
            in_filter = False
            continue

        if line.startswith(":"):
            parts = line[1:].split()
            if len(parts) >= 2:
                chain_name, policy = parts[0], parts[1]
                if policy == "-":
                    custom_chains.add(chain_name)
                    raw_rules.setdefault(chain_name, [])
                else:
                    default_policies[chain_name] = (policy, line_num)
            continue

        if line.startswith("-A "):
            parts = line.split(maxsplit=2)
            if len(parts) >= 2:
                chain_name = parts[1]
                raw_rules.setdefault(chain_name, []).append((line_num, line))

    if not has_filter_table:
        raise ValueError("Il file non contiene una tabella *filter valida di iptables-save")

    def build_rule(line_num: int, line: str, target_chain: str, idx: int) -> tuple[Rule, bool]:
        """Devuelve (Rule con las condiciones de esta línea, es_salto_a_cadena)."""
        tokens = shlex.split(line)
        i = 2
        src_ips = list(ANY_IP)
        dst_ips = list(ANY_IP)
        protocol = "all"
        dst_ports = list(ANY_PORT)
        in_iface = "any"
        out_iface = "any"
        action = ""
        is_established = False
        negate_src = False
        negate_dst = False
        warnings: list[str] = []
        negated = False

        while i < len(tokens):
            tok = tokens[i]
            if tok == "!":
                negated = True
                i += 1
                continue

            if tok in ("-s", "--source") and i + 1 < len(tokens):
                src_ips = [IPv4Network(ip, strict=False) for ip in tokens[i + 1].split(",")]
                if negated:
                    negate_src = True
                    warnings.append(f"Riga {line_num}: negazione su sorgente (! -s)")
                i += 2
            elif tok in ("-d", "--destination") and i + 1 < len(tokens):
                dst_ips = [IPv4Network(ip, strict=False) for ip in tokens[i + 1].split(",")]
                if negated:
                    negate_dst = True
                    warnings.append(f"Riga {line_num}: negazione su destinazione (! -d)")
                i += 2
            elif tok in ("-p", "--protocol") and i + 1 < len(tokens):
                protocol = tokens[i + 1].lower()
                i += 2
            elif tok in ("--dport", "--dports") and i + 1 < len(tokens):
                dst_ports = _parse_ports(tokens[i + 1])
                i += 2
            elif tok in ("-i", "--in-interface") and i + 1 < len(tokens):
                in_iface = tokens[i + 1]
                i += 2
            elif tok in ("-o", "--out-interface") and i + 1 < len(tokens):
                out_iface = tokens[i + 1]
                i += 2
            elif tok in ("-j", "--jump") and i + 1 < len(tokens):
                action = tokens[i + 1]
                i += 2
            elif tok == "-m" and i + 1 < len(tokens):
                mod = tokens[i + 1]
                if mod not in ("state", "conntrack", "tcp", "udp", "multiport"):
                    warnings.append(f"Riga {line_num}: modulo iptables '{mod}' non interpretato")
                i += 2
            elif tok in ("--state", "--ctstate") and i + 1 < len(tokens):
                states = tokens[i + 1].upper().split(",")
                if "ESTABLISHED" in states or "RELATED" in states:
                    is_established = True
                i += 2
            else:
                if tok.startswith("-"):
                    warnings.append(f"Riga {line_num}: opzione '{tok}' non interpretata")
                i += 1

            negated = False

        global_warnings.extend(warnings)
        is_jump = action in custom_chains

        rule = Rule(
            id=f"{target_chain}_{idx}",
            line_num=line_num,
            chain=target_chain,
            action=action,
            src_ips=src_ips,
            dst_ips=dst_ips,
            protocol=protocol,
            dst_ports=dst_ports,
            in_iface=in_iface,
            out_iface=out_iface,
            is_established=is_established,
            negate_src=negate_src,
            negate_dst=negate_dst,
            warnings=warnings,
        )
        return rule, is_jump

    def combine_jump_conditions(parent: Rule, child: Rule, new_id: str) -> Rule | None:
        """Hereda los filtros de la regla que hace el salto hacia la regla interna."""
        src = _intersect_nets(parent.src_ips, child.src_ips)
        dst = _intersect_nets(parent.dst_ips, child.dst_ips)
        if not src or not dst:
            return None

        if parent.protocol != "all" and child.protocol != "all" and parent.protocol != child.protocol:
            return None
        proto = child.protocol if parent.protocol == "all" else parent.protocol

        if parent.in_iface != "any" and child.in_iface != "any" and parent.in_iface != child.in_iface:
            return None
        in_if = child.in_iface if parent.in_iface == "any" else parent.in_iface

        if parent.out_iface != "any" and child.out_iface != "any" and parent.out_iface != child.out_iface:
            return None
        out_if = child.out_iface if parent.out_iface == "any" else parent.out_iface

        ports = _intersect_ports(parent.dst_ports, child.dst_ports)
        if not ports:
            return None


        return Rule(
            id=new_id,
            line_num=child.line_num,
            chain=parent.chain,
            action=child.action,
            src_ips=src,
            dst_ips=dst,
            protocol=proto,
            dst_ports=ports,
            in_iface=in_if,
            out_iface=out_if,
            is_established=parent.is_established or child.is_established,
            negate_src=parent.negate_src or child.negate_src,
            negate_dst=parent.negate_dst or child.negate_dst,
            warnings=list(parent.warnings) + list(child.warnings),
        )

    final_rules: list[Rule] = []
    counter = 1

    def expand_chain(chain_to_read: str, main_chain: str, inherited: Rule | None, visited: set[str]):
        nonlocal counter
        if chain_to_read in visited:
            return
        for l_num, l_text in raw_rules.get(chain_to_read, []):
            parsed, is_jump = build_rule(l_num, l_text, main_chain, counter)
            effective = combine_jump_conditions(inherited, parsed, f"{main_chain}_{counter}") if inherited else parsed
            if effective is None:
                continue

            if is_jump:
                expand_chain(parsed.action, main_chain, effective, visited | {chain_to_read})
            else:
                final_rules.append(effective)
                counter += 1

    for main_c in ("INPUT", "FORWARD", "OUTPUT"):
        expand_chain(main_c, main_c, None, set())

    return final_rules, default_policies, global_warnings
