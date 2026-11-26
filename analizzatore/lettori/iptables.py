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


def parse_iptables(text: str) -> tuple[list[Rule], dict[str, tuple[str, int]], list[str]]:
    """Lee el texto de iptables-save y devuelve:
    1. Lista de reglas en orden de evaluación.
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

    # Paso 1: Leer el archivo línea por línea dentro de *filter
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

        # Políticas por defecto o declaración de cadenas (:INPUT ACCEPT [0:0])
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

        # Reglas (-A CADENA ...)
        if line.startswith("-A "):
            parts = line.split(maxsplit=2)
            if len(parts) >= 2:
                chain_name = parts[1]
                raw_rules.setdefault(chain_name, []).append((line_num, line))

    if not has_filter_table:
        raise ValueError("Il file non contiene una tabella *filter valida di iptables-save")

    # Paso 2: Convertir cada línea de regla en un objeto Rule
    def build_rule(line_num: int, line: str, target_chain: str, idx: int) -> Rule | str:
        tokens = shlex.split(line)
        i = 2  # Saltamos '-A' y el nombre de la cadena
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

        # Si salta a una cadena personalizada, devolvemos su nombre para expandirla
        if action in custom_chains:
            return f"JUMP:{action}"

        return Rule(
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

    # Paso 3: Expandir reglas en orden para INPUT, FORWARD y OUTPUT
    final_rules: list[Rule] = []
    counter = 1

    def expand_chain(chain_to_read: str, main_chain: str, visited: set[str]):
        nonlocal counter
        if chain_to_read in visited:
            return
        for l_num, l_text in raw_rules.get(chain_to_read, []):
            parsed = build_rule(l_num, l_text, main_chain, counter)
            if isinstance(parsed, str) and parsed.startswith("JUMP:"):
                sub_chain = parsed.split(":", 1)[1]
                expand_chain(sub_chain, main_chain, visited | {chain_to_read})
            elif isinstance(parsed, Rule):
                final_rules.append(parsed)
                counter += 1

    for main_c in ("INPUT", "FORWARD", "OUTPUT"):
        expand_chain(main_c, main_c, set())

    return final_rules, default_policies, global_warnings
