from ipaddress import IPv4Network

from analizzatore.confronto import is_rule_covered
from analizzatore.modello import ANY_IP, ANY_PORT, Problem, Rule

# Redes privadas estándar (para detectar tráfico hacia toda una red interna en F4)
REDES_INTERNAS = [
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
]


# ==============================================================================
# F1: Regla oscurata (tapada por una regla anterior con la MISMA acción)
# ==============================================================================
def check_f1_oscurate(rules: list[Rule]) -> list[Problem]:
    problemi = []
    for i, rule in enumerate(rules):
        for prev in rules[:i]:
            if prev.action == rule.action and is_rule_covered(rule, prev):
                problemi.append(Problem(
                    code="F1",
                    severity="media",
                    line_num=rule.line_num,
                    description=f"Non scatta mai: coperta dalla regola a riga {prev.line_num}",
                    caused_by=[prev.line_num],
                ))
                break
    return problemi


# ==============================================================================
# F4: Regla demasiado permisiva (any -> any : any ACCEPT o externa -> interna)
# ==============================================================================
def check_f4_permissive(
    rules: list[Rule],
    untrusted_nets: list[IPv4Network] | None = None,
    trusted_nets: list[IPv4Network] | None = None,
    untrusted_ifaces: list[str] | None = None,
    trusted_ifaces: list[str] | None = None,
) -> list[Problem]:
    esterna_net = untrusted_nets if untrusted_nets else ANY_IP
    interna_net = trusted_nets if trusted_nets else REDES_INTERNAS
    esterna_if = untrusted_ifaces or []
    interna_if = trusted_ifaces or []
    problemi = []

    for rule in rules:
        if rule.action != "ACCEPT":
            continue

        todo_puerto = rule.protocol == "all" and rule.dst_ports == ANY_PORT
        origen_todo = rule.src_ips == ANY_IP
        destino_todo = rule.dst_ips == ANY_IP

        # Caso 1: any -> any : any ACCEPT
        if origen_todo and destino_todo and todo_puerto:
            problemi.append(Problem(
                code="F4",
                severity="alta",
                line_num=rule.line_num,
                description="Regola troppo permissiva: permette qualsiasi traffico (any -> any : any)",
            ))
            continue

        # Caso 2: Toda una red/interfaz externa hacia toda una red/interfaz interna
        es_externa = (
            any(net in rule.src_ips for net in esterna_net)
            or (rule.in_iface in esterna_if)
        )
        es_interna = (
            any(net in rule.dst_ips for net in interna_net)
            or (rule.out_iface in interna_if)
        )
        if es_externa and es_interna and todo_puerto:
            problemi.append(Problem(
                code="F4",
                severity="alta",
                line_num=rule.line_num,
                description="Regola troppo permissiva: espone un'intera rete interna verso una rete esterna",
            ))

    return problemi



# ==============================================================================
# F7: Política de default abierta (cadena con ACCEPT y sin regla final de bloqueo)
# ==============================================================================
def check_f7_default_open(
    rules: list[Rule],
    default_policies: dict[str, tuple[str, int]],
) -> list[Problem]:
    """default_policies tiene formato: {'FORWARD': ('ACCEPT', 4)} -> (política, línea)."""
    problemi = []

    for chain, (policy, line_num) in default_policies.items():
        if policy != "ACCEPT":
            continue

        regole_catena = [r for r in rules if r.chain == chain]
        ha_blocco_finale = False

        if regole_catena:
            ultima = regole_catena[-1]
            if (
                ultima.action in ("DROP", "REJECT")
                and ultima.src_ips == ANY_IP
                and ultima.dst_ips == ANY_IP
                and ultima.protocol == "all"
                and ultima.dst_ports == ANY_PORT
            ):
                ha_blocco_finale = True

        if not ha_blocco_finale:
            problemi.append(Problem(
                code="F7",
                severity="alta",
                line_num=line_num,
                description=f"Politica di default ACCEPT su {chain} senza regola finale di blocco",
            ))

    return problemi
