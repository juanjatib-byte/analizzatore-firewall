from ipaddress import IPv4Network

from analizzatore.confronto import is_rule_covered
from analizzatore.modello import ANY_IP, ANY_PORT, Problem, Rule

# Redes privadas estándar (para detectar tráfico hacia toda una red interna en F4)
REDES_INTERNAS = [
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
]

# Puertos sensibles de administración, sin cifrar o bases de datos (para F5)
PUERTOS_PELIGROSOS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    139: "NetBIOS",
    161: "SNMP",
    162: "SNMP-Trap",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Mgmt",
    8443: "HTTPS-Mgmt",
    27017: "MongoDB",
}

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
# F2: Regla en conflicto (cubierta por una regla anterior con la acción OPUESTA)
# ==============================================================================
def check_f2_conflitto(rules: list[Rule]) -> list[Problem]:
    problemi = []
    for i, rule in enumerate(rules):
        for prev in rules[:i]:
            if prev.action != rule.action and is_rule_covered(rule, prev):
                problemi.append(Problem(
                    code="F2",
                    severity="alta",
                    line_num=rule.line_num,
                    description=f"In conflitto con la regola a riga {prev.line_num} (azione opposta)",
                    caused_by=[prev.line_num],
                ))
                break
    return problemi


# ==============================================================================
# F3: Regla redundante (cubierta por una posterior con la misma acción sin bloqueo en medio)
# ==============================================================================
def check_f3_ridondante(rules: list[Rule]) -> list[Problem]:
    problemi = []
    for i, rule in enumerate(rules):
        for j in range(i + 1, len(rules)):
            next_rule = rules[j]
            # Si hay una regla en medio con acción opuesta que cubre este tráfico, paramos
            if next_rule.action != rule.action and is_rule_covered(rule, next_rule):
                break
            # Si una regla posterior tiene la misma acción y cubre toda esta regla, esta sobra
            if next_rule.action == rule.action and is_rule_covered(rule, next_rule):
                problemi.append(Problem(
                    code="F3",
                    severity="bassa",
                    line_num=rule.line_num,
                    description=f"Regola ridondante: coperta dalla regola successiva a riga {next_rule.line_num}",
                    caused_by=[next_rule.line_num],
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
# F5: Servicio peligroso expuesto desde una zona no fiable
# ==============================================================================
def check_f5_servizi_pericolosi(
    rules: list[Rule],
    untrusted_nets: list[IPv4Network] | None = None,
    untrusted_ifaces: list[str] | None = None,
) -> list[Problem]:
    esterna_net = untrusted_nets if untrusted_nets else ANY_IP
    esterna_if = {i.lower() for i in (untrusted_ifaces or ["wan", "wan1", "wan2"])}
    problemi = []

    for rule in rules:
        if rule.action != "ACCEPT":
            continue

        # Comprobamos si el tráfico viene de una red o interfaz no fiable
        da_zona_non_fidata = (
            any(net in rule.src_ips for net in esterna_net)
            or (rule.in_iface.lower() in esterna_if)
        )
        if not da_zona_non_fidata:
            continue

        # Buscamos si algún puerto peligroso cae dentro de los puertos permitidos por la regla
        # (Ignoramos reglas de puerto 'all' 0-65535 si ya fueron marcadas como F4 demasiado permisivas,
        # o solo reportamos si apunta a un rango específico o incluye puertos peligrosos)
        esposti = []
        for porta, nome in PUERTOS_PELIGROSOS.items():
            for rng in rule.dst_ports:
                if rng.start <= porta <= rng.end and not (rng.start == 0 and rng.end == 65535):
                    esposti.append(f"{nome} ({porta})")
                    break

        if esposti:
            servizi_str = ", ".join(esposti[:4])
            problemi.append(Problem(
                code="F5",
                severity="alta",
                line_num=rule.line_num,
                description=f"Servizio pericoloso esposto da zona non fidata: {servizi_str}",
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
