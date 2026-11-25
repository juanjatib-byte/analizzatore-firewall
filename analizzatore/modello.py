# ==============================================================================
# BLOQUE 1: HERRAMIENTAS BASE
# Carga utilidades internas de Python para crear plantillas y entender redes IP.
# ==============================================================================
from dataclasses import dataclass, field
from ipaddress import IPv4Network, ip_network


# ==============================================================================
# BLOQUE 2: MOLDE DE PUERTOS
# Define un rango de puertos (ej. del 80 al 443), valida que sean reales y comprueba si uno cabe en otro.
# ==============================================================================
@dataclass(frozen=True)
class PortRange:
    start: int  # Puerto inicial
    end: int    # Puerto final

    def __post_init__(self) -> None:
        """Guardia de seguridad: se ejecuta automáticamente al crear el rango de puertos."""
        if self.start < 0 or self.end > 65535:
            raise ValueError(f"Puerto fuera de rango real (0-65535): {self.start}-{self.end}")
        if self.start > self.end:
            raise ValueError(f"El puerto inicial ({self.start}) no puede ser mayor al final ({self.end})")

    def contains(self, other: "PortRange") -> bool:
        """Devuelve True si este rango abarca por completo al otro rango."""
        return self.start <= other.start and self.end >= other.end


# ==============================================================================
# BLOQUE 3: COMODINES POR DEFECTO
# Valores que significan "cualquier IP" y "cualquier puerto".
# ==============================================================================
ANY_IP = [ip_network("0.0.0.0/0")]
ANY_PORT = [PortRange(0, 65535)]


# ==============================================================================
# BLOQUE 4: FICHA DE UNA REGLA DE FIREWALL
# Guarda todos los datos de una regla y verifica si esta regla tapa a otra.
# ==============================================================================
@dataclass
class Rule:
    # --- Datos obligatorios de la regla ---
    id: str             # Identificador de la regla
    line_num: int      # Número de línea en el firewall
    chain: str         # Dirección del tráfico (INPUT, OUTPUT, FORWARD)
    action: str        # Qué hace con el tráfico ("ACCEPT" o "DROP")

    # --- Datos opcionales (si no se ponen, usan los comodines de arriba) ---
    src_ips: list[IPv4Network] = field(default_factory=lambda: list(ANY_IP))       # IPs de origen
    dst_ips: list[IPv4Network] = field(default_factory=lambda: list(ANY_IP))       # IPs de destino
    protocol: str = "all"                                                          # Protocolo ("tcp", "udp", "icmp", "all")
    dst_ports: list[PortRange] = field(default_factory=lambda: list(ANY_PORT))     # Puertos de destino
    in_iface: str = "any"                                                          # Tarjeta de red de entrada
    out_iface: str = "any"                                                         # Tarjeta de red de salida
    is_established: bool = False                                                   # True si es solo para conexiones ya abiertas

    # --- Comparador: comprueba paso a paso si esta regla abarca por completo a 'other' ---
    def covers(self, other: "Rule") -> bool:
        """Devuelve True si esta regla cubre por completo a 'other'."""

        # Paso 1: Si esta regla es solo para conexiones abiertas y la otra no, no la cubre
        if self.is_established and not other.is_established:
            return False

        # Paso 2: Si no coinciden la dirección (chain) o las tarjetas de red, no la cubre
        if self.chain != other.chain:
            return False
        if self.in_iface != "any" and self.in_iface != other.in_iface:
            return False
        if self.out_iface != "any" and self.out_iface != other.out_iface:
            return False

        # Paso 3: Si usan protocolos distintos, no la cubre
        if self.protocol != "all" and self.protocol != other.protocol:
            return False

        # Paso 4: Comprueba que las IPs de origen y destino de 'other' quepan dentro de las de esta regla
        if not all(
            any(o_ip.subnet_of(s_ip) for s_ip in self.src_ips)
            for o_ip in other.src_ips
        ):
            return False
        if not all(
            any(o_ip.subnet_of(s_ip) for s_ip in self.dst_ips)
            for o_ip in other.dst_ips
        ):
            return False

        # Paso 5: Comprueba que los puertos de destino de 'other' quepan dentro de los de esta regla
        if not all(
            any(s_p.contains(o_p) for s_p in self.dst_ports)
            for o_p in other.dst_ports
        ):
            return False

        # Si superó todos los pasos, esta regla cubre totalmente a la otra
        return True
