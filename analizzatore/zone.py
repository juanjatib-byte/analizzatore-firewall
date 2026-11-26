from dataclasses import dataclass, field
from ipaddress import IPv4Network
import yaml


@dataclass
class ZoneConfig:
    untrusted_ifaces: list[str] = field(default_factory=list)
    untrusted_nets: list[IPv4Network] = field(default_factory=list)
    trusted_ifaces: list[str] = field(default_factory=list)
    trusted_nets: list[IPv4Network] = field(default_factory=list)


def load_zones(yaml_text: str) -> ZoneConfig:
    """Lee el contenido de zone.yml y lo convierte en listas limpias."""
    data = yaml.safe_load(yaml_text)
    if not isinstance(data, dict):
        raise ValueError("Il file zone.yml non ha un formato valido")

    non_fidate = data.get("non_fidate") or {}
    fidate = data.get("fidate") or {}

    return ZoneConfig(
        untrusted_ifaces=list(non_fidate.get("interfacce") or []),
        untrusted_nets=[IPv4Network(r, strict=False) for r in (non_fidate.get("reti") or [])],
        trusted_ifaces=list(fidate.get("interfacce") or []),
        trusted_nets=[IPv4Network(r, strict=False) for r in (fidate.get("reti") or [])],
    )
