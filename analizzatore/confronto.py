# Traemos los moldes que ya creaste en modello.py
from analizzatore.modello import PortRange, Rule


# 1. Comprueba si un protocolo (small) queda tapado por otro (large)
def is_protocol_covered(small: str, large: str) -> bool:
    # Si el de arriba es "all" (todos) o son exactamente iguales, devuelve True
    if large == "all" or small == large:
        return True
    return False


# 2. Comprueba si un rango de puertos (small) cabe dentro de otro (large)
def are_ports_covered(small: PortRange, large: PortRange) -> bool:
    # El inicio grande debe ser menor/igual al pequeño Y el fin pequeño menor/igual al grande
    if large.start <= small.start and small.end <= large.end:
        return True
    return False


# 3. Comprueba si una regla completa (rule) queda totalmente tapada por una anterior (previous)
def is_rule_covered(rule: Rule, previous: Rule) -> bool:
    # Usamos la función .covers() que ya tienes programada dentro de modello.py
    return previous.covers(rule)
