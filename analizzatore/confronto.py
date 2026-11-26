# Traemos los moldes que ya creaste en modello.py
from analizzatore.modello import PortRange, Rule


# 1. Comprueba si un protocolo (small) queda tapado por otro (large)
def is_protocol_covered(small: str, large: str) -> bool:
    # Si el de arriba es "all" (todos) o son exactamente iguales, devuelve True
    if large == "all" or small == large:
        return True
    return False


# 2. Comprueba si TODOS los rangos de puertos (small_list) caben dentro de (large_list)
def are_ports_covered(small_list: list[PortRange], large_list: list[PortRange]) -> bool:
    for small in small_list:
        # Buscamos si este rango pequeño cabe en al menos un rango grande de arriba
        cubierto = any(large.contains(small) for large in large_list)
        if not cubierto:
            return False
    return True



# 3. Comprueba si una regla completa (rule) queda totalmente tapada por una anterior (previous)
def is_rule_covered(rule: Rule, previous: Rule) -> bool:
    # Usamos la función .covers() que ya tienes programada dentro de modello.py
    return previous.covers(rule)
