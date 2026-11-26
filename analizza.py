import argparse
import sys

from analizzatore import controlli, report
from analizzatore.lettori import fortigate, iptables
from analizzatore.zone import ZoneConfig, load_zones


def main() -> int:
    parser = argparse.ArgumentParser(description="Analizzatore di regole firewall")
    parser.add_argument("file", help="File di configurazione del firewall")
    parser.add_argument("--formato", choices=["iptables", "fortigate"], required=True)
    parser.add_argument("--zone", help="File YAML delle zone (solo iptables)")
    parser.add_argument("--output", choices=["md", "json"], default="md")
    args = parser.parse_args()

    try:
        with open(args.file, encoding="utf-8") as f:
            testo = f.read()

        zone = ZoneConfig()
        if args.zone:
            with open(args.zone, encoding="utf-8") as zf:
                zone = load_zones(zf.read())

        politiche = {}
        oggetti_forti = []

        if args.formato == "iptables":
            regole, politiche, avvisi = iptables.parse_iptables(testo)
        else:
            regole, oggetti_forti, avvisi = fortigate.parse_fortigate(testo)

        # Ejecutamos los controles correspondientes
        problemi = []
        problemi.extend(controlli.check_f1_oscurate(regole))
        problemi.extend(controlli.check_f2_conflitto(regole))
        problemi.extend(controlli.check_f3_ridondante(regole))
        problemi.extend(
            controlli.check_f4_permissive(
                regole,
                zone.untrusted_nets,
                zone.trusted_nets,
                zone.untrusted_ifaces,
                zone.trusted_ifaces,
            )
        )
        problemi.extend(
            controlli.check_f5_servizi_pericolosi(
                regole,
                zone.untrusted_nets,
                zone.untrusted_ifaces,
            )
        )
        if args.formato == "fortigate":
            problemi.extend(fortigate.check_f6_inutilizzati(oggetti_forti))
        if args.formato == "iptables":
            problemi.extend(controlli.check_f7_default_open(regole, politiche))

        # Imprimimos el reporte
        if args.output == "json":
            print(report.format_json(problemi, avvisi))
        else:
            print(report.format_markdown(problemi, avvisi))

    except (OSError, ValueError) as errore:
        print(f"Errore: {errore}", file=sys.stderr)
        return 2

    return 1 if problemi else 0


if __name__ == "__main__":
    sys.exit(main())
