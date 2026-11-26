import json
from analizzatore.modello import Problem


def format_json(problemi: list[Problem], avvisi: list[str]) -> str:
    """Genera el reporte en formato JSON."""
    payload = {
        "problemi": [
            {
                "codice": p.code,
                "gravita": p.severity,
                "riga": p.line_num,
                "causato_da": p.caused_by,
                "descrizione": p.description,
            }
            for p in problemi
        ],
        "avvisi": avvisi,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def format_markdown(problemi: list[Problem], avvisi: list[str]) -> str:
    """Genera un reporte legible en Markdown agrupado por gravedad."""
    if not problemi and not avvisi:
        return "# Report Analisi Firewall\n\nNessun problema rilevato.\n"

    lines = ["# Report Analisi Firewall\n"]

    for gravita, titolo in [("alta", "Alta"), ("media", "Media"), ("bassa", "Bassa")]:
        gruppo = [p for p in problemi if p.severity == gravita]
        if gruppo:
            lines.append(f"## Gravità {titolo} ({len(gruppo)})\n")
            for p in gruppo:
                causa = f" (causato da riga {', '.join(map(str, p.caused_by))})" if p.caused_by else ""
                lines.append(f"- **[{p.code}] Riga {p.line_num}**{causa}: {p.description}")
            lines.append("")

    if avvisi:
        lines.append(f"## Avvisi ({len(avvisi)})\n")
        for a in avvisi:
            lines.append(f"- {a}")
        lines.append("")

    return "\n".join(lines)
