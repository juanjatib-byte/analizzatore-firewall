# Analizzatore Statico di Regole Firewall

Strumento da riga di comando in Python per l'analisi statica di configurazioni firewall **iptables** (`iptables-save`) e **FortiGate** (`show full-configuration`). Traduce entrambi i formati in un modello comune e rileva 7 categorie di problemi di sicurezza e configurazione (`F1`–`F7`).

## Requisiti e Installazione

- Python 3.10 o superiore
- Dipendenze: `PyYAML` e `pytest` (per i test)

```bash
pip install pyyaml pytest
```

## Utilizzo

```bash
# Analisi di una configurazione iptables con file delle zone (output Markdown)
python3 analizza.py --formato iptables esempi/iptables-01/regole.txt --zone esempi/iptables-01/zone.yml

# Analisi di una configurazione FortiGate con output JSON
python3 analizza.py --formato fortigate esempi/fortigate-01/config.conf --output json
```

### Opzioni CLI
- `--formato {iptables,fortigate}` (obbligatorio): formato del file di input.
- `--zone <file.yml>` (opzionale, solo `iptables`): definisce interfacce e reti `fidate` e `non_fidate`.
- `--output {md,json}` (default `md`): formato del report in uscita.

### Codici di uscita
- `0`: nessun problema rilevato.
- `1`: rilevato almeno un problema (`F1`–`F7`).
- `2`: errore di lettura file o formato non valido.

## Controlli Implementati (`F1`–`F7`)

| Codice | Nome | Gravità | Descrizione |
| :--- | :--- | :--- | :--- |
| **F1** | Regola oscurata | Media | Regola mai raggiunta perché coperta da una regola precedente con la **stessa azione**. |
| **F2** | Regola in conflitto | Alta | Regola coperta da una regola precedente con **azione opposta** (`ACCEPT` vs `DROP`). |
| **F3** | Regola ridondante | Bassa | Regola superflua perché coperta da una regola successiva con la stessa azione senza blocchi intermedi. |
| **F4** | Regola troppo permisiva | Alta | Regola `ACCEPT` con `any -> any : any` oppure da intera rete/interfaccia non fidata verso rete/interfaccia fidata. |
| **F5** | Servizio pericoloso esposto | Alta | Esposizione verso zone non fidate di servizi sensibili (Telnet, SMB, RDP, SNMP, VNC, SSH, database). |
| **F6** | Oggetti inutilizzati | Bassa | *(Solo FortiGate)* Oggetti `address`, `addrgrp`, `service custom` o `service group` definiti ma mai usati nelle `policy`. |
| **F7** | Politica di default aperta | Alta | *(Solo iptables)* Catena principale con politica `ACCEPT` priva di una regola finale di blocco generale. |

## Scelte Progettuali e Limiti Noti

- **Modello comune (`analizzatore/modello.py`):** Per maggiore chiarezza interna nel codice sorgente, le dataclass del modello comune utilizzano identificatori in inglese (`Rule`, `PortRange`, `Problem`), mantenendo invariate tutte le semantiche, i codici (`F1`–`F7`) e l'interfaccia CLI/report in italiano richiesti dalla specifica.
- **Catene personalizzate e gruppi nidificati:** In `iptables`, i salti `-j <CATENA>` vengono espansi ricorsivamente nell'ordine esatto di valutazione conservando il numero di riga originale. In FortiGate, `addrgrp` e `service group` vengono risolti ricorsivamente rilevando anche gli oggetti utilizzati indirettamente.
- **Limiti noti e gestione sicura:**
  - Regole con negazione (`! -s`, `! -d`), opzioni di rate-limiting o moduli non standard vengono segnalate nella sezione **Avvisi** senza interrompere l'analisi né produrre falsi positivi.
  - Il parser FortiGate supporta indirizzi `ipmask`, gruppi di indirizzi/servizi e intervalli porte TCP/UDP; altri tipi di oggetti (es. FQDN o wildcard) generano un avviso esplicito.

## Esecuzione dei Test

Il progetto include 34 test automatici `pytest` (unitari e di integrazione sugli 8 esempi in `esempi/`):

```bash
python3 -m pytest
```
