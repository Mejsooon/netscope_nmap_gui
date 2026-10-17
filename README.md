# NetScope — nmap GUI

Lokalna aplikacja (FastAPI + przeglądarka), która dodaje interaktywne GUI do nmapa.

- **SOFT** — użytkownik wybiera opcje w formularzu i dostaje czytelną tabelę wyników
- **PRO** — dodatkowo silnik reguł ostrzeżeń i agent AI, który dobiera parametry i tłumaczy wyniki

## Status

| Krok | Moduł | Status |
|---|---|---|
| 1 | Parser XML | gotowe |
| 2 | Builder (allowlista + walidacja) | — |
| 3 | Runner (subprocess) | — |
| 4 | API | — |
| 5 | Frontend | — |
| 6 | Reguły ostrzeżeń | — |
| 7 | AI | — |
| 8 | Desktop | — |

## Parser XML

```python
from app.nmap.xml_parser import parse_scan

result = parse_scan(xml_text)          # tekst z `nmap ... -oX -`
for host in result.hosts:
    for port in host.ports:
        print(host.ip, port.port, port.state, port.service_name)
```

`parse_scan()` zwraca model `ScanResult` (Pydantic) albo rzuca `NmapParseError`.
XML jest parsowany przez `defusedxml`, więc ataki typu billion laughs i XXE są blokowane.

## Uruchomienie testów

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

Testy nie wymagają nmapa ani dostępu do sieci — parser jest testowany na zapisanych wynikach w `tests/fixtures/`.

## Zasady

Skanuj wyłącznie systemy, do których masz uprawnienia, albo serwer testowy `scanme.nmap.org` udostępniony przez twórców nmapa.
