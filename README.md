# NetScope — nmap GUI

Lokalna aplikacja (FastAPI + przeglądarka), która dodaje interaktywne GUI do nmapa.

- **SOFT** — użytkownik wybiera opcje w formularzu i dostaje czytelną tabelę wyników
- **PRO** — dodatkowo silnik reguł ostrzeżeń i agent AI, który dobiera parametry i tłumaczy wyniki

## Status

| Krok | Moduł | Status |
|---|---|---|
| 1 | Parser XML | gotowe |
| 2 | Builder (allowlista + walidacja) | gotowe |
| 3 | Runner (subprocess) | gotowe |
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

## Builder komendy

```python
from app.nmap.command_builder import build_command
from app.schemas.scan import ScanRequest

request = ScanRequest(target="192.168.1.0/24", ports="22,80,443", service_detection=True)
build_command(request)
# ['nmap', '-sT', '-sV', '-T3', '-p', '22,80,443', '-oX', '-', '--', '192.168.1.0/24']
```

- klient wysyła **nazwy** opcji (`scan_type="syn"`), a nie flagi — flagi zna tylko `options_catalog.py` (allowlista)
- cel: adres IP, sieć CIDR (maks. 65 536 adresów) albo hostname; nic, co zaczyna się od `-`
- porty: `22`, `1-1000`, `22,80,443` w zakresie 1–65535
- `-sS`, `-sU`, `-O` wymagają roota — bez niego `InsufficientPrivilegesError` z podpowiedzią
- każdy błąd danych wejściowych to podklasa `InvalidScanRequestError`

## Uruchomienie skanu

```python
from app.schemas.scan import ScanRequest
from app.services.scan_service import run_scan

result = run_scan(ScanRequest(target="scanme.nmap.org", ports="22,80"), timeout=300)
```

`run_scan()` łączy builder, runner i parser. Runner (`app/nmap/runner.py`):

- uruchamia nmapa przez `subprocess.Popen` z `shell=False` i pełną ścieżką z `shutil.which`
- po przekroczeniu limitu czasu kończy proces (`terminate()`, a po 5 s `kill()`) → `ScanTimeoutError`
- `NmapRunner.cancel()` z innego wątku przerywa skan → `ScanCancelledError`
- kod wyjścia ≠ 0 → `NmapExecutionError` ze skróconym stderr
- brak nmapa → `NmapNotFoundError`

## Uruchomienie testów

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

Testy nie wymagają nmapa ani dostępu do sieci — parser jest testowany na zapisanych wynikach w `tests/fixtures/`,
a runner na procesach Pythona udających nmapa.

Testy integracyjne na prawdziwym nmapie (wymagają zainstalowanego nmapa i dostępu do sieci):

```bash
pytest -m integration
```

## Zasady

Skanuj wyłącznie systemy, do których masz uprawnienia, albo serwer testowy `scanme.nmap.org` udostępniony przez twórców nmapa.
