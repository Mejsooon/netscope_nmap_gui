export const STATUS_LABELS = {
  queued: "w kolejce",
  running: "w toku",
  done: "zakończony",
  failed: "błąd",
  cancelled: "anulowany",
};

const REQUEST_ERRORS = [
  { pattern: /must not start with '-'/, field: "target", message: "Cel nie może zaczynać się od „-”." },
  { pattern: /the limit is \d+/, field: "target", message: "Sieć jest za duża — maksymalnie 65 536 adresów (np. /16)." },
  { pattern: /Not a valid IP address, network or hostname/, field: "target",
    message: "To nie jest adres IP, sieć ani hostname. Wpisz np. 192.168.1.1, 10.0.0.0/24 albo router.lan." },
  { pattern: /Invalid port specification/, field: "ports", message: "Nieprawidłowy format portów. Użyj np. 22, 1-1000 albo 22,80,443." },
  { pattern: /Port out of range/, field: "ports", message: "Porty muszą mieścić się w zakresie 1–65535." },
  { pattern: /from low to high/, field: "ports", message: "Zakres portów musi iść od mniejszej do większej liczby." },
  { pattern: /require root/, field: "form", message: "Wybrane opcje wymagają uprawnień administratora (root)." },
];

export function translateRequestError(error) {
  if (error.status === 0) {
    return { field: "form", message: "Brak połączenia z serwerem NetScope. Sprawdź, czy aplikacja działa." };
  }
  if (error.status === 503) {
    return { field: "form", message: "Nie znaleziono nmapa. Zainstaluj go i uruchom aplikację ponownie." };
  }
  if (error.status === 403) {
    return { field: "form", message: "Serwer odrzucił żądanie z tej strony." };
  }
  if (error.status === 422) {
    return { field: "form", message: "Nieprawidłowe dane formularza. Sprawdź wpisane wartości." };
  }
  const known = REQUEST_ERRORS.find((entry) => entry.pattern.test(error.detail || ""));
  if (known) return { field: known.field, message: known.message };
  return { field: "form", message: error.detail || "Nie udało się uruchomić skanu." };
}

const JOB_ERRORS = [
  { pattern: /Failed to resolve/, message: "Nie udało się znaleźć hosta w DNS. Sprawdź nazwę albo użyj adresu IP." },
  { pattern: /time limit/, message: "Skan trwał dłużej niż limit czasu i został przerwany." },
  { pattern: /Invalid XML|Unexpected nmap XML/, message: "nmap zwrócił wynik, którego NetScope nie potrafi odczytać." },
];

export function explainJobError(errorText) {
  const known = JOB_ERRORS.find((entry) => entry.pattern.test(errorText || ""));
  return known ? known.message : "Skan zakończył się błędem.";
}
