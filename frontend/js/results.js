import { el } from "./dom.js";
import { STATUS_LABELS, explainJobError } from "./messages.js";

const seconds = new Intl.NumberFormat("pl-PL", { maximumFractionDigits: 2 });
const clock = new Intl.DateTimeFormat("pl-PL", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export function plural(n, one, few, many) {
  if (n === 1) return one;
  const lastDigit = n % 10;
  const lastTwo = n % 100;
  if (lastDigit >= 2 && lastDigit <= 4 && (lastTwo < 12 || lastTwo > 14)) return few;
  return many;
}

const count = (n, one, few, many) => `${n} ${plural(n, one, few, many)}`;

export function formatDuration(milliseconds) {
  const total = Math.max(0, Math.floor(milliseconds / 1000));
  const minutes = String(Math.floor(total / 60)).padStart(2, "0");
  const rest = String(total % 60).padStart(2, "0");
  return `${minutes}:${rest}`;
}

export function isFinished(job) {
  return ["done", "failed", "cancelled"].includes(job.status);
}

export function renderJob(container, job, handlers = {}) {
  const views = { queued: runningView, running: runningView, done: doneView, failed: failedView, cancelled: cancelledView };
  container.replaceChildren(...views[job.status](job, handlers));
}

function header(job, meta, actions = []) {
  return el("div", { className: "result-head" }, [
    el("div", { className: "result-heading" }, [
      el("div", { className: "result-title-row" }, [
        el("h2", { className: "result-title", text: job.request.target, attrs: { id: "result-title" } }),
        el("span", { className: `pill pill--${job.status}`, text: STATUS_LABELS[job.status], attrs: { "data-status": job.status } }),
      ]),
      el("span", { className: "result-meta", text: meta }),
    ]),
    actions.length ? el("div", { className: "result-actions" }, actions) : null,
  ]);
}

function reuseButton(job, handlers) {
  if (!handlers.onReuse) return null;
  return el("button", { className: "button", text: "Użyj ponownie", attrs: { type: "button" }, on: { click: () => handlers.onReuse(job.request) } });
}

function runningView(job, handlers) {
  const meta = job.status === "queued"
    ? "czeka na wolne miejsce — naraz działają najwyżej 2 skany"
    : `rozpoczęty ${clock.format(new Date(job.started_at))}`;
  const actions = handlers.onCancel
    ? [el("button", { className: "button button--danger", text: "Anuluj skan", attrs: { type: "button" }, on: { click: () => handlers.onCancel(job.id) } })]
    : [];

  return [
    header(job, meta, actions),
    el("div", { className: "running-body" }, [
      el("div", { className: "timer-row" }, [
        el("span", { className: "timer", text: "00:00", attrs: { id: "elapsed", "aria-label": "Czas skanu" } }),
        el("span", { className: "hint", text: "limit 10:00" }),
      ]),
      el("div", { className: "progress", attrs: { role: "progressbar", "aria-label": "Skan w toku" } }, [
        el("div", { className: "progress-bar" }),
      ]),
      el("span", { className: "hint", text: "nmap nie podaje postępu w trakcie skanu — wynik pojawi się po zakończeniu." }),
    ]),
  ];
}

function doneView(job, handlers) {
  const result = job.result;
  const upHosts = result.hosts.filter((host) => host.state === "up");
  const isPing = job.request.scan_type === "ping";
  const ports = upHosts.flatMap((host) => host.ports);

  const parts = [count(result.hosts_up, "host aktywny", "hosty aktywne", "hostów aktywnych")];
  if (!isPing) parts.push(count(ports.length, "port", "porty", "portów"));
  if (result.elapsed_seconds !== null) parts.push(`${seconds.format(result.elapsed_seconds)} s`);

  const blocks = upHosts.map((host) => hostBlock(host, isPing));
  if (upHosts.length === 0) {
    blocks.push(el("div", { className: "message-body" }, [
      el("p", { className: "muted-text", text: "Żaden host nie odpowiedział. Może być wyłączony albo blokować sondy nmapa." }),
    ]));
  }
  if (result.hosts_down > 0 && upHosts.length > 0) {
    blocks.push(el("p", { className: "host-note", text: `${count(result.hosts_down, "host nie odpowiedział", "hosty nie odpowiedziały", "hostów nie odpowiedziało")}.` }));
  }

  return [
    header(job, parts.join(" · "), [reuseButton(job, handlers)].filter(Boolean)),
    isPing ? hostStats(result) : portStats(upHosts),
    ...blocks,
  ];
}

function stat(label, value) {
  return el("div", { className: "stat" }, [
    el("div", { className: "stat-label", text: label }),
    el("div", { className: "stat-value", text: value }),
  ]);
}

function portStats(hosts) {
  const totals = { open: 0, closed: 0, filtered: 0 };
  const bucket = (state) => (state === "open" ? "open" : state === "closed" ? "closed" : "filtered");
  for (const host of hosts) {
    for (const port of host.ports) totals[bucket(port.state)] += 1;
    for (const extra of host.extra_ports) totals[bucket(extra.state)] += extra.count;
  }
  return el("div", { className: "stats" }, [
    stat("Otwarte", totals.open),
    stat("Zamknięte", totals.closed),
    stat("Filtrowane", totals.filtered),
  ]);
}

function hostStats(result) {
  return el("div", { className: "stats" }, [
    stat("Aktywne", result.hosts_up),
    stat("Nieaktywne", result.hosts_down),
    stat("Razem", result.hosts_total),
  ]);
}

function hostBlock(host, isPing) {
  const details = [];
  if (host.hostnames.length) details.push(host.hostnames.join(", "));
  if (host.mac) details.push(host.mac_vendor ? `${host.mac} (${host.mac_vendor})` : host.mac);

  const children = [
    el("div", { className: "host-head" }, [
      el("span", { className: "host-ip", text: host.ip ?? "—" }),
      details.length ? el("span", { className: "host-extra", text: details.join(" · ") }) : null,
    ]),
  ];

  if (host.ports.length) children.push(portTable(host.ports));
  for (const extra of host.extra_ports) {
    children.push(el("p", {
      className: "host-note",
      text: `${count(extra.count, "port", "porty", "portów")} w stanie ${extra.state} — nie pokazano w tabeli.`,
    }));
  }
  if (!isPing && !host.ports.length && !host.extra_ports.length) {
    children.push(el("p", { className: "host-note", text: "Brak portów w skanowanym zakresie." }));
  }
  return el("div", { className: "host-block", attrs: { "data-host": host.ip ?? "" } }, children);
}

function portTable(ports) {
  const head = el("thead", {}, [el("tr", {}, ["Port", "Stan", "Usługa", "Produkt", "Wersja"].map(
    (title) => el("th", { text: title, attrs: { scope: "col" } }),
  ))]);
  const rows = ports.map((port) => el("tr", {}, [
    el("td", { className: "mono" }, [String(port.port), el("span", { className: "dim", text: `/${port.protocol}` })]),
    el("td", {}, [el("span", { className: `status-dot state--${port.state}`, text: port.state })]),
    el("td", { className: "mono", text: port.service_name ?? "—" }),
    el("td", { text: port.product ?? "—" }),
    el("td", { className: "dim", text: [port.version, port.extra_info].filter(Boolean).join(" · ") || "—" }),
  ]));
  return el("div", { className: "table-wrap" }, [
    el("table", { className: "table" }, [head, el("tbody", {}, rows)]),
  ]);
}

function failedView(job, handlers) {
  return [
    header(job, "dane były poprawne — nie udało się wykonać skanu", [reuseButton(job, handlers)].filter(Boolean)),
    el("div", { className: "message-body" }, [
      el("p", { className: "muted-text", text: explainJobError(job.error) }),
      el("code", { className: "code-block", text: job.error ?? "" }),
    ]),
  ];
}

function cancelledView(job, handlers) {
  return [
    header(job, "skan przerwany przed zakończeniem", [reuseButton(job, handlers)].filter(Boolean)),
    el("div", { className: "message-body" }, [
      el("p", { className: "muted-text", text: "Skan został anulowany. Wyniki nie zostały zapisane." }),
    ]),
  ];
}
