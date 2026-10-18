import { el } from "./dom.js";
import { STATUS_LABELS } from "./messages.js";

const STATUS_DOT = {
  queued: "status-dot--muted",
  running: "status-dot--accent",
  done: "status-dot--ok",
  failed: "status-dot--danger",
  cancelled: "status-dot--muted",
};

const dateFormat = new Intl.DateTimeFormat("pl-PL", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });

export function relativeTime(isoDate, now = Date.now()) {
  const minutes = Math.floor((now - Date.parse(isoDate)) / 60000);
  if (minutes < 1) return "teraz";
  if (minutes < 60) return `${minutes} min`;
  if (minutes < 24 * 60) return `${Math.floor(minutes / 60)} godz.`;
  return dateFormat.format(new Date(isoDate));
}

export function renderHistory(list, emptyNote, scans, { currentId, flags, onSelect }) {
  emptyNote.hidden = scans.length > 0;
  list.replaceChildren(...scans.map((scan) => el("li", {}, [
    el("button", {
      className: "history-item",
      attrs: { type: "button", "aria-current": scan.id === currentId ? "true" : false, "data-scan-id": scan.id },
      on: { click: () => onSelect(scan.id) },
    }, [
      el("span", { className: "history-target" }, [
        scan.target,
        " ",
        el("span", { className: "dim", text: flags[scan.scan_type] ?? scan.scan_type }),
      ]),
      el("span", { className: `status-dot ${STATUS_DOT[scan.status]}`, text: STATUS_LABELS[scan.status] }),
      el("span", { className: "history-time", text: relativeTime(scan.created_at) }),
    ]),
  ])));
}
