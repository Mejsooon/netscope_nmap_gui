import { ApiError, api } from "./api.js";
import { createScanForm } from "./form.js";
import { renderHistory } from "./history.js";
import { translateRequestError } from "./messages.js";
import { formatDuration, isFinished, renderJob } from "./results.js";

const POLL_INTERVAL_MS = 2000;

const $ = (id) => document.getElementById(id);

const current = { id: null, pollTimer: null, ticker: null };
let scanForm = null;
let scanFlags = {};

async function loadStatus() {
  try {
    const health = await api.health();
    const status = $("nmap-status");
    if (health.nmap_installed) {
      status.textContent = "nmap dostępny";
      status.className = "status-dot status-dot--ok";
    } else {
      status.textContent = "brak nmapa";
      status.className = "status-dot status-dot--danger";
      $("nmap-missing").hidden = false;
    }
  } catch {
    $("nmap-status").textContent = "brak połączenia z serwerem";
    $("nmap-status").className = "status-dot status-dot--danger";
  }
}

function stopTimers() {
  clearTimeout(current.pollTimer);
  clearInterval(current.ticker);
  current.pollTimer = null;
  current.ticker = null;
}

function startTicker(job) {
  clearInterval(current.ticker);
  const startedAt = Date.parse(job.started_at ?? job.created_at);
  const tick = () => {
    const elapsed = $("elapsed");
    if (elapsed) elapsed.textContent = formatDuration(Date.now() - startedAt);
  };
  tick();
  current.ticker = setInterval(tick, 1000);
}

async function refreshHistory() {
  try {
    const scans = await api.listScans();
    renderHistory($("history-list"), $("history-empty"), scans, {
      currentId: current.id,
      flags: scanFlags,
      onSelect: showScan,
    });
  } catch {
    // History is secondary: a failed refresh keeps the previous list.
  }
}

async function showScan(id) {
  stopTimers();
  current.id = id;
  await refreshCurrent();
}

async function refreshCurrent() {
  const id = current.id;
  let job;
  try {
    job = await api.getScan(id);
  } catch {
    if (id === current.id) showFormError("Nie udało się pobrać statusu skanu.");
    return;
  }
  if (id !== current.id) return;

  renderJob($("result"), job, handlers);
  refreshHistory();
  if (isFinished(job)) {
    stopTimers();
  } else {
    if (job.status === "running") startTicker(job);
    current.pollTimer = setTimeout(refreshCurrent, POLL_INTERVAL_MS);
  }
}

function showFormError(message) {
  $("form-error").textContent = message;
  $("form-error").hidden = false;
}

const FIELD_ERRORS = { target: "target-error", ports: "ports-error" };

function showFieldError(field, message) {
  const errorElement = $(FIELD_ERRORS[field]);
  errorElement.textContent = message;
  errorElement.hidden = false;
  $(field).setAttribute("aria-invalid", "true");
  $(field).focus();
}

function clearFieldError(field) {
  $(FIELD_ERRORS[field]).hidden = true;
  $(FIELD_ERRORS[field]).textContent = "";
  $(field).removeAttribute("aria-invalid");
}

function clearErrors() {
  $("form-error").hidden = true;
  $("form-error").textContent = "";
  for (const field of Object.keys(FIELD_ERRORS)) clearFieldError(field);
}

async function submitScan(event) {
  event.preventDefault();
  clearErrors();
  const run = $("run");
  run.disabled = true;
  $("run-label").textContent = "Uruchamianie…";
  try {
    const created = await api.createScan(scanForm.payload());
    await showScan(created.id);
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    const { field, message } = translateRequestError(error);
    if (field in FIELD_ERRORS) showFieldError(field, message);
    else showFormError(message);
  } finally {
    run.disabled = false;
    $("run-label").textContent = "Uruchom skan";
  }
}

const handlers = {
  async onCancel(id) {
    const button = document.querySelector("#result .button--danger");
    if (button) {
      button.disabled = true;
      button.textContent = "Anulowanie…";
    }
    try {
      await api.cancelScan(id);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 409) {
        showFormError("Nie udało się anulować skanu.");
      }
    }
    if (id === current.id) {
      stopTimers();
      await refreshCurrent();
    }
  },
  onReuse(request) {
    scanForm.fill(request);
    $("target").focus();
  },
};

async function init() {
  loadStatus();
  const options = await api.options();
  $("root-status").textContent = options.is_root ? "uprawnienia root" : "bez uprawnień root";
  scanFlags = Object.fromEntries(Object.entries(options.scan_types).map(([name, option]) => [name, option.flag]));
  scanForm = createScanForm($("scan-form"), options);
  refreshHistory();
  $("scan-form").addEventListener("submit", submitScan);
  for (const field of Object.keys(FIELD_ERRORS)) {
    $(field).addEventListener("input", () => clearFieldError(field));
  }
}

init();
