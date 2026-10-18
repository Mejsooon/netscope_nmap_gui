import { el, icon } from "./dom.js";

const SCAN_TYPE_TEXT = {
  connect: { name: "Connect", desc: "Pełne połączenie TCP" },
  syn: { name: "SYN", desc: "Półotwarte, szybsze" },
  udp: { name: "UDP", desc: "Usługi UDP, wolny" },
  ping: { name: "Ping", desc: "Tylko wykrycie hostów" },
};

const DETECTION_TEXT = {
  service_detection: { name: "Usługi i wersje", desc: "Nazwa i wersja programu na porcie" },
  os_detection: { name: "System operacyjny", desc: "Zgadywanie systemu po odpowiedziach" },
};

const TIMING_TEXT = [
  { name: "Paranoid", hint: "jedna próba co 5 minut" },
  { name: "Sneaky", hint: "jedna próba co 15 sekund" },
  { name: "Polite", hint: "wolniej, mniej obciąża sieć" },
  { name: "Normal", hint: "domyślna szybkość nmapa" },
  { name: "Aggressive", hint: "szybciej, zakłada stabilną sieć" },
  { name: "Insane", hint: "bardzo szybko, może pominąć porty" },
];

const PORT_PRESETS = [
  { label: "Domyślne", value: "" },
  { label: "Web 80,443", value: "80,443" },
  { label: "SSH 22", value: "22" },
  { label: "1–1024", value: "1-1024" },
];

const ROOT_ONLY_TEXT = "Wymaga root";

export function createScanForm(root, options) {
  const state = {
    scanType: "connect",
    service_detection: false,
    os_detection: false,
    timing: 3,
  };
  const field = (id) => root.querySelector(`#${id}`);
  const target = field("target");
  const ports = field("ports");

  const typeButtons = new Map();
  for (const [id, option] of Object.entries(options.scan_types)) {
    const text = SCAN_TYPE_TEXT[id] ?? { name: id, desc: option.description };
    const desc = el("span", { className: "option-desc" }, [
      option.available ? null : icon("lock"),
      option.available ? text.desc : ROOT_ONLY_TEXT,
    ]);
    const button = el("button", {
      className: "option",
      attrs: { type: "button", "data-scan-type": id, disabled: !option.available },
      on: { click: () => setScanType(id) },
    }, [
      el("span", { className: "option-head" }, [
        el("span", { className: "option-name", text: text.name }),
        el("span", { className: "option-flag", text: option.flag }),
      ]),
      desc,
    ]);
    typeButtons.set(id, button);
  }
  field("scan-types").replaceChildren(...typeButtons.values());

  const switches = new Map();
  for (const key of ["service_detection", "os_detection"]) {
    const option = options[key];
    const text = DETECTION_TEXT[key];
    const button = el("button", {
      className: "switch",
      attrs: { type: "button", role: "switch", "data-option": key },
      on: { click: () => toggle(key) },
    }, [
      el("span", { className: "switch-text" }, [
        el("span", { className: "switch-name" }, [text.name, " ", el("span", { className: "switch-flag", text: option.flag })]),
        el("span", { className: "switch-desc", text: option.available ? text.desc : ROOT_ONLY_TEXT }),
      ]),
      el("span", { className: "switch-track", attrs: { "aria-hidden": "true" } }),
    ]);
    switches.set(key, button);
  }
  field("detection").replaceChildren(...switches.values());

  const presetButtons = PORT_PRESETS.map((preset) => el("button", {
    className: "chip",
    text: preset.label,
    attrs: { type: "button" },
    on: { click: () => { ports.value = preset.value; update(); } },
  }));
  field("port-presets").replaceChildren(...presetButtons);

  const timingButtons = Object.keys(options.timing).map(Number).sort((a, b) => a - b).map((level) => el("button", {
    className: "segment",
    text: `T${level}`,
    attrs: { type: "button", "aria-label": `T${level} ${TIMING_TEXT[level]?.name ?? ""}`.trim(), "data-timing": level },
    on: { click: () => { state.timing = level; update(); } },
  }));
  field("timing").replaceChildren(...timingButtons);

  target.addEventListener("input", update);
  ports.addEventListener("input", update);

  function setScanType(id) {
    state.scanType = id;
    if (id === "ping") {
      state.service_detection = false;
      state.os_detection = false;
      ports.value = "";
    }
    update();
  }

  function toggle(key) {
    state[key] = !state[key];
    update();
  }

  function isPing() {
    return state.scanType === "ping";
  }

  function update() {
    for (const [id, button] of typeButtons) {
      button.setAttribute("aria-pressed", String(id === state.scanType));
    }
    for (const [key, button] of switches) {
      const locked = !options[key].available || isPing();
      button.disabled = locked;
      button.setAttribute("aria-checked", String(state[key] && !locked));
    }
    ports.disabled = isPing();
    for (const button of presetButtons) button.disabled = isPing();
    for (const button of timingButtons) {
      button.setAttribute("aria-pressed", String(Number(button.dataset.timing) === state.timing));
    }
    const timing = TIMING_TEXT[state.timing];
    field("timing-hint").textContent = timing ? `T${state.timing} · ${timing.hint}` : "";
    field("command").textContent = commandPreview();
  }

  function payload() {
    const data = {
      target: target.value.trim(),
      scan_type: state.scanType,
      service_detection: state.service_detection && !isPing(),
      os_detection: state.os_detection && !isPing(),
      timing: state.timing,
    };
    const portsValue = ports.value.trim();
    if (portsValue && !isPing()) data.ports = portsValue;
    return data;
  }

  function commandPreview() {
    const data = payload();
    const parts = ["nmap", options.scan_types[data.scan_type].flag];
    if (data.service_detection) parts.push(options.service_detection.flag);
    if (data.os_detection) parts.push(options.os_detection.flag);
    parts.push(options.timing[data.timing].flag);
    if (data.ports) parts.push("-p", data.ports);
    parts.push("-oX", "-", "--", data.target || "…");
    return parts.join(" ");
  }

  function fill(request) {
    target.value = request.target;
    state.scanType = request.scan_type in options.scan_types ? request.scan_type : "connect";
    state.service_detection = Boolean(request.service_detection);
    state.os_detection = Boolean(request.os_detection);
    state.timing = request.timing;
    ports.value = request.ports ?? "";
    update();
  }

  update();
  return { payload, fill };
}
