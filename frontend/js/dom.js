const SVG_NS = "http://www.w3.org/2000/svg";

export function el(tag, options = {}, children = []) {
  const node = document.createElement(tag);
  const { className, text, attrs = {}, on = {} } = options;

  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === false || value === null || value === undefined) continue;
    node.setAttribute(name, value === true ? "" : String(value));
  }
  for (const [event, handler] of Object.entries(on)) {
    node.addEventListener(event, handler);
  }
  for (const child of children) {
    if (child !== null && child !== undefined && child !== false) node.append(child);
  }
  return node;
}

const ICONS = {
  lock: { size: 12, paths: [
    { tag: "rect", attrs: { x: "2", y: "5.5", width: "8", height: "5.5", rx: "1.2" } },
    { tag: "path", attrs: { d: "M4 5.5V4a2 2 0 0 1 4 0v1.5" } },
  ] },
  close: { size: 12, paths: [
    { tag: "path", attrs: { d: "M2.5 2.5l7 7M9.5 2.5l-7 7", "stroke-linecap": "round" } },
  ] },
};

export function icon(name) {
  const definition = ICONS[name];
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", definition.size);
  svg.setAttribute("height", definition.size);
  svg.setAttribute("viewBox", `0 0 ${definition.size} ${definition.size}`);
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.4");
  svg.setAttribute("aria-hidden", "true");
  for (const part of definition.paths) {
    const child = document.createElementNS(SVG_NS, part.tag);
    for (const [name, value] of Object.entries(part.attrs)) child.setAttribute(name, value);
    svg.append(child);
  }
  return svg;
}
