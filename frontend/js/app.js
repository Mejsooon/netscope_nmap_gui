import { api } from "./api.js";

const $ = (id) => document.getElementById(id);

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

loadStatus();
