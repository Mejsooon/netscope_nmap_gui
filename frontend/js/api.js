export class ApiError extends Error {
  constructor(status, detail) {
    super(detail || `HTTP ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

async function request(method, path, body) {
  const options = { method, cache: "no-store", credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(path, options);
  } catch {
    throw new ApiError(0, "network");
  }

  if (response.status === 204) return null;

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) throw new ApiError(response.status, extractDetail(data));
  return data;
}

function extractDetail(data) {
  if (!data) return "";
  if (typeof data.detail === "string") return data.detail;
  if (Array.isArray(data.detail)) return data.detail.map((item) => item.msg).join("; ");
  return "";
}

export const api = {
  async health() {
    try {
      return await request("GET", "/health");
    } catch (error) {
      if (error instanceof ApiError && error.status === 503) return { status: "degraded", nmap_installed: false };
      throw error;
    }
  },
  options: () => request("GET", "/options"),
  listScans: () => request("GET", "/scans"),
  getScan: (id) => request("GET", `/scans/${encodeURIComponent(id)}`),
  createScan: (payload) => request("POST", "/scans", payload),
  cancelScan: (id) => request("DELETE", `/scans/${encodeURIComponent(id)}`),
};
