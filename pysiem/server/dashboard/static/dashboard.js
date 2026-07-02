/**
 * PySIEM dashboard — auto-refreshing alert table.
 *
 * Strategy:
 *   1. On load, fetch all alerts and stats and render them.
 *   2. Every 5 seconds, ask the server how many NEW alerts have arrived
 *      since the last full refresh (cheap count query).
 *   3. Only if the count is > 0 do we re-fetch the full alert list.
 *
 * This "cheap poll then fetch" pattern avoids re-downloading the entire
 * alert list on every tick when nothing has changed.
 */

let activeSeverity = "";           // currently active filter ("" means All)
let lastCheck      = new Date(0).toISOString();  // timestamp of last full refresh

// ── API helpers ───────────────────────────────────────────────────────────

async function fetchAlerts() {
  const params = new URLSearchParams({ limit: 200 });
  if (activeSeverity) params.set("severity", activeSeverity);
  const res = await fetch(`/api/alerts?${params}`);
  return res.json();
}

async function fetchStats() {
  const res = await fetch("/api/stats");
  return res.json();
}

async function fetchCountSince(since) {
  const res = await fetch(`/api/alerts/count?since=${encodeURIComponent(since)}`);
  return res.json();
}

// ── Rendering ─────────────────────────────────────────────────────────────

function renderStats(stats) {
  for (const sev of ["critical", "high", "medium", "low"]) {
    document.getElementById(`cnt-${sev}`).textContent = stats[sev] ?? 0;
  }
}

function renderTable(alerts) {
  const tbody = document.getElementById("tbody");
  const empty = document.getElementById("empty-state");

  if (alerts.length === 0) {
    tbody.innerHTML     = "";
    empty.style.display = "block";
    return;
  }

  empty.style.display = "none";
  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td class="mono">${escHtml(fmtTimestamp(a.timestamp))}</td>
      <td><span class="badge ${escHtml(a.severity)}">${escHtml(a.severity)}</span></td>
      <td>${escHtml(a.rule_name)}</td>
      <td class="mono">${escHtml(a.hostname ?? "—")}</td>
      <td class="mono">${a.event_id ?? "—"}</td>
      <td>${escHtml(truncate(a.message ?? "", 120))}</td>
    </tr>
  `).join("");
}

function fmtTimestamp(iso) {
  // "2026-06-14T18:42:01.123456+00:00" → "2026-06-14 18:42:01"
  return iso.replace("T", " ").slice(0, 19);
}

function truncate(str, max) {
  return str.length > max ? str.slice(0, max) + "…" : str;
}

/**
 * Escape HTML special characters before inserting untrusted content into the DOM.
 * Alert messages come from raw log data — they could contain '<', '>', '&', etc.
 * Without escaping, a crafted log message could inject HTML or execute scripts.
 */
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setLastUpdated() {
  document.getElementById("last-updated").textContent =
    `Updated ${new Date().toLocaleTimeString()}`;
}

// ── Refresh logic ─────────────────────────────────────────────────────────

async function fullRefresh() {
  const [alerts, stats] = await Promise.all([fetchAlerts(), fetchStats()]);
  renderTable(alerts);
  renderStats(stats);
  lastCheck = new Date().toISOString();
  setLastUpdated();
}

async function pollForChanges() {
  try {
    const { count } = await fetchCountSince(lastCheck);
    if (count > 0) {
      await fullRefresh();
    } else {
      setLastUpdated();
    }
  } catch {
    document.getElementById("last-updated").textContent =
      "Connection lost — retrying…";
  }
}

// ── Filter buttons ─────────────────────────────────────────────────────────

document.querySelectorAll(".filter").forEach(btn => {
  btn.addEventListener("click", async () => {
    document.querySelectorAll(".filter").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeSeverity = btn.dataset.sev;
    await fullRefresh();
  });
});

// ── Boot ──────────────────────────────────────────────────────────────────

fullRefresh();
setInterval(pollForChanges, 5000);
