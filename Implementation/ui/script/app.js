const API_ASK = location.origin + "/ask";
const API_ETL = location.origin + "/etl/run";
const ETL_TOKEN = "123!";

const qEl = document.getElementById("q");
const askBtn = document.getElementById("askBtn");
const insightsBtn = document.getElementById("insightsBtn");
const resetBtn = document.getElementById("resetBtn");
const fetchBtn = document.getElementById("fetchBtn");
const btnChartByHour = document.getElementById("btnChartByHour");
const btnChartTopIPs = document.getElementById("btnChartTopIPs");
const btnUseServerChart = document.getElementById("btnUseServerChart");
const btnPieFailedVsSuccess = document.getElementById("btnPieFailedVsSuccess");

const sqlEl = document.getElementById("sql");
const rowsEl = document.getElementById("rows");
const errEl = document.getElementById("err");
const metaEl = document.getElementById("meta");
const chartEl = document.getElementById("chart");
const fetchMsg = document.getElementById("fetchMsg");

let chart;
let lastResponse = null; // keep last /ask response for server-provided charts

function setError(msg) {
  errEl.style.display = msg ? "block" : "none";
  errEl.textContent = msg || "";
}
function setMeta(t) {
  metaEl.style.display = t ? "flex" : "none";
  metaEl.innerHTML = t || "";
}
function fmt(s) {
  return String(s).replace(
    /[&<>"']/g,
    (m) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[
        m
      ])
  );
}

async function apiAsk(question) {
  setError("");
  setMeta("");
  sqlEl.textContent = "—";
  rowsEl.innerHTML = "—";
  const r = await fetch(API_ASK, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question }),
  });
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`HTTP ${r.status}: ${t}`);
  }
  return r.json();
}

function renderRows(rows) {
  if (!rows || rows.length === 0) {
    rowsEl.innerHTML = '<span class="muted">No rows.</span>';
    return;
  }
  const cols = Object.keys(rows[0]);
  let thead =
    "<thead><tr>" +
    cols.map((c) => `<th>${fmt(c)}</th>`).join("") +
    "</tr></thead>";
  let tbody =
    "<tbody>" +
    rows
      .map(
        (r) =>
          "<tr>" +
          cols.map((c) => `<td>${fmt(r[c] ?? "")}</td>`).join("") +
          "</tr>"
      )
      .join("") +
    "</tbody>";
  rowsEl.innerHTML = `<table>${thead}${tbody}</table>`;
}

function drawChartGeneric(type, labels, data, title) {
  if (chart) chart.destroy();
  chart = new Chart(chartEl.getContext("2d"), {
    type,
    data: {
      labels,
      datasets: [
        {
          label: title || "",
          data,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: type !== "bar" }, // bars: hide legend
        title: { display: true, text: title || "Chart", color: "#e6edf7" },
      },
      scales:
        type === "bar"
          ? {
              x: { ticks: { color: "#cbd5e1" } },
              y: { ticks: { color: "#cbd5e1" }, beginAtZero: true },
            }
          : {},
    },
  });
}

function maybeDrawServerChart(resp) {
  if (!resp || !resp.chart) return false;
  const c = resp.chart;
  if (!c.labels || !c.values) return false;
  drawChartGeneric(c.type || "pie", c.labels, c.values, c.title || "Chart");
  return true;
}

/* Quick charts powered by raw queries / client transforms */
async function chartByHour() {
  const question =
    "Return raw rows (no grouping). Show sshd authentication failed events with ts, agent_name, src_ip, user_name, rule_desc, limit 500.";
  const data = await apiAsk(question);
  const rows = data.rows || [];
  const buckets = new Map();
  for (const r of rows) {
    const d = new Date(r.ts);
    if (isNaN(d)) continue;
    const k =
      d.getUTCFullYear() +
      "-" +
      (d.getUTCMonth() + 1).toString().padStart(2, "0") +
      "-" +
      d.getUTCDate().toString().padStart(2, "0") +
      " " +
      d.getUTCHours().toString().padStart(2, "0") +
      ":00Z";
    buckets.set(k, (buckets.get(k) || 0) + 1);
  }
  const labels = Array.from(buckets.keys()).sort();
  const values = labels.map((k) => buckets.get(k));
  drawChartGeneric("bar", labels, values, "Failed sshd by hour (last 24h)");
}

async function chartTopIPs() {
  const question =
    "Count sshd authentication failed events grouped by src_ip; return src_ip, count ordered by count desc limit 10.";
  const data = await apiAsk(question);
  const rows = data.rows || [];
  const labels = rows.map((r) => r.src_ip ?? "(null)");
  const values = rows.map((r) => Number(r.count || 0));
  drawChartGeneric(
    "bar",
    labels,
    values,
    "Top src_ip for failed sshd (last 24h)"
  );
}

/* ETL trigger */
async function fetchLatest() {
  fetchMsg.textContent = "Running ETL…";
  try {
    const r = await fetch(API_ETL, {
      method: "POST",
      headers: { "X-ETL-Token": ETL_TOKEN },
    });
    const j = await r.json();
    if (!r.ok || !j.ok) {
      fetchMsg.textContent = "ETL failed";
      console.error(j);
      alert("ETL failed:\n" + (j.stderr_tail || j.error || JSON.stringify(j)));
      return;
    }
    fetchMsg.textContent = "ETL done ✓";
  } catch (e) {
    fetchMsg.textContent = "ETL error";
    alert("ETL error: " + e.message);
  }
}

/* Events */
askBtn.onclick = async () => {
  try {
    const question = qEl.value.trim();
    if (!question) return;
    const data = await apiAsk(question);
    lastResponse = data;
    sqlEl.textContent = data.sql || "—";
    renderRows(data.rows || []);
    setMeta(
      `<div><b>Rows:</b> ${
        data.rowcount ?? (data.rows ? data.rows.length : 0)
      }</div><div><b>Latency:</b> ${data.latency_ms ?? "—"} ms</div>`
    );

    // Auto-draw server chart if present
    maybeDrawServerChart(data);
  } catch (e) {
    setError(e.message);
  }
};

insightsBtn.onclick = chartTopIPs;
btnChartByHour.onclick = chartByHour;
btnChartTopIPs.onclick = chartTopIPs;
btnUseServerChart.onclick = () => {
  if (!maybeDrawServerChart(lastResponse)) {
    alert("No server-provided chart available for the last response.");
  }
};
btnPieFailedVsSuccess.onclick = () => {
  // just ask explicitly to trigger server chart
  qEl.value =
    "Compare failed vs successful SSH for agent Kali4495 with a percentage chart (last 24 hours)";
  askBtn.click();
};

fetchBtn.onclick = fetchLatest;

resetBtn.onclick = () => {
  qEl.value = "";
  sqlEl.textContent = "—";
  rowsEl.innerHTML = "—";
  setError("");
  setMeta("");
  fetchMsg.textContent = "";
  if (chart) chart.destroy();
};

Array.from(document.getElementsByClassName("chip")).forEach((ch) =>
  ch.addEventListener("click", () => {
    qEl.value = ch.textContent;
    askBtn.click();
  })
);
