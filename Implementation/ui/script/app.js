// -----------------------------
// API endpoints + constants
// -----------------------------
const API_ASK         = location.origin + '/ask';
const API_ETL         = location.origin + '/etl/run';
const API_FILTER_AGTS = location.origin + '/filters/agents';
const API_STATS_SEV   = location.origin + '/stats/severity';
const ETL_TOKEN       = '123!';

// -----------------------------
// DOM elements
// -----------------------------
const qEl              = document.getElementById('q');
const askBtn           = document.getElementById('askBtn');
const insightsBtn      = document.getElementById('insightsBtn');
const resetBtn         = document.getElementById('resetBtn');
const fetchBtn         = document.getElementById('fetchBtn');
const btnChartByHour   = document.getElementById('btnChartByHour');
const btnChartTopIPs   = document.getElementById('btnChartTopIPs');
const btnUseServerChart= document.getElementById('btnUseServerChart');
const btnPieFailedVsSuccess = document.getElementById('btnPieFailedVsSuccess');
const btnSeverity24h   = document.getElementById('btnSeverity24h');
const loadingEl        = document.getElementById('loading');

const sqlEl    = document.getElementById('sql');
const rowsEl   = document.getElementById('rows');
const errEl    = document.getElementById('err');
const metaEl   = document.getElementById('meta');
const chartEl  = document.getElementById('chart');
const fetchMsg = document.getElementById('fetchMsg');

// Filters
const agentFilterEl    = document.getElementById('agentFilter');
const severityFilterEl = document.getElementById('severityFilter');

// ETL status labels
const lastUpdatedEl = document.getElementById('lastUpdated');
const nextUpdateEl  = document.getElementById('nextUpdate');

let chart;
let lastResponse = null; // keep last /ask response for server-provided charts

// -----------------------------
// Utility helpers
// -----------------------------
function setError(msg){
  errEl.style.display = msg ? 'block' : 'none';
  errEl.textContent = msg || '';
}

function setMeta(t){
  metaEl.style.display = t ? 'flex' : 'none';
  metaEl.innerHTML = t || '';
}

function fmt(s){
  return String(s).replace(/[&<>"']/g, m => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", "\"":"&quot;", "'":"&#39;"
  }[m]));
}

function toLocal(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d)) return '—';
  return d.toLocaleString(); // browser local timezone
}

// -----------------------------
// API wrappers
// -----------------------------
async function apiAsk(question){
  setError('');
  setMeta('');
  sqlEl.textContent = '—';
  rowsEl.innerHTML = '—';

  const r = await fetch(API_ASK, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({question})
  });
  if(!r.ok){
    const t = await r.text();
    throw new Error(`HTTP ${r.status}: ${t}`);
  }
  return r.json();
}

async function refreshEtlStatus() {
  try {
    const r = await fetch('/etl/status');
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    lastUpdatedEl.textContent = toLocal(j.last_run);
    nextUpdateEl.textContent  = toLocal(j.next_run);
  } catch (e) {
    lastUpdatedEl.textContent = 'unknown';
    nextUpdateEl.textContent  = 'unknown';
    console.error('ETL status error:', e);
  }
}

async function fetchLatest() {
  fetchMsg.textContent = 'Running ETL…';
  try {
    const r = await fetch(API_ETL, {
      method: 'POST',
      headers: { 'X-ETL-Token': ETL_TOKEN }
    });
    const j = await r.json();
    if (!r.ok || !j.ok) {
      fetchMsg.textContent = 'ETL failed';
      console.error(j);
      alert('ETL failed:\n' + (j.stderr_tail || j.error || JSON.stringify(j)));
      return;
    }
    fetchMsg.textContent = 'ETL done ✓';
    await refreshEtlStatus();       // update Last updated / Next update
  } catch (e) {
    fetchMsg.textContent = 'ETL error';
    alert('ETL error: ' + e.message);
  }
}

// Load distinct agents from backend for dropdown
async function loadAgents() {
  try {
    const r = await fetch(API_FILTER_AGTS);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    if (!j.ok) return;

    agentFilterEl.innerHTML = '<option value="">All agents</option>';
    (j.agents || []).forEach(a => {
      const opt = document.createElement('option');
      opt.value = a;
      opt.textContent = a;
      agentFilterEl.appendChild(opt);
    });
  } catch (e) {
    console.error('Failed to load agents:', e);
  }
}

// -----------------------------
// Rendering helpers
// -----------------------------
function renderRows(rows){
  if(!rows || rows.length === 0){
    rowsEl.innerHTML = '<span class="muted">No rows.</span>';
    return;
  }
  const cols = Object.keys(rows[0]);
  let thead = '<thead><tr>' + cols.map(c=>`<th>${fmt(c)}</th>`).join('') + '</tr></thead>';
  let tbody = '<tbody>' +
    rows.map(r=>'<tr>'+cols.map(c=>`<td>${fmt(r[c] ?? '')}</td>`).join('')+'</tr>').join('') +
    '</tbody>';
  rowsEl.innerHTML = `<table>${thead}${tbody}</table>`;
}

function drawChartGeneric(type, labels, data, title){
  if(chart) chart.destroy();
  chart = new Chart(chartEl.getContext('2d'), {
    type,
    data: {
      labels,
      datasets: [{
        label: title || '',
        data
      }]
    },
    options: {
      responsive: true,
      plugins:{
        legend:{display: type !== 'bar'},
        title:{display:true, text:title || 'Chart', color:'#e6edf7'}
      },
      scales: type === 'bar' ? {
        x:{ ticks:{ color:'#cbd5e1' } },
        y:{ ticks:{ color:'#cbd5e1' }, beginAtZero:true }
      } : {}
    }
  });
}

function maybeDrawServerChart(resp){
  if(!resp || !resp.chart) return false;
  const c = resp.chart;
  if(!c.labels || !c.values) return false;
  drawChartGeneric(c.type || 'pie', c.labels, c.values, c.title || 'Chart');
  return true;
}

// -----------------------------
// Quick charts powered by NL → SQL
// -----------------------------
async function chartByHour(){
  const question = "Return raw rows (no grouping). Show sshd authentication failed events with ts, agent_name, src_ip, user_name, rule_desc, limit 500.";
  const data = await apiAsk(question);
  const rows = data.rows || [];
  const buckets = new Map();
  for(const r of rows){
    const d = new Date(r.ts);
    if(isNaN(d)) continue;
    const k = d.getUTCFullYear()+"-"+(d.getUTCMonth()+1).toString().padStart(2,'0')+"-"+d.getUTCDate().toString().padStart(2,'0')+" "+d.getUTCHours().toString().padStart(2,'0')+":00Z";
    buckets.set(k, (buckets.get(k)||0)+1);
  }
  const labels = Array.from(buckets.keys()).sort();
  const values = labels.map(k=>buckets.get(k));
  drawChartGeneric('bar', labels, values, 'Failed sshd by hour (last 24h)');
}

async function chartTopIPs(){
  const question = "Count sshd authentication failed events grouped by src_ip; return src_ip, count ordered by count desc limit 10.";
  const data = await apiAsk(question);
  const rows = data.rows || [];
  const labels = rows.map(r=> r.src_ip ?? '(null)');
  const values = rows.map(r=> Number(r.count || 0));
  drawChartGeneric('bar', labels, values, 'Top src_ip for failed sshd (last 24h)');
}

// Severity distribution chart using dedicated API
async function chartSeverity(hours = 24) {
  try {
    const r = await fetch(`${API_STATS_SEV}?hours=${hours}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j = await r.json();
    if (!j.ok) throw new Error('Backend returned ok=false');

    const labels = j.labels || [];
    const values = j.values || [];
    if (!labels.length) {
      setError('No data for severity chart.');
      return;
    }
    drawChartGeneric('pie', labels, values, `Severity distribution (last ${hours}h)`);
  } catch (e) {
    console.error(e);
    setError('Failed to load severity stats: ' + e.message);
  }
}

// -----------------------------
// Building the question from filters
// -----------------------------
function buildQuestionWithFilters(baseQuestion) {
  let q = (baseQuestion || '').trim();

  // Get filter values
  const agent    = agentFilterEl.value;
  const severity = severityFilterEl.value; // "low"/"medium"/"high"/"critical" or ""

  const parts = [];

  // If user typed nothing, start with a generic base
  if (!q) {
    parts.push("Show logs");
  } else {
    parts.push(q);
  }

  // Agent filter: "for agent Kali4495"
  if (agent) {
    parts.push(`for agent ${agent}`);
  }

  // Severity filter: map value to readable text
  if (severity) {
    parts.push(`with ${severity} severity`);
  }

  return parts.join(' ');
}

// -----------------------------
// Event handlers
// -----------------------------
askBtn.onclick = async () => {
  try {
    const question = buildQuestionWithFilters(qEl.value);
    if (!question.trim()) return;

    loadingEl.style.display = 'flex';
    askBtn.disabled = true;
    setError('');
    setMeta('');
    sqlEl.textContent = '—';
    rowsEl.innerHTML = '—';

    const data = await apiAsk(question);
    lastResponse = data;
    sqlEl.textContent = data.sql || '—';
    renderRows(data.rows || []);
    setMeta(
      `<div><b>Rows:</b> ${
        data.rowcount ?? (data.rows ? data.rows.length : 0)
      }</div>
       <div><b>Latency:</b> ${data.latency_ms ?? '—'} ms</div>`
    );

    // Auto-draw server chart if present (e.g., failed vs successful SSH)
    maybeDrawServerChart(data);
  } catch (e) {
    setError(e.message);
  } finally {
    loadingEl.style.display = 'none';
    askBtn.disabled = false;
  }
};

insightsBtn.onclick        = chartTopIPs;
btnChartByHour.onclick     = chartByHour;
btnChartTopIPs.onclick     = chartTopIPs;
btnSeverity24h.onclick     = () => chartSeverity(24);

btnUseServerChart.onclick = () => {
  if (!maybeDrawServerChart(lastResponse)) {
    alert('No server-provided chart available for the last response.');
  }
};

btnPieFailedVsSuccess.onclick = () => {
  // Force a prompt that triggers the server-side "failed vs successful" chart
  qEl.value = "Compare failed vs successful SSH for agent Kali4495 with a percentage chart (last 24 hours)";
  askBtn.click();
};

fetchBtn.onclick = fetchLatest;

resetBtn.onclick = () => {
  qEl.value = '';
  sqlEl.textContent = '—';
  rowsEl.innerHTML = '—';
  setError('');
  setMeta('');
  fetchMsg.textContent = '';

  // Reset filters
  agentFilterEl.value    = '';
  severityFilterEl.value = '';

  if (chart) chart.destroy();
};

// Chips: each chip replaces the question and triggers Ask
Array.from(document.getElementsByClassName('chip'))
  .forEach(ch => ch.addEventListener('click', () => {
    qEl.value = ch.textContent;
    askBtn.click();
  }));

// Optional: when agent filter changes and the textbox is empty,
// pre-fill a reasonable default query.
agentFilterEl.addEventListener('change', () => {
  if (!qEl.value.trim() && agentFilterEl.value) {
    const a = agentFilterEl.value;
    qEl.value = `Show high severity sshd authentication failed events for agent ${a} in the last 24 hours`;
  }
});

// -----------------------------
// Init on page load
// -----------------------------
refreshEtlStatus();
loadAgents();
