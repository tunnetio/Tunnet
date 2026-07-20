//! Embedded inspector UI.

pub const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Tunnet Inspector</title>
<style>
  :root {
    --bg: #0f1419;
    --panel: #1a222c;
    --border: #2a3542;
    --text: #e7ecf1;
    --muted: #8b9aab;
    --accent: #3d9a78;
    --method-get: #3d9a78;
    --method-post: #4a8fd4;
    --method-put: #c9a227;
    --method-delete: #d45a5a;
    --status-ok: #3d9a78;
    --status-err: #d45a5a;
    --mono: "JetBrains Mono", "SF Mono", ui-monospace, monospace;
    --sans: "Segoe UI", system-ui, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text);
    height: 100vh;
    display: flex;
    flex-direction: column;
  }
  header {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 0.75rem 1.25rem;
    border-bottom: 1px solid var(--border);
    background: var(--panel);
  }
  header h1 {
    margin: 0;
    font-size: 1rem;
    font-weight: 600;
    letter-spacing: 0.02em;
  }
  header .spacer { flex: 1; }
  button {
    font: inherit;
    cursor: pointer;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text);
    padding: 0.35rem 0.75rem;
    border-radius: 4px;
  }
  button:hover { border-color: var(--muted); }
  button.primary {
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
  }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  main {
    flex: 1;
    display: grid;
    grid-template-columns: minmax(280px, 360px) 1fr;
    min-height: 0;
  }
  #list {
    overflow-y: auto;
    border-right: 1px solid var(--border);
  }
  .row {
    padding: 0.65rem 1rem;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    display: grid;
    grid-template-columns: 4.5rem 2.5rem 1fr;
    gap: 0.5rem;
    align-items: center;
    font-size: 0.85rem;
  }
  .row:hover { background: #162028; }
  .row.active { background: #1e2a36; }
  .method {
    font-family: var(--mono);
    font-weight: 600;
    font-size: 0.75rem;
  }
  .method.GET { color: var(--method-get); }
  .method.POST { color: var(--method-post); }
  .method.PUT, .method.PATCH { color: var(--method-put); }
  .method.DELETE { color: var(--method-delete); }
  .status { font-family: var(--mono); font-size: 0.75rem; color: var(--muted); }
  .status.ok { color: var(--status-ok); }
  .status.err { color: var(--status-err); }
  .path {
    font-family: var(--mono);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text);
  }
  .meta { font-size: 0.7rem; color: var(--muted); grid-column: 1 / -1; }
  #detail {
    overflow-y: auto;
    padding: 1.25rem;
  }
  #detail.empty {
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--muted);
  }
  .detail-head {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 1.25rem;
    flex-wrap: wrap;
  }
  .detail-head h2 {
    margin: 0;
    font-family: var(--mono);
    font-size: 1rem;
    font-weight: 500;
  }
  section {
    margin-bottom: 1.5rem;
  }
  section h3 {
    margin: 0 0 0.5rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted);
  }
  pre {
    margin: 0;
    padding: 0.75rem 1rem;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 0.8rem;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
  }
  .truncated { color: var(--method-put); font-size: 0.75rem; margin-top: 0.35rem; }
  .empty-list {
    padding: 2rem 1rem;
    text-align: center;
    color: var(--muted);
    font-size: 0.9rem;
  }
</style>
</head>
<body>
<header>
  <h1>Tunnet Inspector</h1>
  <span class="spacer"></span>
  <button type="button" id="clearBtn">Clear</button>
  <button type="button" class="primary" id="replayBtn" disabled>Replay</button>
</header>
<main>
  <div id="list"><div class="empty-list">Waiting for traffic…</div></div>
  <div id="detail" class="empty">Select a request</div>
</main>
<script>
const listEl = document.getElementById("list");
const detailEl = document.getElementById("detail");
const replayBtn = document.getElementById("replayBtn");
const clearBtn = document.getElementById("clearBtn");
let selectedId = null;
let items = [];

function statusClass(s) {
  if (s >= 200 && s < 400) return "ok";
  if (s >= 400 || s === 0) return "err";
  return "";
}

function renderList() {
  if (!items.length) {
    listEl.innerHTML = '<div class="empty-list">Waiting for traffic…</div>';
    return;
  }
  listEl.innerHTML = items.slice().reverse().map(r => `
    <div class="row ${r.id === selectedId ? "active" : ""}" data-id="${r.id}">
      <span class="method ${r.method}">${r.method}</span>
      <span class="status ${statusClass(r.status)}">${r.status || "—"}</span>
      <span class="path">${escapeHtml(r.path)}</span>
      <span class="meta">${r.latencyMs}ms${r.replayedFrom ? " · replay" : ""}</span>
    </div>
  `).join("");
  listEl.querySelectorAll(".row").forEach(el => {
    el.addEventListener("click", () => select(el.dataset.id));
  });
}

function escapeHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function headersText(headers) {
  if (!headers || !headers.length) return "(none)";
  return headers.map(([k,v]) => k + ": " + v).join("\\n");
}

async function select(id) {
  selectedId = id;
  replayBtn.disabled = !id;
  renderList();
  const res = await fetch("/api/requests/" + id);
  if (!res.ok) {
    detailEl.className = "empty";
    detailEl.textContent = "Request not found";
    return;
  }
  const r = await res.json();
  detailEl.className = "";
  detailEl.innerHTML = `
    <div class="detail-head">
      <span class="method ${r.method}">${r.method}</span>
      <span class="status ${statusClass(r.status)}">${r.status || "—"}</span>
      <h2>${escapeHtml(r.path)}</h2>
    </div>
    <section>
      <h3>Request headers</h3>
      <pre>${escapeHtml(headersText(r.requestHeaders))}</pre>
    </section>
    <section>
      <h3>Request body</h3>
      <pre>${escapeHtml(r.requestBody || "(empty)")}</pre>
      ${r.requestBodyTruncated ? '<div class="truncated">Body truncated at 1 MiB</div>' : ""}
    </section>
    <section>
      <h3>Response headers</h3>
      <pre>${escapeHtml(headersText(r.responseHeaders))}</pre>
    </section>
    <section>
      <h3>Response body</h3>
      <pre>${escapeHtml(r.responseBody || "(empty)")}</pre>
      ${r.responseBodyTruncated ? '<div class="truncated">Body truncated at 1 MiB</div>' : ""}
    </section>
  `;
}

async function refresh() {
  const res = await fetch("/api/requests");
  if (!res.ok) return;
  items = await res.json();
  renderList();
  if (selectedId && !items.find(i => i.id === selectedId)) {
    selectedId = null;
    replayBtn.disabled = true;
    detailEl.className = "empty";
    detailEl.textContent = "Select a request";
  }
}

replayBtn.addEventListener("click", async () => {
  if (!selectedId) return;
  replayBtn.disabled = true;
  const res = await fetch("/api/requests/" + selectedId + "/replay", { method: "POST" });
  replayBtn.disabled = false;
  if (!res.ok) {
    alert(await res.text());
    return;
  }
  const { id } = await res.json();
  await refresh();
  select(id);
});

clearBtn.addEventListener("click", async () => {
  await fetch("/api/requests", { method: "DELETE" });
  selectedId = null;
  replayBtn.disabled = true;
  detailEl.className = "empty";
  detailEl.textContent = "Select a request";
  await refresh();
});

refresh();
setInterval(refresh, 1000);
</script>
</body>
</html>
"#;
