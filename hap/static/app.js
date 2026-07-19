function esc(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
  })[character]);
}

function output(value) {
  document.getElementById('output').textContent = JSON.stringify(value, null, 2);
}

async function api(path) {
  const response = await fetch(path, {headers: {'Accept': 'application/json'}});
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  if (!response.ok) {
    throw new Error(typeof data === 'object' ? (data.detail || JSON.stringify(data)) : data);
  }
  return data;
}

async function loadInfo() {
  const node = document.getElementById('node');
  try { node.textContent = JSON.stringify(await api('/v1/info'), null, 2); }
  catch (error) { node.textContent = error.message; }
}

async function inspect(recordId) {
  try { output(await api(`/v1/records/${encodeURIComponent(recordId)}`)); }
  catch (error) { output({error: error.message}); }
}

function contextCount(view) {
  const context = view.responsible_publication?.context || {};
  return Object.values(context).reduce((total, value) => total + (Array.isArray(value) ? value.length : 0), 0);
}

async function refreshRecords() {
  const root = document.getElementById('records');
  try {
    const rows = await api('/v1/feed?limit=50');
    if (!rows.length) {
      root.innerHTML = '<p class="muted">No records are currently discoverable in the responsible-publication reference feed. Exact-ID access remains available.</p>';
      return;
    }
    root.innerHTML = rows.map((view) => {
      const record = view.record;
      const state = view.responsible_publication?.discovery?.state || 'unknown';
      return `
      <div class="record">
        <strong>${esc(record.title)}</strong>
        <p><span class="pill">${esc(record.kind)}</span><span class="pill">${esc(state)}</span><span class="pill">${contextCount(view)} context object(s)</span></p>
        <p>${esc(record.statement).slice(0, 600)}</p>
        <p class="mono muted">${esc(record.record_id)}</p>
        <button class="secondary inspect" type="button" data-record-id="${esc(record.record_id)}">Inspect record, context, and proofs</button>
      </div>`;
    }).join('');
    root.querySelectorAll('.inspect').forEach((button) => {
      button.addEventListener('click', () => inspect(button.dataset.recordId));
    });
  } catch (error) {
    root.innerHTML = `<p class="bad">${esc(error.message)}</p>`;
  }
}

document.getElementById('refresh').addEventListener('click', refreshRecords);
loadInfo();
refreshRecords();
