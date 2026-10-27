package main

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kubescape scan</title>
<style>
  body { font: 14px/1.5 system-ui, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 16px; color: #111; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .sub { color: #666; margin-bottom: 24px; }
  label { display: block; margin: 16px 0 4px; font-weight: 600; }
  select, button { font: inherit; padding: 8px 10px; border: 1px solid #ccc; border-radius: 6px; background: #fff; }
  select { min-width: 320px; }
  button { cursor: pointer; margin-top: 20px; background: #111; color: #fff; border-color: #111; }
  button:disabled { opacity: .5; cursor: default; }
  .muted { color: #666; font-size: 12px; margin-top: 4px; min-height: 16px; }
  pre { background: #111; color: #eee; padding: 16px; border-radius: 8px; overflow: auto; white-space: pre-wrap; word-break: break-word; }
  .err { color: #b00020; }
</style>
</head>
<body>
  <h1>Kubescape scan</h1>
  <div class="sub">Runs in the runner cluster; reads the selected target cluster with a read-only kubeconfig.</div>

  <label for="cluster">Target cluster</label>
  <select id="cluster"></select>
  <div class="muted" id="server"></div>

  <button id="run">Start scan</button>
  <div id="report"></div>
  <pre id="out">Idle.</pre>

<script>
const sel = document.getElementById('cluster');
const srv = document.getElementById('server');
const out = document.getElementById('out');
const btn = document.getElementById('run');
let clusters = [];

function showServer() {
  const c = clusters.find(x => x.name === sel.value);
  srv.textContent = c ? c.server : '';
}

fetch('/api/clusters').then(r => r.json()).then(cs => {
  clusters = cs || [];
  if (clusters.length === 0) {
    out.textContent = 'No target kubeconfigs found. Put them in the --targets-dir.';
    btn.disabled = true;
    return;
  }
  sel.innerHTML = clusters.map(c => '<option>' + c.name + '</option>').join('');
  showServer();
}).catch(e => { out.textContent = 'Failed to load clusters: ' + e; });

sel.addEventListener('change', showServer);

btn.addEventListener('click', async () => {
  btn.disabled = true;
  out.textContent = 'Submitting...';
  const res = await fetch('/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cluster: sel.value })
  });
  const scan = await res.json();
  if (!res.ok) {
    out.textContent = 'Error: ' + (scan.error || res.status);
    btn.disabled = false;
    return;
  }
  poll(scan.id);
});

async function poll(id) {
  const res = await fetch('/api/scans/' + id);
  const scan = await res.json();
  out.textContent = JSON.stringify(scan, null, 2);
  if (scan.status === 'Pending' || scan.status === 'Running') {
    document.getElementById('report').innerHTML = '';
    setTimeout(() => poll(id), 3000);
  } else {
    btn.disabled = false;
    document.getElementById('report').innerHTML =
      '<a href="/api/scans/' + id + '/results" target="_blank" rel="noopener">View full results &rarr;</a>';
  }
}
</script>
</body>
</html>`
