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
  <p><a href="/sbom">Generate SBOMs &rarr;</a></p>

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

const sbomHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SBOM generation</title>
<style>
  body { font: 14px/1.55 system-ui, sans-serif; max-width: 980px; margin: 40px auto; padding: 0 16px; color: #111; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 15px; margin: 28px 0 8px; }
  .sub { color: #666; margin-bottom: 20px; }
  a { color: #0b57d0; }
  label { display: block; margin: 16px 0 4px; font-weight: 600; }
  select, button { font: inherit; padding: 8px 10px; border: 1px solid #ccc; border-radius: 6px; background: #fff; }
  select { min-width: 320px; }
  button { cursor: pointer; margin-top: 18px; background: #111; color: #fff; border-color: #111; }
  button:disabled { opacity: .5; cursor: default; }
  .muted { color: #666; font-size: 12px; margin-top: 4px; min-height: 16px; }
  table { border-collapse: collapse; width: 100%; margin-top: 8px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  th { font-size: 12px; text-transform: uppercase; letter-spacing: .03em; color: #555; }
  code { background: #f4f4f4; padding: 1px 4px; border-radius: 4px; }
  .badge { display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 11px; font-weight: 600; }
  .b-pending { background: #eee; color: #555; }
  .b-running { background: #fff4ce; color: #7a5b00; }
  .b-ok { background: #e6f4ea; color: #137333; }
  .b-fail { background: #fce8e6; color: #a50e0e; }
  .log { background: #0f1115; color: #d6d6d6; font: 12px/1.5 ui-monospace, monospace; padding: 14px; border-radius: 8px; max-height: 260px; overflow: auto; white-space: pre-wrap; }
  .err { color: #a50e0e; }
  .hidden { display: none; }
</style>
</head>
<body>
  <h1>SBOM generation</h1>
  <div class="sub">Enumerates images from the selected target cluster, pulls them, and runs Syft. Read-only: nothing is written to the target.</div>
  <p><a href="/">&larr; Back to posture scan</a></p>

  <label for="cluster">Target cluster</label>
  <select id="cluster"></select>
  <div class="muted" id="server"></div>

  <button id="run">Generate SBOMs</button>
  <div class="muted" id="phase"></div>

  <div id="imagesWrap" class="hidden">
    <h2>Images found (<span id="imageCount">0</span>)</h2>
    <table id="images"><thead><tr><th>Image</th><th>Registry</th><th>Pods</th></tr></thead><tbody></tbody></table>
  </div>

  <div id="progressWrap" class="hidden">
    <h2>Progress</h2>
    <div class="log" id="log"></div>
  </div>

  <div id="resultsWrap" class="hidden">
    <h2>SBOMs</h2>
    <table id="results"><thead><tr><th>Image</th><th>Status</th><th>Packages</th><th>Size</th><th>SPDX</th></tr></thead><tbody></tbody></table>
  </div>

<script>
var sel = document.getElementById('cluster');
var srv = document.getElementById('server');
var btn = document.getElementById('run');
var phase = document.getElementById('phase');
var log = document.getElementById('log');
var imagesWrap = document.getElementById('imagesWrap');
var progressWrap = document.getElementById('progressWrap');
var resultsWrap = document.getElementById('resultsWrap');
var clusters = [];

function esc(s) {
  return String(s).replace(/[&<>"']/g, function (c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}

function badge(s) {
  var k = s === 'Succeeded' ? 'ok' : (s === 'Failed' ? 'fail' : (s === 'Running' ? 'running' : 'pending'));
  return '<span class="badge b-' + k + '">' + esc(s) + '</span>';
}

function showServer() {
  var c = clusters.find(function (x) { return x.name === sel.value; });
  srv.textContent = c ? c.server : '';
}

fetch('/api/clusters').then(function (r) { return r.json(); }).then(function (cs) {
  clusters = cs || [];
  if (clusters.length === 0) {
    phase.textContent = 'No target kubeconfigs found.';
    btn.disabled = true;
    return;
  }
  sel.innerHTML = clusters.map(function (c) { return '<option>' + esc(c.name) + '</option>'; }).join('');
  showServer();
}).catch(function (e) { phase.textContent = 'Failed to load clusters: ' + e; });

sel.addEventListener('change', showServer);

btn.addEventListener('click', function () {
  btn.disabled = true;
  phase.textContent = 'Submitting...';
  fetch('/api/sboms', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cluster: sel.value })
  }).then(function (r) {
    return r.json().then(function (v) { return { ok: r.ok, status: r.status, v: v }; });
  }).then(function (res) {
    if (!res.ok) {
      phase.innerHTML = '<span class="err">Error: ' + esc(res.v.error || res.status) + '</span>';
      btn.disabled = false;
      return;
    }
    renderImages(res.v);
    phase.textContent = 'Job ' + res.v.jobName + ' created';
    poll(res.v.id);
  }).catch(function (e) {
    phase.innerHTML = '<span class="err">Error: ' + esc(e) + '</span>';
    btn.disabled = false;
  });
});

function renderImages(run) {
  var imgs = run.images || [];
  document.getElementById('imageCount').textContent = imgs.length;
  document.querySelector('#images tbody').innerHTML = imgs.map(function (i) {
    return '<tr><td><code>' + esc(i.image) + '</code></td><td>' + esc(i.registry) + '</td><td>' + i.count + '</td></tr>';
  }).join('');
  imagesWrap.classList.remove('hidden');
}

function describe(p) {
  switch (p.stage) {
    case 'pull': return 'pulling ' + p.image + ' from ' + p.registry;
    case 'syft': return 'pulling image and running syft for ' + p.image;
    case 'sbom': return 'generated SBOM for ' + p.image + ' (' + p.bytes + ' bytes)';
    case 'error': return 'FAILED ' + p.image + ': ' + p.message;
    case 'done': return 'all images processed';
    default: return p.stage + (p.image ? ' ' + p.image : '');
  }
}

function renderProgress(run) {
  progressWrap.classList.remove('hidden');
  var lines = (run.progress || []).map(function (p) {
    var t = p.time ? new Date(p.time).toLocaleTimeString() : '';
    return '[' + t + '] ' + describe(p);
  });
  log.textContent = lines.length ? lines.join('\n') : 'waiting for the first progress line...';
  log.scrollTop = log.scrollHeight;
}

function renderResults(run) {
  var res = run.results || [];
  if (!res.length) {
    return;
  }
  resultsWrap.classList.remove('hidden');
  var base = '/api/sboms/' + run.id + '/results/';
  document.querySelector('#results tbody').innerHTML = res.map(function (r) {
    var href = base + r.image;
    var link = r.status === 'Succeeded' ? '<a href="' + esc(href) + '" target="_blank" rel="noopener">View SPDX</a>' : '';
    var size = r.bytes > 1024 ? Math.round(r.bytes / 1024) + ' KB' : r.bytes + ' B';
    var err = r.error ? '<div class="err">' + esc(r.error) + '</div>' : '';
    return '<tr><td><code>' + esc(r.image) + '</code></td><td>' + badge(r.status) + '</td><td>' + (r.packages || '') + '</td><td>' + (r.status === 'Succeeded' ? size : '') + '</td><td>' + link + err + '</td></tr>';
  }).join('');
}

function poll(id) {
  fetch('/api/sboms/' + id).then(function (r) {
    return r.json().then(function (v) { return { ok: r.ok, status: r.status, v: v }; });
  }).then(function (res) {
    if (!res.ok) {
      phase.innerHTML = '<span class="err">Error: ' + esc(res.v.error || res.status) + '</span>';
      btn.disabled = false;
      return;
    }
    var run = res.v;
    renderImages(run);
    renderProgress(run);
    renderResults(run);
    phase.textContent = 'Status: ' + run.status + (run.error ? ' - ' + run.error : '');
    if (run.status === 'Pending' || run.status === 'Running') {
      setTimeout(function () { poll(id); }, 2000);
    } else {
      btn.disabled = false;
    }
  }).catch(function (e) {
    phase.innerHTML = '<span class="err">Error: ' + esc(e) + '</span>';
    btn.disabled = false;
  });
}
</script>
</body>
</html>`
