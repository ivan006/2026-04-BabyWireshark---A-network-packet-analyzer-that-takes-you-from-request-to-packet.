const WS_URL = 'ws://localhost:8000/inspect';

let ws = null;
let packetCount = 0;
let startTime = null;

const LAYERS = [
{ key: 'L7_Application', label: 'L7 — Application', color: '#a78bfa' },
{ key: 'L5_L6_Session_Presentation', label: 'L5/L6 — Session/Presentation', color: '#67e8f9' },
{ key: 'L4_Transport', label: 'L4 — Transport', color: '#86efac' },
{ key: 'L3_Network', label: 'L3 — Network', color: '#fcd34d' },
{ key: 'L2_DataLink', label: 'L2 — Data Link', color: '#fca5a5' },
];

function setStatus(msg, alertClass = 'alert-secondary') {
const bar = document.getElementById('status-bar');
bar.textContent = msg;
bar.className = `alert ${alertClass} mb-3 py-2 small`;
}

function showResolved(data) {
const wrap = document.getElementById('resolved-info');
const fields = [
['Hostname', data.hostname],
['Resolved IP', data.ip],
['Port', data.port],
['Scheme', data.scheme],
['Path', data.path || '/'],
];
wrap.innerHTML = fields.map(([label, value]) => `
<div class="col-6 col-md-4 col-lg-2">
  <div class="bg-black bg-opacity-25 border border-secondary rounded p-2">
    <div class="text-secondary" style="font-size:11px;text-transform:uppercase;letter-spacing:.05em">${label}</div>
    <div class="text-light" style="font-family:monospace;font-size:13px;word-break:break-all;margin-top:3px">${value}
    </div>
  </div>
</div>`).join('');
wrap.classList.remove('d-none');
}

function protocolStack(layers) {
const parts = [];
if (layers.L2_DataLink) parts.push({ label: 'eth', color: '#fca5a5' });
if (layers.L3_Network) parts.push({ label: 'ip', color: '#fcd34d' });
if (layers.L4_Transport) {
const proto = (layers.L4_Transport.protocol || 'transport').toLowerCase();
parts.push({ label: proto, color: '#86efac' });
}
if (layers.L5_L6_Session_Presentation) parts.push({ label: 'tls', color: '#67e8f9' });
if (layers.L7_Application) {
const proto = (layers.L7_Application.protocol || 'app').toLowerCase().split('/')[0].split(' ')[0];
parts.push({ label: proto, color: '#a78bfa' });
}
return parts
.map(p => `<span style="font-family:monospace;font-size:12px;font-weight:600;color:${p.color}">${p.label}</span>`)
.join('<span class="text-secondary" style="font-size:11px;margin:0 3px">:</span>');
}

function badgesHTML(layers) {
return LAYERS
.filter(l => layers[l.key])
.map(l => `<span class="badge rounded-pill me-1"
  style="background:${l.color}20;color:${l.color};font-size:10px;font-weight:600">${l.label.split('—')[0].trim()}</span>`)
.join('');
}

function fieldsHTML(obj) {
return Object.entries(obj).map(([k, v]) => `
<div class="text-secondary small">${k}</div>
<div class="small" style="font-family:monospace;word-break:break-all">${v}</div>
`).join('');
}

function renderPacket(pkt) {
packetCount++;
const elapsed = startTime ? ((pkt.timestamp - startTime) * 1000).toFixed(1) + ' ms' : '—';
const layers = pkt.layers;
const id = `pkt-${packetCount}`;

const layerSections = LAYERS.filter(l => layers[l.key]).map(l => `
<div class="border-top border-secondary px-3 py-2">
  <div class="fw-semibold small mb-2" style="color:${l.color}">${l.label}</div>
  <div style="display:grid;grid-template-columns:160px 1fr;gap:3px 12px">
    ${fieldsHTML(layers[l.key])}
  </div>
</div>`).join('');

const card = document.createElement('div');
card.className = 'border border-secondary rounded mb-2 overflow-hidden';
card.innerHTML = `
<div class="d-flex align-items-center gap-2 px-3 py-2 bg-black bg-opacity-25" style="cursor:pointer"
  onclick="togglePacket('${id}')">
  <span class="text-secondary" style="font-family:monospace;font-size:11px;min-width:32px">#${packetCount}</span>
  <div class="flex-grow-1">${protocolStack(layers)}</div>
  <span class="text-secondary" style="font-size:11px;font-family:monospace">${elapsed}</span>
  <span class="text-secondary" style="font-size:11px;font-family:monospace">${pkt.size_bytes} B</span>
</div>
<div id="${id}" class="d-none">${layerSections}</div>`;

document.getElementById('packets-wrap').appendChild(card);
}

function togglePacket(id) {
document.getElementById(id).classList.toggle('d-none');
}

function startInspect() {
const url = document.getElementById('url-input').value.trim();
if (!url) return;

packetCount = 0;
startTime = null;
document.getElementById('packets-wrap').innerHTML = '';
document.getElementById('resolved-info').classList.add('d-none');

const btn = document.getElementById('inspect-btn');
btn.disabled = true;

if (ws) ws.close();
ws = new WebSocket(WS_URL);

ws.onopen = () => {
setStatus('Connecting…', 'alert-secondary');
ws.send(JSON.stringify({ url }));
};

ws.onmessage = (e) => {
const msg = JSON.parse(e.data);
if (msg.type === 'resolved') {
showResolved(msg.data);
setStatus(`Resolved ${msg.data.hostname} → ${msg.data.ip}`, 'alert-secondary');
} else if (msg.type === 'capturing') {
setStatus(msg.message, 'alert-warning');
} else if (msg.type === 'packet') {
if (!startTime) startTime = msg.data.timestamp;
renderPacket(msg.data);
} else if (msg.type === 'done') {
setStatus(`Capture complete — ${packetCount} packets`, 'alert-success');
btn.disabled = false;
} else if (msg.type === 'error') {
setStatus('Error: ' + msg.message, 'alert-danger');
btn.disabled = false;
}
};

ws.onerror = () => {
setStatus('WebSocket error — is the backend running?', 'alert-danger');
btn.disabled = false;
};

ws.onclose = () => { btn.disabled = false; };
}

document.getElementById('url-input').addEventListener('keydown', e => {
if (e.key === 'Enter') startInspect();
});