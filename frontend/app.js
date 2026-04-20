const WS_URL = "ws://localhost:8000/inspect";

let ws = null;
let packetCount = 0;
let startTime = null;
let allPackets = [];

// -- Tooltip knowledge base ----------------------------------------------------
const FIELD_TIPS = {
  src_port:
    "The port number on the sender's machine this connection is coming from.",
  dst_port: "The port the receiver is listening on. 443 = HTTPS, 80 = HTTP.",
  seq: "Tracks which byte in the stream this segment starts at, so the receiver can reassemble data in order.",
  ack: "Tells the sender which byte the receiver expects next, confirming everything before it arrived.",
  flags:
    "TCP control flags -- S=SYN (start), A=ACK (acknowledge), F=FIN (close), R=RST (abort), P=PSH (send now).",
  window:
    "How many bytes the receiver will accept before needing an acknowledgement. Controls flow.",
  checksum:
    "Error-detection value. If the receiver recalculates and it doesn't match, the packet is discarded.",
  data_offset:
    "How many 32-bit words are in the TCP header, so the receiver knows where the payload starts.",
  protocol: "Identifies what's inside the packet. 6 = TCP, 17 = UDP.",
  src_ip: "IP address of the machine that sent this packet.",
  dst_ip: "IP address this packet is being sent to.",
  ttl: "Decremented by each router. When it hits 0 the packet is discarded, preventing infinite loops.",
  length: "Total length of this IP packet in bytes, including the header.",
  fragment_offset:
    "If a large packet was split up, this says where this piece fits in the original.",
  frame_type:
    "The format used to wrap data at Layer 2. Ethernet II is the standard for modern networks.",
  src_mac:
    "Hardware address of the network card that sent this frame. MAC addresses are local to your network.",
  dst_mac:
    "Hardware address of the next hop (usually your router), not the final server.",
  ethertype:
    "Tells the receiver what Layer 3 protocol is inside. 0x0800 = IPv4, 0x0806 = ARP.",
  type: "TLS record type -- 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData.",
  version: "TLS version -- 0x0301=TLS 1.0, 0x0303=TLS 1.2, 0x0304=TLS 1.3.",
  payload_bytes: "How many bytes of application data are in this packet.",
  payload_preview:
    "The raw payload. For HTTPS this will be encrypted and unreadable.",
};

const PROTO_TIPS = {
  eth: "Ethernet -- Layer 2, frames data for local network transmission using MAC addresses.",
  ip: "Internet Protocol -- Layer 3, routes packets across networks using IP addresses.",
  tcp: "TCP -- Layer 4, reliable ordered delivery with handshaking and retransmission.",
  udp: "UDP -- Layer 4, fast delivery with no guarantee of order or arrival.",
  tls: "TLS -- encrypts data between client and server so it cannot be read in transit.",
  https: "HTTPS -- HTTP over TLS. The payload is encrypted application data.",
  http: "HTTP -- HyperText Transfer Protocol, the application-layer protocol for web requests.",
};

// -- Phase detection -----------------------------------------------------------
function detectPhase(pkt) {
  const t = pkt.layers;
  const flags = t.L4_Transport?.flags || "";
  const hasTLS = !!t.L5_L6_Session_Presentation;
  const tlsType = t.L5_L6_Session_Presentation?.type;
  const hasRaw = !!t.L7_Application;
  if (flags === "S" || flags === "SA" || (flags === "A" && !hasTLS && !hasRaw))
    return "TCP Handshake";
  if (hasTLS && tlsType === 22) return "TLS Negotiation";
  if (hasTLS && tlsType === 23) return "Data Transfer";
  if (hasTLS && tlsType === 21) return "Connection Teardown";
  if (hasRaw) return "Data Transfer";
  if (flags.includes("F") || flags.includes("R")) return "Connection Teardown";
  return "Data Transfer";
}

const PHASE_COLORS = {
  "TCP Handshake": "#86efac",
  "TLS Negotiation": "#67e8f9",
  "Data Transfer": "#a78bfa",
  "Connection Teardown": "#fca5a5",
};

// -- Packet narrative ----------------------------------------------------------
function packetNarrative(pkt) {
  const t = pkt.layers;
  const flags = t.L4_Transport?.flags || "";
  const src = t.L3_Network?.src_ip || "";
  const tlsType = t.L5_L6_Session_Presentation?.type;
  const isFromMe =
    src.startsWith("10.") ||
    src.startsWith("192.168.") ||
    src.startsWith("172.");

  if (flags === "S") return "yo, you there? I'd like to connect &mdash; SYN";
  if (flags === "SA") return "yeah I'm here, come through &mdash; SYN-ACK";
  if (flags === "A" && !t.L5_L6_Session_Presentation && !t.L7_Application)
    return "cool, we're connected &mdash; ACK";
  if (tlsType === 22 && isFromMe)
    return "before we talk, let's agree on how to encrypt this &mdash; Client Hello";
  if (tlsType === 22 && !isFromMe)
    return "agreed, here's my certificate to prove who I am &mdash; Server Hello";
  if (tlsType === 20)
    return "switching to encrypted mode now &mdash; ChangeCipherSpec";
  if (tlsType === 23 && isFromMe)
    return "here's my request, but you can't read it &mdash; Application Data";
  if (tlsType === 23 && !isFromMe)
    return "here's my response, also encrypted &mdash; Application Data";
  if (tlsType === 21) return "alright I'm done talking &mdash; TLS Alert";
  if (flags.includes("F") && isFromMe)
    return "I'm done sending, close your end too &mdash; FIN";
  if (flags.includes("F") && !isFromMe) return "same, I'm done too &mdash; FIN";
  if (flags.includes("R"))
    return "something went wrong, killing this connection &mdash; RST";
  if (t.L7_Application)
    return "here's the data you asked for &mdash; Application Data";
  return "just keeping track of where we are &mdash; TCP control";
}

// -- Protocol stack ------------------------------------------------------------
function protocolStack(layers) {
  const parts = [];
  if (layers.L2_DataLink) parts.push({ label: "eth", color: "#fca5a5" });
  if (layers.L3_Network) parts.push({ label: "ip", color: "#fcd34d" });
  if (layers.L4_Transport)
    parts.push({
      label: (layers.L4_Transport.protocol || "tcp").toLowerCase(),
      color: "#86efac",
    });
  if (layers.L5_L6_Session_Presentation)
    parts.push({ label: "tls", color: "#67e8f9" });
  if (layers.L7_Application)
    parts.push({
      label: (layers.L7_Application.protocol || "app")
        .toLowerCase()
        .split("/")[0]
        .split(" ")[0],
      color: "#a78bfa",
    });
  return parts
    .map((p) => {
      const tip = PROTO_TIPS[p.label] || "";
      return `<span title="${tip}"
  style="font-family:monospace;font-size:12px;font-weight:600;color:${p.color};cursor:help">${p.label}</span>`;
    })
    .join('<span class="text-secondary mx-1" style="font-size:10px">:</span>');
}

// -- Status / resolved ---------------------------------------------------------
function setStatus(msg, alertClass = "alert-secondary") {
  const bar = document.getElementById("status-bar");
  bar.textContent = msg;
  bar.className = `alert ${alertClass} mb-3 py-2 small`;
}

function showResolved(data) {
  const wrap = document.getElementById("resolved-info");
  const fields = [
    ["Hostname", data.hostname],
    ["Resolved IP", data.ip],
    ["Port", data.port],
    ["Scheme", data.scheme],
    ["Path", data.path || "/"],
  ];
  wrap.innerHTML = fields
    .map(
      ([label, value]) => `
<div class="col-6 col-md-4 col-lg-2">
  <div class="bg-black bg-opacity-25 border border-secondary rounded p-2">
    <div class="text-secondary" style="font-size:11px;text-transform:uppercase;letter-spacing:.05em">${label}</div>
    <div class="text-light" style="font-family:monospace;font-size:13px;word-break:break-all;margin-top:3px">${value}
    </div>
  </div>
</div>`,
    )
    .join("");
  wrap.classList.remove("d-none");
}

// -- Modal ---------------------------------------------------------------------
const LAYERS = [
  { key: "L7_Application", label: "L7 -- Application", color: "#a78bfa" },
  {
    key: "L5_L6_Session_Presentation",
    label: "L5/L6 -- Session/Presentation",
    color: "#67e8f9",
  },
  { key: "L4_Transport", label: "L4 -- Transport", color: "#86efac" },
  { key: "L3_Network", label: "L3 -- Network", color: "#fcd34d" },
  { key: "L2_DataLink", label: "L2 -- Data Link", color: "#fca5a5" },
];

function openModal(idx) {
  const pkt = allPackets[idx];
  const layers = pkt.layers;
  const phase = detectPhase(pkt);
  const phaseColor = PHASE_COLORS[phase] || "#aaa";

  const layerSections = LAYERS.filter((l) => layers[l.key]).map((l) => {
    const fields = Object.entries(layers[l.key])
      .map(([k, v]) => {
        const tip = FIELD_TIPS[k] || "";
        return `
<tr>
  <td class="text-secondary pe-3 py-1"
    style="font-size:12px;white-space:nowrap;${tip ? "cursor:help;text-decoration:underline dotted" : ""}" ${
      tip ? `title="${tip}" ` : ""
    }>${k}</td>
  <td class="py-1" style="font-family:monospace;font-size:12px;word-break:break-all">${v}</td>
</tr>`;
      })
      .join("");
    return `
<div class="mb-3">
  <div class="fw-semibold small mb-2" style="color:${l.color}">${l.label}</div>
  <table class="w-100">
    <tbody>${fields}</tbody>
  </table>
</div>`;
  }).join(`
<hr class="border-secondary my-2">`);

  document.getElementById("modal-title").innerHTML = `
<span class="me-2" style="font-family:monospace;font-size:13px">#${idx + 1}</span>
${protocolStack(layers)}
<span class="ms-3 badge" style="background:${phaseColor}22;color:${phaseColor};font-size:10px">${phase}</span>`;
  document.getElementById("modal-narrative").innerHTML = packetNarrative(pkt);
  document.getElementById("modal-body").innerHTML = layerSections;
  document.getElementById("modal-meta").textContent =
    `${pkt.size_bytes} bytes -- ${
      startTime
        ? ((pkt.timestamp - startTime) * 1000).toFixed(1) + " ms"
        : "0 ms"
    }`;

  new bootstrap.Modal(document.getElementById("pktModal")).show();
}

// -- Table rendering -----------------------------------------------------------
function addTableRow(pkt, idx) {
  const elapsed = startTime
    ? ((pkt.timestamp - startTime) * 1000).toFixed(1)
    : "0.0";
  const phase = detectPhase(pkt);
  const phaseColor = PHASE_COLORS[phase] || "#aaa";
  const tbody = document.getElementById("packets-tbody");

  const tr = document.createElement("tr");
  tr.style.cssText = "cursor:pointer";
  tr.onclick = () => openModal(idx);
  tr.innerHTML = `
<td class="text-secondary pe-3" style="font-family:monospace;font-size:12px">${idx + 1}</td>
<td class="pe-3">${protocolStack(pkt.layers)}</td>
<td class="pe-3"><span class="badge"
    style="background:${phaseColor}18;color:${phaseColor};font-size:10px;font-weight:500">${phase}</span></td>
<td class="pe-4" style="font-size:12px;color:#94a3b8;max-width:320px">${packetNarrative(pkt)}</td>
<td class="text-secondary text-end pe-3" style="font-family:monospace;font-size:12px;white-space:nowrap">${elapsed} ms
</td>
<td class="text-secondary text-end" style="font-family:monospace;font-size:12px;white-space:nowrap">${pkt.size_bytes} B
</td>`;

  tbody.appendChild(tr);
}

// -- WebSocket -----------------------------------------------------------------
function startInspect() {
  const url = document.getElementById("url-input").value.trim();
  if (!url) return;

  packetCount = 0;
  startTime = null;
  allPackets = [];
  document.getElementById("packets-tbody").innerHTML = "";
  document.getElementById("resolved-info").classList.add("d-none");
  document.getElementById("packets-table").classList.add("d-none");

  const btn = document.getElementById("inspect-btn");
  btn.disabled = true;

  if (ws) ws.close();
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    setStatus("Connecting?", "alert-secondary");
    ws.send(JSON.stringify({ url }));
  };

  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.type === "resolved") {
      showResolved(msg.data);
      setStatus(
        `Resolved ${msg.data.hostname} ? ${msg.data.ip}`,
        "alert-secondary",
      );
    } else if (msg.type === "capturing") {
      setStatus(msg.message, "alert-warning");
    } else if (msg.type === "packet") {
      if (!startTime) startTime = msg.data.timestamp;
      const idx = allPackets.length;
      allPackets.push(msg.data);
      packetCount++;
      document.getElementById("packets-table").classList.remove("d-none");
      addTableRow(msg.data, idx);
    } else if (msg.type === "done") {
      setStatus(`Capture complete -- ${packetCount} packets`, "alert-success");
      btn.disabled = false;
    } else if (msg.type === "error") {
      setStatus("Error: " + msg.message, "alert-danger");
      btn.disabled = false;
    }
  };

  ws.onerror = () => {
    setStatus("WebSocket error -- is the backend running?", "alert-danger");
    btn.disabled = false;
  };

  ws.onclose = () => {
    btn.disabled = false;
  };
}

document.getElementById("url-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") startInspect();
});
