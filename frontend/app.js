const WS_URL = "ws://localhost:8000/inspect";

let ws = null;
let packetCount = 0;
let startTime = null;
let allPackets = [];

const FIELD_TIPS = {
  src_port:
    "The port number on the sender machine this connection is coming from.",
  dst_port: "The port the receiver is listening on. 443=HTTPS, 80=HTTP.",
  seq: "Tracks which byte in the stream this segment starts at so the receiver can reassemble data in order.",
  ack: "Tells the sender which byte the receiver expects next, confirming everything before it arrived.",
  flags:
    "TCP control flags: S=SYN (start), A=ACK (acknowledge), F=FIN (close), R=RST (abort), P=PSH (send now).",
  window:
    "How many bytes the receiver will accept before needing an acknowledgement.",
  checksum:
    "Error-detection value. If the receiver recalculates and it does not match, the packet is discarded.",
  data_offset:
    "How many 32-bit words are in the TCP header so the receiver knows where payload starts.",
  protocol: "Identifies what is inside the packet. 6=TCP, 17=UDP.",
  src_ip: "IP address of the machine that sent this packet.",
  dst_ip: "IP address this packet is being sent to.",
  ttl: "Decremented by each router. When it hits 0 the packet is discarded, preventing infinite loops.",
  length: "Total length of this IP packet in bytes including the header.",
  fragment_offset:
    "If a large packet was split up, this says where this piece fits in the original.",
  frame_type:
    "The format used to wrap data at Layer 2. Ethernet II is standard for modern networks.",
  src_mac: "Hardware address of the network card that sent this frame.",
  dst_mac:
    "Hardware address of the next hop (usually your router), not the final server.",
  ethertype:
    "Tells the receiver what Layer 3 protocol is inside. 0x0800=IPv4, 0x0806=ARP.",
  type: "TLS record type: 20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=ApplicationData.",
  version: "TLS version: 0x0301=TLS 1.0, 0x0303=TLS 1.2, 0x0304=TLS 1.3.",
  payload_bytes: "How many bytes of application data are in this packet.",
  payload_preview:
    "The raw payload. For HTTPS this will be encrypted and unreadable.",
};

const PROTO_TIPS = {
  eth: "Ethernet: Layer 2, frames data for local network transmission using MAC addresses.",
  ip: "Internet Protocol: Layer 3, routes packets across networks using IP addresses.",
  tcp: "TCP: Layer 4, reliable ordered delivery with handshaking and retransmission.",
  udp: "UDP: Layer 4, fast delivery with no guarantee of order or arrival.",
  tls: "TLS: encrypts data between client and server so it cannot be read in transit.",
  https: "HTTPS: HTTP over TLS. The payload is encrypted application data.",
  http: "HTTP: HyperText Transfer Protocol, the application-layer protocol for web requests.",
};

var _handshakeDone = false;

function resetPhaseState() {
  _handshakeDone = false;
}

function detectPhase(pkt) {
  var t = pkt.layers;
  var flags = (t.L4_Transport && t.L4_Transport.flags) || "";
  var hasTLS = !!t.L5_L6_Session_Presentation;
  var tlsType = hasTLS ? t.L5_L6_Session_Presentation.type : null;
  var hasRaw = !!t.L7_Application;

  if (flags === "S") return "TCP Handshake";
  if (flags === "SA") return "TCP Handshake";
  if (flags === "A" && !_handshakeDone && !hasTLS && !hasRaw) {
    _handshakeDone = true;
    return "TCP Handshake";
  }
  if (flags.indexOf("R") >= 0) return "Connection Teardown";
  if (flags.indexOf("F") >= 0) return "Connection Teardown";
  if (hasTLS && tlsType === 22) return "TLS Negotiation";
  if (hasTLS && tlsType === 23) return "Data Transfer";
  if (hasTLS && tlsType === 21) return "Connection Teardown";
  if (hasRaw) return "Data Transfer";
  return "Data Transfer";
}

var PHASE_COLORS = {
  "TCP Handshake": "#86efac",
  "TLS Negotiation": "#67e8f9",
  "Data Transfer": "#a78bfa",
  "Connection Teardown": "#fca5a5",
};

function packetNarrative(pkt) {
  var t = pkt.layers;
  var flags = (t.L4_Transport && t.L4_Transport.flags) || "";
  var src = (t.L3_Network && t.L3_Network.src_ip) || "";
  var tlsType = t.L5_L6_Session_Presentation
    ? t.L5_L6_Session_Presentation.type
    : null;
  var isFromMe =
    src.indexOf("10.") === 0 ||
    src.indexOf("192.168.") === 0 ||
    src.indexOf("172.") === 0;
  if (flags === "S") return '"yo, you there? I\'d like to connect" -- SYN';
  if (flags === "SA") return '"yeah I\'m here, come through" -- SYN-ACK';
  if (flags === "A" && !t.L5_L6_Session_Presentation && !t.L7_Application)
    return '"cool, we\'re connected" -- ACK';
  if (tlsType === 22 && isFromMe)
    return '"before we talk, let\'s agree on how to encrypt this" -- Client Hello';
  if (tlsType === 22 && !isFromMe)
    return '"agreed, here\'s my certificate to prove who I am" -- Server Hello';
  if (tlsType === 20)
    return '"switching to encrypted mode now" -- ChangeCipherSpec';
  if (tlsType === 23 && isFromMe)
    return "\"here's my request, you can't read it\" -- Application Data";
  if (tlsType === 23 && !isFromMe)
    return '"here\'s my response, also encrypted" -- Application Data';
  if (tlsType === 21) return '"alright I\'m done talking" -- TLS Alert';
  if (flags.indexOf("F") >= 0 && isFromMe)
    return '"I\'m done sending, close your end too" -- FIN';
  if (flags.indexOf("F") >= 0 && !isFromMe)
    return '"same, I\'m done too" -- FIN';
  if (flags.indexOf("R") >= 0)
    return '"something went wrong, killing this connection" -- RST';
  if (t.L7_Application)
    return '"here\'s the data you asked for" -- Application Data';
  return '"just keeping track of where we are" -- TCP control';
}

function protocolStack(layers) {
  var parts = [];
  if (layers.L2_DataLink) parts.push({ label: "eth", color: "#fca5a5" });
  if (layers.L3_Network) parts.push({ label: "ip", color: "#fcd34d" });
  if (layers.L4_Transport) {
    var proto = (layers.L4_Transport.protocol || "tcp").toLowerCase();
    var flags = layers.L4_Transport.flags || "";
    var flagMap = {
      S: "SYN",
      SA: "SYN-ACK",
      A: "ACK",
      FA: "FIN-ACK",
      F: "FIN",
      R: "RST",
      RA: "RST-ACK",
      PA: "PSH-ACK",
      PA: "PSH-ACK",
    };
    var flagLabel = flagMap[flags] || (flags ? flags : null);
    var label = flagLabel ? proto + "[" + flagLabel + "]" : proto;
    parts.push({ label: label, color: "#86efac" });
  }
  if (layers.L5_L6_Session_Presentation)
    parts.push({ label: "tls", color: "#67e8f9" });
  if (layers.L7_Application) {
    var p = (layers.L7_Application.protocol || "app")
      .toLowerCase()
      .split("/")[0]
      .split(" ")[0];
    parts.push({ label: p, color: "#a78bfa" });
  }
  return parts
    .map(function (p) {
      var tip = PROTO_TIPS[p.label] || "";
      return (
        '<span title="' +
        tip +
        '" style="font-family:monospace;font-size:12px;font-weight:600;color:' +
        p.color +
        ';cursor:help">' +
        p.label +
        "</span>"
      );
    })
    .join('<span class="text-secondary mx-1" style="font-size:10px">:</span>');
}

function setStatus(msg, alertClass) {
  alertClass = alertClass || "alert-secondary";
  var bar = document.getElementById("status-bar");
  bar.textContent = msg;
  bar.className = "alert " + alertClass + " mb-3 py-2 small";
}

function showResolved(data) {
  var wrap = document.getElementById("resolved-info");
  var fields = [
    ["Hostname", data.hostname],
    ["Resolved IP", data.ip],
    ["Port", data.port],
    ["Scheme", data.scheme],
    ["Path", data.path || "/"],
  ];
  var html = "";
  fields.forEach(function (f) {
    html += '<div class="col-6 col-md-4 col-lg-2">';
    html +=
      '<div class="bg-black bg-opacity-25 border border-secondary rounded p-2">';
    html +=
      '<div class="text-secondary" style="font-size:11px;text-transform:uppercase;letter-spacing:.05em">' +
      f[0] +
      "</div>";
    html +=
      '<div class="text-light" style="font-family:monospace;font-size:13px;word-break:break-all;margin-top:3px">' +
      f[1] +
      "</div>";
    html += "</div></div>";
  });
  wrap.innerHTML = html;
  wrap.classList.remove("d-none");
}

var LAYERS = [
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
  var pkt = allPackets[idx];
  var layers = pkt.layers;
  var phase = detectPhase(pkt);
  var phaseColor = PHASE_COLORS[phase] || "#aaa";

  var html = "";
  LAYERS.forEach(function (l) {
    if (!layers[l.key]) return;
    var fields = "";
    Object.entries(layers[l.key]).forEach(function (entry) {
      var k = entry[0],
        v = entry[1];
      var tip = FIELD_TIPS[k] || "";
      var tdStyle =
        "font-size:12px;white-space:nowrap;" +
        (tip ? "cursor:help;text-decoration:underline dotted" : "");
      var titleAttr = tip ? ' title="' + tip + '"' : "";
      fields += "<tr>";
      fields +=
        '<td class="text-secondary pe-3 py-1" style="' +
        tdStyle +
        '"' +
        titleAttr +
        ">" +
        k +
        "</td>";
      fields +=
        '<td class="py-1" style="font-family:monospace;font-size:12px;word-break:break-all">' +
        v +
        "</td>";
      fields += "</tr>";
    });
    html += '<div class="mb-3">';
    html +=
      '<div class="fw-semibold small mb-2" style="color:' +
      l.color +
      '">' +
      l.label +
      "</div>";
    html += '<table class="w-100"><tbody>' + fields + "</tbody></table>";
    html += '</div><hr class="border-secondary my-2">';
  });

  var titleHtml =
    '<span class="me-2" style="font-family:monospace;font-size:13px">#' +
    (idx + 1) +
    "</span>";
  titleHtml += protocolStack(layers);
  titleHtml +=
    '<span class="ms-3 badge" style="background:' +
    phaseColor +
    "22;color:" +
    phaseColor +
    ';font-size:10px">' +
    phase +
    "</span>";

  document.getElementById("modal-title").innerHTML = titleHtml;
  document.getElementById("modal-narrative").innerHTML = packetNarrative(pkt);
  document.getElementById("modal-body").innerHTML = html;
  var elapsed = startTime
    ? ((pkt.timestamp - startTime) * 1000).toFixed(1) + " ms"
    : "0 ms";
  document.getElementById("modal-meta").textContent =
    pkt.size_bytes + " bytes -- " + elapsed;

  new bootstrap.Modal(document.getElementById("pktModal")).show();
}

function addTableRow(pkt, idx) {
  var elapsed = startTime
    ? ((pkt.timestamp - startTime) * 1000).toFixed(1)
    : "0.0";
  var phase = detectPhase(pkt);
  var phaseColor = PHASE_COLORS[phase] || "#aaa";
  var tbody = document.getElementById("packets-tbody");

  var tr = document.createElement("tr");
  tr.style.cssText = "cursor:pointer";
  tr.onclick = function () {
    openModal(idx);
  };

  var html = "";
  html +=
    '<td class="text-secondary pe-3" style="font-family:monospace;font-size:12px">' +
    (idx + 1) +
    "</td>";
  html += '<td class="pe-3">' + protocolStack(pkt.layers) + "</td>";
  html +=
    '<td class="pe-3"><span class="badge" style="background:' +
    phaseColor +
    "18;color:" +
    phaseColor +
    ';font-size:10px;font-weight:500">' +
    phase +
    "</span></td>";
  html +=
    '<td class="pe-4" style="font-size:12px;color:#94a3b8;max-width:320px">' +
    packetNarrative(pkt) +
    "</td>";
  html +=
    '<td class="text-secondary text-end pe-3" style="font-family:monospace;font-size:12px;white-space:nowrap">' +
    elapsed +
    " ms</td>";
  html +=
    '<td class="text-secondary text-end" style="font-family:monospace;font-size:12px;white-space:nowrap">' +
    pkt.size_bytes +
    " B</td>";
  tr.innerHTML = html;
  tbody.appendChild(tr);
}

function startInspect() {
  var url = document.getElementById("url-input").value.trim();
  if (!url) return;

  packetCount = 0;
  startTime = null;
  allPackets = [];
  resetPhaseState();
  document.getElementById("packets-tbody").innerHTML = "";
  document.getElementById("resolved-info").classList.add("d-none");
  document.getElementById("packets-table").classList.add("d-none");

  var btn = document.getElementById("inspect-btn");
  btn.disabled = true;

  if (ws) ws.close();
  ws = new WebSocket(WS_URL);

  ws.onopen = function () {
    setStatus("Connecting...", "alert-secondary");
    ws.send(JSON.stringify({ url: url }));
  };

  ws.onmessage = function (e) {
    var msg = JSON.parse(e.data);
    if (msg.type === "resolved") {
      showResolved(msg.data);
      setStatus(
        "Resolved " + msg.data.hostname + " to " + msg.data.ip,
        "alert-secondary",
      );
    } else if (msg.type === "capturing") {
      setStatus(msg.message, "alert-warning");
    } else if (msg.type === "packet") {
      if (!startTime) startTime = msg.data.timestamp;
      var idx = allPackets.length;
      allPackets.push(msg.data);
      packetCount++;
      document.getElementById("packets-table").classList.remove("d-none");
      addTableRow(msg.data, idx);
    } else if (msg.type === "done") {
      setStatus(
        "Capture complete -- " + packetCount + " packets",
        "alert-success",
      );
      btn.disabled = false;
    } else if (msg.type === "error") {
      setStatus("Error: " + msg.message, "alert-danger");
      btn.disabled = false;
    }
  };

  ws.onerror = function () {
    setStatus("WebSocket error -- is the backend running?", "alert-danger");
    btn.disabled = false;
  };

  ws.onclose = function () {
    btn.disabled = false;
  };
}

document.getElementById("url-input").addEventListener("keydown", function (e) {
  if (e.key === "Enter") startInspect();
});
