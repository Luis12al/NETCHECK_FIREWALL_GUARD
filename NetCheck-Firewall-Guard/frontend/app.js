"use strict";
const byId = id => document.getElementById(id);
const nf = new Intl.NumberFormat("es-CO");
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Token de sesión: lo inserta el servidor en la página. Sin él la API responde 401.
const TOKEN = document.querySelector('meta[name="netcheck-token"]').content;

async function rawFetch(path, options = {}) {
  const r = await fetch(path, { ...options, credentials: "same-origin", headers: { ...(options.headers || {}), "X-NetCheck-Token": TOKEN } });
  if (!r.ok) {
    const e = new Error("HTTP " + r.status); e.status = r.status;
    try { const b = await r.json(); e.detail = typeof b.detail === "string" ? b.detail : ""; } catch (_) { e.detail = ""; }
    if (r.status === 429 && !e.detail) e.detail = "Demasiadas peticiones; espera un momento.";
    throw e;
  }
  return r;
}
async function api(path, options) { return (await rawFetch(path, options)).json(); }
function showMsg(el, kind, text) { el.className = `notice ${kind} msg show`; el.textContent = text; }

// Las descargas también llevan el token, así que se hacen con fetch y se entregan como blob.
async function download(url, msgEl) {
  try {
    const r = await rawFetch(url);
    const name = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || "netcheck.pcapng";
    const sha = r.headers.get("X-Content-SHA256");
    const blobUrl = URL.createObjectURL(await r.blob());
    const a = document.createElement("a"); a.href = blobUrl; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 2000);
    if (msgEl) showMsg(msgEl, "good", `Descargado ${name}. SHA-256: ${sha} (compáralo con Get-FileHash para comprobar que el archivo no cambió).`);
  } catch (e) { if (msgEl) showMsg(msgEl, "bad", e.detail || "No se pudo descargar."); }
}
const exportUrl = source => `/api/packets/${source}/export${byId("showPayload").checked ? "?payload=true" : ""}`;

const PAGES = {
  live: ["Monitor en vivo", "Tráfico real de la tarjeta de red de este equipo, inspeccionado paquete a paquete."],
  pcap: ["Archivo de captura", "Analiza un .pcap / .pcapng de Wireshark o tcpdump con el mismo inspector."],
  lab: ["Laboratorio", "Construye un paquete con un defecto concreto y mira cómo lo evalúa cada regla."],
  alerts: ["Auditoría", "Descartes registrados en netcheck.log y contadores de la sesión."],
  security: ["Seguridad (CID)", "Controles de confidencialidad, integridad y disponibilidad, con su estado en vivo."],
  how: ["Cómo funciona", "Qué hace el programa con cada paquete y cómo verificarlo."]
};
function goto(page) {
  document.querySelectorAll("[data-page]").forEach(b => b.classList.toggle("active", b.dataset.page === page));
  document.querySelectorAll(".page").forEach(s => s.classList.toggle("active", s.id === page));
  byId("pageTitle").textContent = PAGES[page][0];
  byId("pageSubtitle").textContent = PAGES[page][1];
  if (page === "alerts") refreshGlobal();
  if (page === "security") refreshSecurity();
}
document.querySelectorAll("[data-page]").forEach(b => b.addEventListener("click", () => goto(b.dataset.page)));
goto("live");

/* ===================== Visor de paquetes (tabla + disección + hex) ===================== */
function fmtTime(ts, t0) {
  if (!ts) return "—";
  if (t0 != null) return (ts - t0).toFixed(6);
  return new Date(ts * 1000).toLocaleTimeString("es-CO", { hour12: false }) + "." + String(Math.floor((ts % 1) * 1000)).padStart(3, "0");
}
function verdictTag(r) {
  if (r.status === "SKIPPED") return '<span class="v v-skip">OMITIDO</span>';
  if (r.status === "VALID") return r.checksum_offload ? '<span class="v v-off" title="Saliente: checksum por la tarjeta">ALLOW·NIC</span>' : '<span class="v v-ok">ALLOW</span>';
  return `<span class="v v-drop">DROP</span>`;
}

function renderDetail(container, d, opts = {}) {
  if (!d) { container.innerHTML = '<div class="empty">Selecciona un paquete de la lista para ver sus cabeceras campo por campo.</div>'; return; }
  const cls = d.status === "VALID" ? "ok" : d.status === "SKIPPED" ? "skip" : "drop";
  const head = d.status === "SKIPPED"
    ? `<b>Paquete #${d.no}: no es IPv4</b><br>${esc(d.reason)}. Se cuenta y se deja pasar sin inspección.`
    : d.status === "VALID"
      ? `<b>Paquete #${d.no}: VÁLIDO → ALLOW</b><br>${esc(d.reason)}`
      : `<b>Paquete #${d.no}: ${d.status === "INVALID" ? "ANOMALÍA" : "NO VERIFICADO"} → DROP</b><br>${esc(d.reason)}${opts.monitor ? "<br><span style='opacity:.8'>Modo monitor: registrado en el log, no bloqueado.</span>" : ""}`;
  const layers = d.layers || [];
  const byteLayer = new Array(d.hex.length / 2).fill(3);
  const badBytes = new Set();
  layers.forEach(l => {
    const li = l.name.startsWith("Datos") ? 3 : l.name.startsWith("IPv") ? 1 : ["TCP", "UDP", "ICMP"].includes(l.name) ? 2 : 0;
    for (let k = l.offset; k < l.offset + l.length && k < byteLayer.length; k++) byteLayer[k] = li;
    l.fields.forEach(f => { if (f.state === "bad") for (let k = f.offset; k < f.offset + f.length; k++) badBytes.add(k); });
  });
  const layerHtml = layers.map((l, li) => `
    <details class="layer" ${l.name.startsWith("Datos") ? "" : "open"}>
      <summary>${esc(l.name)}<span>bytes ${l.offset}–${l.offset + l.length - 1}</span></summary>
      ${l.fields.map(f => `<div class="field ${f.state || ""}" data-o="${f.offset}" data-l="${f.length}"><span class="fn">${esc(f.name)}</span><span class="fv">${esc(f.value)}</span></div>`).join("")}
    </details>`).join("");
  let hex = "";
  const bytes = d.hex.match(/../g) || [];
  for (let row = 0; row < bytes.length; row += 16) {
    const chunk = bytes.slice(row, row + 16);
    const hx = chunk.map((b, j) => {
      const i = row + j;
      return `<span class="b L${byteLayer[i]}${badBytes.has(i) ? " badb" : ""}" data-i="${i}">${b}</span>` + (j === 7 ? "  " : " ");
    }).join("");
    const pad = "   ".repeat(16 - chunk.length) + (chunk.length <= 8 ? " " : "");
    const ascii = chunk.map(b => { const c = parseInt(b, 16); return c >= 32 && c < 127 ? esc(String.fromCharCode(c)) : "."; }).join("");
    hex += `<span class="off">${row.toString(16).padStart(4, "0")}</span>${hx}${pad}<span class="ascii">${ascii}</span>\n`;
  }
  const extra = [];
  if (d.src) extra.push(`${esc(d.src)} → ${esc(d.dst)}`);
  if (d.direction) extra.push(`dirección: ${esc(d.direction)}`);
  extra.push(`${d.length} bytes en el cable`);
  container.innerHTML = `
    <div class="card-head"><div><h3>Detalle del paquete #${d.no}</h3><p class="mono">${extra.join(" · ")}</p></div></div>
    <div class="verdict ${cls}">${head}</div>
    <div class="layers">${layerHtml}</div>
    <div class="hexbox"><h4>Bytes capturados${d.hex_truncated ? " (primeros 4096)" : ""}</h4><div class="hex">${hex}</div>
      ${d.payload_hidden ? `<div class="notice info" style="margin:8px 0 0"><span>🔒</span><span>Se muestran solo las cabeceras. Los ${d.payload_bytes} bytes de contenido (payload) no se enviaron al navegador. Actívalos con «Mostrar contenido» en la barra superior.</span></div>` : ""}
      <div class="legend"><span><i style="background:#8fb3e8"></i>Enlace</span><span><i style="background:#6fe0c6"></i>IPv4</span><span><i style="background:#e6c07b"></i>Transporte</span><span><i style="background:#6d7d99"></i>Datos</span><span><i style="background:rgba(255,93,108,.6)"></i>Campo con anomalía</span><span>Pasa el cursor por un campo para ver sus bytes</span></div></div>`;
  const hexSpans = container.querySelectorAll(".hex span.b");
  container.querySelectorAll(".field").forEach(f => {
    const o = +f.dataset.o, l = +f.dataset.l;
    f.addEventListener("mouseenter", () => { for (let k = o; k < o + l && k < hexSpans.length; k++) hexSpans[k].classList.add("hl"); });
    f.addEventListener("mouseleave", () => hexSpans.forEach(s => s.classList.remove("hl")));
  });
  hexSpans.forEach(s => s.addEventListener("mouseenter", () => {
    const i = +s.dataset.i;
    container.querySelectorAll(".field").forEach(f => f.classList.toggle("hl", i >= +f.dataset.o && i < +f.dataset.o + +f.dataset.l && +f.dataset.l < 64));
  }));
}

class PacketViewer {
  constructor(root, source, { monitor = false, max = 3000, relative = false } = {}) {
    this.source = source; this.monitor = monitor; this.max = max; this.relative = relative;
    this.rows = []; this.lastNo = 0; this.selected = null; this.t0 = null;
    root.innerHTML = `
      <section class="card">
        <div class="controls" style="border-bottom:1px solid var(--line)">
          <select data-r="only"><option value="all">Todos</option><option value="ipv4">Solo IPv4</option><option value="anomalies">Solo anomalías (DROP)</option></select>
          <select data-r="proto"><option value="">Todo protocolo</option><option>TCP</option><option>UDP</option><option>ICMP</option><option>DNS</option><option>IPv6</option><option>ARP</option></select>
          <input data-r="ip" placeholder="Filtrar por IP" style="width:140px">
          <span class="muted" data-r="shown" style="margin-left:auto;font-size:11.5px"></span>
        </div>
        <div class="pkt-table-wrap"><table class="pkts"><thead><tr><th class="num">No.</th><th>${relative ? "Tiempo (s)" : "Hora"}</th><th>Origen</th><th>Destino</th><th>Proto</th><th class="num">Long.</th><th class="num">TTL</th><th>Info</th><th>Veredicto</th></tr></thead><tbody data-r="body"></tbody></table></div>
      </section>
      <section class="card detail" data-r="detail"></section>`;
    this.$ = n => root.querySelector(`[data-r="${n}"]`);
    ["only", "proto"].forEach(n => this.$(n).addEventListener("change", () => this.render()));
    this.$("ip").addEventListener("input", () => this.render());
    this.$("body").addEventListener("click", e => { const tr = e.target.closest("tr[data-no]"); if (tr) this.select(+tr.dataset.no); });
    renderDetail(this.$("detail"), null);
  }
  reset() { this.rows = []; this.lastNo = 0; this.selected = null; this.t0 = null; this.render(); renderDetail(this.$("detail"), null); }
  async poll() {
    const res = await api(`/api/packets/${this.source}?after=${this.lastNo}&limit=1000`);
    if (res.rows.length) {
      if (this.t0 == null) this.t0 = res.rows[0].ts;
      res.rows.forEach(r => r._fresh = this.lastNo > 0);
      this.rows.push(...res.rows);
      if (this.rows.length > this.max) this.rows.splice(0, this.rows.length - this.max);
      this.lastNo = res.rows[res.rows.length - 1].no;
      this.render();
    }
    return res;
  }
  filtered() {
    const only = this.$("only").value, proto = this.$("proto").value.toLowerCase(), ip = this.$("ip").value.trim();
    return this.rows.filter(r =>
      (only === "all" || (only === "ipv4" ? r.status !== "SKIPPED" : (r.status === "INVALID" || r.status === "UNVERIFIED"))) &&
      (!proto || r.protocol.toLowerCase() === proto) && (!ip || r.src === ip || r.dst === ip || (r.src || "").startsWith(ip) || (r.dst || "").startsWith(ip)));
  }
  render() {
    const list = this.filtered();
    const shown = list.slice(-600).reverse();   // los más recientes arriba
    this.$("shown").textContent = `${nf.format(list.length)} de ${nf.format(this.rows.length)} en pantalla` + (list.length > 600 ? " (se muestran los 600 más recientes)" : "");
    this.$("body").innerHTML = shown.length ? shown.map(r => {
      const cls = [r.status === "SKIPPED" ? "skip" : (r.status === "INVALID" || r.status === "UNVERIFIED") ? "bad" : "", r.no === this.selected ? "sel" : "", r._fresh ? "fresh" : ""].join(" ");
      const dir = r.direction === "saliente" ? "↑" : r.direction === "entrante" ? "↓" : "";
      return `<tr class="${cls}" data-no="${r.no}"><td class="num">${r.no}</td><td>${fmtTime(r.ts, this.relative ? this.t0 : null)}</td>
        <td>${esc(r.src ?? "—")}${r.src_port != null ? `<span class="dir">:${r.src_port}</span>` : ""}</td>
        <td>${esc(r.dst ?? "—")}${r.dst_port != null ? `<span class="dir">:${r.dst_port}</span>` : ""} <span class="dir">${dir}</span></td>
        <td>${esc(r.protocol)}</td><td class="num">${r.length}</td><td class="num">${r.ttl ?? ""}</td>
        <td title="${esc(r.status === "VALID" || r.status === "SKIPPED" ? r.info : r.reason)}">${esc(r.status === "INVALID" || r.status === "UNVERIFIED" ? r.reason : r.info)}</td><td>${verdictTag(r)}</td></tr>`;
    }).join("") : `<tr><td colspan="9" class="empty">${this.emptyText || "Sin paquetes."}</td></tr>`;
    this.rows.forEach(r => r._fresh = false);
  }
  async select(no) {
    this.selected = no;
    this.$("body").querySelectorAll("tr").forEach(tr => tr.classList.toggle("sel", +tr.dataset.no === no));
    try { renderDetail(this.$("detail"), await api(`/api/packets/${this.source}/${no}${byId("showPayload").checked ? "?payload=true" : ""}`), { monitor: this.monitor }); }
    catch (e) { this.$("detail").innerHTML = `<div class="empty">${esc(e.detail || "No se pudo cargar el paquete.")}</div>`; }
  }
}

/* ===================== Monitor en vivo ===================== */
const liveViewer = new PacketViewer(byId("liveViewer"), "live", { monitor: true });
liveViewer.emptyText = "Elige una interfaz y pulsa “Iniciar captura”. Luego abre una página web o haz ping para ver tu tráfico real.";
liveViewer.render();
let interfaces = [], capState = { running: false }, ppsHistory = [], lastCount = null;

async function loadInterfaces() {
  try {
    const info = await api("/api/capture/interfaces");
    byId("libInfo").innerHTML = info.available ? `Captura: <code>${esc(info.version.split(",")[0])}</code>` : "Captura en vivo: <b style='color:var(--orange)'>no disponible</b>";
    const nl = byId("noLib");
    if (!info.available || info.error) {
      nl.hidden = false;
      nl.innerHTML = `<span>⚠</span><span><b>No se puede capturar en este equipo.</b> ${esc(info.error || "")}<br>${esc(info.hint || "")} El análisis de archivos PCAP y el laboratorio siguen funcionando.</span>`;
    } else nl.hidden = true;
    interfaces = info.interfaces || [];
    const sel = byId("ifaceSel"), prev = sel.value;
    sel.innerHTML = interfaces.map(i => {
      const ips = i.ips.length ? i.ips.join(", ") : "sin IPv4";
      const tag = i.loopback ? " · loopback (pruebas)" : i.wireless ? " · Wi‑Fi" : "";
      return `<option value="${esc(i.id)}">${esc(i.description)} — ${esc(ips)}${tag}${i.connected ? "" : " · desconectada"}</option>`;
    }).join("") || "<option value=''>No se encontraron interfaces</option>";
    if (prev && interfaces.some(i => i.id === prev)) sel.value = prev;
    byId("startBtn").disabled = !interfaces.length;
  } catch (e) {
    byId("libInfo").textContent = "No se pudo consultar la captura.";
  }
}

function sparkline(values) {
  const max = Math.max(1, ...values), w = 120, h = 26;
  const pts = values.map((v, i) => `${(i / Math.max(1, values.length - 1)) * w},${h - 2 - (v / max) * (h - 4)}`).join(" ");
  byId("spark").innerHTML = values.length > 1 ? `<polyline points="${pts}" fill="none" stroke="#3fd0c9" stroke-width="1.5"/>` : "";
}

function applyCapState(s) {
  const was = capState.running;
  capState = s;
  const c = s.counts;
  byId("lkTotal").textContent = nf.format(c.total);
  byId("lkIpv4").textContent = nf.format(c.ipv4);
  byId("lkValid").textContent = nf.format(c.valid);
  byId("lkInvalid").textContent = nf.format(c.invalid + c.unverified);
  byId("lkSkipped").textContent = nf.format(c.skipped);
  byId("lkLogged").textContent = `registradas en log: ${nf.format(s.logged)}`;
  byId("startBtn").hidden = s.running; byId("stopBtn").hidden = !s.running;
  byId("ifaceSel").disabled = s.running;
  const pill = byId("capPill");
  if (s.running) {
    const secs = Math.round(Date.now() / 1000 - s.started_at);
    byId("lkElapsed").textContent = `capturando hace ${secs < 60 ? secs + " s" : Math.floor(secs / 60) + " min " + (secs % 60) + " s"}`;
    pill.className = "pill live";
    byId("capPillText").textContent = `Capturando · ${s.interface.description.slice(0, 32)}${s.interface.ips[0] ? " · " + s.interface.ips[0] : ""}`;
    if (lastCount != null) { ppsHistory.push(Math.max(0, c.total - lastCount)); if (ppsHistory.length > 60) ppsHistory.shift(); }
    lastCount = c.total;
    byId("lkPps").textContent = nf.format(ppsHistory.at(-1) ?? 0);
    sparkline(ppsHistory);
  } else {
    pill.className = "pill off";
    byId("capPillText").textContent = s.error ? "Captura detenida por error" : "Sin captura";
    byId("lkElapsed").textContent = c.total ? "captura detenida" : "—";
    byId("lkPps").textContent = "0"; lastCount = null;
  }
  if (s.error) showMsg(byId("probeMsg"), "bad", "Captura: " + s.error);
  if (s.interface && s.running && !was) byId("ifaceSel").value = s.interface.id;
}

async function liveTick() {
  try {
    const s = await api("/api/capture/status");
    applyCapState(s);
    if (s.running || liveViewer.lastNo < s.counts.total) await liveViewer.poll();
    setApi(true);
  } catch (e) { setApi(false); }
}

byId("startBtn").addEventListener("click", async () => {
  const id = byId("ifaceSel").value;
  if (!id) return;
  byId("startBtn").disabled = true;
  try {
    liveViewer.reset(); ppsHistory = []; lastCount = null;
    applyCapState(await api("/api/capture/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ interface: id }) }));
    byId("probeMsg").className = "notice warn msg";
  } catch (e) { showMsg(byId("probeMsg"), "bad", e.detail || "No se pudo iniciar la captura."); }
  byId("startBtn").disabled = false;
});
byId("stopBtn").addEventListener("click", async () => { applyCapState(await api("/api/capture/stop", { method: "POST" })); });
byId("refreshIfaces").addEventListener("click", loadInterfaces);
byId("liveExport").addEventListener("click", () => liveViewer.rows.length ? download(exportUrl("live"), byId("probeMsg")) : showMsg(byId("probeMsg"), "warn", "Todavía no hay paquetes capturados para exportar."));

const PROBE_TEXT = { ok: "paquete correcto", checksum: "checksum alterado", ttl: "TTL = 0", version: "versión IP = 5", length: "longitud total falsa" };
document.querySelectorAll("[data-probe]").forEach(b => b.addEventListener("click", async () => {
  const msg = byId("probeMsg");
  if (!(capState.running && capState.interface && capState.interface.loopback)) {
    const lo = interfaces.find(i => i.loopback);
    if (!lo) { showMsg(msg, "bad", "No hay interfaz de loopback disponible en este equipo."); return; }
    if (!confirm("Para inyectar paquetes de prueba hay que capturar en la interfaz de loopback (127.0.0.1). ¿Cambiar ahora?")) return;
    byId("ifaceSel").value = lo.id;
    if (capState.running) await api("/api/capture/stop", { method: "POST" });
    liveViewer.reset(); ppsHistory = []; lastCount = null;
    applyCapState(await api("/api/capture/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ interface: lo.id }) }));
  }
  try {
    await api("/api/capture/probe", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind: b.dataset.probe }) });
    showMsg(msg, b.dataset.probe === "ok" ? "good" : "warn", `Inyectado: ${PROBE_TEXT[b.dataset.probe]}. Búscalo arriba (UDP 40000 → 9); el filtro “Solo anomalías” lo aísla.`);
    setTimeout(async () => {
      await liveTick();
      const hit = [...liveViewer.rows].reverse().find(r => r.dst_port === 9 && r.src_port === 40000);
      if (hit) liveViewer.select(hit.no);
    }, 700);
  } catch (e) { showMsg(msg, "bad", e.detail || "No se pudo inyectar el paquete."); }
}));

/* ===================== PCAP ===================== */
const pcapViewer = new PacketViewer(byId("pcapViewer"), "pcap", { relative: true, max: 50000 });
pcapViewer.emptyText = "Sube un archivo .pcap / .pcapng o usa la captura de ejemplo.";
pcapViewer.render();
async function runPcap(request, name) {
  const msg = byId("pcapMsg");
  showMsg(msg, "info", "Analizando…");
  try {
    const res = await request();
    byId("pkTotal").textContent = nf.format(res.frames_total);
    byId("pkFormat").textContent = `${res.format} · ${res.linktype_name}`;
    byId("pkIpv4").textContent = nf.format(res.ipv4_analyzed);
    byId("pkValid").textContent = nf.format(res.valid);
    byId("pkInvalid").textContent = nf.format(res.invalid + res.unverified);
    byId("pkSkipped").textContent = nf.format(res.skipped_non_ipv4);
    byId("pkLogged").textContent = `en log: ${res.logged} (máx. ${res.log_limit})`;
    byId("pkName").textContent = name;
    pcapViewer.reset();
    while (true) { const r = await pcapViewer.poll(); if (r.rows.length < 1000) break; }
    const first = pcapViewer.rows.find(r => r.status === "INVALID" || r.status === "UNVERIFIED");
    if (first) pcapViewer.select(first.no);
    const notes = [`Análisis terminado: ${res.valid} válidos y ${res.invalid + res.unverified} con anomalías.`];
    (res.warnings || []).forEach(w => notes.push(w));
    showMsg(msg, res.invalid + res.unverified ? "warn" : "good", notes.join(" "));
  } catch (e) {
    showMsg(msg, "bad", e.status === 413 ? "El archivo supera el máximo de 25 MB." : e.detail || "No se pudo analizar la captura.");
  }
}
byId("pcapBtn").addEventListener("click", () => {
  const f = byId("pcapFile").files[0];
  if (!f) return showMsg(byId("pcapMsg"), "warn", "Selecciona primero un archivo .pcap o .pcapng.");
  if (f.size > 25 * 1024 * 1024) return showMsg(byId("pcapMsg"), "warn", "El archivo supera el máximo de 25 MB.");
  runPcap(() => api("/api/analyze-pcap", { method: "POST", headers: { "Content-Type": "application/octet-stream", "X-Filename": encodeURIComponent(f.name) }, body: f }), f.name);
});
byId("pcapSampleBtn").addEventListener("click", () => runPcap(() => api("/api/analyze-sample", { method: "POST" }), "samples/ejemplo.pcap"));
byId("pcapExport").addEventListener("click", () => pcapViewer.rows.length ? download(exportUrl("pcap"), byId("pcapMsg")) : showMsg(byId("pcapMsg"), "warn", "Analiza primero un archivo."));

/* ===================== Laboratorio ===================== */
const ipv4Re = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
byId("labForm").addEventListener("submit", async e => {
  e.preventDefault();
  const msg = byId("labMsg"), ip = byId("labIp").value.trim(), len = Number(byId("labLen").value);
  if (!ipv4Re.test(ip)) return showMsg(msg, "warn", "Escribe una IPv4 válida, por ejemplo 192.168.1.10.");
  if (!Number.isInteger(len) || len < 20 || len > 60 || len % 4) return showMsg(msg, "warn", "La cabecera debe medir entre 20 y 60 bytes, en múltiplos de 4.");
  const manual = document.querySelector('input[name="labAction"]:checked').value;
  try {
    const res = await api("/api/simulate", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: byId("labIface").value, ip, headerLength: len, checksum: byId("labCk").value, issue: byId("labIssue").value, action: manual }) });
    const kind = res.result === "VALID" ? "good" : res.manual_conflict ? "warn" : "bad";
    showMsg(msg, kind, `Resultado: ${res.result} → ${res.action}. ${res.reason}.` + (res.manual_conflict ? " Tu acción esperada (ALLOW) contradice al motor: revisar." : "") + (res.action === "DROP" ? " Registrado en el log." : ""));
    const d = await api(`/api/packets/lab/${res.packet_no}`);
    renderDetail(byId("labDetail"), d);
  } catch (err) {
    showMsg(msg, "bad", err.status === 422 ? "El backend rechazó los datos (validación de entrada)." : "No se pudo contactar con el backend.");
  }
});

/* ===================== Auditoría y global ===================== */
let gStats = { total: 0, valid: 0, dropped: 0, pending: 0 }, alerts = [];
function setApi(ok) {
  byId("apiPill").className = "pill" + (ok ? "" : " off");
  byId("apiPillText").textContent = ok ? "API conectada" : "API sin conexión";
}
async function refreshGlobal() {
  try {
    const [s, a] = await Promise.all([api("/api/statistics"), api("/api/alerts")]);
    gStats = s; alerts = a.alerts;
    byId("gTotal").textContent = nf.format(s.total); byId("gValid").textContent = nf.format(s.valid);
    byId("gDrop").textContent = nf.format(s.dropped); byId("gPending").textContent = nf.format(s.pending);
    const badge = byId("navBadge"); badge.hidden = !s.pending; badge.textContent = s.pending > 999 ? "999+" : s.pending;
    byId("alertTable").innerHTML = alerts.length ? alerts.map(x => `<tr><td class="mono">${esc(x.timestamp)}</td><td class="mono">${esc(x.ip_src)}</td><td class="mono">${esc(x.ip_dst)}</td><td>${esc(x.reason)}</td><td><span class="v ${x.action === "DROP" ? "v-drop" : "v-off"}">${esc(x.action)}</span>${x.signed ? ' <span title="Línea firmada con HMAC" class="dir">🔏</span>' : ""}</td></tr>`).join("")
      : '<tr><td colspan="5" class="empty">No hay descartes en el registro.</td></tr>';
    setApi(true);
  } catch (e) { setApi(false); }
}
byId("ackBtn").addEventListener("click", async () => { await api("/api/alerts/ack", { method: "POST" }); refreshGlobal(); });
byId("resetStatsBtn").addEventListener("click", async () => {
  if (!confirm("¿Poner en cero los contadores globales de la sesión? No se borra el log ni los paquetes capturados.")) return;
  await api("/api/reset", { method: "POST" }); refreshGlobal();
});
byId("exportBtn").addEventListener("click", async () => {
  await refreshGlobal();
  const c = capState.counts || {};
  let sec = null;
  try { sec = await api("/api/security"); } catch (_) {}
  const lg = sec?.integrity.log;
  const lines = [
    "NetCheck Firewall Guard v2.1 — Reporte", `Generado: ${new Date().toISOString()}`, "",
    "== Tríada CID ==",
    `Confidencialidad: token de sesión obligatorio, Host/Origin validados, CSP, payload oculto por defecto, sin modo promiscuo.`,
    lg ? `Integridad del log: ${lg.ok ? "ÍNTEGRO" : "ALTERADO"} · ${lg.signed} líneas firmadas (HMAC-SHA256 encadenado) · ${lg.detail}` : "Integridad del log: no disponible",
    sec?.integrity.last_export ? `Última exportación: ${sec.integrity.last_export.file} · SHA-256 ${sec.integrity.last_export.sha256}` : "Última exportación: ninguna",
    sec ? `Disponibilidad: activo ${Math.round(sec.availability.uptime_s / 60)} min · disco libre ${(sec.availability.disk_free_bytes / 1e9).toFixed(1)} GB · peticiones rechazadas por límite: ${sec.confidentiality.rejected.rate_limited}` : "",
    "",
    "== Captura en vivo (modo monitor) ==",
    capState.interface ? `Interfaz: ${capState.interface.description} (${capState.interface.ips.join(", ")})` : "Interfaz: (sin captura)",
    `Tramas vistas: ${c.total ?? 0} | IPv4: ${c.ipv4 ?? 0} | Válidos: ${c.valid ?? 0} | Anomalías: ${(c.invalid ?? 0) + (c.unverified ?? 0)} | No IPv4: ${c.skipped ?? 0}`,
    "", "== Totales de la sesión (vivo + PCAP + laboratorio) ==",
    `Revisados: ${gStats.total} | Válidos: ${gStats.valid} | Descartados: ${gStats.dropped} | Sin revisar: ${gStats.pending}`,
    "", "== Últimos descartes en netcheck.log ==",
    ...(alerts.length ? alerts.slice(0, 30).map(a => `${a.timestamp} UTC | ${a.ip_src} -> ${a.ip_dst} | ${a.action} | ${a.reason}`) : ["(sin eventos)"]),
    "", "Nota: en modo monitor la decisión DROP se registra pero el tráfico no se bloquea.",
    "El checksum IPv4 detecta corrupción accidental; no acredita autenticidad."
  ];
  const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a"); a.href = url; a.download = "reporte-netcheck.txt"; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
});

/* ===================== Arranque ===================== */
loadInterfaces();
liveTick();
refreshGlobal();
setInterval(liveTick, 1000);
setInterval(refreshGlobal, 5000);

/* ===================== Seguridad (tríada CID) ===================== */
const fmtBytes = n => n >= 1e9 ? (n / 1e9).toFixed(1) + " GB" : n >= 1e6 ? (n / 1e6).toFixed(1) + " MB" : n >= 1e3 ? (n / 1e3).toFixed(0) + " KB" : n + " B";
const check = (ok, text, sub = "") => `<li class="${ok ? "ok" : "bad"}"><span>${ok ? "✓" : "✗"}</span><div>${text}${sub ? `<small>${sub}</small>` : ""}</div></li>`;

function renderLogResult(r) {
  const el = byId("logVerify");
  el.className = `notice ${r.ok ? "good" : "bad"} msg show`;
  el.innerHTML = `<span>${r.ok ? "🔏" : "⚠"}</span><span><b>${r.ok ? "Registro íntegro." : "Registro ALTERADO."}</b> ${esc(r.detail)}<br>
    ${r.signed} líneas firmadas · ${r.unsigned} sin firma (anteriores a la v2.1) · archivos: ${esc((r.files || []).join(", "))}</span>`;
}

async function refreshSecurity() {
  let s;
  try { s = await api("/api/security"); } catch (e) { return; }
  const c = s.confidentiality, i = s.integrity, a = s.availability, rj = c.rejected;
  byId("secConf").innerHTML = [
    check(true, "Token de sesión obligatorio en toda la API", `Peticiones sin token rechazadas: ${rj.rejected_token}`),
    check(true, `Solo responde a ${esc(c.allowed_hosts.join(", "))}`, `Bloquea DNS rebinding · Host rechazados: ${rj.rejected_host}`),
    check(true, "Origen validado (anti-CSRF)", `Peticiones de otros sitios bloqueadas: ${rj.rejected_origin}`),
    check(true, "Cabeceras de seguridad y CSP sin scripts externos", esc(c.headers.join(", "))),
    check(c.payload_hidden_by_default, "Contenido de los paquetes oculto por defecto", "Ni el panel ni la exportación lo incluyen salvo que se active «Mostrar contenido»"),
    check(!c.promiscuous, "Captura sin modo promiscuo", "Solo tráfico de este equipo, no el de otros dispositivos de la red"),
    check(!c.log_has_payload, "El log nunca guarda payload", "Solo fecha, IPs, acción y motivo"),
    check(true, "Servidor ligado a 127.0.0.1", "No es accesible desde otros equipos"),
  ].join("");
  const lg = i.log;
  byId("secInt").innerHTML = [
    check(lg.ok, `Registro de auditoría ${lg.ok ? "íntegro" : "ALTERADO"}`, `${esc(i.log_signature)} · ${lg.signed} líneas firmadas · ${esc(lg.detail)}`),
    check(true, "Acciones del operador registradas", "Inicio/fin de captura, inyecciones, reinicios, exportaciones y verificaciones"),
    check(true, "Checksum IPv4 recalculado (RFC 1071)", "Integridad de cabeceras; no autentica al emisor"),
    check(true, "Huella SHA-256 de archivos analizados y exportados", i.last_export ? `Última: ${esc(i.last_export.file)} · <span class="mono">${esc(i.last_export.sha256)}</span>` : "Aún no se exportó nada"),
    check(true, "Validación estricta de entradas (Pydantic) y de interfaces", "Solo se aceptan interfaces que reporta el sistema"),
    check(true, "Dependencias con versión fija", "requirements.txt"),
  ].join("");
  const cap = a.capture;
  byId("secAvail").innerHTML = [
    check(true, `Servidor activo hace ${Math.floor(a.uptime_s / 3600)} h ${Math.floor(a.uptime_s % 3600 / 60)} min`, "Concurrencia limitada a 64 conexiones; keep-alive 5 s"),
    check(rj.rate_limited === 0, "Límite de peticiones por segundo", `${c.rate_limit.per_second}/s (ráfaga ${c.rate_limit.burst}) · rechazadas: ${rj.rate_limited}`),
    check(true, `Log con rotación: ${fmtBytes(a.log_rotation.max_bytes)} × ${a.log_rotation.files} archivos`, `Máx. ${a.log_limit_live} líneas por captura en vivo · omitidas: ${a.log_skipped_live}`),
    check(!a.disk_low, `Disco libre: ${fmtBytes(a.disk_free_bytes)}`, a.disk_low ? "Queda poco espacio" : "Suficiente"),
    check(true, "Memoria acotada", `Búferes: vivo ${a.buffers.live}, PCAP ${a.buffers.pcap}, laboratorio ${a.buffers.lab} paquetes · subida máx. ${fmtBytes(a.upload_limit_bytes)}`),
    cap ? check(cap.running && !cap.error, `Captura ${cap.running ? "activa" : "detenida"}${cap.error ? ": " + esc(cap.error) : ""}`,
      `Reconexiones: ${cap.reconnects}/${cap.max_reconnects} · perdidas por el driver: ${cap.driver_stats.dropped} · errores de paquete: ${cap.packet_errors}`)
      : check(true, "Captura en espera", "Se reconecta sola hasta 5 veces si la tarjeta falla"),
  ].join("");
}

byId("verifyLogBtn").addEventListener("click", async () => {
  try { renderLogResult(await api("/api/audit/verify")); refreshSecurity(); }
  catch (e) { showMsg(byId("logVerify"), "bad", e.detail || "No se pudo verificar."); }
});
byId("showPayload").addEventListener("change", () => {
  [liveViewer, pcapViewer].forEach(v => v.selected && v.select(v.selected));
});
setInterval(() => { if (byId("security").classList.contains("active")) refreshSecurity(); }, 5000);
