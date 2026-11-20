"use strict";

// iEXAM's map palette (GraphPreview.tsx): fixed slate boxes in both themes.
const MAP = { node: "#1e293b", nodeBorder: "#475569", vuln: "#f59e0b", exploited: "#ef4444", edge: "#94a3b8",
  selected: "#3b82f6", self: "#64748b" };
const ICONS = {
  check: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>',
  cross: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  spinner: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12a9 9 0 1 1-6.2-8.6"/></svg>',
  back: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m15 18-6-6 6-6"/></svg>',
  sun: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  moon: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>',
};
const KIND_NAMES = { router: "Router", switch: "Switch", camera: "Camera", computer: "Computer", phone: "Phone", tablet: "Tablet",
  tv: "TV", speaker: "Speaker", printer: "Printer", iot: "Smart device", unknown: "Unknown device" };

// Page stages. Scan Your Network = run.py scan + cveinfo; Plan = export + plan (see web/jobs.py).
const STAGES = ["discover", "gather", "scan", "plan", "mitigate"];
const NETWORK_STAGES = STAGES.slice(0, 3);  // Plan and Mitigate run from their own pages
const STAGE_PAGE = { plan: "#/plan", mitigate: "#/mitigate" };
const STAGE_NAMES = { discover: "Discover Your Devices", gather: "Gather", scan: "Scan Your Network",
  plan: "Start Planning", mitigate: "Mitigate", optimal: "Optimal plan", topk: "Top-K plans", guide: "Explain how to fix" };
const PAGE_NAMES = { plan: "Security Profile", mitigate: "Mitigate" };
const STEP_NAMES = { scan: "network scan", cveinfo: "CVE details", export: "preparing iEXAM's input files", plan: "building the attack graph" };

let model = null;
let plans = null;       // phase 7 plans.json for the loaded run, or null
let mitigation = null;  // phase 8 mitigation.json, or null
let guide = null;       // phase 8b guide.json, or null
let runs = [];
let currentRun = null;
let cy = null;
let showWeak = false;
let job = null;
let pollTimer = null;
let followJob = false;  // reload the page's run as the job's stages finish
let lastDone = -1;

const $ = (sel) => document.querySelector(sel);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

function tier(node) {
  if (node.kev_count > 0) return "exploited";
  if (node.risk >= 7) return "high";
  if (node.risk > 0) return "low";
  return "clean";
}
function scoreTier(cve) {
  if (cve.kev) return "exploited";
  if ((cve.cvss || 0) >= 7) return "high";
  if ((cve.cvss || 0) > 0) return "low";
  return "clean";
}
// Until Gather has run we only know addresses: show the IP and a generic router/device type.
const gathered = () => model.stages.includes("gather");
const shownName = (n) => (gathered() || n.kind === "attacker" ? n.name : n.ip);
function kindName(node) {
  if (node.kind === "attacker") return "Internet attacker";
  if (node.kind === "self") return "This monitor";
  if (!gathered()) return node.kind === "router" ? "Router" : "Device";
  return node.kind === "router" ? "Router" : KIND_NAMES[node.label] || "Device";
}
const devices = () => model.nodes.filter((n) => n.kind !== "attacker" && n.kind !== "self");
const strongCves = (node) => node.cves.filter((c) => !c.weak);

async function getJSON(url, options) {
  const res = await fetch(url, options);
  const body = await res.json();
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}
async function getOptional(url) {
  const res = await fetch(url);
  if (res.status === 404) return null;
  const body = await res.json();
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}
const postJSON = (url, body) => getJSON(url, {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

// ---- Theme toggle (dark by default, as in iEXAM; the choice is remembered per browser) ----
function renderThemeToggle() {
  const light = document.documentElement.classList.contains("light");
  const b = $("#theme-toggle");
  b.innerHTML = light ? ICONS.moon : ICONS.sun;
  b.setAttribute("aria-label", light ? "Switch to dark theme" : "Switch to light theme");
  b.title = b.getAttribute("aria-label");
}
function toggleTheme() {
  const light = document.documentElement.classList.toggle("light");
  try { localStorage.setItem("edgeplanner.theme", light ? "light" : "dark"); } catch (e) { /* private mode: not remembered */ }
  renderThemeToggle();
  if (model) {
    const sel = cy?.$(":selected").id();
    renderGraph();
    if (sel) cy.getElementById(sel).select();
  }
}

// ---- Logs drawer ----
let logsReturnFocus = null;
function renderLogs() {
  if ($("#logs").hidden) return;
  const body = $("#logs-body");
  if (!job || job.state === "idle") {
    $("#logs-sub").textContent = "";
    body.textContent = `No pipeline job has run since the server started. Start one with ${STAGE_NAMES.discover} or a stage button.`;
    return;
  }
  $("#logs-sub").textContent = `Scan of ${formatRun(job.run)} · ${job.state}${job.current ? ` · ${STAGE_NAMES[job.current]}` : ""} · last 4 KB`;
  const atEnd = body.scrollTop + body.clientHeight >= body.scrollHeight - 8;
  body.textContent = job.log_tail || "(empty)";
  if (atEnd) body.scrollTop = body.scrollHeight;
}
function openLogs() {
  logsReturnFocus = document.activeElement;
  $("#logs").hidden = false;
  $("#logs-backdrop").hidden = false;
  renderLogs();
  $("#logs-body").scrollTop = $("#logs-body").scrollHeight;
  $("#logs-close").focus();
}
function closeLogs() {
  $("#logs").hidden = true;
  $("#logs-backdrop").hidden = true;
  logsReturnFocus?.focus();
}

async function init() {
  renderThemeToggle();
  $("#theme-toggle").addEventListener("click", toggleTheme);
  $("#logs-open").addEventListener("click", openLogs);
  $("#logs-close").addEventListener("click", closeLogs);
  $("#logs-backdrop").addEventListener("click", closeLogs);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#logs").hidden) closeLogs(); });
  $("#new-scan").addEventListener("click", newScan);
  $("#view-start").addEventListener("click", (e) => {
    const b = e.target.closest("[data-open-run]");
    if (b) openRun(b.dataset.openRun);
    if (e.target.closest("[data-new-scan]")) newScan();
  });
  for (const id of ["#view-network", "#view-iexam"]) $(id).addEventListener("click", (e) => {
    const b = e.target.closest("button[data-stage]");
    if (b && !b.disabled) runStage(b.dataset.stage);
    const a = e.target.closest("button[data-action]");
    if (a && !a.disabled) startStage({ run: currentRun, stage: a.dataset.action, goal: iexam.goal, k: iexam.k });
  });
  $("#view-iexam").addEventListener("change", (e) => { if (e.target.id === "k-select") iexam.k = Number(e.target.value); });
  // Always open on the empty Start page: nothing is loaded until the operator picks a scan.
  history.replaceState(null, "", location.pathname);
  try {
    await refreshRuns();
  } catch (err) {
    startError = err.message;
  }
  route();
  pollJob();
}

let startError = null;

async function openRun(runId) {
  followJob = job?.state === "running" && job.run === runId;
  try {
    await load(runId);
    if (currentView() === "start") location.hash = "#/network";
  } catch (err) {
    startError = `Scan ${formatRun(runId)} could not be opened: ${err.message}`;
    route();
  }
}

async function refreshRuns() {
  runs = await getJSON("/api/runs");
  if (currentView() === "start") renderStart();
}

// ---- Pipeline control: one stage at a time, started by the operator ----

const STAGE_HELP = {
  discover: "Finds every device on your network and guesses what it is (router, camera, computer).",
  gather: "Lists each device's open ports, software versions and firmware.",
  scan: "Matches that software against known vulnerabilities (CVEs), then adds severity, fixed versions, fix commits, " +
    "exploit status and a short AI explanation. Detection only, nothing is attacked.",
  plan: "Prepares iEXAM's four input files from the scan and builds the attack connectivity graph. Attack plans are then " +
    "found per device, when you ask for them below.",
  mitigate: "iEXAM Metric 1 finds the smallest changes that block every path; each one is re-checked.",
};
let jobError = null;

async function newScan() {
  await loadSetup();
  if (setupState && !setupState.consent.ok) {
    if (!setupState.consent.networks.length) return alert("This box is not connected to a network.");
    if (await askPermission(setupState.consent.networks)) await startStage({ run: null, stage: "discover" });
    return;
  }
  const where = "the network this machine is connected to";
  if (!confirm(`${STAGE_NAMES.discover} on ${where}?\n\nThis starts a new scan and runs this stage only: it finds the devices (detection only). ` +
    "You then run each next stage yourself from the Network page.")) return;
  await startStage({ run: null, stage: "discover" });
}

// Done stages can be run again; the next stage runs straight away; later ones stay locked.
async function runStage(stage) {
  if (!currentRun) return;
  const done = runs.find((r) => r.id === currentRun)?.stages || [];
  if (done.includes(stage)) {
    const later = STAGES.slice(STAGES.indexOf(stage) + 1).filter((s) => done.includes(s)).map((s) => STAGE_NAMES[s]);
    if (!confirm(`Run ${STAGE_NAMES[stage]} again on the scan of ${formatRun(currentRun)}?\n\nIt replaces ${STAGE_NAMES[stage]}'s result.` +
      (later.length ? ` ${later.join(", ")} will keep their old results until you run them again.` : ""))) return;
  }
  await startStage({ run: currentRun, stage });
}

async function startStage(body) {
  try {
    jobError = null;
    job = await postJSON("/api/pipeline", body);
    followJob = true;
    lastDone = -1;
    renderJob();
    pollTimer = setTimeout(pollJob, 2000);
  } catch (err) {
    jobError = err.message;
    alert(`Could not start ${STAGE_NAMES[body.stage]}: ${err.message}`);
    renderJob();
  }
}

async function pollJob() {
  clearTimeout(pollTimer);
  try {
    job = await getJSON("/api/job");
    jobError = null;
  } catch (err) {
    jobError = `Lost contact with the server: ${err.message}`;
    renderJob();
    pollTimer = setTimeout(pollJob, 5000);
    return;
  }
  renderJob();
  if (job.state === "idle") return;
  if (job.state === "running") pollTimer = setTimeout(pollJob, 3000);
  if (job.done.length !== lastDone) {
    // The stage finished: show its result.
    lastDone = job.done.length;
    await refreshRuns().catch(() => {});
    if (followJob && runs.some((r) => r.id === job.run)) {
      await load(job.run).catch(() => {});
      if (currentView() === "start") location.hash = "#/network";
    } else renderStages();
  } else if (job.state !== "running") {
    renderStages();
  }
}

// Job status lives on the header's Logs button and on the stage buttons; there is no status bar.
function renderJob() {
  const busy = job?.state === "running";
  $("#new-scan").disabled = busy;
  const badge = $("#logs-status");
  const failed = job?.state === "failed";
  badge.hidden = !(busy || failed || jobError);
  badge.className = `logs-status ${busy ? "running" : "failed"}`;
  badge.innerHTML = busy ? `${ICONS.spinner}${esc(STAGE_NAMES[job.current])}`
    : failed ? `${ICONS.cross}${esc(STAGE_NAMES[job.current])} failed` : jobError ? `${ICONS.cross}Offline` : "";
  $("#logs-open").setAttribute("aria-label", busy ? `Logs: ${STAGE_NAMES[job.current]} is running` : failed ? `Logs: ${STAGE_NAMES[job.current]} failed` : "Logs");
  renderLogs();
  renderStages();
  const card = $("#stage-card");
  if (card) card.outerHTML = stageCard(card.dataset.for);
  document.querySelectorAll("button[data-action]").forEach((b) => {
    b.disabled = busy;
    if (busy && job.current === b.dataset.action && job.goal === iexam.goal) b.textContent = "Working…";
  });
  if (currentView() === "start") renderStart();
}

function stageState(s, done) {
  const mine = job && job.run === currentRun;
  if (mine && job.state === "running" && job.current === s) return "running";
  if (mine && job.state === "failed" && job.current === s) return "failed";
  if (done.includes(s)) return "done";
  const before = STAGES[STAGES.indexOf(s) - 1];
  return done.includes(before) ? "next" : "locked";
}

// Stage control shown at the top of the Plan and Mitigate pages.
function stageCard(stage) {
  const done = runs.find((r) => r.id === currentRun)?.stages || [];
  const st = stageState(stage, done);
  const busy = job?.state === "running";
  const i = STAGES.indexOf(stage);
  const before = STAGES[i - 1];
  const beforeAt = STAGE_PAGE[before] || "#/network";
  const now = st === "running" && job.steps?.length > 1 && STEP_NAMES[job.step] ? ` (${STEP_NAMES[job.step]})` : "";
  const status = { done: "Done for this scan.", running: `Running now${now}; follow it in Logs.`,
    failed: "The last attempt failed; the reason is in Logs.", next: "Ready to run.",
    locked: `Run <a href="${beforeAt}">${STAGE_NAMES[before]}</a> first.` }[st];
  const verb = stage === "plan" ? STAGE_NAMES[stage] : `Run ${STAGE_NAMES[stage]}`;  // "Start Planning" is already a verb
  const label = st === "done" ? `${verb} again` : st === "running" ? `${STAGE_NAMES[stage]} is running…` : verb;
  return `<section class="card stage-card" id="stage-card" data-for="${stage}">
    <p>${esc(STAGE_HELP[stage])} <span class="stage-status">${status}</span></p>
    <button type="button" class="primary" data-stage="${stage}" ${st === "locked" || busy ? "disabled" : ""}>${label}</button>
  </section>`;
}

function renderStages() {
  if (!currentRun) return;
  const done = runs.find((r) => r.id === currentRun)?.stages || [];
  const busy = job?.state === "running";
  const states = STAGES.map((s) => stageState(s, done));
  $("#stages").innerHTML = NETWORK_STAGES.map((s, i) => {
    const st = states[i];
    // State is shown by icon and word as well as colour.
    const mark = { done: ICONS.check, running: ICONS.spinner, failed: ICONS.cross }[st] || String(i + 1);
    const word = { running: "running", failed: "failed", next: "next" }[st];
    const title = s === "discover" ? (st === "done" ? `done; use ${STAGE_NAMES.discover} at the top to start a new scan` : `use ${STAGE_NAMES.discover} at the top`)
      : { done: "done; select to run again", running: "running", failed: "failed; select to try again",
          next: "select to run", locked: `run ${STAGE_NAMES[STAGES[i - 1]]} first` }[st];
    const disabled = busy || s === "discover" || st === "locked";
    return `<li><button type="button" data-stage="${s}" class="step ${st}" ${disabled ? "disabled" : ""}
      title="${esc(title)}" aria-label="${STAGE_NAMES[s]}: ${esc(title)}"><span class="n">${mark}</span>${STAGE_NAMES[s]}${word ? `<span class="state">${word}</span>` : ""}</button></li>`;
  }).join("");

  // Next step card: what to run now, in words.
  const running = states.indexOf("running");
  const failed = states.indexOf("failed");
  const next = failed >= 0 ? failed : states.indexOf("next");
  const el = $("#next-step");
  if (running >= 0) {
    const step = job.steps?.length > 1 && STEP_NAMES[job.step] ? ` (now: ${STEP_NAMES[job.step]})` : "";
    el.innerHTML = `<p><strong>${STAGE_NAMES[STAGES[running]]} is running${step}.</strong> ${esc(STAGE_HELP[STAGES[running]])} Follow it in <strong>Logs</strong>.</p>`;
  } else if (busy) {
    el.innerHTML = `<p>${STAGE_NAMES[job.current]} is running on another scan (${esc(formatRun(job.run))}). Wait for it to finish.</p>`;
  } else if (next >= 0 && STAGE_PAGE[STAGES[next]]) {
    const s = STAGES[next];
    el.innerHTML = `<div><p class="eyebrow">Network stages done</p>
        <p>Next: <strong>${STAGE_NAMES[s]}</strong> on ${PAGE_NAMES[s]} · ${esc(STAGE_HELP[s])}</p></div>
      <a class="primary" href="${STAGE_PAGE[s]}">Go to ${PAGE_NAMES[s]}</a>`;
  } else if (next >= 0) {
    const s = STAGES[next];
    el.innerHTML = `<div><p class="eyebrow">Step ${next + 1} of ${NETWORK_STAGES.length}${failed >= 0 ? " · last attempt failed, see Logs" : ""}</p>
        <p><strong>${STAGE_NAMES[s]}</strong> · ${esc(STAGE_HELP[s])}</p></div>
      <button type="button" class="primary" data-stage="${s}">Run ${STAGE_NAMES[s]}</button>`;
  } else {
    el.innerHTML = `<p><strong>All seven stages are done.</strong> See the attack paths in <a href="#/plan">Security Profile</a> and the fixes in <a href="#/mitigate">Mitigate</a>.</p>`;
  }
}

function formatRun(id) {
  const m = id.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})/);
  return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]} UTC` : id;
}

async function load(runId) {
  const base = `/api/runs/${encodeURIComponent(runId)}`;
  [model, plans, mitigation, guide] = await Promise.all([getJSON(`${base}/model`), getOptional(`${base}/plans`),
    getOptional(`${base}/mitigation`), getOptional(`${base}/guide`)]);
  currentRun = runId;
  renderStages();
  renderLede();
  renderGraph();
  const fromHash = location.hash.slice(1);
  if (model.nodes.some((n) => n.id === fromHash)) selectNode(fromHash); else renderOverview();
  route();
}

function renderStats() {
  const devs = devices();
  const cves = new Set(devs.flatMap((d) => strongCves(d).map((c) => c.id))).size;
  const kev = devs.reduce((a, d) => a + d.kev_count, 0);
  const tiles = [["Devices", devs.length, ""], ["Vulnerabilities", model.stages.includes("scan") ? cves : "–", cves ? "high" : ""],
    ["Exploited in the wild", model.stages.includes("scan") ? kev : "–", kev ? "exploited" : ""]];
  $("#stats").innerHTML = tiles.map(([label, value, cls]) =>
    `<div class="stat ${cls}"><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join("");
}

function renderLede() {
  renderStats();
  const devs = devices();
  const withCves = devs.filter((d) => strongCves(d).length);
  const total = new Set(devs.flatMap((d) => strongCves(d).map((c) => c.id))).size;
  const sub = `${plural(devs.length, "device", "devices")} found on ${model.subnets.join(", ")}.`;
  if (!model.stages.includes("scan")) {
    $("#headline").textContent = `${plural(devs.length, "device", "devices")} found. Not yet checked for vulnerabilities.`;
    $("#subline").textContent = "Run gather and scan to see open ports and known vulnerabilities.";
    return;
  }
  if (!withCves.length) {
    $("#headline").textContent = "No known vulnerabilities matched any device.";
    $("#subline").textContent = sub;
    return;
  }
  const worst = [...withCves].sort((a, b) =>
    b.kev_count - a.kev_count || b.risk - a.risk || strongCves(b).length - strongCves(a).length)[0];
  const n = strongCves(worst).length;
  const kev = worst.kev_count;
  $("#headline").textContent = `The ${kindName(worst).toLowerCase()} is the weakest point: ` +
    `${plural(n, "known vulnerability", "known vulnerabilities")}` +
    (kev ? `, ${kev} exploited in the wild.` : `, worst rated ${worst.risk} of 10.`);
  $("#subline").textContent = `${sub} ${plural(total, "vulnerability", "vulnerabilities")} across ` +
    `${plural(withCves.length, "device", "devices")}. Select a device to see why.`;
}

// Map icons (Lucide shapes), drawn white on the slate circles.
const MAP_ICONS = {
  router: '<rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6.01 18H6M10.01 18H10M15 10v4M17.84 7.17a4 4 0 0 0-5.66 0M20.66 4.34a8 8 0 0 0-11.31 0"/>',
  device: '<rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9" rx="1"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/>',
  switch: '<rect width="20" height="8" x="2" y="8" rx="2"/><path d="M6 12h.01M10 12h.01M14 12h.01M18 12h.01"/>',
  camera: '<path d="m16 13 5.223 3.482a.5.5 0 0 0 .777-.416V7.87a.5.5 0 0 0-.752-.432L16 10.5"/><rect x="2" y="6" width="14" height="12" rx="2"/>',
  computer: '<path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16"/>',
  phone: '<rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/>',
  tablet: '<rect width="16" height="20" x="4" y="2" rx="2"/><path d="M12 18h.01"/>',
  tv: '<rect width="20" height="15" x="2" y="7" rx="2"/><path d="m17 2-5 5-5-5"/>',
  speaker: '<rect width="16" height="20" x="4" y="2" rx="2"/><path d="M12 6h.01"/><circle cx="12" cy="14" r="4"/><path d="M12 14h.01"/>',
  printer: '<path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 9V3a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v6"/><rect x="6" y="14" width="12" height="8" rx="1"/>',
  iot: '<path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5M9 18h6M10 22h4"/>',
  self: '<path d="m4 17 6-6-6-6M12 19h8"/>',
};
const iconUri = (name) => "data:image/svg+xml;utf8," + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="#f8fafc" ` +
  `stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${MAP_ICONS[name]}</svg>`);

function iconFor(n) {
  if (n.kind === "router") return "router";
  if (n.kind === "self") return "self";
  if (!gathered()) return "device";
  return MAP_ICONS[n.label] ? n.label : "device";  // unknown or unrecognised type: the default device icon
}

// Router in the middle, every other device on a circle around it;
// devices behind a bridge (extender) fan out beyond that bridge.
function layout(nodes) {
  // The hub is the gateway router: the one the (undrawn) attacker reaches first.
  const gw = model.edges.find((e) => e.source === "n0")?.target;
  const hub = nodes.find((n) => n.id === gw) || nodes.find((n) => n.kind === "router");
  const bridgeOf = (n) => n.uplink && nodes.find((b) => b.ip === n.uplink && b !== hub);
  const ring = nodes.filter((n) => n !== hub && !bridgeOf(n))
    .sort((a, b) => (a.kind === "self") - (b.kind === "self") || a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  const r = Math.max(170, ring.length * 30);
  const pos = {};
  if (hub) pos[hub.id] = { x: 0, y: 0 };
  ring.forEach((n, i) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / ring.length;
    pos[n.id] = { x: Math.round(r * Math.cos(a)), y: Math.round(r * Math.sin(a)) };
  });
  const clients = {};
  for (const n of nodes) if (bridgeOf(n)) (clients[bridgeOf(n).id] ||= []).push(n);
  for (const [bid, kids] of Object.entries(clients)) {
    const b = pos[bid], a0 = Math.atan2(b.y, b.x);
    kids.forEach((n, i) => {
      const a = a0 + (i - (kids.length - 1) / 2) * 0.8;
      pos[n.id] = { x: Math.round(b.x + 200 * Math.cos(a)), y: Math.round(b.y + 200 * Math.sin(a)) };
    });
  }
  return pos;
}

function nodeLabel(n) {
  if (!gathered()) return n.kind === "self" ? `${n.ip}\nthis machine` : n.ip;
  const head = n.name && n.name !== n.ip ? `${n.name}\n${n.ip}` : n.ip;
  if (n.kind === "self") return `${head}\nthis machine (not scanned)`;
  if (!model.stages.includes("scan")) return head;
  const count = strongCves(n).length;
  // Risk in words too, not only the ring colour.
  const risk = n.kev_count ? `${n.kev_count} exploited` : n.risk ? `worst CVSS ${n.risk.toFixed(1)}` : "";
  return `${head}\n${count ? `${plural(count, "CVE", "CVEs")}${risk ? ` · ${risk}` : ""}` : "no known CVEs"}`;
}

function renderGraph() {
  // The attacker is not drawn on the network map; attack paths live on the Plan page.
  const nodes = model.nodes.filter((n) => n.kind !== "attacker");
  const ids = new Set(nodes.map((n) => n.id));
  const pos = layout(nodes);
  $(".legend-note").hidden = gathered();
  const elements = [
    ...nodes.map((n) => ({ data: { id: n.id, label: nodeLabel(n), tier: tier(n), kind: n.kind, icon: iconUri(iconFor(n)) }, position: pos[n.id] })),
    ...model.edges.filter((e) => ids.has(e.source) && ids.has(e.target))
      .map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, kind: e.kind } })),
  ];
  if (cy) cy.destroy();
  const css = getComputedStyle(document.documentElement);
  const v = (name) => css.getPropertyValue(name).trim();
  cy = cytoscape({
    container: $("#graph"),
    elements,
    layout: { name: "preset", fit: true, padding: 60 },
    wheelSensitivity: 0.2,
    minZoom: 0.3, maxZoom: 2.5,
    style: [
      { selector: "node", style: {
        shape: "ellipse", width: 56, height: 56, "background-color": MAP.node,
        "background-image": "data(icon)", "background-width": "55%", "background-height": "55%",
        "border-width": 2, "border-color": MAP.nodeBorder,
        label: "data(label)", "text-wrap": "wrap", "text-max-width": 170, "text-valign": "bottom", "text-halign": "center",
        "text-margin-y": 8, color: v("--text"), "font-size": 14, "font-family": v("--font"), "line-height": 1.35,
        "text-background-color": v("--surface"), "text-background-opacity": 0.85, "text-background-padding": 2,
        "text-background-shape": "roundrectangle" } },
      { selector: "node[kind = 'router']", style: { width: 76, height: 76, "font-weight": 600 } },
      { selector: "node[tier = 'low'], node[tier = 'high']", style: { "border-color": MAP.vuln, "border-width": 3 } },
      { selector: "node[tier = 'exploited']", style: { "border-color": MAP.exploited, "border-width": 4 } },
      { selector: "node[kind = 'self']", style: { "border-style": "dashed", "border-color": MAP.self, color: v("--text-muted") } },
      { selector: ":selected", style: { "overlay-color": MAP.selected, "overlay-opacity": 0.25, "overlay-padding": 6 } },
      { selector: "edge", style: { width: 1.5, "line-color": MAP.edge, "curve-style": "straight", opacity: 0.7 } },
      { selector: "edge[kind = 'monitor']", style: { "line-style": "dashed" } },
    ],
  });
  cy.ready(() => { cy.resize(); cy.fit(undefined, 64); });
  cy.on("tap", "node", (evt) => {
    const node = model.nodes.find((n) => n.id === evt.target.id());
    if (node) renderNode(node);
  });
  cy.on("tap", (evt) => { if (evt.target === cy) renderOverview(); });
}

// ---- Plans and mitigation (phases 7-8). iEXAM renumbers nodes, so they are matched by IP. ----

const pddlToken = (s) => String(s).trim().toLowerCase().replace(/\./g, "-dot-").replace(/\s+/g, "-")
  .replace(/[^a-z0-9_-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
const untoken = (s) => s.replace(/-dot-/g, ".").replace(/-/g, " ");
const iexamNode = (node) => plans?.attack_graph.nodes.find((g) => g.ip === node.ip && g.id !== "n0");

function stepText(step) {
  const names = { attacker1: "the attacker" };
  for (const g of plans.attack_graph.nodes) names[pddlToken(g.label)] = model.nodes.find((n) => n.ip === g.ip)?.name || g.label;
  const name = (t) => names[t] || untoken(t);
  const [act, ...args] = step.replace(/^\(|\)$/g, "").split(/\s+/);
  if (act.startsWith("attacker-has-access-to-")) return `The attacker reaches ${name(args[0])} over the network.`;
  const m = act.match(/^attacker-exploit-(cve-\d+-\d+)-to-compromise-/);
  if (!m) return untoken(step.replace(/^\(|\)$/g, ""));
  const via = act.includes("-via-");
  const software = args.slice(2).map(untoken).join(", ") || "a service";
  return `${via ? `From ${name(args[1])}, the attacker exploits` : "The attacker exploits"} ` +
    `${m[1].toUpperCase()} in ${software} on ${name(args[0])}.`;
}

const safeUrl = (u) => /^https?:\/\//.test(u || "");
const nvdLink = (id) => `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a>`;
const linkList = (urls, label) => urls.filter(safeUrl).map((u, i) =>
  ` <a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${label}${urls.length > 1 ? ` ${i + 1}` : ""}</a>`).join(",");

// Network shows scanning results only; attack paths and fixes live on the Plan and Mitigate pages.
function iexamLinks(n) {
  const g = iexamNode(n);
  if (!g) return "";
  const goal = encodeURIComponent(g.label);
  return `<h3>Attack paths and fixes</h3>
    <p class="sub">This device is a goal in the attack model.
      <a href="#/plan?goal=${goal}">How an attacker gets here</a> · <a href="#/mitigate?goal=${goal}">How to block it</a></p>`;
}

function evidenceRow(e) {
  const fix = e.fixed_in.length ? `fixed in ${esc(e.fixed_in.join(", "))}`
    : e.last_affected.length ? `affects up to ${esc(e.last_affected.join(", "))}` : "no fix published";
  return `<li>${nvdLink(e.cve)}${e.cvss != null ? ` (CVSS ${e.cvss})` : ""}: ${fix}.${linkList(e.fix_commits, "fix commit")}${linkList(e.advisories, "advisory")}</li>`;
}

function renderOverview() {
  if (cy) cy.$(":selected").unselect();
  if (currentView() === "network") history.replaceState(null, "", "#/network");
  // Before Scan there are no CVE results yet: list devices without scores rather than a misleading "0".
  const scanned = model.stages.includes("scan");
  const ranked = scanned
    ? devices().sort((a, b) => b.kev_count - a.kev_count || b.risk - a.risk || strongCves(b).length - strongCves(a).length)
    : devices().sort((a, b) => (b.kind === "router") - (a.kind === "router") || a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  $("#panel").innerHTML = `
    <h2>${scanned ? "Devices by exposure" : plural(ranked.length, "device found", "devices found")}</h2>
    <p class="sub">${scanned ? "Highest risk first. Score is the worst CVSS rating among a device's known vulnerabilities."
      : "Not checked for vulnerabilities yet: run Gather and Scan Your Network."}</p>
    <ul class="ranking">${ranked.map((n) => `
      <li><button type="button" data-node="${esc(n.id)}">
        ${scanned ? `<span class="score ${tier(n)}">${n.risk ? n.risk.toFixed(1) : "0"}</span>` : `<span class="score unscanned" title="not scanned yet">–</span>`}
        <span><span class="name">${esc(shownName(n))}</span>
        <span class="meta">${esc(kindName(n))}${shownName(n) === n.ip ? "" : `, ${esc(n.ip)}`}${scanned
          ? `, ${plural(strongCves(n).length, "vulnerability", "vulnerabilities")}${n.kev_count ? `, ${n.kev_count} exploited in the wild` : ""}` : ""}</span></span>
      </button></li>`).join("")}
    </ul>`;
  $("#panel").querySelectorAll("button[data-node]").forEach((b) =>
    b.addEventListener("click", () => selectNode(b.dataset.node)));
}

function selectNode(id) {
  const node = model.nodes.find((n) => n.id === id);
  if (!node) return;
  if (cy) { cy.$(":selected").unselect(); cy.getElementById(id).select(); }
  renderNode(node);
}

function renderNode(n) {
  if (currentView() === "network") history.replaceState(null, "", `#${n.id}`);
  if (n.kind === "attacker") {
    $("#panel").innerHTML = `<button type="button" class="back">${ICONS.back}All devices</button>
      <h2>Internet attacker</h2>
      <p class="sub">The starting point of every attack path: someone outside the home who can reach the router from the internet.</p>`;
    $("#panel .back").addEventListener("click", renderOverview);
    return;
  }
  const id = n.identity || {};
  const fw = id.firmware ? `${esc(id.firmware)} <span class="label">(${esc(id.firmware_source)})</span>` : "not revealed";
  const via = n.uplink && model.nodes.find((m) => m.ip === n.uplink);
  const os = n.os ? `${esc(n.os.name)} (${n.os.accuracy}% match)` : "no guess";
  const cves = showWeak ? n.cves : strongCves(n);
  const weakCount = n.cves.length - strongCves(n).length;
  $("#panel").innerHTML = `
    <button type="button" class="back">${ICONS.back}All devices</button>
    <h2>${esc(shownName(n))}</h2>
    <p class="sub">${esc(kindName(n))} at ${esc(n.ip)}</p>
    <dl class="facts">
      <dt>MAC address</dt><dd>${esc(n.mac || "unknown")}${n.vendor ? `, ${esc(n.vendor)}` : ""}</dd>
      ${via ? `<dt>Connected via</dt><dd>${esc(shownName(via))} (${esc(via.ip)})</dd>` : ""}
      <dt>Operating system</dt><dd>${os}</dd>
      <dt>Firmware</dt><dd>${fw}</dd>
      <dt>Identified by</dt><dd>${n.evidence.length ? n.evidence.slice(0, 4).map(esc).join("<br>") : "no distinctive signal"}</dd>
    </dl>
    ${n.kind === "self" ? `<p class="empty">This is the monitoring machine. It is not scanned.</p>` : `
    ${iexamLinks(n)}
    <h3>Open ports</h3>
    ${!n.scanned ? `<p class="empty">Not scanned yet. Run gather.</p>` : n.ports.length ? `
    <table class="ports"><thead><tr><th scope="col">Port</th><th scope="col">Service</th><th scope="col">Software</th></tr></thead>
    <tbody>${n.ports.map((p) => `<tr><td>${p.port}/${esc(p.proto)}</td><td>${esc(p.service || "unknown")}</td>
      <td>${esc([p.product, p.version].filter(Boolean).join(" ") || "not identified")}</td></tr>`).join("")}</tbody></table>`
      : `<p class="empty">No open TCP ports found.</p>`}
    <h3>Known vulnerabilities</h3>
    ${weakCount ? `<label class="toggle"><input type="checkbox" id="weak" ${showWeak ? "checked" : ""}>
      Include ${plural(weakCount, "weak match", "weak matches")} (listed by NVD without a version)</label>` : ""}
    <div class="cves">${cves.length ? cves.map(cveRow).join("") : `<p class="empty">None matched.</p>`}</div>`}`;
  $("#panel .back").addEventListener("click", renderOverview);
  const weak = $("#weak");
  if (weak) weak.addEventListener("change", () => { showWeak = weak.checked; renderNode(n); });
  $("#panel").scrollTop = 0;
}

const productName = (p) => (p && p.endsWith("_firmware") ? "firmware" : p);

function cveRow(c) {
  const info = model.cves[c.id] || {};
  const fixed = [...new Set((info.fixed?.nvd || []).filter((f) => f.kind === "fixed_in").map((f) => f.version))];
  const lastAffected = [...new Set((info.fixed?.nvd || []).filter((f) => f.kind === "last_affected").map((f) => f.version))];
  const ex = info.explanation;
  const patches = (info.patches || []).filter((p) => p.for_our_product !== false && /^https?:\/\//.test(p.url)).slice(0, 4);
  const flags = [
    c.kev ? `<span class="flag kev">Exploited in the wild</span>` : "",
    c.public_exploit && !c.kev ? `<span class="flag exploit">Public exploit</span>` : "",
    fixed.length ? `<span class="flag">Fixed in ${esc(fixed.join(", "))}</span>` : "",
    c.weak ? `<span class="flag">Weak match</span>` : "",
  ].join("");
  return `<details>
    <summary>
      <span class="score ${scoreTier(c)}">${c.cvss != null ? c.cvss.toFixed(1) : "?"}</span>
      <span><span class="id">${esc(c.id)}</span>
        <span class="what"> in ${esc([productName(c.product), c.version].filter(Boolean).join(" ") || "detected service")}${c.port ? `, port ${c.port}` : ""}</span>
        <span class="flags">${flags}</span></span>
    </summary>
    <div class="cve-body">
      ${ex ? `<p><span class="label">Cause:</span> ${esc(ex.cause)}</p><p><span class="label">If exploited:</span> ${esc(ex.consequence)}</p>` : ""}
      ${info.description ? `<p class="label">${esc(info.description)}</p>` : ""}
      ${lastAffected.length && !fixed.length ? `<p><span class="label">Affected up to:</span> ${esc(lastAffected.join(", "))}</p>` : ""}
      ${info.epss ? `<p><span class="label">Chance of exploitation in the next 30 days (EPSS):</span> ${(info.epss.epss * 100).toFixed(1)}%</p>` : ""}
      ${patches.length ? `<p class="label">Fix commits</p><ul>${patches.map((p) => `<li><a href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.repo || p.url)}${p.sha ? ` @ ${esc(p.sha.slice(0, 10))}` : ""}</a></li>`).join("")}</ul>` : ""}
      <p><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}" target="_blank" rel="noopener noreferrer">NVD entry for ${esc(c.id)}</a></p>
    </div>
  </details>`;
}

// Refit whenever the map box changes size (window resize, or the layout settling after load).
let resizeTimer;
new ResizeObserver(() => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => { if (cy) { cy.resize(); cy.fit(undefined, 64); } }, 150);
}).observe($("#graph"));

// ---- Views: Network (this page) and iEXAM's Plan / Mitigate (iexam.js), like iEXAM's sidebar ----

const NAV_ICONS = {
  history: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l4 2"/></svg>',
  start: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/></svg>',
  network: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M5 16v-3h14v3M12 8v5"/></svg>',
  plan: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="m10 8 6 4-6 4z"/></svg>',
  mitigate: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m15.6 2.7a10 10 0 1 0 5.7 5.7"/><circle cx="12" cy="12" r="2"/><path d="M13.4 10.6 19 5"/></svg>',
  keys: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14 9l2 2"/></svg>',
  pulse: '<svg class="pulse" viewBox="0 0 24 24" aria-hidden="true"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
};

function currentView() {
  const h = location.hash;
  if (h.startsWith("#/keys")) return "keys";
  if (!model) return "start";
  if (h.startsWith("#/plan")) return "plan";
  if (h.startsWith("#/mitigate")) return "mitigate";
  if (h.startsWith("#/network") || /^#n\d+$/.test(h)) return "network";
  return "start";
}

const stageDone = (s) => (runs.find((r) => r.id === currentRun)?.stages || []).includes(s);

function renderSidebar(view) {
  const noScan = !model && `Open a scan from History or run ${STAGE_NAMES.discover} first`;
  const items = [
    { id: "start", label: "Start", href: "#/" },
    { id: "network", label: "Network", href: "#/network", off: noScan },
    { id: "plan", label: "Security Profile", href: "#/plan", off: noScan || (!stageDone("scan") && "Available once Scan Your Network has run on this scan") },
    { id: "mitigate", label: "Mitigate", href: "#/mitigate", off: noScan || (!stageDone("plan") && "Available once Plan has run on this scan") },
    { id: "keys", label: "API keys", href: "#/keys" },
  ];
  $("#side-nav").innerHTML = items.map((i) => i.off
    ? `<span class="nav-item disabled" aria-disabled="true" title="${esc(i.off)}">${NAV_ICONS[i.id]}${i.label}${NAV_ICONS.pulse}<span class="visually-hidden"> (${esc(i.off)})</span></span>`
    : `<a class="nav-item" href="${i.href}" ${i.id === view ? 'aria-current="page"' : ""}>${NAV_ICONS[i.id]}${i.label}</a>`).join("");
  const devs = model ? devices() : [];
  const cves = new Set(devs.flatMap((d) => strongCves(d).map((c) => c.id))).size;
  $("#side-foot").innerHTML = currentRun ? `<p class="eyebrow">Scan</p>
    <p>${esc(formatRun(currentRun))}</p>
    <p>${plural(devs.length, "device", "devices")} · ${plural(cves, "CVE", "CVEs")}</p>
    <p>${plans ? plural(plans.targets.filter((t) => t.optimal).length, "goal planned", "goals planned") : "Not planned yet"}</p>`
    : `<p class="eyebrow">Scan</p><p>No scan loaded</p>`;
}

function route() {
  const view = currentView();
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  $("#view-start").hidden = view !== "start";
  $("#view-keys").hidden = view !== "keys";
  $("#view-network").hidden = view !== "network";
  $("#view-iexam").hidden = view !== "plan" && view !== "mitigate";
  renderSidebar(view);
  renderJob();
  if (view === "keys") {
    renderKeys();
    loadSetup();
  } else if (view === "start") {
    renderStart();
  } else if (view === "network") {
    if (cy) { cy.resize(); cy.fit(undefined, 64); }
  } else {
    renderIexamView(view, params);
  }
}

window.addEventListener("hashchange", () => {
  route();
  if (currentView() !== "network") $("#main").scrollTop = 0;
});

// ---- Start page (iEXAM Start: what this is, how it works, pick a source) ----

function runRow(r) {
  const busy = job?.state === "running";
  const complete = r.stages.length === STAGES.length;
  const isOpen = r.id === currentRun;
  return `<li><button type="button" class="pick" data-open-run="${esc(r.id)}" aria-pressed="${isOpen}">
    <span class="pick-title">${esc(formatRun(r.id))}
      ${complete ? `<span class="flag ok">Complete</span>` : `<span class="flag">${r.stages.length} of ${STAGES.length} stages</span>`}
      ${busy && job.run === r.id ? `<span class="flag exploit">Running</span>` : ""}
      ${isOpen ? `<span class="flag">Open</span>` : ""}</span>
    <span class="pick-meta">${complete ? "Devices, attack plans and fixes"
      : `Done: ${esc(r.stages.map((s) => STAGE_NAMES[s]).join(", "))} · next: ${STAGE_NAMES[STAGES[r.stages.length]] || "–"}`}</span>
  </button></li>`;
}

function renderStart() {
  const busy = job?.state === "running";
  const discovering = busy && job.current === "discover";
  $("#view-start").innerHTML = `
    <header class="page-head">
      <h1>Start</h1>
      <p>EdgePlanner checks your home network the way an outside attacker would: it finds every device, works out how
        someone on the internet could break in, and tells you the smallest fixes that stop them. It never logs in to a
        device or runs an exploit.</p>
    </header>
    ${startError ? notice(esc(startError)) : ""}
    ${setupState && !setupState.keys.NVIDIA_API_KEY.set ? notice(`Add an NVIDIA API key on <a href="#/keys">API keys</a> to get the AI explanations.`) : ""}

    <section>
      <h2 class="eyebrow section-label">Begin</h2>
      <div class="start-grid">
        <div class="card source">
          <div class="card-head">${NAV_ICONS.start}<h2>${STAGE_NAMES.discover}</h2></div>
          <p class="hint">Starts a new scan: works out which network this machine is connected to and finds every device on it. When it finishes,
            the Network page opens and you run the remaining stages one at a time, checking each result before the next.</p>
          <button type="button" class="primary" data-new-scan ${busy ? "disabled" : ""}>
            ${discovering ? `${STAGE_NAMES.discover} is running…` : busy ? `${STAGE_NAMES[job.current]} is running…` : STAGE_NAMES.discover}</button>
        </div>
        <div class="card source">
          <div class="card-head">${NAV_ICONS.history}<h2>History</h2></div>
          <p class="hint">Every scan saved on this machine (<code>runs/</code>), newest first. Open one to look at it or to
            continue its stages where it stopped.</p>
          ${runs.length ? `<ul class="pick-list">${runs.map((r) => runRow(r)).join("")}</ul>`
            : `<p class="empty">No scans yet. Start with ${STAGE_NAMES.discover}.</p>`}
        </div>
      </div>
    </section>

    <section>
      <h2 class="eyebrow section-label">How it works</h2>
      <p class="hint">Each stage reads the previous stage's result, so they run in this order. You start each one yourself.</p>
      <ol class="how">${STAGES.map((s, i) => `<li><span class="n">${i + 1}</span><div><strong>${STAGE_NAMES[s]}</strong><p>${esc(STAGE_HELP[s])}</p></div></li>`).join("")}</ol>
    </section>

    <section>
      <h2 class="eyebrow section-label">What you will see</h2>
      <div class="start-grid three">
        <div class="card"><div class="card-head">${NAV_ICONS.network}<h2>Network</h2></div>
          <p class="hint">Stages 1–3. The map from the attacker to every device, coloured by risk. Select a device
            for its ports, software and vulnerabilities.</p></div>
        <div class="card"><div class="card-head">${NAV_ICONS.plan}<h2>Security Profile</h2></div>
          <p class="hint">Stage 4. Start Planning builds iEXAM's attack connectivity graph. Then pick a device and ask for its
            optimal plan (shortest attack path, with an AI explanation) and its top-K alternative paths.</p></div>
        <div class="card"><div class="card-head">${NAV_ICONS.mitigate}<h2>Mitigate</h2></div>
          <p class="hint">Stage 5, iEXAM Metric 1. The smallest sets of changes (upgrade or close a service) that make a
            device unreachable, with evidence and where the attack breaks.</p></div>
      </div>
    </section>

    <section class="card">
      <div class="card-head"><h2>Good to know</h2></div>
      <ul class="tips">
        <li>The network is found automatically from this machine's own connection. Only private home/office ranges (no larger than a /16) are scanned, never the internet, and all checks are detection-only.</li>
        <li>While a stage runs, its button spins and the <strong>Logs</strong> button at the top shows which stage; Logs has the live output.</li>
        <li>A stage unlocks once the one before it is done. A finished stage can be run again on its own, e.g. <strong>Start Planning</strong> to rebuild the attack graph without re-scanning.</li>
        <li>AI explanations need an NVIDIA API key; add it on <a href="#/keys">API keys</a>. Everything else works without it.</li>
      </ul>
    </section>`;
}

// ---- API keys page and the scan-permission dialog (web/setup.py) ----

let setupState = null;  // {consent: {ok, networks, accepted_at}, keys: {NAME: {set, hint}}}
let keysMsg = null;     // {text, bad}

async function loadSetup() {
  try {
    setupState = await getJSON("/api/setup");
  } catch (err) {
    keysMsg = { text: `Could not read the settings: ${err.message}`, bad: true };
  }
  if (currentView() === "keys") renderKeys();
  if (currentView() === "start") renderStart();
}

const keyState = (k) => setupState.keys[k].set
  ? `<span class="flag ok">Saved · ends in ${esc(setupState.keys[k].hint)}</span>` : `<span class="flag">Not set</span>`;

function renderKeys() {
  const el = $("#view-keys");
  if (!setupState) {
    el.innerHTML = `<header class="page-head"><h1>API keys</h1></header>${keysMsg ? notice(esc(keysMsg.text)) : '<p class="empty">Loading…</p>'}`;
    return;
  }
  el.innerHTML = `
    <header class="page-head">
      <h1>API keys</h1>
      <p>Two free keys from outside services. They are kept only on this box and never shown again in full.</p>
    </header>

    <section class="card setup-step" aria-labelledby="k-nvidia">
      <div class="card-head">${NAV_ICONS.keys}<h2 id="k-nvidia">NVIDIA API key</h2>${keyState("NVIDIA_API_KEY")}</div>
      <p class="hint">Needed for the AI explanations of vulnerabilities, attack plans and fix guides. Everything else works without it.</p>
      <ol class="howto">
        <li>Open <a href="https://build.nvidia.com" target="_blank" rel="noopener">build.nvidia.com</a> and sign in, or create a free NVIDIA account.</li>
        <li>Open your account menu (top right), choose <strong>API Keys</strong>, then <strong>Generate API Key</strong>.</li>
        <li>Copy the key (it starts with <code>nvapi-</code>) and paste it here.</li>
      </ol>
      <label class="field"><span>NVIDIA API key</span>
        <input id="key-NVIDIA_API_KEY" type="password" autocomplete="off" spellcheck="false" placeholder="nvapi-…"></label>
    </section>

    <section class="card setup-step" aria-labelledby="k-nvd">
      <div class="card-head">${NAV_ICONS.keys}<h2 id="k-nvd">NVD API key</h2>${keyState("NVD_API_KEY")}</div>
      <p class="hint">Optional. The U.S. National Vulnerability Database answers about 10 times faster with a key, so Scan Your Network finishes sooner.</p>
      <ol class="howto">
        <li>Open the <a href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noopener">NVD API key request page</a>.</li>
        <li>Enter an organisation name (your own name is fine), your email address and organisation type, accept the terms and submit.</li>
        <li>Open the email from NVD and follow its link within 7 days. The page shows your key (36 characters, like <code>a1b2c3d4-…</code>); paste it here.</li>
      </ol>
      <label class="field"><span>NVD API key</span>
        <input id="key-NVD_API_KEY" type="password" autocomplete="off" spellcheck="false" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"></label>
    </section>

    <div class="action-row">
      <button type="button" class="primary" id="keys-save">Save keys</button>
      ${keysMsg ? `<p class="setup-msg ${keysMsg.bad ? "bad" : ""}" role="status">${esc(keysMsg.text)}</p>` : ""}
    </div>`;
}

async function saveKeys() {
  const body = {};
  for (const k of ["NVIDIA_API_KEY", "NVD_API_KEY"]) if ($(`#key-${k}`).value.trim()) body[k] = $(`#key-${k}`).value.trim();
  try {
    if (!Object.keys(body).length) throw new Error("Paste a key first.");
    setupState.keys = await postJSON("/api/setup/keys", body);
    keysMsg = { text: "Saved. The next stage you run uses them." };
  } catch (err) {
    keysMsg = { text: err.message, bad: true };
  }
  renderKeys();
}

$("#view-keys").addEventListener("click", (e) => { if (e.target.closest("#keys-save")) saveKeys(); });

// First Discover on a network: ask once whether the operator may scan it. Resolves true when confirmed.
function askPermission(networks) {
  const d = $("#consent");
  $("#consent-net").textContent = networks.join(", ");
  $("#consent-box").checked = false;
  $("#consent-ok").disabled = true;
  $("#consent-error").textContent = "";
  d.returnValue = "";  // Esc keeps the previous value otherwise
  d.showModal();
  return new Promise((resolve) => {
    d.onclose = () => resolve(d.returnValue === "ok");
  });
}
$("#consent-box").addEventListener("change", (e) => { $("#consent-ok").disabled = !e.target.checked; });
$("#consent-ok").addEventListener("click", async (e) => {
  e.preventDefault();
  try {
    setupState.consent = await postJSON("/api/setup/consent", { accept: true });
    $("#consent").close("ok");
  } catch (err) {
    $("#consent-error").textContent = err.message;
  }
});

init();
loadSetup();
