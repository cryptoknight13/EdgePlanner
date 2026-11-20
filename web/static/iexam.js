"use strict";
// iEXAM views (Plan, Mitigate = iEXAM Metric 1), laid out like iEXAM's own web app (upstream/iEXAM/web: Plan.tsx,
// OptimalPanel, TopKPanel, PddlPanel, Metric1.tsx, OptionsList). Each page runs its own stage (Plan,
// Mitigate) and then shows that stage's files (plans.json, mitigation.json). Uses app.js globals.

// iEXAM GraphPreview colours.
const ACG = { node: "#1e293b", text: "#f8fafc", border: "#334155", vuln: "#f59e0b", attacker: "#7f1d1d",
  attackerBorder: "#dc2626", attackerText: "#fef2f2", edge: "#94a3b8", attack: "#dc2626", cve: "#fef3c7",
  cveBorder: "#b45309", cveText: "#7c2d12", hit: "#ef4444", hitBorder: "#7f1d1d", path: "#14532d",
  pathBorder: "#22c55e", pathText: "#ecfccb", goal: "#1e3a8a", goalBorder: "#3b82f6", goalText: "#dbeafe",
  changed: "#7c2d12", changedBorder: "#f97316", changedText: "#ffedd5", removed: "#3b82f6", removedBorder: "#1e3a8a" };
const IEXAM_ICONS = {
  target: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
  route: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/></svg>',
  shield: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>',
  alert: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m21.7 18-8-14a2 2 0 0 0-3.4 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3"/><path d="M12 9v4M12 17h.01"/></svg>',
};

const iexam = { goal: null, tab: "optimal", topk: 0, option: 0, k: 3, raw: new Set() };
let acg = null;

const iexamLabel = (id) => plans.attack_graph.nodes.find((n) => n.id === id)?.label || id;
const targetFor = (goal) => plans.targets.find((t) => t.goal === goal);

function renderIexamView(view, params) {
  const el = $("#view-iexam");
  if (params.get("goal")) iexam.goal = params.get("goal");
  const head = (view === "plan"
    ? pageHead("Security Profile", "How an attacker on the internet could take over each device on your network, " +
        "worked out by iEXAM from the vulnerabilities found by Scan Your Network.")
    : pageHead("Mitigate", "iEXAM Metric 1 (Impenetrability): the smallest sets of changes that make the goal unreachable " +
        "(no heuristic). Each option is re-checked on the full network.")) + stageCard(view);
  if (acg) { acg.destroy(); acg = null; }
  if (!plans) {
    el.innerHTML = head + (view === "plan"
      ? notice("Nothing planned for this scan yet. Press <strong>Start Planning</strong> above to build the attack graph.")
      : notice(`Mitigate needs the attack graph. Press <strong>Start Planning</strong> on the <a href="#/plan">Security Profile</a> page first.`));
    return;
  }
  if (!targetFor(iexam.goal)) iexam.goal = (plans.targets.find((t) => t.optimal) || plans.targets[0])?.goal || null;
  if (!iexam.goal) {
    el.innerHTML = head + notice("The attack model has no goal nodes: no device had an exportable vulnerability.");
    return;
  }
  if (view === "plan") renderPlanPage(el, head); else renderMitigatePage(el, head);
}

const pageHead = (title, sub) => `<header class="page-head"><h1>${esc(title)}</h1><p>${esc(sub)}</p></header>`;
const notice = (html) => `<div class="notice">${IEXAM_ICONS.alert}<div>${html}</div></div>`;

function goalCard(view) {
  const note = (t) => plans.unreachable_goals.includes(t.goal) || t.error ? " (no attack path)" : t.optimal || t.topk ? "" : " (not planned yet)";
  const items = [...plans.targets.map((t) => ({ goal: t.goal, note: note(t) })),
    ...plans.unreachable_goals.filter((g) => !targetFor(g)).map((g) => ({ goal: g, note: " (no attack path)" }))];
  return `<section class="card">
    <div class="card-head">${IEXAM_ICONS.target}<h2>Pick a goal</h2></div>
    <p class="hint">The goal is the device the attacker wants to compromise. It is drawn in blue on the graph.</p>
    <div class="goal-row">
      <select id="goal-select" aria-label="Goal node">
        ${items.map((i) => `<option value="${esc(i.goal)}" ${i.goal === iexam.goal ? "selected" : ""}>${esc(i.goal)}${i.note}</option>`).join("")}
      </select>
      <span class="current">Current: <span class="mono">${esc(iexam.goal)}</span></span>
    </div>
  </section>`;
}

function bindGoal(view) {
  $("#goal-select").addEventListener("change", (e) => {
    iexam.topk = 0;
    iexam.option = 0;
    location.hash = `#/${view}?goal=${encodeURIComponent(e.target.value)}`;
  });
}

// ---- Attack connectivity graph (iEXAM GraphPreview) ----

function acgCard(title, legendExtra, hint) {
  return `<section class="card">
    <div class="card-head">${IEXAM_ICONS.route}<h2>${esc(title)}</h2></div>${hint || ""}
    <div class="acg"><div id="acg" class="acg-graph" role="img" aria-label="Attack connectivity graph"></div>
      <div class="map-legend" aria-hidden="true">
        <span><i class="dot attacker"></i>Attacker</span><span><i class="dot"></i>Node</span>
        <span><i class="dot vuln"></i>Has CVEs</span><span><i class="dot cve"></i>CVE</span>
        <span><i class="dot goal"></i>Goal</span><span><i class="dot path"></i>On plan</span>
        <span><i class="dot cvehit"></i>CVE used</span>${legendExtra || ""}
        <span><i class="dot outside"></i><i class="line dotted"></i>No usable CVE</span>
      </div></div>
  </section>`;
}

// h: { nodeIds, edgeIds, cveIds, goalId, changed (node ids), removed ("node::CVE", the CVE removed on that node) }.
// Every CVE on a connection is its own box (one attack step); devices outside the attack model (no usable
// CVE) hang off their router on a dotted line. Columns follow attack depth; each node gets a slot as tall
// as the CVE boxes leading into it, so nothing overlaps however many CVEs a device has.
const BOX_H = 26, NODE_SLOT = 76, COL_W = 460;

function drawAcg(h) {
  const g = plans.attack_graph;
  const inModel = new Set(g.nodes.map((n) => n.ip));
  const routerOf = (n) => {
    const e = model.edges.find((x) => x.target === n.id && x.source !== "n0");
    const src = e && model.nodes.find((m) => m.id === e.source);
    return src && g.nodes.find((x) => x.ip === src.ip);
  };
  const outside = model.nodes.filter((n) => n.kind !== "attacker" && n.kind !== "self" && !inModel.has(n.ip))
    .map((n) => ({ id: `x::${n.id}`, label: n.name && n.name !== n.ip ? n.name : n.ip, ip: n.ip, from: routerOf(n)?.id }))
    .filter((n) => n.from);
  const nodes = [...g.nodes.map((n) => ({ ...n, outside: false })), ...outside.map((n) => ({ ...n, outside: true }))];
  const edges = [...g.edges.map((e) => ({ ...e, cves: g.attack_edges.filter((a) => a.edge === e.id).map((a) => a.cve) })),
    ...outside.map((n) => ({ id: `xe::${n.id}`, source: n.from, target: n.id, cves: [], dotted: true }))];

  // Columns by attack depth; slot height grows with the CVE boxes on the way in.
  const depth = { n0: 0 };
  const queue = ["n0"];
  while (queue.length) {
    const id = queue.shift();
    for (const e of edges) if (e.source === id && !(e.target in depth)) { depth[e.target] = depth[id] + 1; queue.push(e.target); }
  }
  const boxesInto = (id) => edges.filter((e) => e.target === id).reduce((k, e) => k + e.cves.length, 0);
  const slot = (n) => Math.max(NODE_SLOT, boxesInto(n.id) * BOX_H + 24);
  const cols = {};
  for (const n of nodes) (cols[depth[n.id] ?? 1] ||= []).push(n);
  const pos = {};
  let tallest = 0;
  for (const [d, col] of Object.entries(cols)) {
    col.sort((a, b) => a.outside - b.outside || boxesInto(b.id) - boxesInto(a.id));
    const total = col.reduce((k, n) => k + slot(n), 0);
    tallest = Math.max(tallest, total);
    let y = -total / 2;
    for (const n of col) { pos[n.id] = { x: Number(d) * COL_W, y: y + slot(n) / 2 }; y += slot(n); }
  }

  const els = nodes.map((n) => ({
    data: { id: n.id, label: n.id === "n0" ? "Attacker" : n.label === n.ip ? n.ip : `${n.label}\n${n.ip}`, kind: "node", attacker: n.id === "n0",
      outside: n.outside, cves: n.cve_count || 0,
      state: n.id === h.goalId ? "goal" : h.changed.has(n.id) ? "changed" : h.nodeIds.has(n.id) ? "path" : "" },
    position: pos[n.id] }));
  for (const e of edges) {
    const onPlan = h.edgeIds.has(e.id);
    if (!e.cves.length) {
      els.push({ data: { id: `e::${e.id}`, source: e.source, target: e.target, kind: e.dotted ? "dotted" : "plain", hit: onPlan } });
      continue;
    }
    const a = pos[e.source], b = pos[e.target];
    e.cves.forEach((c, i) => {
      const id = `cve::${e.id}::${c}`;
      const state = h.removed.has(`${e.target}::${c}`) ? "removed" : onPlan && h.cveIds.has(c) ? "hit" : "";
      els.push({ data: { id, label: c, kind: "cvebox", state },
        position: { x: (a.x + b.x) / 2, y: b.y + (i - (e.cves.length - 1) / 2) * BOX_H } });
      const hit = state === "hit", removed = state === "removed";
      els.push({ data: { id: `${id}::pre`, source: e.source, target: id, kind: "attack", hit, removed } });
      els.push({ data: { id: `${id}::post`, source: id, target: e.target, kind: "attack", hit, removed } });
    });
  }
  // Tall enough that every box is readable; the page scrolls, and the graph still zooms and pans.
  $("#acg").parentElement.style.height = `${Math.round(Math.min(4200, Math.max(560, tallest * 0.95 + 140)))}px`;

  if (acg) acg.destroy();
  const font = getComputedStyle(document.documentElement).getPropertyValue("--font").trim();
  acg = cytoscape({
    container: $("#acg"), elements: els, layout: { name: "preset", fit: true, padding: 48 },
    wheelSensitivity: 0.2, minZoom: 0.2, maxZoom: 2.5, autoungrabify: true,
    style: [
      { selector: "node[kind = 'node']", style: { shape: "round-rectangle", width: 170, height: 52, "background-color": ACG.node,
        label: "data(label)", color: ACG.text, "font-size": 12, "font-family": font, "text-wrap": "wrap", "text-max-width": 160,
        "text-valign": "center", "text-halign": "center", "border-width": 1, "border-color": ACG.border } },
      { selector: "node[?attacker]", style: { "background-color": ACG.attacker, "border-color": ACG.attackerBorder, color: ACG.attackerText } },
      { selector: "node[cves > 0]", style: { "border-color": ACG.vuln, "border-width": 2 } },
      { selector: "node[kind = 'cvebox']", style: { shape: "round-rectangle", width: 150, height: 24, "background-color": ACG.cve,
        "border-color": ACG.cveBorder, "border-width": 1, label: "data(label)", color: ACG.cveText, "font-size": 10,
        "font-weight": "bold", "font-family": font, "text-valign": "center", "text-halign": "center" } },
      { selector: "node[kind = 'cvebox'][state = 'hit']", style: { "background-color": ACG.hit, "border-color": ACG.hitBorder, color: "#ffffff", "border-width": 2 } },
      { selector: "node[kind = 'cvebox'][state = 'removed']", style: { "background-color": ACG.removed, "border-color": ACG.removedBorder, color: "#ffffff", "border-width": 2 } },
      { selector: "node[state = 'path']", style: { "border-color": ACG.pathBorder, "border-width": 3, "background-color": ACG.path, color: ACG.pathText } },
      { selector: "node[state = 'changed']", style: { "border-color": ACG.changedBorder, "border-width": 3, "background-color": ACG.changed, color: ACG.changedText } },
      { selector: "node[state = 'goal']", style: { "border-color": ACG.goalBorder, "border-width": 4, "background-color": ACG.goal, color: ACG.goalText } },
      { selector: "edge[kind = 'plain']", style: { width: 1.5, "line-color": ACG.edge, "target-arrow-color": ACG.edge,
        "target-arrow-shape": "triangle", "curve-style": "bezier" } },
      { selector: "edge[kind = 'attack']", style: { width: 1.5, "line-color": ACG.attack, "line-style": "dashed",
        "target-arrow-color": ACG.attack, "target-arrow-shape": "triangle", "curve-style": "bezier", opacity: 0.55 } },
      { selector: "edge[kind = 'dotted']", style: { width: 2, "line-color": ACG.edge, "line-style": "dashed",
        "line-dash-pattern": [2, 7], "curve-style": "bezier", "target-arrow-shape": "none", opacity: 0.9 } },
      { selector: "node[?outside]", style: { "border-style": "dashed", "border-color": ACG.edge, opacity: 0.85 } },
      { selector: "edge[?hit][kind = 'plain']", style: { width: 3, "line-color": ACG.pathBorder, "target-arrow-color": ACG.pathBorder } },
      { selector: "edge[?hit][kind = 'attack']", style: { width: 3, "line-color": ACG.hit, "target-arrow-color": ACG.hit, opacity: 1 } },
      { selector: "edge[?removed]", style: { "line-color": ACG.removed, "target-arrow-color": ACG.removed } },
    ],
  });
  acg.ready(() => { acg.resize(); acg.fit(undefined, 48); });
}

function planHighlight(plan, goal) {
  const hl = plan?.highlights || {};
  const goalId = plans.attack_graph.nodes.find((n) => n.label === goal)?.id;
  return { nodeIds: new Set(hl.node_ids || []), edgeIds: new Set(hl.edge_ids || []), cveIds: new Set(hl.cve_ids || []),
    goalId, changed: new Set(), removed: new Set() };
}

// ---- Plan page ----

function renderPlanPage(el, head) {
  const t = targetFor(iexam.goal);
  const topk = t?.topk?.plans || [];
  if (iexam.topk >= topk.length) iexam.topk = 0;
  const shownPlan = iexam.tab === "topk" ? topk[iexam.topk] : t?.optimal;
  el.innerHTML = `${head}${goalCard("plan")}${acgCard("Attack connectivity graph")}
    <div class="tabs" role="tablist" aria-label="Plan type">
      <button type="button" role="tab" class="tab" data-tab="optimal" aria-selected="${iexam.tab === "optimal"}">Optimal plan</button>
      <button type="button" role="tab" class="tab" data-tab="topk" aria-selected="${iexam.tab === "topk"}">Top-K plans</button>
    </div>
    <div role="tabpanel">${iexam.tab === "optimal" ? optimalPanel(t) : topkPanel(t)}</div>`;
  bindGoal("plan");
  el.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { iexam.tab = b.dataset.tab; renderPlanPage(el, head); }));
  el.querySelectorAll("[data-topk]").forEach((b) => b.addEventListener("click", () => { iexam.topk = Number(b.dataset.topk); renderPlanPage(el, head); }));
  drawAcg(planHighlight(t?.error ? null : shownPlan, iexam.goal));
}

// What each kind of plan is, shown above its button.
const ABOUT_OPTIMAL = `<div class="about"><p><strong>What is the optimal plan?</strong> The shortest attack path: the fewest
  steps an attacker on the internet needs to take over this device, where each step uses one vulnerability (CVE) on a
  device it can reach. iEXAM's planner (Fast Downward, A* search with the LM-cut heuristic) checks every possible chain
  and guarantees there is no shorter one. It is the attacker's easiest way in, so it is the first path to close.</p>
  <p>Each step is also explained in plain words by an AI model (needs <code>NVIDIA_API_KEY</code>).</p></div>`;
const ABOUT_TOPK = `<div class="about"><p><strong>What are top-K plans?</strong> The K shortest attack paths, best first.
  Plan 1 is the optimal plan; the others are what an attacker would try next if that path were blocked, so they show
  whether one fix is enough or several routes need closing. iEXAM's top-K planner (ForbidIterative) finds them by
  forbidding each plan it has found and searching again.</p></div>`;

const busyNow = () => job?.state === "running";
const runningHere = (action) => busyNow() && job.current === action && job.run === currentRun && job.goal === iexam.goal;

function actionButton(action, label, again) {
  const text = runningHere(action) ? "Working…" : again ? `${label} again` : label;
  return `<button type="button" class="primary" data-action="${action}" ${busyNow() ? "disabled" : ""}>${text}</button>`;
}

function planSummary(goal, p) {
  const hl = p.highlights || {};
  return `<dl class="kv">
    <div><dt>Goal</dt><dd>${esc(goal)}</dd></div>
    <div><dt>Steps</dt><dd>${p.step_count}</dd></div>
    <div><dt>Cost</dt><dd>${esc(p.cost ?? "–")}</dd></div>
    <div><dt>CVEs used</dt><dd class="mono">${esc((hl.cve_ids || []).join(", ") || "–")}</dd></div>
    <div><dt>Nodes touched</dt><dd>${(hl.node_ids || []).length}</dd></div>
  </dl>`;
}

const rawSteps = (steps) => `<ol class="raw-steps">${steps.map((s) =>
  `<li><span class="plain">${esc(stepText(s))}</span><code>${esc(s)}</code></li>`).join("")}</ol>`;

function optimalPanel(t) {
  const ex = t?.optimal_explanation;
  let result = "";
  if (t?.error || plans.unreachable_goals.includes(iexam.goal)) {
    result = `<p class="empty">No attack path reaches this device. ${esc(t?.error || "")}</p>`;
  } else if (t?.optimal) {
    result = `${planSummary(t.goal, t.optimal)}${rawSteps(t.optimal.steps)}
      ${ex?.text ? `<div class="llm"><h3>AI explanation <span class="flag">AI-generated</span><span class="model">${esc(ex.model || "")}</span></h3>
        <div class="ai-text">${esc(ex.text)}</div></div>` : `<p class="hint llm">No AI explanation (no NVIDIA_API_KEY, or the AI service did not answer; the reason is in Logs).</p>`}`;
  }
  return `<section class="card">
    <div class="card-head"><h2>Optimal plan</h2></div>
    ${ABOUT_OPTIMAL}
    <div class="action-row">${actionButton("optimal", "Find optimal plan", !!(t?.optimal || t?.error))}
      ${t?.optimal_seconds != null ? `<span class="hint">Found in ${t.optimal_seconds}s.</span>` : ""}</div>
    ${result}
  </section>`;
}

function topkPanel(t) {
  const list = t?.topk?.plans || [];
  const k = t?.topk?.k_requested || iexam.k;
  let result = "";
  if (t?.topk_error) result = `<p class="empty">The top-K planner found no plans: ${esc(t.topk_error)}</p>`;
  else if (list.length) {
    const p = list[iexam.topk];
    result = `<p class="hint">Top-${t.topk.k_requested}: ${plural(t.topk.k_returned, "plan", "plans")} found. The selected one is highlighted on the graph.</p>
      <div class="two-col">
        <ul class="pick-list">${list.map((x, i) => `<li><button type="button" class="pick" data-topk="${i}" aria-pressed="${i === iexam.topk}">
          <span class="pick-title">Plan ${i + 1}${i === 0 ? ` <span class="flag">shortest</span>` : ""}</span>
          <span class="pick-meta">${plural(x.step_count, "step", "steps")} · cost ${esc(x.cost ?? "–")} · ${esc((x.highlights.cve_ids || []).join(", "))}</span>
        </button></li>`).join("")}</ul>
        <div>${planSummary(t.goal, p)}${rawSteps(p.steps)}</div>
      </div>`;
  }
  return `<section class="card">
    <div class="card-head"><h2>Top-K plans</h2></div>
    ${ABOUT_TOPK}
    <div class="action-row">
      <label class="k-pick">K <select id="k-select" aria-label="Number of plans">
        ${Array.from({ length: 10 }, (_, i) => i + 1).map((n) => `<option value="${n}" ${n === k ? "selected" : ""}>${n}</option>`).join("")}
      </select></label>
      ${actionButton("topk", "Find top-K plans", !!(t?.topk || t?.topk_error))}
      ${t?.topk_seconds != null ? `<span class="hint">Found in ${t.topk_seconds}s.</span>` : ""}</div>
    ${result}
  </section>`;
}

// ---- Mitigate page (iEXAM Metric 1) ----

const optionLabel = (o, i) => `Option ${i + 1}: Make a change in ` +
  o.actions.map((a) => untoken(a.token)).join(", ").replace(/, ([^,]*)$/, " and $1");

// Where the optimal plan breaks: the first step that needs a removed fact (iEXAM's "Plan failures").
function planFailures(t, o) {
  const steps = t.optimal?.steps || [];
  return o.actions.map((a) => {
    const target = pddlToken(iexamLabel(a.node));
    const i = steps.findIndex((s) => { const args = s.replace(/^\(|\)$/g, "").split(/\s+/).slice(1); return args[0] === target && args.includes(a.token); });
    return i < 0 ? null : { step: i + 1, action: steps[i], predicate: `(has-${a.node}-${a.fact}-… ${a.token})` };
  }).filter(Boolean);
}

function renderMitigatePage(el, head) {
  const t = targetFor(iexam.goal);
  const m = mitigation?.targets.find((x) => x.goal === iexam.goal);
  const opts = m?.options || [];
  if (iexam.option >= opts.length) iexam.option = 0;
  const o = opts[iexam.option];
  let body;
  if (!mitigation) body = notice("No mitigation options for this scan yet. Run <strong>Mitigate</strong> above to find them.");
  else if (t?.error || m?.unreachable || plans.unreachable_goals.includes(iexam.goal)) body = notice("No attack path reaches this goal, so there is nothing to block.");
  else if (!opts.length) body = notice(`Metric 1 found no option for this goal. ${esc(mitigation.notes.join(" "))}`);
  else body = `${optionsCard(opts)}${resultsCard(t, o, iexam.option)}`;

  el.innerHTML = `${head}${goalCard("mitigate")}
    ${acgCard("Attack path on the network", `<span><i class="dot changed"></i>Changed by option</span><span><i class="dot removed"></i>CVE removed</span>`,
      t?.optimal ? `<p class="hint">Steps: ${t.optimal.step_count} · CVEs used: <span class="mono">${esc(t.optimal.highlights.cve_ids.join(", "))}</span></p>`
        : `<p class="hint">Find the optimal plan on <a href="#/plan?goal=${encodeURIComponent(iexam.goal)}">Security Profile</a> to see the attack path here.</p>`)}
    ${body}`;
  bindGoal("mitigate");
  el.querySelectorAll("[data-option]").forEach((b) => b.addEventListener("click", () => { iexam.option = Number(b.dataset.option); renderMitigatePage(el, head); }));
  el.querySelectorAll("[data-raw]").forEach((b) => b.addEventListener("click", () => {
    const k = b.dataset.raw;
    iexam.raw.has(k) ? iexam.raw.delete(k) : iexam.raw.add(k);
    renderMitigatePage(el, head);
  }));
  const h = planHighlight(t?.optimal, iexam.goal);
  if (o) {
    o.actions.forEach((a) => h.changed.add(a.node));
    o.actions.forEach((a) => a.evidence.forEach((e) => h.removed.add(`${a.node}::${e.cve}`)));
    h.changed.delete(h.goalId);  // the goal keeps its blue border
  }
  drawAcg(h);
}

function optionsCard(opts) {
  return `<section class="card">
    <div class="card-head">${IEXAM_ICONS.shield}<h2>Mitigation options</h2></div>
    <p class="hint">Each option is a set of changes; any one option blocks every attack path to the goal. Select one to see it on the graph.</p>
    <div class="action-row">${actionButton("guide", "Explain how to fix", opts.every((o) => o.actions.every((a) => guide?.guides[actionKey(a)])))}
      <span class="hint">An LLM reads the advisories and patch pages linked below and writes the steps.</span></div>
    <ul class="pick-list">${opts.map((o, i) => {
      const key = `${iexam.goal}/${i}`;
      return `<li><div class="opt-row">
        <button type="button" class="pick" data-option="${i}" aria-pressed="${i === iexam.option}">
          <span class="pick-title">${esc(optionLabel(o, i))}
            ${o.blocks_all_plans ? `<span class="flag ok">Verified</span>` : `<span class="flag kev">Not verified</span>`}</span>
          <span class="pick-meta">${plural(o.actions.length, "change", "changes")} · ${plural(o.actions.reduce((n, a) => n + a.cves_fixed, 0), "CVE", "CVEs")} removed</span>
        </button>
        <button type="button" class="linkish" data-raw="${esc(key)}" aria-expanded="${iexam.raw.has(key)}">${iexam.raw.has(key) ? "Hide raw" : "Show raw"}</button>
      </div>${iexam.raw.has(key) ? `<pre class="raw">${esc(o.pddl)}</pre>` : ""}</li>`;
    }).join("")}</ul>
  </section>`;
}

const actionKey = (a) => `${a.node}|${a.fact}|${a.token}`;
const safeHref = (u) => /^https?:\/\//i.test(u) ? esc(u) : "#";

// Phase 8b: the LLM's how-to for one action, from guide.json.
function guideBlock(a) {
  const g = guide?.guides[actionKey(a)];
  if (!g) return "";
  return `<div class="llm guide"><h3>How to fix <span class="flag">AI-generated</span></h3>
    <p>${esc(g.how_it_blocks)}</p>
    <ol>${g.steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
    ${g.links.length ? `<ul class="evidence">${g.links.map((l) => `<li><a href="${safeHref(l.url)}" target="_blank" rel="noopener noreferrer">${esc(l.title)}</a></li>`).join("")}</ul>` : ""}
    <p class="hint">AI-written guidance — check against the vendor's page before acting.${g.no_sources ? " No source page could be fetched; written from the CVE data only." : ""}</p>
  </div>`;
}

function resultsCard(t, o, i) {
  const fails = planFailures(t, o);
  const cves = [...new Set(o.actions.flatMap((a) => a.evidence.map((e) => e.cve)))];
  return `<section class="card">
    <div class="card-head"><h2>Option ${i + 1} — results</h2>
      ${o.blocks_all_plans ? `<span class="flag ok">Verified: the goal is unreachable with these changes</span>` : `<span class="flag kev">Did not block every path</span>`}</div>
    <div class="two-col">
      <div>
        <h3 class="eyebrow">Changes</h3>
        <ul class="actions">${o.actions.map((a) => `<li>${esc(a.text)}.${guideBlock(a)}
          ${a.evidence.length ? `<details><summary>Evidence: ${plural(a.cves_fixed, "vulnerability", "vulnerabilities")} removed</summary>
            <ul class="evidence">${a.evidence.map(evidenceRow).join("")}</ul></details>` : ""}</li>`).join("")}</ul>
      </div>
      <div>
        <h3 class="eyebrow">Plan failures</h3>
        ${fails.length ? `<ul class="actions">${fails.map((f) => `<li>Step ${f.step} fails.
          <div class="raw">Failing action: ${esc(f.action)}</div><div class="raw">Unsatisfied predicate: ${esc(f.predicate)}</div></li>`).join("")}</ul>`
          : t.optimal ? `<p class="empty">No step of the optimal plan uses these facts directly; the option blocks the alternative paths.</p>`
          : `<p class="empty">Find the optimal plan on Security Profile to see where it breaks.</p>`}
        <h3 class="eyebrow" style="margin-top: var(--space-4)">CVEs</h3>
        ${cves.length ? `<p class="mono raw">${cves.map(esc).join(", ")}</p>` : `<p class="empty">No CVEs identified.</p>`}
      </div>
    </div>
  </section>`;
}
