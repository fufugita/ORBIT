/* ORBIT browser harness client — WebSocket (actions) + SSE (events).
 * Same protocol as the Go TUI bridge; the SPA is a thin view. */
"use strict";

// ── tiny helpers ────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
};
const fmtCost = (microcents) =>
  microcents > 0 ? `$${(microcents / 1_000_000).toFixed(4)}` : "—";
const fmtTime = () =>
  new Date().toTimeString().slice(0, 5);

// ── state ───────────────────────────────────────────────────────────
const S = {
  ws: null,
  es: null,
  model: "—", provider: "—", session: "—", sessionShort: "—",
  cost: null, turns: 0,
  busy: false,             // a turn is streaming
  streamingBody: null,     // the assistant .body being appended to
  pendingApprovals: [],    // [{call_id, name, summary}] — server-issued
  approvalModalOpen: false,
};

// ── rendering ───────────────────────────────────────────────────────
function setStatus() {
  $("st-model").textContent = S.model;
  $("st-model").dataset.k = "model";
  $("st-provider").textContent = S.provider;
  $("st-provider").dataset.k = "provider";
  $("st-session").textContent = S.sessionShort;
  $("st-session").dataset.k = "session";
  $("st-cost").textContent = S.cost === null ? "n/a" : fmtCost(S.cost);
  $("st-cost").dataset.k = "cost";
  $("st-turns").textContent = S.turns;
  $("st-turns").dataset.k = "turns";
  $("us-in").textContent = S.input ?? "—";
  $("us-out").textContent = S.output ?? "—";
  $("us-cost").textContent = S.cost === null ? "n/a" : fmtCost(S.cost);
  $("us-turns").textContent = S.turns;
  $("btn-cancel").hidden = !S.busy;
  $("btn-send").disabled = S.busy;
}

function scrollDown() {
  // Sticky scroll: only follow the stream when the operator is already at
  // (or within 40px of) the bottom. A mid-drag selection or a manual
  // scroll-up must never be yanked back down — the old unconditional
  // scrollTop assignment made text selection impossible during streaming.
  const t = $("transcript");
  const atBottom = t.scrollHeight - t.scrollTop - t.clientHeight < 40;
  if (atBottom) t.scrollTop = t.scrollHeight;
}

function addMsg(role, text) {
  const m = el("div", `msg ${role}`);
  m.appendChild(el("div", "who", role === "user" ? "you" : role === "assistant" ? "orbit" : "system"));
  const body = el("div", "body");
  body.textContent = text;
  m.appendChild(body);
  $("transcript").appendChild(m);
  scrollDown();
  return body;
}

function ensureStreaming() {
  if (S.streamingBody) return S.streamingBody;
  const m = el("div", "msg assistant");
  m.appendChild(el("div", "who", "orbit"));
  const body = el("div", "body");
  const cursor = el("span"); cursor.id = "streaming-cursor";
  body.appendChild(cursor);
  m.appendChild(body);
  $("transcript").appendChild(m);
  S.streamingBody = body;
  scrollDown();
  return body;
}

function finishStreaming(text) {
  if (S.streamingBody) {
    S.streamingBody.textContent = text || S.streamingBody.textContent;
    S.streamingBody = null;
  } else if (text) {
    addMsg("assistant", text);
  }
}

function addActivity(kind, text) {
  const li = el("li", kind);
  li.appendChild(el("span", "t", fmtTime()));
  li.appendChild(document.createTextNode(text));
  $("activity-list").appendChild(li);
  li.scrollIntoView({ block: "end" });
}

function toast(text, isError) {
  const t = $("toast");
  t.textContent = text;
  t.classList.toggle("error", !!isError);
  t.hidden = false;
  clearTimeout(toast._h);
  toast._h = setTimeout(() => (t.hidden = true), 3500);
}

// ── approval modal ──────────────────────────────────────────────────
function showApproval() {
  const next = S.pendingApprovals[0];
  if (!next) { $("approval-modal").hidden = true; S.approvalModalOpen = false; return; }
  $("ap-tool").textContent = next.name;
  $("ap-summary").textContent = next.summary;
  $("approval-modal").hidden = false;
  S.approvalModalOpen = true;
}

function sendVerdict(verdict) {
  const next = S.pendingApprovals.shift();
  if (!next) return;
  send({ type: "approve", call_id: next.call_id, verdict });
  $("approval-modal").hidden = true;
  S.approvalModalOpen = false;
  showApproval(); // next in queue, if any
}

// ── transport ───────────────────────────────────────────────────────
function send(action) {
  if (S.ws && S.ws.readyState === 1) S.ws.send(JSON.stringify(action));
}

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const token = new URLSearchParams(location.search).get("token");
  const tk = token ? `?token=${encodeURIComponent(token)}` : "";

  // SSE: server → browser events
  S.es = new EventSource(`/events${tk}`);
  const on = (kind, fn) => S.es.addEventListener(kind, (e) => fn(JSON.parse(e.data || "{}")));
  on("identity", (d) => {
    S.model = d.model; S.provider = d.provider;
    S.session = d.session_id || d.session; S.sessionShort = d.session;
    setStatus();
  });
  on("resumed", (d) => { S.turns = d.turns ?? 0; S.cost = d.cost_microcents ?? null; setStatus(); });
  on("delta", (d) => {
    S.busy = true; setStatus();
    const body = ensureStreaming();
    body.insertBefore(document.createTextNode(d.text), body.lastChild);
    scrollDown();
  });
  on("cost", (d) => { S.input = d.input_tokens; S.output = d.output_tokens; setStatus(); });
  on("tool_call_started", (d) => {
    const card = el("div", "tool-card");
    card.dataset.callId = d.call_id;
    card.appendChild(el("span", "name", `⚙ ${d.name}`));
    card.appendChild(document.createTextNode(` ${d.summary}`));
    $("transcript").appendChild(card);
    scrollDown();
  });
  S.es.addEventListener("approval", (e) => {
    const d = JSON.parse(e.data || "{}");
    S.pendingApprovals.push(d);
    showApproval();
  });
  on("tool_call_finished", (d) => {
    const card = document.querySelector(`.tool-card[data-call-id="${CSS.escape(d.call_id)}"]`);
    if (card) {
      card.classList.add(d.ok ? "finished-ok" : "finished-err");
    }
    addActivity(d.ok ? "ok" : "err", d.name);
    // If this finished an approved call, drop it from the pending queue.
    S.pendingApprovals = S.pendingApprovals.filter((p) => p.call_id !== d.call_id);
    if (!S.pendingApprovals.length) { $("approval-modal").hidden = true; S.approvalModalOpen = false; }
    else showApproval();
  });
  on("models", (d) => {
    const lines = (d.models || []).map((m) => `${m.provider} \t${m.model}`);
    addMsg("system", lines.join("\n") || "(no providers configured)");
  });
  on("sessions", (d) => {
    const ul = $("sessions-list");
    ul.textContent = "";
    for (const s of d.sessions || []) {
      const li = el("li", s.session_id === S.session ? "active" : "");
      li.textContent = `${s.session_id.slice(0, 8)} · ${s.turns}t · ${s.model}`;
      li.title = `resume ${s.session_id}`;
      li.onclick = () => send({ type: "resume", id: s.session_id });
      ul.appendChild(li);
    }
  });
  on("transcript", (d) => {
    $("transcript").textContent = "";
    for (const m of d.messages || []) addMsg(m.role, m.text);
    S.session = d.session_id || S.session;
    S.sessionShort = (d.session_id || S.session).slice(0, 8);
    S.turns = d.turns ?? S.turns;
    S.input = d.input_tokens; S.output = d.output_tokens;
    S.cost = d.cost_microcents ?? S.cost;
    setStatus();
    toast("session loaded");
  });
  on("model_changed", (d) => { S.model = d.model; setStatus(); toast(`model → ${d.model}`); });
  on("error", (d) => {
    finishStreaming();
    S.busy = false; setStatus();
    addMsg("system", d.message || "error");
    toast(d.message || "error", true);
  });
  on("finished", (d) => {
    finishStreaming(d.output || "");
    S.busy = false;
    if (d.cancelled) addMsg("system", "cancelled");
    S.input = d.input_tokens ?? S.input;
    S.output = d.output_tokens ?? S.output;
    S.cost = d.cost_microcents ?? S.cost;
    S.turns = d.turns ?? S.turns;
    setStatus();
  });

  S.es.onerror = () => connState("err", "reconnecting");
  S.es.onopen = () => connState("ok", "live");

  // WS: browser → Rust actions
  S.ws = new WebSocket(`${proto}://${location.host}/actions${tk}`);
  S.ws.onopen = () => {
    connState("ok", "live");
    send({ type: "list_sessions" });
  };
  S.ws.onclose = () => { connState("err", "offline"); setTimeout(connect, 2000); };
}

function connState(cls, text) {
  const c = $("conn");
  c.className = cls;
  $("conn-text").textContent = text;
}

// ── composer ────────────────────────────────────────────────────────
function submit() {
  const box = $("composer");
  const text = box.value.trim();
  if (!text || S.busy) return;

  // Slash commands (client-visible subset; the server handles the rest).
  const cmd = text.match(/^\/(\w+)\s*(.*)$/);
  if (cmd) {
    const [, name, rest] = cmd;
    if (name === "clear") { $("transcript").textContent = ""; box.value = ""; return; }
    if (name === "models") { send({ type: "list_models" }); box.value = ""; return; }
    if (name === "sessions") { send({ type: "list_sessions" }); box.value = ""; return; }
    if (name === "model") {
      if (!rest) { toast("usage: /model <name>", true); return; }
      send({ type: "set_model", model: rest.trim() });
      box.value = "";
      return;
    }
    if (name === "resume") {
      if (!rest) { toast("usage: /resume <id>", true); return; }
      send({ type: "resume", id: rest.trim() });
      box.value = "";
      return;
    }
    // unknown → send as prompt? No: show help, don't leak typos to the model.
    toast(`unknown command /${name} — try /model /models /sessions /resume /clear`, true);
    return;
  }

  addMsg("user", text);
  box.value = "";
  S.busy = true;
  setStatus();
  send({ type: "prompt", text });
}

// Click-to-focus (TUI parity): a click in the chat pane focuses the
// composer so typing always lands somewhere. Listen on 'click' (mouseup),
// NEVER 'mousedown' — mousedown is when a text-selection drag STARTS, and
// focusing the composer at that instant aborts the drag. A finished drag
// has a Range selection at click time and is left alone; Ctrl+C then
// copies it natively.
$("chat-pane").addEventListener("click", (e) => {
  if (e.target.closest("button, a, .tool-card")) return;
  const sel = window.getSelection();
  if (sel && !sel.isCollapsed) return; // user just selected text
  $("composer").focus();
});

$("btn-send").onclick = submit;
$("btn-cancel").onclick = () => send({ type: "cancel" });
$("btn-refresh-sessions").onclick = () => send({ type: "list_sessions" });
$("composer").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); }
});
$("ap-allow").onclick = () => sendVerdict("allow");
$("ap-session").onclick = () => sendVerdict("session");
$("ap-deny").onclick = () => sendVerdict("deny");

// Global keys (approval modal has y / n / R).
document.addEventListener("keydown", (e) => {
  if (!S.approvalModalOpen) return;
  if (e.key === "y") sendVerdict("allow");
  else if (e.key === "n" || e.key === "Escape") sendVerdict("deny");
  else if (e.key === "R") sendVerdict("session");
});

connect();
