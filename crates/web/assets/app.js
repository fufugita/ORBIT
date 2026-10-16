/* Browser view over the leased session owner. Model requests are never replayed. */
"use strict";
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};
const fmtCost = (cost) => cost > 0 ? `$${(cost / 1_000_000).toFixed(4)}` : "—";
const S = {
  ws: null, es: null, generation: 0, reconnectTimer: null, controlling: false,
  cursor: null, model: "—", provider: "—", session: "—", sessionShort: "—",
  cost: null, turns: 0, busy: false, streamingBody: null,
  contextUsage: null, contextProgress: null,
  pendingApprovals: [], approvalModalOpen: false, effort: null,
};
const tokenCount = (value) => Number.isSafeInteger(value) && value >= 0;
function clearContext() {
  S.contextUsage=null; S.contextProgress=null;
}
function contextSample(data) {
  if (!tokenCount(data.used_tokens) || !tokenCount(data.window_tokens) || data.window_tokens===0) return null;
  const sample={used:data.used_tokens,window:data.window_tokens,compactAt:null,reserve:null};
  if (data.breakdown !== undefined && data.breakdown !== null) {
    if (!tokenCount(data.breakdown.compact_at) || !tokenCount(data.breakdown.reserve)) return null;
    sample.compactAt=data.breakdown.compact_at; sample.reserve=data.breakdown.reserve;
  }
  return sample;
}
function contextEstimate() {
  return S.contextUsage ? `${S.contextUsage.used} / ${S.contextUsage.window} tokens` : "Unavailable";
}
function renderContext() {
  $("st-context").dataset.k="context estimate";
  $("st-context").textContent=S.contextProgress ?? contextEstimate();
  $("us-context").textContent=`Estimate: ${contextEstimate()}`;
  $("us-compact").textContent=S.contextUsage?.compactAt ?? "Unavailable";
  $("us-reserve").textContent=S.contextUsage?.reserve ?? "Unavailable";
  $("us-context-progress").textContent=S.contextProgress ?? "—";
}
// Profiles remain checked on the host; only literal bounded presentation reaches DOM styles.
function customizationAvailable() {
  return typeof fetch === "function" && !!document.documentElement?.style;
}
function customizationControls() {
  if (!S.customEnabled) return;
  for (const node of document.querySelectorAll("[data-custom-write]")) node.disabled = !S.controlling || !S.profile;
  $("custom-reload").disabled = false;
}
function customizationCommand(command) {
  if (!S.profile) { toast("Reload customization first", true); return false; }
  return send({type:"customize",command,expected_revision:S.profile.revision});
}
function customizationRead(generation) {
  if (!S.customEnabled) return;
  const epoch=S.customEpoch, session=S.session;
  const token=new URLSearchParams(location.search).get("token");
  const query=new URLSearchParams(); if (token) query.set("token",token);
  fetch(`/customization?${query.toString()}`,{cache:"no-store",credentials:"same-origin"})
    .then(async response=>{if (!response.ok) throw new Error((await response.text()).slice(0,512)); return response.json();})
    .then(data=>{if (generation===S.generation && epoch===S.customEpoch && session===S.session) applyCustomization(data);})
    .catch(error=>{if (generation===S.generation && epoch===S.customEpoch && session===S.session) {$("custom-status").textContent=`Customization unavailable: ${error.message}`;customizationControls();}});
}
function applyCustomization(data) {
  if (!S.customEnabled) return false;
  if (typeof data.session_id!=="string" || (S.session!=="—" && data.session_id!==S.session)) return false;
  const resolved=data.resolved, profile=resolved?.profile;
  if (!profile || typeof resolved.revision!=="string" || resolved.revision.length>256) {toast("Invalid customization response",true);return false;}
  const font=profile.browser?.font_family, size=profile.browser?.font_size_px;
  if (typeof font!=="string" || font.length>128 || !/^[a-zA-Z0-9 _,\-]+$/.test(font) || !Number.isFinite(size) || size<10 || size>24) {toast("Invalid customization font",true);return false;}
  const root=document.documentElement;
  for (const key of ["bg","bg-raised","bg-inset","line","text","dim","faint","accent","accent-dim","ok","warn","error","denied"]) {
    const value=data.palette?.[key]; if (typeof value==="string" && /^#[a-fA-F0-9]{6}$/.test(value)) root.style.setProperty(`--${key}`,value);
  }
  root.style.setProperty("--mono",font);
  root.style.setProperty("--font-size",`${size}px`);
  root.dataset.density=profile.density==="compact" ? "compact" : "comfortable";
  root.dataset.glyphs=profile.glyphs==="ascii" ? "ascii" : "unicode";
  root.dataset.motion=profile.reduced_motion ? "reduced" : "full";
  S.profile=resolved; S.customEpoch++;
  S.paneOutputs=new Map((data.panes || []).slice(0,32).map(p=>[p.id,p]));
  $("custom-theme").value=profile.theme;
  $("custom-density").value=profile.density;
  $("custom-glyphs").value=profile.glyphs;
  $("custom-mode").value=profile.color_mode;
  $("custom-motion").checked=!!profile.reduced_motion;
  $("custom-font").value=font; $("custom-font-size").value=String(size);
  $("custom-layout").value=profile.layout?.preset || "custom";
  $("custom-tree").value=JSON.stringify(profile.layout?.tree,null,2);
  $("custom-panes").value=JSON.stringify(profile.panes || [],null,2);
  $("custom-status").textContent=data.message || `${profile.name} · ${resolved.revision.slice(0,8)}`;
  $("custom-capabilities").textContent=[resolved.capabilities?.terminal_font,resolved.capabilities?.instruction_mods,resolved.capabilities?.signed_packages].filter(Boolean).join("\n");
  $("profile-area").hidden=false;
  renderProfileLayout(); customizationControls();
  return true;
}
function selectProfilePane(id, focus=false) {
  if (!S.customEnabled) return;
  S.activePane=id;
  for (const leaf of document.querySelectorAll(".layout-leaf")) leaf.dataset.active=String(leaf.dataset.pane===id);
  for (const tab of $("profile-tabs").children) {
    const active=tab.dataset.pane===id; tab.setAttribute("aria-selected",String(active));tab.tabIndex=active ? 0 : -1;
    if (active && focus) tab.focus();
  }
}
function markCustomPanesStale() {
  if (!S.customEnabled || !S.profile) return;
  for (const output of S.paneOutputs.values()) {output.state="stale";output.text="Session changed; refresh this pane";}
  renderProfileLayout();
}
function focusProfileConversation() { selectProfilePane("conversation"); $("composer").focus(); }
function paneAction(pane,index) {
  send({type:"pane_action",pane_id:pane.id,action_index:index,revision:S.profile.revision});
}
function renderCustomPane(def, identity) {
  const section=el("section","layout-leaf custom-pane"); section.dataset.pane=identity;section.dataset.sourcePane=def.id;
  section.setAttribute("role","tabpanel");section.setAttribute("aria-label",def.title);
  section.appendChild(el("h2","",def.title));
  const output=S.paneOutputs.get(def.id);
  const state=el("div","pane-state",output?.state || "loading"); section.appendChild(state);
  const text=el("pre","pane-content",output?.text || (output?.state==="empty" ? "No content" : "Refresh to load this pane"));section.appendChild(text);
  if(output?.truncated) section.appendChild(el("p","pane-state","Output truncated"));
  const actions=el("div","pane-actions");
  const refresh=el("button","","Refresh");refresh.onclick=()=>S.controlling ? send({type:"pane_refresh",pane_id:def.id,revision:S.profile.revision}) : customizationRead(S.generation);actions.appendChild(refresh);
  for (const [index,action] of (output?.actions || []).entries()) {
    if (action.kind==="refresh") continue;
    const labels={focus_conversation:"Conversation",insert_prompt:"Insert draft",owner_cancel:"Cancel current turn"};
    if (!labels[action.kind]) continue;
    const button=el("button","",labels[action.kind]);button.dataset.customWrite="";button.disabled=!S.controlling;
    button.onclick=()=>paneAction(def,index);actions.appendChild(button);
  }
  section.appendChild(actions);return section;
}
function renderBuiltinPane(view,identity) {
  const section=el("section","layout-leaf builtin-pane"); section.dataset.pane=identity;section.dataset.view=view;
  section.setAttribute("role","tabpanel");section.setAttribute("aria-label",view);
  section.appendChild(el("h2","",view));section.appendChild(el("pre","pane-content",""));return section;
}
function renderBuiltinContent() {
  if (!S.customEnabled) return;
  for (const node of document.querySelectorAll(".builtin-pane")) {
    const content=node.children[1],view=node.dataset.view;
    if(view==="changes" || view==="review") content.textContent=S.changedFiles?.length ? S.changedFiles.map(v=>`${v.path} +${v.added || 0} -${v.removed || 0}`).join("\n") : "No file changes in this session";
    else if(view==="agent") content.textContent=S.visibleAgents?.size ? [...S.visibleAgents.values()].map(v=>`${v.name || v.agent_id}: ${v.state}`).join("\n") : "No agents in this session";
    else if(view==="context") content.textContent=`${S.provider}/${S.model}\nContext estimate: ${contextEstimate()}\nCompact at: ${S.contextUsage?.compactAt ?? "Unavailable"}\nOutput reserve: ${S.contextUsage?.reserve ?? "Unavailable"}\n${S.contextProgress || "No compaction reported"}\nCumulative input: ${S.input ?? "Unavailable"}\nCumulative output: ${S.output ?? "Unavailable"}\n${S.routeText || "No route selected yet"}`;
    else if(view==="plan") content.textContent="No plan shared in this session";
    else content.textContent=S.activityRows?.length ? S.activityRows.join("\n") : "No tool activity in this session";
  }
}
function renderProfileLayout() {
  const tree=S.profile?.profile?.layout?.tree;if(!tree)return;
  const chat=$("chat-pane");chat.classList.add("layout-leaf");chat.dataset.pane="conversation";chat.setAttribute("role","tabpanel");chat.setAttribute("aria-label","Conversation");
  const output=$("profile-layout"),tabs=$("profile-tabs");
  const leaves=[];let count=0;
  const build=(node,depth=0,path="root")=>{
    if(depth>8 || ++count>256)throw new Error("Layout exceeds display bounds");
    if(node.kind==="split") {
      const split=el("div","profile-split");split.style.flexDirection=node.dir==="down" ? "column" : "row";
      for(const [i,child] of (node.children || []).entries()) {const piece=build(child,depth+1,`${path}.${i}`);piece.style.flex=`${Math.max(1,Math.min(10000,node.shares?.[i] || 1))} 1 0`;split.appendChild(piece);}
      return split;
    }
    let leaf,title;
    if(node.kind==="custom") {const def=S.profile.profile.panes.find(p=>p.id===node.pane_id && p.surfaces.includes("browser"));
      if(def){leaf=renderCustomPane(def,`custom:${def.id}@${path}`);title=def.title;}else {leaf=renderBuiltinPane("unavailable",`unavailable:${path}`);leaf.children[1].textContent="This pane is unavailable on the browser surface";title="Unavailable pane";}}
    else if(node.kind==="panel" && node.view==="conversation") {leaf=chat;title="Conversation";}
    else {leaf=renderBuiltinPane(node.view || "unknown",`${node.view || "unknown"}:${path}`);title=node.view || "Panel";}
    leaves.push([leaf,title]);return leaf;
  };
  try {
    const built=build(tree);output.textContent="";output.appendChild(built);tabs.textContent="";
    for(const [leaf,title] of leaves) {const button=el("button","",title);button.dataset.pane=leaf.dataset.pane;button.setAttribute("role","tab");
      button.onclick=()=>selectProfilePane(leaf.dataset.pane);button.addEventListener("keydown",event=>{
        if(!["ArrowLeft","ArrowRight","Home","End"].includes(event.key))return;event.preventDefault();
        const index=leaves.findIndex(([candidate])=>candidate.dataset.pane===button.dataset.pane);
        const next=event.key==="Home" ? 0 : event.key==="End" ? leaves.length-1 : (index+(event.key==="ArrowRight" ? 1 : -1)+leaves.length)%leaves.length;
        selectProfilePane(leaves[next][0].dataset.pane,true);
      });tabs.appendChild(button);}
    if(!leaves.some(([leaf])=>leaf.dataset.pane===S.activePane))S.activePane="conversation";
    selectProfilePane(S.activePane);renderBuiltinContent();
  } catch(error) {toast(error.message,true);}
}
function setupCustomization() {
  S.customEnabled=customizationAvailable();S.customEpoch=0;S.profile=null;S.activePane="conversation";
  S.paneOutputs=new Map();S.visibleAgents=new Map();S.changedFiles=[];S.activityRows=[];
  if(!S.customEnabled)return;
  $("customization-settings").hidden=false;
  for(const [id,key] of [["custom-theme","theme"],["custom-density","density"],["custom-glyphs","glyphs"],["custom-mode","color_mode"],["custom-layout","layout.preset"]])
    $(id).onchange=()=>customizationCommand({kind:"set",key,value:$(id).value});
  $("custom-motion").onchange=()=>customizationCommand({kind:"set",key:"reduced_motion",value:String($("custom-motion").checked)});
  $("custom-font-apply").onclick=()=>{
    const font=$("custom-font").value,size=Number($("custom-font-size").value);
    if(font.length>128 || !/^[a-zA-Z0-9 _,\-]+$/.test(font) || !Number.isFinite(size) || size<10 || size>24){toast("Use literal font names and a size from 10 to 24",true);return;}
    // Sequential commands avoid submitting the second edit against the first edit's old revision.
    S.pendingFontSize={size:String(size),font};if(!customizationCommand({kind:"set",key:"browser.font_family",value:font}))S.pendingFontSize=null;
  };
  $("custom-color-apply").onclick=()=>customizationCommand({kind:"set",key:`token_overrides.${$("custom-color-key").value}`,value:$("custom-color").value});
  $("custom-tree-apply").onclick=()=>customizationCommand({kind:"set",key:"layout.tree",value:$("custom-tree").value});
  $("custom-panes-apply").onclick=()=>customizationCommand({kind:"set",key:"panes",value:$("custom-panes").value});
  $("custom-reset").onclick=()=>customizationCommand({kind:"reset",key:null});
  $("custom-reload").onclick=()=>S.controlling ? send({type:"customize",command:{kind:"reload"},expected_revision:null}) : customizationRead(S.generation);
  for(const op of ["validate","import","export"]) $("custom-"+op).onclick=()=>customizationCommand({kind:op,path:$("custom-path").value});
  customizationControls();
}

function setStatus() {
  for (const [key, value] of Object.entries({model:S.model,provider:S.provider,session:S.sessionShort,cost:S.cost === null ? "n/a" : fmtCost(S.cost),turns:S.turns})) {
    $(`st-${key}`).textContent = value; $(`st-${key}`).dataset.k = key;
  }
  $("us-in").textContent = S.input ?? "—"; $("us-out").textContent = S.output ?? "—";
  $("us-cost").textContent = S.cost === null ? "n/a" : fmtCost(S.cost); $("us-turns").textContent = S.turns;
  renderContext();
  $("btn-cancel").hidden = !S.busy; $("btn-cancel").disabled = !S.controlling;
  $("btn-send").disabled = S.busy || !S.controlling;
  $("effort-select").disabled = S.busy || !S.controlling;
  $("effort-reset").disabled = S.busy || !S.controlling;
  $("effort-query").disabled = !S.controlling;
  customizationControls();
  renderBuiltinContent();
}
function scrollDown() {
  const transcript = $("transcript");
  if (transcript.scrollHeight - transcript.scrollTop - transcript.clientHeight < 40) transcript.scrollTop = transcript.scrollHeight;
}
function addMsg(role, text) {
  const message = el("div", `msg ${["user","assistant","system","tool","status"].includes(role) ? role : "system"}`);
  message.appendChild(el("div", "who", role === "user" ? "you" : role === "assistant" ? "orbit" : "system"));
  const body = el("div", "body", text); message.appendChild(body); $("transcript").appendChild(message); scrollDown(); return body;
}
function ensureStreaming() {
  if (!S.streamingBody) S.streamingBody = addMsg("assistant", "");
  return S.streamingBody;
}
function finishStreaming(text) {
  if (S.streamingBody) { if (text) S.streamingBody.textContent = text; S.streamingBody = null; }
  else if (text) addMsg("assistant", text);
}
function toast(text, error) {
  $("toast").textContent = text; $("toast").classList.toggle("error", !!error); $("toast").hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { $("toast").hidden = true; }, 3500);
}
function addActivity(kind, text) {
  if (S.customEnabled) { S.activityRows.push(String(text).slice(0,4096));S.activityRows=S.activityRows.slice(-64);renderBuiltinContent(); }
  const item = el("li", kind, text); $("activity-list").appendChild(item); item.scrollIntoView({block:"end"});
}
function showApproval() {
  const approval = S.pendingApprovals[0]; S.approvalModalOpen = !!approval; $("approval-modal").hidden = !approval;
  if (approval) { $("ap-tool").textContent = approval.tool_name || approval.name; $("ap-summary").textContent = approval.summary; }
  for (const id of ["ap-allow","ap-session","ap-deny"]) $(id).disabled = !S.controlling;
}
function sendVerdict(verdict) {
  const approval = S.pendingApprovals[0];
  if (approval) send({type:"approval", call_id:approval.call_id, verdict, note:null});
}
function renderEffort() {
  const snapshot = S.effort;
  if (!snapshot) return;
  const select = $("effort-select"); select.textContent = "";
  const reset = {mode:"default"};
  const defaultOption = el("option", "", "Model default"); defaultOption.value = JSON.stringify(reset); select.appendChild(defaultOption);
  for (const value of snapshot.supported_efforts || []) {
    const option = el("option", "", `${JSON.stringify(value)} (${typeof value === "boolean" ? "boolean" : "level"})`);
    option.value = JSON.stringify({mode:"value",value}); select.appendChild(option);
  }
  select.value = JSON.stringify(snapshot.effort || reset);
  const provenance = snapshot.effort === null ? "No override" : snapshot.effort.mode === "default" ? "Explicit reset" : "Selected override";
  const support = snapshot.supported_efforts === null ? "Choices unknown" : snapshot.supported_efforts.length ? "Configured choices" : "Unsupported; default only";
  $("effort-provenance").textContent = `${provenance} · ${support}`;
  $("effort-status").textContent = snapshot.effort_status || "No effort status";
}
function routeDescription(route) {
  return route?.provider_id && route?.raw_model ? `${route.phase}/${route.difficulty}: ${route.provider_id}/${route.raw_model}` : "No route selected yet";
}
function setOwnerSession(id) {
  const changed=S.session!==id;
  S.session=id;S.sessionShort=id.slice(0,8);
  if(changed) clearContext();
  if(S.customEnabled && changed) {
    S.customEpoch++;S.visibleAgents.clear();S.changedFiles=[];S.activityRows=[];S.routeText="";
    markCustomPanesStale();customizationRead(S.generation);
  }
}
function applySnapshot(snapshot) {
  // Snapshots carry cumulative traffic, not a current request-size estimate.
  clearContext();
  S.model = snapshot.model; S.provider = snapshot.provider; setOwnerSession(snapshot.session_id);
  if(S.customEnabled)S.routeText=routeDescription(snapshot.last_route);
  S.turns = snapshot.turns; S.input = snapshot.input_tokens; S.output = snapshot.output_tokens; S.cost = snapshot.cost_microcents;
  S.busy = snapshot.state === "running"; S.effort = snapshot;
  $("transcript").textContent = ""; S.streamingBody = null;
  for (const message of snapshot.messages || []) addMsg(message.role, message.text);
  if (snapshot.partial_response) ensureStreaming().textContent = snapshot.partial_response;
  S.pendingApprovals = [...(snapshot.pending_approvals || [])]; showApproval(); renderEffort(); setStatus();
  if (["interrupted","stopped"].includes(snapshot.state)) toast(`Session ${snapshot.state}; no request was resubmitted`, true);
}
function applySettings(settings) {
  if (S.model!==settings.model || S.provider!==settings.provider) clearContext();
  S.model=settings.model; S.provider=settings.provider; setOwnerSession(settings.session_id);
  if(S.customEnabled && Object.prototype.hasOwnProperty.call(settings,"last_route"))S.routeText=routeDescription(settings.last_route);
  S.effort=settings; renderEffort(); setStatus();
}
function applyRecovery(recovery) {
  if (recovery.snapshot) { applySnapshot(recovery.snapshot); S.cursor = recovery.snapshot.cursor; }
  for (const event of recovery.events || []) receive(event.kind, {...event.payload,_cursor:event.cursor});
  S.cursor = recovery.cursor;
}
function receive(kind, data) {
  if (data._cursor) {
    const cursor = data._cursor;
    if (S.cursor && cursor.instance === S.cursor.instance && cursor.sequence <= S.cursor.sequence) return;
    S.cursor = cursor;
  }
  switch (kind) {
    case "identity": if (S.model!==data.model || S.provider!==data.provider) clearContext(); S.model=data.model; S.provider=data.provider; setOwnerSession(data.session_id || data.session); setStatus(); break;
    case "text_delta": S.busy=true; ensureStreaming().appendChild(document.createTextNode(data.text)); setStatus(); scrollDown(); break;
    case "response_finished": finishStreaming(data.output || ""); break;
    case "request_accepted": clearContext(); S.busy=true; S.turnBaseCost=S.cost || 0; if (data.message) addMsg(data.message.role,data.message.text); setStatus(); break;
    case "request_finished": S.busy=false; S.turns=data.turns ?? S.turns; S.input=data.input_tokens ?? S.input; S.output=data.output_tokens ?? S.output; S.cost=data.cost_microcents ?? S.cost; finishStreaming(); setStatus(); send({type:"effort"}); break;
    case "turn_ended": if (data.interrupted) toast("Turn interrupted",true); setStatus(); break;
    case "cost_updated": S.cost=(S.turnBaseCost || 0)+(data.total_microcents || 0); setStatus(); break;
    case "usage": S.contextUsage=contextSample(data); S.contextProgress=null; setStatus(); break;
    case "compacting":
      S.contextUsage=null;
      S.contextProgress=tokenCount(data.used_tokens) && tokenCount(data.window_tokens) && data.window_tokens>0
        ? `Compacting context (estimate ${data.used_tokens} / ${data.window_tokens} tokens)` : "Compacting context; estimate unavailable";
      setStatus(); break;
    case "compacted":
      S.contextUsage=null;
      S.contextProgress=tokenCount(data.after_tokens) ? `Context compacted; estimated input ${data.after_tokens} tokens` : "Context compacted; estimate unavailable";
      setStatus(); break;
    case "activity": if(S.customEnabled) addActivity(data.kind || "",[data.target,data.fact].filter(Boolean).join(" · "));break;
    case "file_changed": if(S.customEnabled) {S.changedFiles.push(data);S.changedFiles=S.changedFiles.slice(-64);renderBuiltinContent();}break;
    case "subagent_started": if(S.customEnabled && S.visibleAgents.size<32){S.visibleAgents.set(data.agent_id,{...data,state:"running"});renderBuiltinContent();}break;
    case "subagent_finished": if(S.customEnabled){const previous=S.visibleAgents.get(data.agent_id)||{};S.visibleAgents.set(data.agent_id,{...previous,...data,state:data.ok ? "done" : "failed"});renderBuiltinContent();}break;
    case "routing": {
      const route=data.last_route || data;
      if(S.customEnabled){S.routeText=routeDescription(route);renderBuiltinContent();}
      if (route.provider_id && route.raw_model) addMsg("system",`route ${route.phase}/${route.difficulty} → ${route.provider_id}/${route.raw_model}${route.suppressed_reason ? " · "+route.suppressed_reason : ""}`);
      else addMsg("system",`Model selection: ${data.selection_origin || "default"}`);
      break;
    }
    case "effort": if (data.settings) applySettings(data.settings); else if (data.text) $("effort-status").textContent=data.text; break;
    case "transcript": applySnapshot({...data.settings,...data,partial_response:"",pending_approvals:[],cursor:data._cursor}); break;
    case "approval_requested": if (!S.pendingApprovals.some(approval=>approval.call_id===data.call_id)) S.pendingApprovals.push(data); showApproval(); break;
    case "approval_resolved": S.pendingApprovals=S.pendingApprovals.filter(approval=>approval.call_id!==data.call_id); showApproval(); break;
    case "tool_started_full": {
      const card=el("div","tool-card"); card.dataset.callId=data.call_id; card.appendChild(el("span","name",data.tool_name || data.name)); card.appendChild(document.createTextNode(` ${data.summary || ""}`)); $("transcript").appendChild(card); scrollDown(); break;
    }
    case "tool_finished_full": {
      const card=document.querySelector(`.tool-card[data-call-id="${CSS.escape(data.call_id)}"]`); if (card) card.classList.add(data.ok ? "finished-ok" : "finished-err"); addActivity(data.ok ? "ok" : "err",data.tool_name || data.name || "tool"); break;
    }
    case "models": addMsg("system",(data.models || []).map(model=>`${model.provider}/${model.model}`).join("\n") || "No configured models"); break;
    case "sessions": {
      $("sessions-list").textContent="";
      for (const session of data.sessions || []) { const item=el("li",session.session_id===S.session ? "active" : "",`${session.session_id.slice(0,8)} · ${session.turns}t · ${session.model}`); item.onclick=()=>send({type:"resume",session_id:session.session_id}); $("sessions-list").appendChild(item); } break;
    }
    case "status": if (data.text) addMsg("system",data.text); break;
    case "error": toast(data.message || "Session error",true); addMsg("system",data.message || "Session error"); break;
    case "stopped": S.busy=false; S.controlling=false; setStatus(); toast("Session stopped"); break;
  }
}
function send(action) {
  if (!S.controlling || !S.ws || S.ws.readyState !== 1) { toast("Reconnect before sending an action",true); return false; }
  S.ws.send(JSON.stringify(action)); return true;
}
function connState(cls,text) { $("conn").className=cls; $("conn-text").textContent=text; }
function disconnect() {
  if (S.es) { S.es.close(); S.es=null; }
  if (S.ws) { S.ws.onclose=null; S.ws.onerror=null; S.ws.close(); S.ws=null; }
  S.controlling=false; setStatus(); showApproval();
}
function reconnect() {
  disconnect(); connState("err","reconnecting");
  if (S.reconnectTimer === null) S.reconnectTimer=setTimeout(()=>{S.reconnectTimer=null;connect();},2000);
}
function connect() {
  disconnect(); const generation=++S.generation;
  const token=new URLSearchParams(location.search).get("token");
  const query=new URLSearchParams(); if (token) query.set("token",token);
  const actionQuery=query.toString();
  if (S.cursor) { query.set("instance",S.cursor.instance); query.set("sequence",String(S.cursor.sequence)); }
  const es=S.es=new EventSource(`/events?${query.toString()}`);
  es.addEventListener("recovery",event=>{if (generation===S.generation) applyRecovery(JSON.parse(event.data || "{}"));});
  for (const kind of ["identity","transcript","text_delta","response_finished","request_accepted","request_finished","turn_ended","cost_updated","usage","compacting","compacted","routing","effort","approval_requested","approval_resolved","tool_started_full","tool_finished_full","models","sessions","status","error","stopped","activity","file_changed","subagent_started","subagent_finished"]) {
    es.addEventListener(kind,event=>{if (generation===S.generation) receive(kind,JSON.parse(event.data || "{}"));});
  }
  es.onerror=()=>{if (generation===S.generation) reconnect();};
  customizationRead(generation);
  const ws=S.ws=new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/actions?${actionQuery}`);
  ws.onmessage=event=>{
    if (generation!==S.generation) return;
    const data=JSON.parse(event.data || "{}");
    if (data.type==="controller_ready") { S.controlling=true; connState("ok","live"); setStatus(); showApproval(); send({type:"list_sessions"}); send({type:"effort"}); if(S.customEnabled)send({type:"customize",command:{kind:"reload"},expected_revision:null}); }
    else if(data.type==="customization") {
      if(!applyCustomization(data))return;
      if(data.effect?.kind==="insert_draft") {$("composer").value=String(data.effect.text || "").slice(0,8192);focusProfileConversation();}
      else if(data.effect?.kind==="focus_conversation") focusProfileConversation();
      if(S.pendingFontSize && data.applied_command?.kind==="set" && data.applied_command?.key==="browser.font_family" && data.applied_command?.value===S.pendingFontSize.font){const size=S.pendingFontSize.size;S.pendingFontSize=null;customizationCommand({kind:"set",key:"browser.font_size_px",value:size});}
    }
    else if (data.type==="action_error") { S.pendingFontSize=null;renderEffort();customizationControls();toast(data.message || "Action rejected",true); }
  };
  ws.onclose=()=>{if (generation===S.generation) reconnect();};
  ws.onerror=()=>{if (generation===S.generation) reconnect();};
}
function submit() {
  const box=$("composer"), text=box.value.trim(); if (!text || S.busy) return;
  const command=text.match(/^\/(\w+)\s*(.*)$/);
  if (command) {
    const [,name,rest]=command;
    if (S.customEnabled && (name==="theme" || name==="customize")) {
      let operation;
      if(name==="theme") operation=rest.trim() ? {kind:"theme",name:rest.trim()} : {kind:"show"};
      else { const [verb,...parts]=rest.trim().split(/\s+/);const tail=parts.join(" ");
        if(["show","reload","capabilities"].includes(verb || "show"))operation={kind:verb || "show"};
        else if(verb==="reset")operation={kind:"reset",key:tail || null};
        else if(["import","export","validate"].includes(verb))operation={kind:verb,path:tail};
        else if(verb==="set" && parts.length>=2)operation={kind:"set",key:parts[0],value:parts.slice(1).join(" ")};
      }
      if(!operation){toast("Use /customize show, set KEY VALUE, reset, import, export or reload",true);return;}
      if(customizationCommand(operation))box.value="";return;
    }
    if (name==="clear") {$("transcript").textContent="";box.value="";return;}
    if (name==="models" || name==="sessions") {if(send({type:`list_${name}`})) box.value="";return;}
    if (name==="route") {
      if (!["","status","auto"].includes(rest.trim())) {toast("Use /route status or /route auto; configure routes with orbit route",true);return;}
      if(send({type:rest.trim()==="auto" ? "route_auto" : "routing"})) box.value="";return;
    }
    if (name==="effort") {
      if (!rest) {send({type:"effort"});box.value="";return;}
      let choice;
      try { choice=rest==="default" ? {mode:"default"} : {mode:"value",value:["true","false"].includes(rest) || rest.startsWith('"') ? JSON.parse(rest) : rest}; }
      catch (_) {toast("Use an exact effort level, true, false, or default",true);return;}
      if(send({type:"set_effort",choice})) box.value="";return;
    }
    if (name==="model" || name==="resume") {
      if (!rest) {toast(`Usage: /${name} <${name==="model" ? "model" : "session id"}>`,true);return;}
      if(send(name==="model" ? {type:"set_model",model:rest.trim(),provider:null} : {type:"resume",session_id:rest.trim()})) box.value="";return;
    }
    toast(`Unknown command /${name} — try /route /effort /model /models /sessions /resume /clear`,true);return;
  }
  const requestId=crypto.randomUUID();
  if(send({type:"prompt",request_id:requestId,text})) {box.value="";S.busy=true;setStatus();}
}
$("chat-pane").addEventListener("click",event=>{if(event.target.closest("button, a, select, .tool-card")) return;const selection=window.getSelection();if(selection && !selection.isCollapsed) return;$("composer").focus();});
$("btn-send").onclick=submit; $("btn-cancel").onclick=()=>send({type:"cancel"});
$("btn-refresh-sessions").onclick=()=>send({type:"list_sessions"});
$("effort-query").onclick=()=>send({type:"effort"});
$("effort-reset").onclick=()=>send({type:"set_effort",choice:{mode:"default"}});
$("effort-select").onchange=()=>{try{send({type:"set_effort",choice:JSON.parse($("effort-select").value)});}catch(_){toast("Invalid effort choice",true);renderEffort();}};
$("composer").addEventListener("keydown",event=>{if(event.key==="Enter" && !event.shiftKey){event.preventDefault();submit();}});
$("ap-allow").onclick=()=>sendVerdict("allow_once"); $("ap-session").onclick=()=>sendVerdict("allow_session"); $("ap-deny").onclick=()=>sendVerdict("deny");
document.addEventListener("keydown",event=>{if(!S.approvalModalOpen)return;if(event.key==="y")sendVerdict("allow_once");else if(event.key==="n" || event.key==="Escape")sendVerdict("deny");else if(event.key==="R")sendVerdict("allow_session");});
setupCustomization();
connect();
