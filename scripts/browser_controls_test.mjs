#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';

// A controlled browser surface executes the shipped client and records actual
// DOM changes and WebSocket sends. No frontend dependency installation is used.
const source=fs.readFileSync(new URL('../crates/web/assets/app.js',import.meta.url),'utf8');
const html=fs.readFileSync(new URL('../crates/web/assets/index.html',import.meta.url),'utf8');
class Node {
  constructor(tag='div'){this.tagName=tag;this.children=[];this._text='';this.value='';this.dataset={};this.hidden=false;this.disabled=false;this.className='';this.events={};this.scrollHeight=100;this.scrollTop=0;this.clientHeight=100;this.classList={add:(name)=>{this.className+=` ${name}`;},toggle:(name,enabled)=>{this.className=this.className.split(' ').filter(value=>value!==name).join(' ');if(enabled)this.className+=` ${name}`;}};}
  get textContent(){return this._text+this.children.map(child=>child.textContent).join('');}
  set textContent(value){this._text=String(value);this.children=[];}
  appendChild(node){this.children.push(node);return node;}
  addEventListener(name,fn){(this.events[name]??=[]).push(fn);}
  scrollIntoView(){}
  closest(){return null;}
  focus(){this.focused=true;}
}
function fixture(){
  const nodes=new Map([...html.matchAll(/id="([^"]+)"/g)].map(match=>[match[1],new Node()]));
  const timers=new Map();let timerId=0;
  const sockets=[],streams=[];
  class WebSocket {constructor(url){this.url=url;this.readyState=1;this.sent=[];this.closed=false;sockets.push(this);}send(text){this.sent.push(JSON.parse(text));}close(){this.closed=true;this.readyState=3;}message(value){this.onmessage?.({data:JSON.stringify(value)});}}
  class EventSource {constructor(url){this.url=url;this.events={};this.closed=false;streams.push(this);}addEventListener(kind,fn){(this.events[kind]??=[]).push(fn);}emit(kind,value){for(const fn of this.events[kind]||[])fn({data:JSON.stringify(value)});}close(){this.closed=true;}}
  const document={getElementById:id=>{assert(nodes.has(id),`missing DOM id ${id}`);return nodes.get(id);},createElement:tag=>new Node(tag),createTextNode:text=>{const node=new Node('#text');node.textContent=text;return node;},querySelector:()=>null,addEventListener:()=>{}};
  const context=vm.createContext({document,window:{getSelection:()=>({isCollapsed:true})},location:{protocol:'http:',host:'127.0.0.1:4173',search:'?token=fixture-token'},WebSocket,EventSource,URLSearchParams,CSS:{escape:value=>value},crypto:{randomUUID:()=>crypto.randomUUID()},console,setTimeout:(fn,delay)=>{const id=++timerId;timers.set(id,{fn,delay});return id;},clearTimeout:id=>timers.delete(id)});
  vm.runInContext(source,context,{filename:'app.js'});
  const current=()=>sockets.at(-1);
  const ready=()=>{current().message({type:'controller_ready'});current().sent=[];};
  ready();
  const snapshot=(changes={})=>({cursor:{instance:'fixture-owner',sequence:1},session_id:'browser-fixture',provider:'fixture',model:'vendor/model',effort:null,supported_efforts:['low','high'],resolved_effort:'low',effort_status:'Configured effort: low',state:'idle',messages:[],partial_response:'',pending_approvals:[],turns:0,input_tokens:0,output_tokens:0,cost_microcents:0,...changes});
  const recover=value=>streams.at(-1).emit('recovery',{snapshot:value,events:[],cursor:value.cursor});
  const click=id=>{assert(!nodes.get(id).disabled,`${id} is disabled`);nodes.get(id).onclick();};
  return {nodes,sockets,streams,current,ready,snapshot,recover,click,timers,runReconnect:()=>{const entry=[...timers].find(([,timer])=>timer.delay===2000);assert(entry,'reconnect timer is scheduled');timers.delete(entry[0]);entry[1].fn();}};
}
const scenarios={};
function check(name,fn){let assertions=0;const verify=(value,message)=>{assert(value,message);assertions++;};fn(verify);assert(assertions>0);scenarios[name]={passed:true,assertions};console.log(`PASS ${name}: ${assertions} assertions`);}
check('effort_query_is_a_setting_action',(ok)=>{const f=fixture();f.recover(f.snapshot());f.click('effort-query');ok(f.current().sent.length===1);ok(f.current().sent[0].type==='effort');ok(!f.current().sent.some(action=>action.type==='prompt'));});
check('boolean_choices_preserve_json_type',(ok)=>{const f=fixture();f.recover(f.snapshot({supported_efforts:[false,true],resolved_effort:false}));const select=f.nodes.get('effort-select');const option=select.children.find(option=>option.textContent==='false (boolean)');ok(!!option);select.value=option.value;select.onchange();ok(f.current().sent[0].choice.value===false);ok(typeof f.current().sent[0].choice.value==='boolean');});
check('string_false_is_a_distinct_choice',(ok)=>{const f=fixture();f.recover(f.snapshot({supported_efforts:['false','true'],resolved_effort:'false'}));const select=f.nodes.get('effort-select');select.value=select.children.find(option=>option.textContent==='"false" (level)').value;select.onchange();ok(f.current().sent[0].choice.value==='false');ok(typeof f.current().sent[0].choice.value==='string');});
check('reset_uses_explicit_default_and_no_prompt',(ok)=>{const f=fixture();f.recover(f.snapshot({effort:{mode:'value',value:'high'},resolved_effort:'high'}));f.click('effort-reset');ok(f.current().sent[0].type==='set_effort');ok(f.current().sent[0].choice.mode==='default');ok(!f.current().sent.some(action=>action.type==='prompt'));});
check('rejected_change_restores_displayed_selection',(ok)=>{const f=fixture();f.recover(f.snapshot({effort:{mode:'value',value:'low'}}));const select=f.nodes.get('effort-select');select.value=JSON.stringify({mode:'value',value:'high'});select.onchange();f.current().message({type:'action_error',message:'Choice rejected'});ok(JSON.parse(select.value).value==='low');ok(f.nodes.get('toast').textContent==='Choice rejected');ok(f.nodes.get('st-model').textContent==='vendor/model');});
check('recovery_renders_provenance_and_pending_approval',(ok)=>{const f=fixture();f.recover(f.snapshot({effort:{mode:'default'},pending_approvals:[{call_id:'exact-id',tool_name:'Bash',summary:'fixture command'}]}));ok(f.nodes.get('effort-provenance').textContent.includes('Explicit reset'));ok(!f.nodes.get('approval-modal').hidden);f.click('ap-deny');ok(f.current().sent[0].call_id==='exact-id');ok(f.current().sent[0].verdict==='deny');});
check('unknown_and_unsupported_are_visible',(ok)=>{const f=fixture();f.recover(f.snapshot({supported_efforts:null}));ok(f.nodes.get('effort-provenance').textContent.includes('Choices unknown'));f.recover(f.snapshot({supported_efforts:[]}));ok(f.nodes.get('effort-provenance').textContent.includes('Unsupported; default only'));ok(f.nodes.get('effort-select').children.length===1);});
check('reconnect_disposes_old_streams_and_never_replays_prompt',(ok)=>{const f=fixture();f.recover(f.snapshot());f.nodes.get('composer').value='fixture prompt';f.click('btn-send');const old=f.current();ok(old.sent[0].type==='prompt'&&typeof old.sent[0].request_id==='string');old.onclose();ok(old.closed);ok(f.streams[0].closed);f.runReconnect();f.ready();ok(f.sockets.length===2);ok(!f.current().sent.some(action=>action.type==='prompt'));ok(f.streams.at(-1).url.includes('instance=fixture-owner'));});
check('hostile_status_and_conversation_are_inert_text',(ok)=>{const f=fixture();const hostile='<img src=x onerror=alert(1)>';f.recover(f.snapshot({effort_status:hostile,messages:[{role:'assistant',text:hostile}]}));ok(f.nodes.get('effort-status').textContent===hostile);ok(f.nodes.get('effort-status').children.length===0);const body=f.nodes.get('transcript').children[0].children[1];ok(body.textContent===hostile);ok(body.children.length===0);});
check('busy_setting_rejection_does_not_unlock_prompt',(ok)=>{const f=fixture();f.recover(f.snapshot({state:'running',partial_response:'partial response'}));f.current().message({type:'action_error',message:'Session busy'});ok(f.nodes.get('btn-send').disabled);ok(f.nodes.get('effort-select').disabled);ok(f.nodes.get('transcript').textContent.includes('partial response'));});
check('slash_effort_uses_typed_setting_action',(ok)=>{const f=fixture();f.recover(f.snapshot());f.nodes.get('composer').value='/effort false';f.click('btn-send');ok(f.current().sent[0].type==='set_effort');ok(f.current().sent[0].choice.value===false);ok(f.nodes.get('composer').value==='');});
check('recovered_events_are_not_applied_twice',(ok)=>{const f=fixture();const snapshot=f.snapshot({state:'running',partial_response:'existing'});f.recover(snapshot);f.streams[0].emit('text_delta',{text:' duplicate',_cursor:snapshot.cursor});ok(f.nodes.get('transcript').textContent.includes('existing'));ok(!f.nodes.get('transcript').textContent.includes('duplicate'));f.streams[0].emit('text_delta',{text:' next',_cursor:{instance:'fixture-owner',sequence:2}});ok(f.nodes.get('transcript').textContent.includes('existing next'));});
check('ack_first_keeps_ordered_lists_and_effort',(ok)=>{const f=fixture();f.recover(f.snapshot());f.current().message({type:'action_ack',snapshot:f.snapshot({cursor:{instance:'fixture-owner',sequence:3}})});f.streams[0].emit('sessions',{sessions:[{session_id:'listed-session',model:'listed-model',turns:2}],_cursor:{instance:'fixture-owner',sequence:2}});f.streams[0].emit('effort',{settings:f.snapshot({effort:{mode:'value',value:'high'},effort_status:'high setting'}),_cursor:{instance:'fixture-owner',sequence:3}});ok(f.nodes.get('sessions-list').textContent.includes('listed-model'));ok(f.nodes.get('effort-status').textContent==='high setting');});
check('sse_first_model_list_survives_settings_ack',(ok)=>{const f=fixture();f.recover(f.snapshot());f.streams[0].emit('models',{models:[{provider:'fixture',model:'listed-model'}],_cursor:{instance:'fixture-owner',sequence:2}});f.current().message({type:'action_ack',snapshot:f.snapshot({cursor:{instance:'fixture-owner',sequence:3}})});ok(f.nodes.get('transcript').textContent.includes('fixture/listed-model'));});
check('stale_ack_cannot_roll_back_stream_or_identity',(ok)=>{const f=fixture();f.recover(f.snapshot());f.streams[0].emit('text_delta',{text:'newer response',_cursor:{instance:'fixture-owner',sequence:3}});f.streams[0].emit('identity',{provider:'new-provider',model:'new-model',session_id:'browser-fixture',_cursor:{instance:'fixture-owner',sequence:4}});f.current().message({type:'action_ack',snapshot:f.snapshot({cursor:{instance:'fixture-owner',sequence:2},partial_response:'stale response'})});ok(f.nodes.get('transcript').textContent.includes('newer response'));ok(!f.nodes.get('transcript').textContent.includes('stale response'));ok(f.nodes.get('st-model').textContent==='new-model');f.current().onclose();f.runReconnect();ok(f.streams.at(-1).url.includes('sequence=4'));});
check('ordered_acceptance_renders_user_once_and_completion_uses_session_totals',(ok)=>{const f=fixture();f.recover(f.snapshot({turns:4,input_tokens:100,output_tokens:50,cost_microcents:1000}));f.current().message({type:'action_ack',snapshot:f.snapshot({cursor:{instance:'fixture-owner',sequence:8}})});f.streams[0].emit('request_accepted',{message:{role:'user',text:'accepted prompt'},_cursor:{instance:'fixture-owner',sequence:2}});f.streams[0].emit('text_delta',{text:'answer',_cursor:{instance:'fixture-owner',sequence:3}});f.streams[0].emit('turn_ended',{input_tokens:3,output_tokens:2,_cursor:{instance:'fixture-owner',sequence:4}});f.streams[0].emit('request_finished',{turns:5,input_tokens:103,output_tokens:52,cost_microcents:1200,_cursor:{instance:'fixture-owner',sequence:5}});ok(f.nodes.get('transcript').textContent.split('accepted prompt').length===2);ok(f.nodes.get('us-in').textContent==='103');ok(f.nodes.get('us-out').textContent==='52');ok(f.nodes.get('st-turns').textContent==='5');});
check('resume_projects_ordered_transcript_and_typed_settings',(ok)=>{const f=fixture();f.recover(f.snapshot({messages:[{role:'assistant',text:'old session'}]}));const state=f.snapshot({session_id:'new-session',model:'new-model',turns:7,input_tokens:800,output_tokens:90,cost_microcents:123});f.streams[0].emit('transcript',{...state,settings:state,messages:[{role:'user',text:'saved new session'}],_cursor:{instance:'fixture-owner',sequence:2}});f.current().message({type:'action_ack',snapshot:f.snapshot()});ok(f.nodes.get('transcript').textContent.includes('saved new session'));ok(!f.nodes.get('transcript').textContent.includes('old session'));ok(f.nodes.get('st-model').textContent==='new-model');ok(f.nodes.get('us-in').textContent==='800');});
check('acks_do_not_erase_tool_activity_or_stream_errors',(ok)=>{const f=fixture();f.recover(f.snapshot());f.streams[0].emit('tool_started_full',{call_id:'tool-a',tool_name:'Read',summary:'safe file',_cursor:{instance:'fixture-owner',sequence:2}});f.streams[0].emit('error',{message:'visible failure',_cursor:{instance:'fixture-owner',sequence:3}});f.current().message({type:'action_ack',snapshot:f.snapshot({cursor:{instance:'fixture-owner',sequence:4}})});ok(f.nodes.get('transcript').textContent.includes('safe file'));ok(f.nodes.get('transcript').textContent.includes('visible failure'));});
const contextDisplay = f => [...f.nodes.entries()]
  .filter(([id]) => /context|compact|reserve/.test(id) && !id.startsWith('custom-'))
  .map(([,node]) => node.textContent).join('\n');
const allVisibleText = f => [...f.nodes.values()].map(node=>node.textContent).join('\n');
const hasContextNumber = (text,value) => new RegExp(`(^|[^0-9])${String(value)}([^0-9]|$)`).test(text.replaceAll(',',''));
const contextUsage = (changes={}) => ({used_tokens:4321,window_tokens:64000,
  breakdown:{system:100,memory:20,tools:200,messages:4001,compact_at:56576,reserve:1024},...changes});
const emitContext = (f,kind,value,sequence) => f.streams.at(-1).emit(kind,{...value,_cursor:{instance:'fixture-owner',sequence}});

check('context_sse_usage_renders_estimate_and_preserves_cumulative_totals',ok=>{
  const f=fixture(); f.recover(f.snapshot({turns:7,input_tokens:99,output_tokens:101}));
  emitContext(f,'usage',contextUsage(),2);
  const visible=contextDisplay(f);
  ok(/estimate|approx/i.test(visible),'actual shipped usage surface labels its approximation');
  for(const value of [4321,64000,56576,1024]) ok(hasContextNumber(visible,value),`visible actual context number ${value}`);
  ok(f.nodes.get('us-in').textContent==='99'); ok(f.nodes.get('us-out').textContent==='101');
  ok(f.nodes.get('st-turns').textContent==='7'); ok(f.current().sent.length===0);
});

check('context_zero_breakdown_and_maximum_safe_integer_remain_exact',ok=>{
  const f=fixture(); f.recover(f.snapshot({turns:7,input_tokens:99,output_tokens:101}));
  emitContext(f,'usage',contextUsage({used_tokens:0,breakdown:{system:0,memory:0,tools:0,messages:0,compact_at:0,reserve:0}}),2);
  let visible=contextDisplay(f);
  ok(hasContextNumber(visible,64000));
  ok((visible.match(/(^|[^0-9])0(?=[^0-9]|$)/g)||[]).length>=3,'zero occupancy, trigger and output reserve are visible');
  emitContext(f,'usage',contextUsage({used_tokens:Number.MAX_SAFE_INTEGER,window_tokens:Number.MAX_SAFE_INTEGER,
    breakdown:{system:0,memory:0,tools:0,messages:0,compact_at:Number.MAX_SAFE_INTEGER,reserve:0}}),3);
  visible=contextDisplay(f); ok(hasContextNumber(visible,Number.MAX_SAFE_INTEGER));
  ok(f.nodes.get('us-in').textContent==='99'); ok(f.current().sent.length===0);
});

check('context_duplicate_cursor_and_obsolete_generation_cannot_replace_newer_meter',ok=>{
  const f=fixture(); f.recover(f.snapshot());
  emitContext(f,'usage',contextUsage(),5); ok(hasContextNumber(contextDisplay(f),4321));
  for(const sequence of [4,5]) emitContext(f,'usage',contextUsage({used_tokens:8765,window_tokens:123456}),sequence);
  ok(hasContextNumber(contextDisplay(f),4321)); ok(!hasContextNumber(contextDisplay(f),8765));
  const old=f.streams.at(-1); f.current().onclose(); f.runReconnect(); f.ready();
  f.recover(f.snapshot({cursor:{instance:'fixture-owner',sequence:6}}));
  emitContext(f,'usage',contextUsage({used_tokens:3333}),7);
  old.emit('usage',{...contextUsage({used_tokens:8888}),_cursor:{instance:'fixture-owner',sequence:99}});
  ok(hasContextNumber(contextDisplay(f),3333)); ok(!hasContextNumber(contextDisplay(f),8888));
  ok(!f.current().sent.some(action=>action.type==='prompt'));
});

check('context_session_replacement_and_cold_recovery_do_not_reuse_old_occupancy',ok=>{
  const f=fixture(); f.recover(f.snapshot()); emitContext(f,'usage',contextUsage(),2);
  ok(hasContextNumber(contextDisplay(f),4321));
  f.recover(f.snapshot({session_id:'other-context-session',cursor:{instance:'fixture-owner',sequence:3},input_tokens:8000,output_tokens:9000}));
  let visible=contextDisplay(f); ok(!hasContextNumber(visible,4321));
  ok(/unavailable|unknown|—/i.test(visible)); ok(!hasContextNumber(visible,8000),'session traffic is not context occupancy');
  emitContext(f,'usage',contextUsage({used_tokens:2222}),4); ok(hasContextNumber(contextDisplay(f),2222));
  f.recover(f.snapshot({session_id:'other-context-session',cursor:{instance:'fixture-owner',sequence:5},input_tokens:8001,output_tokens:9001}));
  visible=contextDisplay(f); ok(!hasContextNumber(visible,2222)); ok(/unavailable|unknown|—/i.test(visible));
  ok(f.nodes.get('us-in').textContent==='8001'); ok(f.current().sent.length===0);
});

check('context_invalid_or_unsafe_numbers_are_unavailable_not_rounded_or_zeroed',ok=>{
  const f=fixture(); f.recover(f.snapshot({input_tokens:99,output_tokens:101}));
  let sequence=2;
  for(const invalid of [
    {used_tokens:-1}, {used_tokens:'64000'}, {window_tokens:Number.MAX_SAFE_INTEGER+1},
    {window_tokens:null}, {breakdown:{compact_at:0,reserve:-1}}, {breakdown:{compact_at:null,reserve:0}},
  ]) {
    emitContext(f,'usage',contextUsage(),sequence++); ok(hasContextNumber(contextDisplay(f),4321));
    emitContext(f,'usage',contextUsage(invalid),sequence++);
    const visible=contextDisplay(f); ok(/unavailable|unknown|—/i.test(visible));
    ok(!hasContextNumber(visible,4321),'invalid current sample cannot retain a stale valid occupancy');
    ok(!visible.includes(String(Number.MAX_SAFE_INTEGER+1)));
  }
  ok(f.nodes.get('us-in').textContent==='99'); ok(f.nodes.get('us-out').textContent==='101');
});

check('context_media_warning_stays_visible_beside_approximation_without_fit_claim',ok=>{
  const f=fixture(); f.recover(f.snapshot());
  emitContext(f,'status',{text:'Media request cost is unknown; text estimate does not verify provider capacity.'},2);
  emitContext(f,'usage',contextUsage(),3);
  ok(f.nodes.get('transcript').textContent.includes('Media request cost is unknown'));
  const visible=contextDisplay(f); ok(/estimate|approx/i.test(visible)); ok(hasContextNumber(visible,64000));
  ok(!/guaranteed|verified fit|capacity verified/i.test(visible)); ok(f.current().sent.length===0);
});

check('context_compaction_events_render_numeric_progress_without_summary_or_actions',ok=>{
  const f=fixture(); f.recover(f.snapshot()); emitContext(f,'usage',contextUsage(),2);
  emitContext(f,'compacting',{used_tokens:100000,window_tokens:128000},3);
  ok(/compacting/i.test(allVisibleText(f)),'actual compacting listener reaches visible state');
  const summary='<img src=x onerror=alert(1)> private-summary-must-not-render';
  emitContext(f,'compacted',{summary,after_tokens:2234},4);
  const visible=allVisibleText(f); ok(/compacted/i.test(visible)); ok(hasContextNumber(visible,2234));
  ok(!visible.includes('private-summary-must-not-render')); ok(!visible.includes('<img src=x'));
  emitContext(f,'usage',contextUsage({used_tokens:7777}),5);
  const current=f.nodes.get('st-context').textContent;
  ok(hasContextNumber(current,7777)&&hasContextNumber(current,64000),'latest usage replaces stale progress in the header');
  ok(!hasContextNumber(current,2234));
  ok(f.current().sent.length===0);
});

console.log(`ORBIT_CHECK_RECEIPT ${JSON.stringify({scenarios})}`);
