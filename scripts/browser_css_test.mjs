#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';

// Five REAL CSS checks over the actual shipped stylesheet — the same bytes the
// web bridge serves from crates/web/assets (rust-embed), not a paraphrase.
// Each check asserts a rule the client actually depends on (app.js toggles or
// index.html structure), so a dropped or renamed rule fails here.
const css = fs.readFileSync(new URL('../crates/web/assets/styles.css', import.meta.url), 'utf8');
const html = fs.readFileSync(new URL('../crates/web/assets/index.html', import.meta.url), 'utf8');

const rule = selector => {
  // Match the whole rule block for an exact selector occurrence.
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = css.match(new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`));
  return match ? match[1] : null;
};

const scenarios = {};
async function check(name, fn) {
  let count = 0;
  const ok = (condition, message) => { assert(condition, message); count++; };
  await fn(ok);
  assert(count > 0);
  scenarios[name] = { passed: true, assertions: count };
  console.log(`PASS ${name}`);
}

await check('the_stylesheet_defines_the_palette_variables_every_rule_depends_on', async ok => {
  const root = rule(':root');
  ok(root, ':root rule must exist');
  for (const name of ['--accent', '--bg', '--text', '--dim', '--line', '--ok', '--error', '--warn']) {
    ok(new RegExp(`${name}\\s*:`).test(root), `${name} must be declared on :root`);
  }
  // The variables are consumed by real rules, not declared unused.
  ok(rule('#logo').includes('var(--accent)'), '#logo must consume --accent');
  ok(rule('#conn-dot').includes('var(--warn)'), '#conn-dot must consume --warn');
});

await check('the_layout_skeleton_matches_the_index_structure', async ok => {
  // index.html declares the panes grid; the stylesheet must lay it out.
  ok(html.includes('id="app"') && rule('#app').includes('display: flex'), '#app must be flex');
  const panes = rule('#panes');
  ok(panes.includes('grid-template-columns'), '#panes must declare grid columns');
  ok(panes.includes('220px') && panes.includes('1fr') && panes.includes('240px'),
    '#panes must keep the work/chat/side column template');
  ok(html.includes('id="work-pane"') && html.includes('id="chat-pane"'),
    'index.html must declare the panes the grid positions');
  ok(rule('#chat-pane').includes('min-height: 0'), 'the chat pane must be allowed to shrink');
});

await check('transcript_messages_are_distinct_by_role', async ok => {
  ok(rule('#transcript'), 'the transcript container must be styled');
  const user = rule('.msg.user .who::before');
  const assistant = rule('.msg.assistant .who::before');
  ok(user && user.includes('content:'), 'user messages must have a role marker');
  ok(assistant && assistant.includes('content:'), 'assistant messages must have a role marker');
  ok(user !== assistant && !user.includes('◆'), 'the role markers must differ');
  ok(rule('.msg').includes('max-width'), 'message bodies must be width-bounded');
});

await check('tool_cards_render_their_terminal_states', async ok => {
  ok(rule('.tool-card'), '.tool-card must be styled');
  ok((rule('.tool-card.finished-ok') || '').includes('var(--ok)'), 'finished-ok must use --ok');
  ok((rule('.tool-card.finished-err') || '').includes('var(--error)'), 'finished-err must use --error');
  ok((rule('.tool-card.finished-denied') || '').includes('var(--denied)'), 'finished-denied must use --denied');
});

await check('toast_states_and_mobile_collapse_are_real', async ok => {
  const toast = rule('#toast');
  ok(toast, '#toast must be styled');
  ok((rule('#toast[hidden]') || '').includes('display: none'), 'hidden toasts must not render');
  ok((rule('#toast.error') || '').includes('var(--error)'), 'error toasts must use --error');
  // The responsive collapse is a real media rule, not inline styles.
  ok(/@media\s*\(max-width:\s*900px\)[\s\S]*?#panes\s*\{[^}]*grid-template-rows/.test(css),
    'the 900px breakpoint must collapse the panes grid');
});

console.log(`ORBIT_CHECK_RECEIPT ${JSON.stringify({ scenarios })}`);
