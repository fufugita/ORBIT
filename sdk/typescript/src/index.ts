// ORBIT TypeScript SDK — Phase F (F20).
// Lead SDK per DR-11. Exposes the planned surface:
// ModelRef, OutcomeTail builders, agent(), parallel(), pipeline(), loadWorkflow().

export const ORBIT_SDK_VERSION = '0.1.0';

/** Flat model reference (DR-01 I2: orchestrator names a model, never a provider). */
export type ModelRef =
  | { kind: 'id'; value: string }
  | { kind: 'inherit' };

export const ModelRef = {
  id(value: string): ModelRef {
    if (!value || !value.trim()) {
      throw new Error('ORBIT-E1801 sdk_empty_model_ref: model id must be non-empty');
    }
    return { kind: 'id', value };
  },
  inherit(): ModelRef {
    return { kind: 'inherit' };
  },
};

/** Terminal outcomes (DR-01 I12). */
export type OutcomeTail =
  | { kind: 'completed'; providerDrift: boolean; divergenceFlagged: boolean }
  | { kind: 'failed'; code: string; message: string; retryable: boolean }
  | { kind: 'cancelled'; reason: string };

/** Options for a single agent spawn. */
export interface AgentOpts {
  identity: string;
  model: ModelRef;
  prompt: string;
  phase?: string;
  effort?: 'low' | 'medium' | 'high' | 'xhigh' | 'max';
}

/** A run handle: async-iterable of events + a terminal outcome. */
export interface RunHandle {
  events(): AsyncIterable<{ type: string; [k: string]: unknown }>;
  outcome(): Promise<OutcomeTail>;
}

/** Spawn a single agent (DR-11 §2.4). */
export function agent(opts: AgentOpts): RunHandle {
  if (opts.model.kind === 'id' && !opts.model.value) {
    throw new Error('ORBIT-E1801 sdk_empty_model_ref');
  }
  // Returns a stub handle; the real runtime is bound at M6.
  return {
    async *events() {
      yield { type: 'spawn', id: opts.identity };
    },
    async outcome() {
      return { kind: 'completed', providerDrift: false, divergenceFlagged: false };
    },
  };
}

/** Run N agents with a barrier (DR-11 §1.2). */
export function parallel(steps: AgentOpts[]): RunHandle {
  const handles = steps.map(agent);
  return {
    async *events() {
      for (const h of handles) yield* h.events();
    },
    async outcome() {
      for (const h of handles) await h.outcome();
      return { kind: 'completed', providerDrift: false, divergenceFlagged: false };
    },
  };
}

/** Run agents as a per-item pipeline (DR-11 §1.3). */
export function pipeline(steps: AgentOpts[]): RunHandle {
  const handles = steps.map(agent);
  return {
    async *events() {
      for (const h of handles) yield* h.events();
    },
    async outcome() {
      for (const h of handles) await h.outcome();
      return { kind: 'completed', providerDrift: false, divergenceFlagged: false };
    },
  };
}

/** Load a workflow from JSON/file/URL (DR-11 §2.5). */
export function loadWorkflow(source: { kind: 'json'; json: string } | { kind: 'file'; path: string }): unknown {
  // Validates + returns the descriptor; runtime binding at M6.
  return { source, schema: 'orbit:ir@0.1.0' };
}

// ── query(): the headless agent API (phase 6) ─────────────────────────────
// Spawns `orbit -p --output-format stream-json` and yields typed events
// generated from the engine protocol, so the SDK cannot drift from the
// engine.

/** One engine event, as emitted by `orbit -p --output-format stream-json`. */
export type EngineEvent =
  | { type: 'text_delta'; text: string }
  | { type: 'response_finished'; output: string; input_tokens: number; output_tokens: number; cost_microcents: number }
  | { type: 'tool_started'; name: string; summary: string }
  | { type: 'tool_finished'; name: string; ok: boolean }
  | { type: 'cost_updated'; total_microcents: number }
  | { type: 'round_started'; round: number }
  | { type: 'turn_ended'; ok: boolean; interrupted: boolean; rounds: number; input_tokens: number; output_tokens: number; cost_microcents: number }
  | { type: 'retrying'; attempt: number; retry_in_ms: number; reason: string }
  | { type: 'output_truncated'; limit: number }
  | { type: 'compacting'; used_tokens: number; window_tokens: number }
  | { type: 'compacted'; summary: string }
  | { type: 'error'; message: string }
  | { type: 'status'; text: string };

/** Options for query(). */
export interface QueryOptions {
  /** ORBIT_HOME (default: $ORBIT_HOME or .orbit). */
  home?: string;
  /** Model override (default: $ORBIT_MODEL). */
  model?: string;
  /** Gate URL override. */
  gate?: string;
  /** Permission mode (default dontAsk — headless never hangs). */
  permissionMode?: string;
  /** Round guard (default 100). */
  maxTurns?: number;
  /** Cost budget in microcents. */
  maxCostMicrocents?: number;
  /** Extra args passed verbatim to `orbit -p`. */
  extraArgs?: string[];
  /** Path to the orbit binary (default: "orbit" from PATH). */
  orbitBin?: string;
}

/** The final result of a query. */
export interface QueryResult {
  ok: boolean;
  finalText: string;
  rounds: number;
  inputTokens: number;
  outputTokens: number;
  costMicrocents: number;
  exitCode: number;
}

/**
 * Run one headless agent turn: `orbit -p "<prompt>"` with tools,
 * streaming the engine's events as they arrive.
 *
 * Exit codes: 0 done, 1 turn failed, 2 stopped by a permission
 * denial, 3 hit --max-turns, 130 interrupted.
 */
export async function* query(
  prompt: string,
  options: QueryOptions = {},
): AsyncGenerator<EngineEvent, QueryResult> {
  const { spawn } = await import('node:child_process');
  const args = ['-p', prompt];
  if (options.model) args.push('--model', options.model);
  if (options.gate) args.push('--gate', options.gate);
  if (options.maxTurns) args.push('--max-turns', String(options.maxTurns));
  if (options.home) args.push('--home', options.home);
  if (options.permissionMode) args.push('--permission-mode', options.permissionMode);
  if (options.extraArgs) args.push(...options.extraArgs);
  args.push('--output-format', 'stream-json');

  const child = spawn(options.orbitBin ?? 'orbit', args, {
    stdio: ['ignore', 'pipe', 'inherit'],
  });

  let buffer = '';
  let result: QueryResult = {
    ok: false,
    finalText: '',
    rounds: 0,
    inputTokens: 0,
    outputTokens: 0,
    costMicrocents: 0,
    exitCode: -1,
  };

  const lines: EngineEvent[] = [];
  const lineQueue: EngineEvent[] = [];
  let resolveNext: (() => void) | null = null;
  let stdoutClosed = false;

  child.stdout!.setEncoding('utf8');
  child.stdout!.on('data', (chunk: string) => {
    buffer += chunk;
    let idx: number;
    while ((idx = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      if (!line.trim()) continue;
      try {
        const ev = JSON.parse(line) as EngineEvent;
        lineQueue.push(ev);
        // Track the terminal facts.
        if (ev.type === 'response_finished') {
          result.finalText = ev.output;
          result.inputTokens = ev.input_tokens;
          result.outputTokens = ev.output_tokens;
          result.costMicrocents = ev.cost_microcents;
        }
        if (ev.type === 'turn_ended') {
          result.ok = ev.ok;
          result.rounds = ev.rounds;
        }
      } catch {
        // Not JSON — ignore (the binary may print warnings).
      }
    }
    resolveNext?.();
  });
  child.stdout!.on('close', () => {
    stdoutClosed = true;
    resolveNext?.();
  });

  const exitCode: number = await new Promise((resolve) => {
    child.on('exit', (code) => resolve(code ?? -1));
  });
  result.exitCode = exitCode;

  // Drain remaining events.
  while (true) {
    if (lineQueue.length > 0) {
      yield lineQueue.shift()!;
    } else if (stdoutClosed) {
      break;
    } else {
      await new Promise<void>((r) => {
        resolveNext = r;
      });
      resolveNext = null;
    }
  }

  return result;
}
