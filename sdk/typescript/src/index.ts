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
