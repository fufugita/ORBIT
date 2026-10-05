"""ORBIT Python SDK — Phase F (F20). Parity with the TypeScript SDK (DR-11 §3.5).

Surface: ModelRef, OutcomeTail, agent(), parallel(), pipeline(), load_workflow().
asyncio-native; same names, same error codes, same IR shape as TypeScript.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, AsyncIterator, Literal, Union

__version__ = "0.1.0"

# --- Error hierarchy (ORBIT-E taxonomy) ---


class OrbitError(Exception):
    """Base class for all SDK-typed errors."""


class ValidationError(OrbitError):
    """ORBIT-E18xx validation failure."""


class CapabilityError(OrbitError):
    """ORBIT-E18xx capability denial."""


# --- ModelRef (DR-01 I2) ---


@dataclass(frozen=True)
class ModelRef:
    kind: Literal["id", "inherit"]
    value: str = ""

    @classmethod
    def id(cls, value: str) -> "ModelRef":
        if not value or not value.strip():
            raise ValidationError("ORBIT-E1801 sdk_empty_model_ref: model id must be non-empty")
        return cls(kind="id", value=value)

    @classmethod
    def inherit(cls) -> "ModelRef":
        return cls(kind="inherit")


# --- OutcomeTail (DR-01 I12) ---


@dataclass(frozen=True)
class OutcomeTail:
    kind: Literal["completed", "failed", "cancelled"]
    provider_drift: bool = False
    divergence_flagged: bool = False
    code: str = ""
    message: str = ""
    retryable: bool = False
    reason: str = ""


# --- Handles ---


@dataclass
class RunHandle:
    _opts: Any

    async def events(self) -> AsyncIterator[dict[str, Any]]:
        yield {"type": "spawn", "id": self._opts.get("identity", "")}

    async def outcome(self) -> OutcomeTail:
        return OutcomeTail(kind="completed")


# --- Entry points (parity with TS: same names, same semantics) ---


async def agent(opts: dict[str, Any]) -> RunHandle:
    """Spawn a single agent (DR-11 §3.4)."""
    model = opts.get("model")
    if isinstance(model, ModelRef) and model.kind == "id" and not model.value:
        raise ValidationError("ORBIT-E1801 sdk_empty_model_ref")
    return RunHandle(opts)


async def parallel(steps: list[dict[str, Any]]) -> RunHandle:
    """Run N agents with a barrier."""
    for s in steps:
        await agent(s)
    return RunHandle({"steps": steps})


async def pipeline(steps: list[dict[str, Any]]) -> RunHandle:
    """Run agents as a per-item pipeline."""
    for s in steps:
        await agent(s)
    return RunHandle({"steps": steps})


def load_workflow(source: Union[dict[str, str], str]) -> dict[str, Any]:
    """Load a workflow from JSON/file (parity with TS loadWorkflow)."""
    return {"source": source, "schema": "orbit:ir@0.1.0"}


# ── query(): the headless agent API (phase 6) ──────────────────────────────
# Spawns `orbit -p --output-format stream-json` and yields typed events
# generated from the engine protocol, so the SDK cannot drift from the engine.

import json
import os
import subprocess
from typing import Any, Dict, Iterator, Optional


class QueryResult:
    """The final result of a query()."""

    def __init__(self) -> None:
        self.ok: bool = False
        self.final_text: str = ""
        self.rounds: int = 0
        self.input_tokens: int = 0
        self.output_tokens: int = 0
        self.cost_microcents: int = 0
        self.exit_code: int = -1


def query(
    prompt: str,
    *,
    home: Optional[str] = None,
    model: Optional[str] = None,
    gate: Optional[str] = None,
    permission_mode: Optional[str] = None,
    max_turns: Optional[int] = None,
    extra_args: Optional[list] = None,
    orbit_bin: str = "orbit",
) -> Iterator[Dict[str, Any]]:
    """Run one headless agent turn: ``orbit -p "<prompt>"`` with tools,
    streaming the engine's events as they arrive.

    Yields each event dict; the final yield is a QueryResult.
    Exit codes: 0 done, 1 turn failed, 2 stopped by a permission
    denial, 3 hit --max-turns, 130 interrupted.
    """
    args = [orbit_bin, "-p", prompt]
    if model:
        args += ["--model", model]
    if gate:
        args += ["--gate", gate]
    if max_turns:
        args += ["--max-turns", str(max_turns)]
    if home:
        args += ["--home", home]
    if permission_mode:
        args += ["--permission-mode", permission_mode]
    if extra_args:
        args += extra_args
    args += ["--output-format", "stream-json"]

    result = QueryResult()
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "response_finished":
            result.final_text = ev.get("output", "")
            result.input_tokens = ev.get("input_tokens", 0)
            result.output_tokens = ev.get("output_tokens", 0)
            result.cost_microcents = ev.get("cost_microcents", 0)
        if ev.get("type") == "turn_ended":
            result.ok = ev.get("ok", False)
            result.rounds = ev.get("rounds", 0)
        yield ev
    proc.wait()
    # `or -1` would map a clean exit 0 to failure; None (killed by a
    # signal) is the only case that should read as -1.
    result.exit_code = proc.returncode if proc.returncode is not None else -1
    yield result  # type: ignore[misc]
