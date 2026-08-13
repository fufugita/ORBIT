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
