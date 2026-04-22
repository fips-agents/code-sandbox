"""Multi-stage code execution pipeline.

Orchestrates pre-execution validation stages, code execution, and
post-execution review stages.  Each profile defines which stages run.

Usage::

    from sandbox.pipeline import run_pipeline
    from sandbox.profiles import get_active_profile

    profile = get_active_profile()
    result = await run_pipeline(code, profile, timeout=10.0)
    if result.rejected:
        # surface result.violations to the LLM
        ...
"""

from __future__ import annotations

import dataclasses

from sandbox.audit import SecurityEvent, Severity, emit
from sandbox.executor import ExecutionResult, execute_code
from sandbox.guardrails import blocklist_audit, validate_code
from sandbox.profiles import Profile


@dataclasses.dataclass
class PipelineResult:
    """Outcome of the code execution pipeline."""

    rejected: bool
    violations: list[str] = dataclasses.field(default_factory=list)
    result: ExecutionResult | None = None


# Registry of pre-execution stage functions.
# Each takes (source, profile) and returns a list of violation strings.
_PRE_STAGES: dict[str, object] = {
    "ast_scan": lambda source, profile: validate_code(
        source, profile.allowed_imports,
    ),
    "blocklist_audit": lambda source, profile: blocklist_audit(
        source, profile.blocklist,
    ),
}

# Registry of post-execution stage functions.
# Each takes (source, result, profile) and returns a list of violation strings.
_POST_STAGES: dict[str, object] = {}


async def run_pipeline(
    code: str,
    profile: Profile,
    timeout: float = 10.0,
) -> PipelineResult:
    """Run the full code execution pipeline for the given profile.

    Stages execute in order.  The pipeline short-circuits on the first
    stage that returns violations.

    Args:
        code: Python source code to validate and execute.
        profile: Active sandbox profile (determines which stages run).
        timeout: Execution timeout in seconds (capped by profile max).

    Returns:
        A :class:`PipelineResult` indicating whether the code was rejected
        or executed, with violations or execution output.
    """
    timeout = min(timeout, profile.resources.timeout_max)

    # Pre-execution stages.
    for stage_name in profile.scan_stages.pre:
        stage_fn = _PRE_STAGES.get(stage_name)
        if stage_fn is None:
            return PipelineResult(
                rejected=True,
                violations=[f"Unknown pre-execution stage: {stage_name}"],
            )
        violations = stage_fn(code, profile)
        if violations:
            mode = profile.audit.get_mode(stage_name)
            # Emit audit event for each violation.
            for v in violations:
                emit(SecurityEvent(
                    layer=stage_name,
                    action="violation",
                    message=v,
                    severity=Severity.HIGH,
                    mode=mode,
                ))
            if mode == "enforce":
                return PipelineResult(rejected=True, violations=violations)
            # observe mode: log but continue execution

    # Execute.
    memory_mb = profile.resources.subprocess_memory_mb
    result = await execute_code(
        code,
        timeout,
        memory_limit_mb=memory_mb,
        preimport=profile.preimport or None,
        allowed_imports=profile.allowed_imports,
        subprocess_landlock=True,
    )

    if result.timed_out:
        emit(SecurityEvent(
            layer="timeout",
            action="timeout_kill",
            message=f"Execution killed after {timeout}s",
            severity=Severity.MEDIUM,
            details={"timeout_seconds": timeout},
        ))

    if result.exit_code != 0 and not result.timed_out:
        # Check stderr for memory limit hits
        if "MemoryError" in result.stderr:
            emit(SecurityEvent(
                layer="memory",
                action="oom_kill",
                message=f"Process hit memory limit ({memory_mb}MB)",
                severity=Severity.MEDIUM,
                details={"memory_limit_mb": memory_mb},
            ))

    # Post-execution stages.
    for stage_name in profile.scan_stages.post:
        stage_fn = _POST_STAGES.get(stage_name)
        if stage_fn is None:
            continue
        violations = stage_fn(code, result, profile)
        if violations:
            return PipelineResult(
                rejected=True, violations=violations, result=result,
            )

    return PipelineResult(rejected=False, result=result)
