"""Internal approval-binding semantics for Agent Plugin drift.

This module deliberately sits above the PR3 drift model.  It records which
content and capability scopes a caller chose to bind, checks the exact PR3
coverage prerequisites for those scopes, and maps PR3 drift states to
per-dimension review state.  It does not apply policy, create findings, or
persist approval records.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from skillgate.agent_plugin_drift import (
    DRIFT_CHANGED,
    DRIFT_UNCHANGED,
    DRIFT_UNKNOWN,
    AgentPluginDriftReport,
    AgentPluginDriftSnapshot,
    compare_agent_plugin_drift,
)

AGENT_PLUGIN_APPROVAL_BINDING_VERSION = "1"

APPROVAL_MATCHES = "MATCHES"
APPROVAL_STALE = "STALE"
APPROVAL_UNKNOWN = "UNKNOWN"
APPROVAL_NOT_BOUND = "NOT_BOUND"

ELIGIBILITY_ELIGIBLE = "ELIGIBLE"
ELIGIBILITY_INELIGIBLE = "INELIGIBLE"
ELIGIBILITY_NOT_BOUND = "NOT_BOUND"

APPROVAL_SCOPE_PORTABLE_CORE = "portable_core"
APPROVAL_SCOPE_OVERALL_ARTIFACT = "overall_artifact"

REVIEW_CONTENT_CHANGE = "review_content_change"
REVIEW_CAPABILITY_CHANGE = "review_capability_change"
RESOLVE_CONTENT_IDENTITY = "resolve_content_identity"
RESOLVE_CAPABILITY_COVERAGE = "resolve_capability_coverage"
REBUILD_COMPATIBLE_REVIEW = "rebuild_compatible_review"

_APPROVAL_SCOPES = frozenset({APPROVAL_SCOPE_PORTABLE_CORE, APPROVAL_SCOPE_OVERALL_ARTIFACT})


@dataclass(frozen=True)
class AgentPluginApprovalContract:
    """The independently bound content and capability review scopes."""

    content_scope: str | None = None
    capability_scope: str | None = None

    def __post_init__(self) -> None:
        for field_name, scope in (
            ("content_scope", self.content_scope),
            ("capability_scope", self.capability_scope),
        ):
            if scope is not None and (not isinstance(scope, str) or scope not in _APPROVAL_SCOPES):
                raise ValueError(f"{field_name} must be portable_core, overall_artifact, or None")
        if self.content_scope is None and self.capability_scope is None:
            raise ValueError("an approval contract must bind content, capability, or both")

    def to_data(self) -> dict[str, str | None]:
        return {
            "content_scope": self.content_scope,
            "capability_scope": self.capability_scope,
        }


@dataclass(frozen=True)
class AgentPluginApprovalDimensionEligibility:
    """Binding prerequisites for one independently requested dimension."""

    scope: str | None
    status: str
    reasons: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        return self.status == ELIGIBILITY_ELIGIBLE

    def to_data(self) -> dict[str, object]:
        return {
            "scope": self.scope,
            "status": self.status,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class AgentPluginApprovalEligibility:
    """Typed, per-dimension prerequisites for creating or replacing a binding."""

    content: AgentPluginApprovalDimensionEligibility
    capability: AgentPluginApprovalDimensionEligibility

    @property
    def eligible(self) -> bool:
        """Whether every dimension requested by the contract is eligible."""
        return self.content.status != ELIGIBILITY_INELIGIBLE and self.capability.status != (
            ELIGIBILITY_INELIGIBLE
        )

    @property
    def content_eligibility(self) -> AgentPluginApprovalDimensionEligibility:
        return self.content

    @property
    def capability_eligibility(self) -> AgentPluginApprovalDimensionEligibility:
        return self.capability

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((*self.content.reasons, *self.capability.reasons)))

    def to_data(self) -> dict[str, object]:
        return {
            "content": self.content.to_data(),
            "capability": self.capability.to_data(),
            "eligible": self.eligible,
        }


class AgentPluginApprovalEligibilityError(ValueError):
    """Raised when explicit binding creation is requested without prerequisites."""

    def __init__(self, eligibility: AgentPluginApprovalEligibility) -> None:
        self.eligibility = eligibility
        super().__init__(
            "Agent Plugin approval binding prerequisites are incomplete: "
            + ", ".join(eligibility.reasons)
        )


@dataclass(frozen=True)
class AgentPluginApprovalBinding:
    """An in-memory binding to one complete reference review snapshot."""

    contract: AgentPluginApprovalContract
    reference_snapshot: AgentPluginDriftSnapshot
    binding_format_version: str = AGENT_PLUGIN_APPROVAL_BINDING_VERSION

    @property
    def snapshot(self) -> AgentPluginDriftSnapshot:
        """Convenience alias for callers that call the reference a snapshot."""
        return self.reference_snapshot

    def to_data(self) -> dict[str, object]:
        """Return deterministic internal data; this is not a persisted schema."""
        return {
            "binding_format_version": self.binding_format_version,
            "contract": self.contract.to_data(),
            "reference_snapshot": self.reference_snapshot.to_data(),
        }


@dataclass(frozen=True)
class AgentPluginApprovalEvaluation:
    """Per-dimension state for one binding evaluated against a current snapshot."""

    contract: AgentPluginApprovalContract
    content_status: str
    capability_status: str
    current_eligibility: AgentPluginApprovalEligibility
    drift: AgentPluginDriftReport
    required_actions: tuple[str, ...] = ()
    diagnostics: tuple[Any, ...] = ()

    @property
    def content_approval_status(self) -> str:
        return self.content_status

    @property
    def capability_approval_status(self) -> str:
        return self.capability_status

    def to_data(self) -> dict[str, object]:
        return {
            "contract": self.contract.to_data(),
            "content_status": self.content_status,
            "capability_status": self.capability_status,
            "current_eligibility": self.current_eligibility.to_data(),
            "drift": self.drift.to_data(),
            "required_actions": list(self.required_actions),
            "diagnostics": [
                item.to_data() if hasattr(item, "to_data") else item for item in self.diagnostics
            ],
        }


def _dimension_eligibility(
    scope: str | None,
    complete: str,
    reason: str,
) -> AgentPluginApprovalDimensionEligibility:
    if scope is None:
        return AgentPluginApprovalDimensionEligibility(
            scope=None,
            status=ELIGIBILITY_NOT_BOUND,
        )
    if complete == "COMPLETE":
        return AgentPluginApprovalDimensionEligibility(
            scope=scope,
            status=ELIGIBILITY_ELIGIBLE,
        )
    return AgentPluginApprovalDimensionEligibility(
        scope=scope,
        status=ELIGIBILITY_INELIGIBLE,
        reasons=(reason,),
    )


def _scope_value(value: Any, scope: str) -> Any:
    """Select one validated scope from a PR3 report or coverage object."""
    return getattr(value, scope)


def assess_agent_plugin_approval_eligibility(
    snapshot: AgentPluginDriftSnapshot,
    contract: AgentPluginApprovalContract,
) -> AgentPluginApprovalEligibility:
    """Assess exact prerequisites without creating an approval binding."""
    content_coverage = (
        _scope_value(snapshot.content_identity_coverage, contract.content_scope)
        if (contract.content_scope is not None)
        else "UNBOUND"
    )
    capability_coverage = (
        _scope_value(snapshot.capability_coverage, contract.capability_scope)
        if (contract.capability_scope is not None)
        else "UNBOUND"
    )
    return AgentPluginApprovalEligibility(
        content=_dimension_eligibility(
            contract.content_scope,
            content_coverage,
            "content_identity_incomplete",
        ),
        capability=_dimension_eligibility(
            contract.capability_scope,
            capability_coverage,
            "capability_coverage_incomplete",
        ),
    )


def create_agent_plugin_approval_binding(
    snapshot: AgentPluginDriftSnapshot,
    contract: AgentPluginApprovalContract,
) -> AgentPluginApprovalBinding:
    """Create a binding only after its requested evidence is explicitly eligible.

    Ineligible creation raises :class:`AgentPluginApprovalEligibilityError`;
    the exception retains the full typed eligibility result for callers that
    need the exact failed dimension and reason.
    """
    eligibility = assess_agent_plugin_approval_eligibility(snapshot, contract)
    if not eligibility.eligible:
        raise AgentPluginApprovalEligibilityError(eligibility)
    return AgentPluginApprovalBinding(
        contract=contract,
        reference_snapshot=snapshot,
    )


def _approval_status(state: str) -> str:
    if state == DRIFT_UNCHANGED:
        return APPROVAL_MATCHES
    if state == DRIFT_CHANGED:
        return APPROVAL_STALE
    if state == DRIFT_UNKNOWN:
        return APPROVAL_UNKNOWN
    return APPROVAL_UNKNOWN


def _dimension_status(
    scope: str | None,
    drift: Any,
) -> str:
    if scope is None:
        return APPROVAL_NOT_BOUND
    return _approval_status(_scope_value(drift, scope))


def _required_actions(
    content_status: str,
    capability_status: str,
    diagnostics: tuple[Any, ...],
) -> tuple[str, ...]:
    actions: list[str] = []
    if content_status == APPROVAL_STALE:
        actions.append(REVIEW_CONTENT_CHANGE)
    elif content_status == APPROVAL_UNKNOWN:
        actions.append(RESOLVE_CONTENT_IDENTITY)
    if capability_status == APPROVAL_STALE:
        actions.append(REVIEW_CAPABILITY_CHANGE)
    elif capability_status == APPROVAL_UNKNOWN:
        actions.append(RESOLVE_CAPABILITY_COVERAGE)
    if any(getattr(item, "code", None) == "drift_snapshot_format_mismatch" for item in diagnostics):
        actions.append(REBUILD_COMPATIBLE_REVIEW)
    return tuple(actions)


def evaluate_agent_plugin_approval(
    binding: AgentPluginApprovalBinding,
    current_snapshot: AgentPluginDriftSnapshot,
) -> AgentPluginApprovalEvaluation:
    """Evaluate a binding by reusing the complete PR3 snapshot comparison."""
    drift = compare_agent_plugin_drift(binding.reference_snapshot, current_snapshot)
    content_status = _dimension_status(binding.contract.content_scope, drift.content)
    capability_status = _dimension_status(
        binding.contract.capability_scope,
        drift.capability,
    )
    current_eligibility = assess_agent_plugin_approval_eligibility(
        current_snapshot,
        binding.contract,
    )
    diagnostics = drift.diagnostics
    return AgentPluginApprovalEvaluation(
        contract=binding.contract,
        content_status=content_status,
        capability_status=capability_status,
        current_eligibility=current_eligibility,
        drift=drift,
        required_actions=_required_actions(
            content_status,
            capability_status,
            diagnostics,
        ),
        diagnostics=diagnostics,
    )


def agent_plugin_approval_binding_to_data(
    binding: AgentPluginApprovalBinding,
) -> dict[str, object]:
    """Return deterministic internal binding data for tests and adapters."""
    return binding.to_data()


def agent_plugin_approval_evaluation_to_data(
    evaluation: AgentPluginApprovalEvaluation,
) -> dict[str, object]:
    """Return deterministic internal evaluation data for tests and adapters."""
    return evaluation.to_data()


# Intuitive aliases for internal callers; none are wired to the public CLI.
evaluate_agent_plugin_approval_binding = evaluate_agent_plugin_approval
assess_agent_plugin_approval = assess_agent_plugin_approval_eligibility
