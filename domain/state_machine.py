"""
Pure Deterministic Compliance State Machine Engine
==================================================
Zero-I/O, framework-agnostic finite state machines governing lifecycle
transitions across all 5 regulated compliance entities:
  1. Alerts (AlertStatus)
  2. Investigation Cases (CaseStatus)
  3. FinCEN SAR Drafts (SARDraftStatus)
  4. BSA Currency Transaction Reports (CTRFilingStatus)
  5. External Customer RFIs (RFIStatus)

Raises pure domain exceptions (`CorruptedDomainStateError`, `DomainStateTransitionError`)
with zero coupling to FastAPI/HTTP transport.
"""

from __future__ import annotations

from enum import Enum
from typing import Mapping, Set, Type, TypeVar

from domain.money import DomainError

StatusT = TypeVar("StatusT", bound=Enum)


class CorruptedDomainStateError(DomainError):
    """Raised when persisted state is unrecognized or corrupted (maps to HTTP 409)."""

    def __init__(self, entity_type: str, current_state: str) -> None:
        self.entity_type = entity_type
        self.current_state = current_state
        super().__init__(
            f"Corrupted or unrecognized current {entity_type} state: '{current_state}'. "
            "Manual admin review required."
        )


class DomainStateTransitionError(DomainError):
    """Raised when a requested transition violates the entity's FSM (maps to HTTP 400)."""

    def __init__(
        self,
        entity_type: str,
        current_state: str,
        target_state: str,
        allowed_states: list[str] | None = None,
        *,
        is_terminal: bool = False,
        invalid_target: bool = False,
        valid_states: list[str] | None = None,
    ) -> None:
        self.entity_type = entity_type
        self.current_state = current_state
        self.target_state = target_state
        self.allowed_states = allowed_states or []
        self.is_terminal = is_terminal
        self.invalid_target = invalid_target
        self.valid_states = valid_states or []

        if invalid_target:
            msg = (
                f"Invalid target {entity_type} status: '{target_state}'. "
                f"Must be one of {self.valid_states}."
            )
        elif is_terminal:
            if entity_type == "Case" and current_state == "CLOSED":
                msg = "Deterministic state guard violation: Case is already CLOSED and cannot be modified."
            else:
                msg = (
                    f"Deterministic state guard violation: {entity_type} is already terminal "
                    f"('{current_state}') and cannot be transitioned."
                )
        else:
            msg = (
                f"Illegal {entity_type} state transition from '{current_state}' to '{target_state}'. "
                f"Permitted next states: {self.allowed_states}."
            )
        super().__init__(msg)


# ── 1. Investigation Cases ────────────────────────────────────────────────────

class CaseStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    INVESTIGATING = "INVESTIGATING"
    PENDING_EDD = "PENDING_EDD"
    PENDING_SAR = "PENDING_SAR"
    CLOSED = "CLOSED"


CASE_TRANSITIONS: Mapping[CaseStatus, Set[CaseStatus]] = {
    CaseStatus.OPEN: {
        CaseStatus.IN_REVIEW,
        CaseStatus.INVESTIGATING,
        CaseStatus.PENDING_EDD,
        CaseStatus.CLOSED,
    },
    CaseStatus.IN_REVIEW: {
        CaseStatus.INVESTIGATING,
        CaseStatus.PENDING_EDD,
        CaseStatus.PENDING_SAR,
        CaseStatus.CLOSED,
    },
    CaseStatus.INVESTIGATING: {
        CaseStatus.PENDING_EDD,
        CaseStatus.PENDING_SAR,
        CaseStatus.CLOSED,
    },
    CaseStatus.PENDING_EDD: {
        CaseStatus.IN_REVIEW,
        CaseStatus.INVESTIGATING,
        CaseStatus.PENDING_SAR,
        CaseStatus.CLOSED,
    },
    CaseStatus.PENDING_SAR: {
        CaseStatus.CLOSED,
    },
    CaseStatus.CLOSED: set(),
}


# ── 2. Alerts ─────────────────────────────────────────────────────────────────

class AlertStatus(str, Enum):
    NEW = "NEW"
    OPEN = "OPEN"
    CLAIMED = "CLAIMED"
    IN_REVIEW = "IN_REVIEW"
    ESCALATED = "ESCALATED"
    PENDING_SAR = "PENDING_SAR"
    CLOSED_SAR = "CLOSED_SAR"
    CLOSED_FALSE_POSITIVE = "CLOSED_FALSE_POSITIVE"
    CLOSED = "CLOSED"


ALERT_TRANSITIONS: Mapping[AlertStatus, Set[AlertStatus]] = {
    AlertStatus.NEW: {
        AlertStatus.OPEN,
        AlertStatus.CLAIMED,
        AlertStatus.IN_REVIEW,
        AlertStatus.ESCALATED,
    },
    AlertStatus.OPEN: {
        AlertStatus.CLAIMED,
        AlertStatus.IN_REVIEW,
        AlertStatus.ESCALATED,
        AlertStatus.CLOSED_SAR,
        AlertStatus.CLOSED_FALSE_POSITIVE,
    },
    AlertStatus.CLAIMED: {
        AlertStatus.IN_REVIEW,
        AlertStatus.ESCALATED,
        AlertStatus.CLOSED_SAR,
        AlertStatus.CLOSED_FALSE_POSITIVE,
    },
    AlertStatus.IN_REVIEW: {
        AlertStatus.ESCALATED,
        AlertStatus.PENDING_SAR,
        AlertStatus.CLOSED_SAR,
        AlertStatus.CLOSED_FALSE_POSITIVE,
    },
    AlertStatus.ESCALATED: {
        AlertStatus.PENDING_SAR,
        AlertStatus.CLOSED_SAR,
        AlertStatus.CLOSED_FALSE_POSITIVE,
    },
    AlertStatus.PENDING_SAR: {
        AlertStatus.CLOSED_SAR,
        AlertStatus.CLOSED_FALSE_POSITIVE,
        AlertStatus.CLOSED,
    },
    AlertStatus.CLOSED_SAR: set(),
    AlertStatus.CLOSED_FALSE_POSITIVE: set(),
    AlertStatus.CLOSED: set(),
}


# ── 3. FinCEN SAR Drafts ──────────────────────────────────────────────────────

class SARDraftStatus(str, Enum):
    DRAFT = "DRAFT"
    PENDING_MLRO_REVIEW = "PENDING_MLRO_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    FILED = "FILED"


SAR_DRAFT_TRANSITIONS: Mapping[SARDraftStatus, Set[SARDraftStatus]] = {
    SARDraftStatus.DRAFT: {
        SARDraftStatus.PENDING_MLRO_REVIEW,
    },
    SARDraftStatus.PENDING_MLRO_REVIEW: {
        SARDraftStatus.APPROVED,
        SARDraftStatus.REJECTED,
    },
    SARDraftStatus.REJECTED: {
        SARDraftStatus.DRAFT,
        SARDraftStatus.PENDING_MLRO_REVIEW,
    },
    SARDraftStatus.APPROVED: {
        SARDraftStatus.FILED,
    },
    SARDraftStatus.FILED: set(),  # Terminal regulatory filing record
}


# ── 4. BSA Currency Transaction Reports (CTR) ─────────────────────────────────

class CTRFilingStatus(str, Enum):
    PENDING = "PENDING"
    FILED = "FILED"
    EXEMPT = "EXEMPT"
    REJECTED = "REJECTED"


CTR_TRANSITIONS: Mapping[CTRFilingStatus, Set[CTRFilingStatus]] = {
    CTRFilingStatus.PENDING: {
        CTRFilingStatus.FILED,
        CTRFilingStatus.EXEMPT,
        CTRFilingStatus.REJECTED,
    },
    CTRFilingStatus.REJECTED: {
        CTRFilingStatus.PENDING,
        CTRFilingStatus.FILED,
    },
    CTRFilingStatus.FILED: set(),   # Terminal: cannot overwrite filed tracking ID
    CTRFilingStatus.EXEMPT: set(),  # Terminal
}


# ── 5. External Requests for Information (RFI) ────────────────────────────────

class RFIStatus(str, Enum):
    OPEN = "OPEN"
    SUBMITTED = "SUBMITTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


RFI_TRANSITIONS: Mapping[RFIStatus, Set[RFIStatus]] = {
    RFIStatus.OPEN: {
        RFIStatus.SUBMITTED,
        RFIStatus.CANCELLED,
        RFIStatus.EXPIRED,
    },
    RFIStatus.SUBMITTED: set(),  # Terminal
    RFIStatus.CANCELLED: set(),  # Terminal
    RFIStatus.EXPIRED: set(),    # Terminal
}


def validate_transition(
    entity_type: str,
    status_enum: Type[StatusT],
    transition_matrix: Mapping[StatusT, Set[StatusT]],
    current_status: str,
    target_status: str,
    *,
    allow_noop: bool = True,
) -> StatusT:
    """Generic deterministic FSM guard returning the validated target status enum."""
    try:
        current_enum = status_enum(str(current_status).strip().upper())
    except ValueError as exc:
        raise CorruptedDomainStateError(entity_type, str(current_status)) from exc

    try:
        target_enum = status_enum(str(target_status).strip().upper())
    except ValueError as exc:
        raise DomainStateTransitionError(
            entity_type,
            current_enum.value,
            str(target_status),
            invalid_target=True,
            valid_states=[s.value for s in status_enum],
        ) from exc

    allowed = transition_matrix.get(current_enum, set())
    if not allowed:
        raise DomainStateTransitionError(
            entity_type,
            current_enum.value,
            target_enum.value,
            is_terminal=True,
        )

    if current_enum == target_enum and allow_noop:
        return target_enum

    if target_enum not in allowed:
        raise DomainStateTransitionError(
            entity_type,
            current_enum.value,
            target_enum.value,
            allowed_states=sorted(s.value for s in allowed),
        )

    return target_enum


def validate_case_transition_pure(current_status: str, target_status: str) -> CaseStatus:
    return validate_transition("Case", CaseStatus, CASE_TRANSITIONS, current_status, target_status)


def validate_alert_transition_pure(current_status: str, target_status: str) -> AlertStatus:
    return validate_transition("Alert", AlertStatus, ALERT_TRANSITIONS, current_status, target_status)


def validate_sar_draft_transition_pure(
    current_status: str,
    target_status: str,
    *,
    allow_noop: bool = True,
) -> SARDraftStatus:
    return validate_transition(
        "SAR draft",
        SARDraftStatus,
        SAR_DRAFT_TRANSITIONS,
        current_status,
        target_status,
        allow_noop=allow_noop,
    )


def validate_ctr_transition_pure(current_status: str, target_status: str) -> CTRFilingStatus:
    return validate_transition(
        "CTR filing",
        CTRFilingStatus,
        CTR_TRANSITIONS,
        current_status,
        target_status,
        allow_noop=False,
    )


def validate_rfi_transition_pure(current_status: str, target_status: str) -> RFIStatus:
    return validate_transition(
        "RFI",
        RFIStatus,
        RFI_TRANSITIONS,
        current_status,
        target_status,
        allow_noop=False,
    )
