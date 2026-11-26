"""
Deterministic Compliance State Machine Adapter (GAP-FSM)
========================================================
Thin FastAPI HTTP adapter over the pure, zero-I/O state machine engine in
`domain/state_machine.py`. Translates domain state violations into RFC-compliant
HTTP 400 (illegal/terminal transition) and HTTP 409 (corrupted persisted state)
responses while preserving 100% backward compatibility.
"""

import logging
from fastapi import HTTPException, status

from domain.state_machine import (
    ALERT_TRANSITIONS,
    AlertStatus,
    CASE_TRANSITIONS,
    CTR_TRANSITIONS,
    CTRFilingStatus,
    CaseStatus,
    CorruptedDomainStateError,
    DomainStateTransitionError,
    RFI_TRANSITIONS,
    RFIStatus,
    SAR_DRAFT_TRANSITIONS,
    SARDraftStatus,
    validate_alert_transition_pure,
    validate_case_transition_pure,
    validate_ctr_transition_pure,
    validate_rfi_transition_pure,
    validate_sar_draft_transition_pure,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ALERT_TRANSITIONS",
    "AlertStatus",
    "CASE_TRANSITIONS",
    "CTR_TRANSITIONS",
    "CTRFilingStatus",
    "CaseStatus",
    "RFI_TRANSITIONS",
    "RFIStatus",
    "SAR_DRAFT_TRANSITIONS",
    "SARDraftStatus",
    "validate_alert_transition",
    "validate_case_transition",
    "validate_ctr_transition",
    "validate_rfi_transition",
    "validate_sar_draft_transition",
]


def _translate_fsm_call(fn, current_status: str, target_status: str) -> None:
    try:
        fn(current_status, target_status)
    except CorruptedDomainStateError as exc:
        logger.error("Corrupted or unrecognized current %s state: %s", exc.entity_type, exc.current_state)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except DomainStateTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


def validate_case_transition(current_status: str, target_status: str) -> None:
    """Validates that a Case state transition conforms to the deterministic transition matrix."""
    _translate_fsm_call(validate_case_transition_pure, current_status, target_status)


def validate_alert_transition(current_status: str, target_status: str) -> None:
    """Validates that an Alert state transition conforms to the deterministic transition matrix."""
    _translate_fsm_call(validate_alert_transition_pure, current_status, target_status)


def validate_sar_draft_transition(
    current_status: str,
    target_status: str,
    *,
    allow_noop: bool = True,
) -> None:
    """Validates that a SAR Draft state transition conforms to the deterministic transition matrix."""
    try:
        validate_sar_draft_transition_pure(current_status, target_status, allow_noop=allow_noop)
    except CorruptedDomainStateError as exc:
        logger.error("Corrupted or unrecognized current %s state: %s", exc.entity_type, exc.current_state)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except DomainStateTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


def validate_ctr_transition(current_status: str, target_status: str) -> None:
    """Validates that a CTR Filing state transition conforms to the deterministic transition matrix."""
    _translate_fsm_call(validate_ctr_transition_pure, current_status, target_status)


def validate_rfi_transition(current_status: str, target_status: str) -> None:
    """Validates that an External RFI state transition conforms to the deterministic transition matrix."""
    _translate_fsm_call(validate_rfi_transition_pure, current_status, target_status)
