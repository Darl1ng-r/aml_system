"""
Deterministic Compliance State Machine Engine (GAP-FSM)
=========================================================
Enforces strict, non-bypassable lifecycle state transitions for AML Cases,
Alerts, and SAR Filings to prevent illegal state jumps, phantom resolutions,
and compliance audit trail tampering.
"""

from enum import Enum
from typing import Dict, Set, Optional, List
from fastapi import HTTPException, status
import logging

logger = logging.getLogger(__name__)


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    INVESTIGATING = "INVESTIGATING"
    PENDING_EDD = "PENDING_EDD"
    PENDING_SAR = "PENDING_SAR"
    CLOSED = "CLOSED"


# Formal Case Transition Table
CASE_TRANSITIONS: Dict[CaseStatus, Set[CaseStatus]] = {
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
    CaseStatus.CLOSED: set(),  # Terminal: Cannot reopen a closed case directly
}


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


# Formal Alert Transition Table
ALERT_TRANSITIONS: Dict[AlertStatus, Set[AlertStatus]] = {
    AlertStatus.NEW: {
        AlertStatus.OPEN,
        AlertStatus.CLAIMED,
        AlertStatus.IN_REVIEW,
        AlertStatus.ESCALATED,
        AlertStatus.CLOSED_SAR,
        AlertStatus.CLOSED_FALSE_POSITIVE,
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
        AlertStatus.IN_REVIEW,
        AlertStatus.PENDING_SAR,
        AlertStatus.CLOSED_SAR,
        AlertStatus.CLOSED_FALSE_POSITIVE,
    },
    AlertStatus.PENDING_SAR: {
        AlertStatus.CLOSED_SAR,
        AlertStatus.CLOSED_FALSE_POSITIVE,
        AlertStatus.CLOSED,
    },
    AlertStatus.CLOSED_SAR: set(),             # Terminal
    AlertStatus.CLOSED_FALSE_POSITIVE: set(),  # Terminal
    AlertStatus.CLOSED: set(),                 # Terminal
}


def validate_case_transition(current_status: str, target_status: str) -> None:
    """Validates that a Case state transition conforms to the deterministic transition matrix."""
    try:
        current_enum = CaseStatus(current_status.upper())
    except ValueError:
        logger.warning(f"Unknown current case state: {current_status}")
        return

    try:
        target_enum = CaseStatus(target_status.upper())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target case status: '{target_status}'. Must be one of {[s.value for s in CaseStatus]}."
        )

    if current_enum == CaseStatus.CLOSED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Deterministic state guard violation: Case is already CLOSED and cannot be modified."
        )

    if current_enum == target_enum:
        return

    allowed = CASE_TRANSITIONS.get(current_enum, set())
    if target_enum not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Illegal Case state transition from '{current_enum.value}' to '{target_enum.value}'. "
                f"Permitted next states: {[s.value for s in allowed]}."
            )
        )


def validate_alert_transition(current_status: str, target_status: str) -> None:
    """Validates that an Alert state transition conforms to the deterministic transition matrix."""
    try:
        current_enum = AlertStatus(current_status.upper())
    except ValueError:
        logger.warning(f"Unknown current alert state: {current_status}")
        return

    try:
        target_enum = AlertStatus(target_status.upper())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target alert status: '{target_status}'. Must be one of {[s.value for s in AlertStatus]}."
        )

    if current_enum in {AlertStatus.CLOSED_SAR, AlertStatus.CLOSED_FALSE_POSITIVE, AlertStatus.CLOSED}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Deterministic state guard violation: Alert is already terminal ('{current_enum.value}') and cannot be transitioned."
        )

    if current_enum == target_enum:
        return

    allowed = ALERT_TRANSITIONS.get(current_enum, set())
    if target_enum not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Illegal Alert state transition from '{current_enum.value}' to '{target_enum.value}'. "
                f"Permitted next states: {[s.value for s in allowed]}."
            )
        )
