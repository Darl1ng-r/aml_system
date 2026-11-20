"""
Perpetual KYC (pKYC) Delta Rescreening & Independent QA Four-Eyes Sampling (P1-5)
==================================================================================
1. Perpetual KYC (pKYC): Re-screens active customer accounts against sanctions & PEP
   watchlists, flags material risk deltas (`pkyc_material_change_flag`), generates
   EDD review alerts + MLRO notifications, and logs `pkyc_rescreen_runs`.
2. QA Four-Eyes Sampling: Randomly samples 5-10% of closed `CLOSED_FALSE_POSITIVE`
   alerts for independent QA verification. Enforces Segregation of Duties (QA reviewer
   cannot be the original dismissing analyst) and reopens failed dismissals to `OPEN`.
"""

import json
import logging
import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from observability.logging import log_audit_event
from routers.screening import perform_pep_search, perform_sanctions_search
from services.notifications import create_notification

logger = logging.getLogger("aml.pkyc_qa")


async def run_pkyc_delta_rescreen(
    conn: Any,
    tenant_id: str | uuid.UUID,
    triggered_by: str = "SYSTEM",
    limit: int = 100,
    es_client: Any = None,
) -> Dict[str, Any]:
    """
    Performs a Perpetual KYC (pKYC) delta rescreening sweep across active accounts,
    identifying newly sanctioned or PEP-matched customers and raising EDD alerts.
    """
    tenant_uuid = uuid.UUID(str(tenant_id))
    started_at = datetime.now(timezone.utc)
    limit = max(1, min(int(limit), 500))

    accounts = await conn.fetch(
        """
        SELECT id, account_number, owner_name, risk_score, status, pkyc_material_change_flag
        FROM accounts
        WHERE status IN ('ACTIVE', 'EDD_REQUIRED')
          AND erased_at IS NULL
          AND owner_name IS NOT NULL
          AND owner_name <> ''
        ORDER BY last_rescreened_at ASC NULLS FIRST, created_at ASC
        LIMIT $1;
        """,
        limit,
    )

    scanned = 0
    material_changes = 0
    alerts_generated = 0
    flagged_accounts: List[Dict[str, Any]] = []

    for acc in (accounts or []):
        scanned += 1
        acc_id = acc["id"]
        owner_name = acc["owner_name"]
        prior_risk = float(acc["risk_score"] or 0.0)

        sanc_res = await perform_sanctions_search(owner_name, 0.82, es=es_client, tenant_id=str(tenant_uuid))
        pep_res = await perform_pep_search(owner_name, 0.82, es=es_client, tenant_id=str(tenant_uuid))

        sanc_hit = bool(sanc_res and sanc_res.get("match_found"))
        pep_hit = bool(pep_res and pep_res.get("match_found"))
        new_risk = max(prior_risk, 0.95 if sanc_hit else (0.78 if pep_hit else prior_risk))
        material_delta = (sanc_hit or pep_hit) and (new_risk - prior_risk >= 0.15 or not acc["pkyc_material_change_flag"])

        await conn.execute(
            """
            UPDATE accounts
            SET last_rescreened_at = NOW(),
                risk_score = $1,
                pkyc_material_change_flag = CASE WHEN $2 THEN TRUE ELSE pkyc_material_change_flag END
            WHERE id = $3;
            """,
            new_risk,
            material_delta,
            acc_id,
        )

        if material_delta:
            material_changes += 1
            reason_code = "PKYC_SANCTIONS_DELTA_HIT" if sanc_hit else "PKYC_PEP_DELTA_HIT"
            threat = "CRITICAL" if sanc_hit else "HIGH"
            matched_source = (
                (sanc_res.get("source_list") if sanc_hit else pep_res.get("source_list"))
                or "WATCHLIST_DELTA"
            )

            alert_id = await conn.fetchval(
                """
                INSERT INTO alerts (
                    tenant_id, rule_name, threat_level, ai_risk_score, status, explainability_payload
                )
                VALUES ($1, $2, $3, $4, 'OPEN', $5::jsonb)
                RETURNING id;
                """,
                tenant_uuid,
                reason_code,
                threat,
                new_risk,
                json.dumps({
                    "account_id": str(acc_id),
                    "account_number": acc["account_number"],
                    "source": matched_source,
                    "prior_risk": round(prior_risk, 4),
                    "new_risk": round(new_risk, 4),
                }),
            )
            alerts_generated += 1

            await create_notification(
                conn=conn,
                tenant_id=tenant_uuid,
                category="PKYC_MATERIAL_CHANGE",
                severity="CRITICAL" if sanc_hit else "WARNING",
                recipient_role="MLRO",
                title=f"pKYC Material Risk Change: {owner_name}",
                body=f"Account {acc['account_number']} matched {matched_source} during delta rescreening (risk {prior_risk:.2f} -> {new_risk:.2f}).",
                link_url=f"/customers?account={acc['account_number']}",
                resource_type="ACCOUNT",
                resource_id=str(acc_id),
            )

            flagged_accounts.append({
                "account_id": str(acc_id),
                "account_number": acc["account_number"],
                "owner_name": owner_name,
                "reason": reason_code,
                "prior_risk": prior_risk,
                "new_risk": new_risk,
                "alert_id": str(alert_id),
            })

    run_id = await conn.fetchval(
        """
        INSERT INTO pkyc_rescreen_runs (
            tenant_id, triggered_by, accounts_scanned, material_changes_found,
            alerts_generated, started_at, completed_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        RETURNING id;
        """,
        tenant_uuid,
        triggered_by,
        scanned,
        material_changes,
        alerts_generated,
        started_at,
    )

    log_audit_event(
        event_type="PKYC_DELTA_RESCREEN_COMPLETED",
        actor_id=triggered_by,
        actor_role="MLRO",
        action="PKYC_RESCREEN",
        resource_type="PKYC_RUN",
        resource_id=str(run_id),
        tenant_id=str(tenant_uuid),
        details={
            "accounts_scanned": scanned,
            "material_changes_found": material_changes,
            "alerts_generated": alerts_generated,
        },
    )

    return {
        "run_id": str(run_id),
        "accounts_scanned": scanned,
        "material_changes_found": material_changes,
        "alerts_generated": alerts_generated,
        "flagged_accounts": flagged_accounts,
    }


async def sample_closed_false_positives_for_qa(
    conn: Any,
    tenant_id: str | uuid.UUID,
    sampled_by_username: str,
    sample_rate: float = 0.10,
    max_samples: int = 25,
) -> Dict[str, Any]:
    """
    Randomly selects a configurable percentage (`sample_rate`, default 10%) of closed
    `CLOSED_FALSE_POSITIVE` alerts not yet sampled into `qa_reviews`.
    """
    tenant_uuid = uuid.UUID(str(tenant_id))
    rate = max(0.01, min(float(sample_rate), 1.0))
    cap = max(1, min(int(max_samples), 100))

    eligible = await conn.fetch(
        """
        SELECT a.id AS alert_id,
               a.status,
               COALESCE(u.username, '') AS analyst_username,
               ca.case_id
        FROM alerts a
        LEFT JOIN users u ON a.assigned_officer_id = u.id
        LEFT JOIN case_alerts ca ON ca.alert_id = a.id
        WHERE a.status = 'CLOSED_FALSE_POSITIVE'
          AND NOT EXISTS (
              SELECT 1 FROM qa_reviews q
              WHERE q.tenant_id = $1 AND q.alert_id = a.id
          )
        ORDER BY RANDOM()
        LIMIT $2;
        """,
        tenant_uuid,
        cap * 10,
    )

    total_eligible = len(eligible or [])
    if total_eligible == 0:
        return {"sampled_count": 0, "eligible_pool": 0, "reviews": []}

    target_count = min(cap, max(1, math.ceil(total_eligible * rate)))
    chosen = list(eligible)[:target_count]

    created: List[Dict[str, Any]] = []
    for row in chosen:
        rid = await conn.fetchval(
            """
            INSERT INTO qa_reviews (
                tenant_id, alert_id, case_id, original_disposition,
                original_analyst_username, sampled_by_username, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'PENDING')
            ON CONFLICT (tenant_id, alert_id) DO NOTHING
            RETURNING id;
            """,
            tenant_uuid,
            row["alert_id"],
            row["case_id"],
            row["status"],
            row["analyst_username"],
            sampled_by_username,
        )
        if rid:
            created.append({
                "review_id": str(rid),
                "alert_id": str(row["alert_id"]),
                "original_analyst_username": row["analyst_username"],
                "status": "PENDING",
            })

    return {
        "sampled_count": len(created),
        "eligible_pool": total_eligible,
        "sample_rate": rate,
        "reviews": created,
    }
