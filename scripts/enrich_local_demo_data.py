"""
Idempotent local dev seed-data enrichment script.
Replaces repetitive 'Foreign Senior Official' demo owner names with realistic
distinct entities, aligns account risk_category with risk_score, and enriches
generic alert explainability text for local demonstration clarity.
"""
import asyncio
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.postgres import init_db_pool, get_async_db_conn

DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001"

REALISTIC_ENTITIES = [
    "Meridian Trade Holdings Ltd",
    "Viktor Petrov",
    "Caspian Freight Logistics LLC",
    "Al-Noor Capital Group",
    "Elena Rostova",
    "Nordic Marine Charter AS",
    "Bosphorus Commodities SA",
    "Kestrel Offshore Ventures",
    "Dmitri Sokolov",
    "Vanguard Metals Trading DMCC",
    "Sovereign Bridge Advisors",
    "Hafiz Al-Mansoor",
    "Baltic Bulk Carriers OÜ",
    "Aurelia Precious Metals AG",
    "Tariq Al-Rashid",
    "Eastgate Clearing Corp",
    "Nadia Volkov",
    "Red Sea Petrochem FZE",
    "Helios Energy Brokerage",
    "Sergei Morozov",
    "Atlas Maritime Services",
    "Crownwell Import-Export Ltd",
    "Farid Khoury",
    "Pacific Rim Supply Chain Co",
]


def pick_entity_name(account_number: str) -> str:
    digest = int(hashlib.sha256(account_number.encode("utf-8")).hexdigest()[:8], 16)
    return REALISTIC_ENTITIES[digest % len(REALISTIC_ENTITIES)]


def derive_risk_category(risk_score: float) -> str:
    if risk_score >= 0.85:
        return "CRITICAL"
    if risk_score >= 0.65:
        return "HIGH"
    if risk_score >= 0.35:
        return "MEDIUM"
    return "LOW"


async def enrich() -> None:
    await init_db_pool()
    async with get_async_db_conn(tenant_id=DEFAULT_TENANT) as conn:
        # 1. Diversify repetitive 'Foreign Senior Official' accounts
        accounts = await conn.fetch(
            """
            SELECT id, account_number, owner_name, risk_score, risk_category
            FROM accounts
            WHERE owner_name = 'Foreign Senior Official'
               OR risk_category IS NULL
               OR (risk_score >= 0.65 AND COALESCE(risk_category, 'LOW') = 'LOW');
            """
        )
        updated_accounts = 0
        for row in accounts:
            new_name = (
                pick_entity_name(row["account_number"])
                if row["owner_name"] == "Foreign Senior Official"
                else row["owner_name"]
            )
            score = float(row["risk_score"] or 0.0)
            new_cat = derive_risk_category(score)
            await conn.execute(
                """
                UPDATE accounts
                SET owner_name = $1,
                    risk_category = $2
                WHERE id = $3;
                """,
                new_name,
                new_cat,
                row["id"],
            )
            updated_accounts += 1

        # 2. Enrich generic tautological explainability payloads (JSONB column)
        alerts = await conn.fetch(
            """
            SELECT a.id, a.rule_name, a.explainability_payload::text AS payload_text,
                   t.amount, t.currency,
                   s.owner_name AS sender_name, s.account_number AS sender_acc,
                   r.owner_name AS receiver_name, r.account_number AS receiver_acc
            FROM alerts a
            JOIN transactions t ON a.transaction_id = t.id
            JOIN accounts s ON t.sender_account_id = s.id
            JOIN accounts r ON t.receiver_account_id = r.id
            WHERE a.explainability_payload IS NULL
               OR a.explainability_payload::text LIKE '%Triggered %'
               OR LENGTH(a.explainability_payload::text) < 45;
            """
        )
        updated_alerts = 0
        for a in alerts:
            amt = float(a["amount"] or 0.0)
            ccy = a["currency"] or "USD"
            rule = (a["rule_name"] or "MONITORING_HIT").upper()
            if "STRUCTUR" in rule:
                reason = (
                    f"Potential structuring detected: {a['sender_name']} ({a['sender_acc']}) "
                    f"transferred {amt:,.2f} {ccy} to {a['receiver_name']} ({a['receiver_acc']}), "
                    f"sitting within the sub-$10,000 CTR reporting evasion band."
                )
            elif "RAPID" in rule:
                reason = (
                    f"Rapid pass-through velocity: {a['sender_name']} ({a['sender_acc']}) "
                    f"routed {amt:,.2f} {ccy} to {a['receiver_name']} ({a['receiver_acc']}) "
                    f"exceeding the 24h rapid-movement velocity threshold."
                )
            else:
                reason = (
                    f"{rule.replace('_', ' ')} triggered on {amt:,.2f} {ccy} transfer from "
                    f"{a['sender_name']} ({a['sender_acc']}) to {a['receiver_name']} ({a['receiver_acc']})."
                )
            payload_json = json.dumps({"reason": reason, "summary": reason, "rule": rule})
            await conn.execute(
                "UPDATE alerts SET explainability_payload = $1::jsonb WHERE id = $2;",
                payload_json,
                a["id"],
            )
            updated_alerts += 1

        print(f"Enriched {updated_accounts} accounts and {updated_alerts} alert explanations.")


if __name__ == "__main__":
    asyncio.run(enrich())
