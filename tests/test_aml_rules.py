import pytest
import uuid
from services.rules import RulesEngine, get_rules_config


def test_rules_config_loader():
    """Verify get_rules_config returns active AML rules dictionary."""
    config = get_rules_config()
    assert "rules" in config
    assert "LARGE_TRANSACTION" in config["rules"]
    assert "GEOGRAPHIC_SANCTIONS" in config["rules"]


@pytest.mark.anyio
async def test_rules_engine_large_transaction():
    """Verify large transaction threshold rule triggers when amount >= $10,000."""
    triggered = await RulesEngine.evaluate_transaction(
        sender_id=str(uuid.uuid4()),
        receiver_id=str(uuid.uuid4()),
        amount=15000.0,
        sender_name="Alice Schmidt",
        sender_bic="DBANKDE1XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX"
    )
    assert "LARGE_TRANSACTION_THRESHOLD" in triggered


@pytest.mark.anyio
async def test_rules_engine_geographic_risk():
    """Verify geographic risk rule triggers for SWIFT BICs in high-risk jurisdictions."""
    triggered = await RulesEngine.evaluate_transaction(
        sender_id=str(uuid.uuid4()),
        receiver_id=str(uuid.uuid4()),
        amount=500.0,
        sender_name="Vladimir Smirnov",
        sender_bic="SBERRU88XXX",
        receiver_name="Bob Jones",
        receiver_bic="CHASEUS3XXX"
    )
    assert "GEOGRAPHIC_RISK" in triggered
