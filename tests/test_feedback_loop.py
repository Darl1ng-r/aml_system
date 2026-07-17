import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi import BackgroundTasks
from routers.ml_feedback import retrain_model_now
from services.feedback_loop import ActiveLearningFeedbackService


@pytest.mark.anyio
async def test_retrain_endpoint_dispatches_background_task():
    """Verify retrain_model_now enqueues background task and returns 202 status payload instantly."""
    background_tasks = BackgroundTasks()
    current_user = {"username": "test_analyst", "role": "ANALYST"}

    response = await retrain_model_now(
        background_tasks=background_tasks,
        current_user=current_user,
        _rate_limit=True
    )

    assert response["status"] == "QUEUED"
    assert "dispatched in background" in response["message"]
    assert response["triggered_by"] == "test_analyst"

    # Assert task was added to background_tasks list
    assert len(background_tasks.tasks) == 1


@pytest.mark.anyio
async def test_retrain_model_with_feedback_offloads_fitting():
    """Verify retrain_model_with_feedback fits the model off-thread via asyncio.to_thread."""
    service = ActiveLearningFeedbackService()

    fake_rows = [
        {"features_json": '{"amount": 500.0, "sender_risk": 0.1, "receiver_risk": 0.2, "hour": 14, "is_geo": 0}', "label": 0},
        {"features_json": '{"amount": 15000.0, "sender_risk": 0.8, "receiver_risk": 0.9, "hour": 2, "is_geo": 1}', "label": 1}
    ]

    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = fake_rows

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("services.feedback_loop.get_async_db_conn", return_value=mock_ctx), \
         patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
        result = await service.retrain_model_with_feedback()

        assert result["status"] == "RETRAINED"
        assert result["samples_count"] == 2
        assert result["false_positives_learned"] == 1
        assert result["true_sars_learned"] == 1
        # Assert fitting was dispatched to asyncio.to_thread
        mock_to_thread.assert_called_once()
