import urllib.request
import urllib.error
import json
import logging
from config import TRANSACTIONS_TOPIC

logger = logging.getLogger(__name__)

# Redpanda REST Proxy address. Port 8082 was exposed in docker-compose.yml
REST_PROXY_URL = f"http://localhost:8082/topics/{TRANSACTIONS_TOPIC}"

def publish_transaction(transaction_payload: dict):
    """
    Publishes a scored transaction payload to the Redpanda/Kafka topic using the REST Proxy API.
    """
    # Format according to Kafka REST Proxy v2 specification
    payload = {
        "records": [
            {
                "key": transaction_payload.get("transaction_id"),
                "value": transaction_payload
            }
        ]
    }
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(REST_PROXY_URL, data=data)
    # REST Proxy header for JSON payload records
    req.add_header('Content-Type', 'application/vnd.kafka.json.v2+json')
    
    try:
        # Perform synchronous POST request
        with urllib.request.urlopen(req, timeout=3) as response:
            res_body = response.read().decode('utf-8')
            logger.info(f"Published transaction {transaction_payload.get('transaction_id')} to Redpanda via REST Proxy.")
            logger.debug(f"REST Proxy response: {res_body}")
    except Exception as e:
        # Fallback to local logs if the Redpanda queue is still starting up
        logger.warning(f"Redpanda REST Proxy unavailable, fell back to log-only. Details: {e}")
        logger.info(f"[LOG ONLY - REDPANDA OFFLINE] Message: {json.dumps(transaction_payload)}")

def flush_producer():
    pass
