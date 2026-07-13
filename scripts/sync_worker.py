import sys
import os
import time
import json
import logging
from datetime import datetime

# Add parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import KAFKA_BOOTSTRAP_SERVERS, TRANSACTIONS_TOPIC
from database.neo4j_db import get_neo4j_driver
from database.postgres import get_db_cursor

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("sync_worker")

def sync_transaction_to_neo4j(tx_payload: dict, neo4j_driver) -> bool:
    """
    Syncs a transaction to Neo4j, creating nodes if missing and adding a TRANSFERS_TO edge.
    """
    try:
        tx_id = tx_payload.get("transaction_id")
        sender_id = tx_payload.get("sender_id")
        sender_acc = tx_payload.get("sender_account")
        receiver_id = tx_payload.get("receiver_id")
        receiver_acc = tx_payload.get("receiver_account")
        amount = float(tx_payload.get("amount", 0.0))
        status = tx_payload.get("status")
        timestamp_str = tx_payload.get("timestamp")
        
        # Parse timestamp to epoch integer
        try:
            # ISO timestamp e.g. "2026-07-13T10:35:00Z"
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1]
            dt = datetime.fromisoformat(timestamp_str)
            epoch = int(dt.timestamp())
        except Exception:
            epoch = int(time.time())

        # Cypher Query to create accounts and the transfer relationship
        query = """
        MERGE (s:Account {id: $sender_id})
        ON CREATE SET s.account_number = $sender_acc
        
        MERGE (r:Account {id: $receiver_id})
        ON CREATE SET r.account_number = $receiver_acc
        
        CREATE (s)-[t:TRANSFERS_TO {
            transaction_id: $tx_id,
            amount: $amount,
            status: $status,
            timestamp: $epoch
        }]->(r)
        """
        
        with neo4j_driver.session() as session:
            session.run(
                query,
                sender_id=sender_id,
                sender_acc=sender_acc,
                receiver_id=receiver_id,
                receiver_acc=receiver_acc,
                tx_id=tx_id,
                amount=amount,
                status=status,
                epoch=epoch
            )
        logger.info(f"Graph Sync: Recorded transfer of ${amount} from {sender_acc} -> {receiver_acc} in Neo4j.")
        return True
    except Exception as e:
        logger.error(f"Graph Sync Failed for transaction {tx_payload.get('transaction_id')}: {e}")
        return False

def run_kafka_consumer(neo4j_driver):
    from confluent_kafka import Consumer, KafkaError
    
    conf = {
        'bootstrap.servers': KAFKA_BOOTSTRAP_SERVERS,
        'group.id': 'aml-graph-sync-group',
        'auto.offset.reset': 'earliest',
        'enable.auto.commit': True
    }
    
    consumer = Consumer(conf)
    consumer.subscribe([TRANSACTIONS_TOPIC])
    logger.info(f"Redpanda/Kafka Graph Sync Worker started. Subscribed to topic: {TRANSACTIONS_TOPIC}")

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                else:
                    logger.error(f"Kafka error: {msg.error()}")
                    time.sleep(2)
                    continue

            # Process transaction
            try:
                tx_payload = json.loads(msg.value().decode('utf-8'))
                sync_transaction_to_neo4j(tx_payload, neo4j_driver)
            except Exception as e:
                logger.error(f"Failed to process message payload: {e}")
    finally:
        consumer.close()

def run_postgres_poll_fallback(neo4j_driver):
    """
    Fallback loop that polls PostgreSQL transactions table for un-synced transactions
    and writes them to Neo4j. (Simulates real-time messaging sync when Redpanda is unavailable).
    """
    logger.info("Starting PostgreSQL polling fallback worker...")
    synced_tx_ids = set()
    
    while True:
        try:
            with get_db_cursor() as cur:
                # Query recent transactions
                cur.execute(
                    """
                    SELECT t.id, t.sender_account_id, s.account_number, 
                           t.receiver_account_id, r.account_number, 
                           t.amount, t.status, t.timestamp
                    FROM transactions t
                    JOIN accounts s ON t.sender_account_id = s.id
                    JOIN accounts r ON t.receiver_account_id = r.id
                    ORDER BY t.timestamp DESC
                    LIMIT 50;
                    """
                )
                rows = cur.fetchall()
                
                for row in rows:
                    tx_id = str(row[0])
                    if tx_id not in synced_tx_ids:
                        payload = {
                            "transaction_id": tx_id,
                            "sender_id": str(row[1]),
                            "sender_account": row[2],
                            "receiver_id": str(row[3]),
                            "receiver_account": row[4],
                            "amount": float(row[5]),
                            "status": row[6],
                            "timestamp": row[7].isoformat()
                        }
                        success = sync_transaction_to_neo4j(payload, neo4j_driver)
                        if success:
                            synced_tx_ids.add(tx_id)
                            
        except Exception as e:
            logger.error(f"PostgreSQL sync poll error: {e}")
            
        time.sleep(5)

def main():
    logger.info("Initializing Graph Synchronization Worker...")
    
    # Wait for databases to start up
    time.sleep(5)
    
    try:
        neo4j_driver = get_neo4j_driver()
    except Exception as e:
        logger.error(f"Could not connect to Neo4j. Exiting worker. Error: {e}")
        return

    # Check if confluent_kafka consumer is available
    use_kafka = False
    try:
        from confluent_kafka import Consumer
        use_kafka = True
    except ImportError:
        logger.warning("confluent_kafka is not installed. Defaulting to PostgreSQL polling sync fallback.")

    if use_kafka:
        try:
            run_kafka_consumer(neo4j_driver)
        except Exception as e:
            logger.error(f"Kafka consumer runtime failed: {e}. Falling back to PostgreSQL polling.")
            run_postgres_poll_fallback(neo4j_driver)
    else:
        run_postgres_poll_fallback(neo4j_driver)

if __name__ == "__main__":
    main()
