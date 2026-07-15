from elasticsearch import Elasticsearch, AsyncElasticsearch
import logging
from config import ELASTICSEARCH_HOST

logger = logging.getLogger(__name__)

_es_client = None
_async_es_client = None

def get_elasticsearch_client():
    global _es_client
    if _es_client is None:
        try:
            # Set connections_per_node=10 to explicitly configure persistent HTTP keep-alive connection pooling
            _es_client = Elasticsearch(
                hosts=[ELASTICSEARCH_HOST],
                connections_per_node=10
            )
            # Test connection
            if _es_client.ping():
                logger.info("Elasticsearch connection established.")
            else:
                logger.warning("Elasticsearch ping failed.")
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            raise e
    return _es_client

async def get_async_elasticsearch_client():
    global _async_es_client
    if _async_es_client is None:
        try:
            # Set connections_per_node=10 to explicitly configure persistent HTTP keep-alive connection pooling
            _async_es_client = AsyncElasticsearch(
                hosts=[ELASTICSEARCH_HOST],
                connections_per_node=10
            )
            # Test connection
            if await _async_es_client.ping():
                logger.info("Async Elasticsearch connection established.")
            else:
                logger.warning("Async Elasticsearch ping failed.")
        except Exception as e:
            logger.error(f"Failed to connect to Async Elasticsearch: {e}")
            raise e
    return _async_es_client

