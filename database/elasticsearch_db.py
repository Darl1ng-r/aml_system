from elasticsearch import Elasticsearch
import logging
from config import ELASTICSEARCH_HOST

logger = logging.getLogger(__name__)

_es_client = None

def get_elasticsearch_client():
    global _es_client
    if _es_client is None:
        try:
            _es_client = Elasticsearch(hosts=[ELASTICSEARCH_HOST])
            # Test connection
            if _es_client.ping():
                logger.info("Elasticsearch connection established.")
            else:
                logger.warning("Elasticsearch ping failed.")
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            raise e
    return _es_client
