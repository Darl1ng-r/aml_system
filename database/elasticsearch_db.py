from elasticsearch import Elasticsearch, AsyncElasticsearch
import logging
from config import ELASTICSEARCH_HOST, settings

logger = logging.getLogger(__name__)

_es_client = None
_async_es_client = None

def get_elasticsearch_client():
    global _es_client
    if _es_client is None:
        try:
            # Build kwargs — only pass basic_auth if ELASTIC_PASSWORD is configured.
            # This lets developers run without xpack security locally while
            # production always has the password set via the aml-secrets K8s Secret.
            kwargs = {"hosts": [ELASTICSEARCH_HOST], "connections_per_node": 10}
            if settings.elastic_password:
                kwargs["basic_auth"] = (settings.elastic_user, settings.elastic_password)

            _es_client = Elasticsearch(**kwargs)
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
            kwargs = {"hosts": [ELASTICSEARCH_HOST], "connections_per_node": 10}
            if settings.elastic_password:
                kwargs["basic_auth"] = (settings.elastic_user, settings.elastic_password)

            _async_es_client = AsyncElasticsearch(**kwargs)
            if await _async_es_client.ping():
                logger.info("Async Elasticsearch connection established.")
            else:
                logger.warning("Async Elasticsearch ping failed.")
        except Exception as e:
            logger.error(f"Failed to connect to Async Elasticsearch: {e}")
            raise e
    return _async_es_client

