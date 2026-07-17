from elasticsearch import Elasticsearch, AsyncElasticsearch
import logging
from config import ELASTICSEARCH_HOST, settings
from services.tls_manager import get_ssl_context

logger = logging.getLogger(__name__)

_es_client = None
_async_es_client = None

def get_elasticsearch_client():
    global _es_client
    if _es_client is None:
        try:
            ssl_ctx = get_ssl_context()
            kwargs = {"hosts": [ELASTICSEARCH_HOST], "connections_per_node": 10}
            if settings.elastic_password:
                kwargs["basic_auth"] = (settings.elastic_user, settings.elastic_password)
            if ssl_ctx:
                kwargs["ssl_context"] = ssl_ctx

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
            ssl_ctx = get_ssl_context()
            kwargs = {"hosts": [ELASTICSEARCH_HOST], "connections_per_node": 10}
            if settings.elastic_password:
                kwargs["basic_auth"] = (settings.elastic_user, settings.elastic_password)
            if ssl_ctx:
                kwargs["ssl_context"] = ssl_ctx

            _async_es_client = AsyncElasticsearch(**kwargs)
            if await _async_es_client.ping():
                logger.info("Async Elasticsearch connection established.")
            else:
                logger.warning("Async Elasticsearch ping failed.")
        except Exception as e:
            _async_es_client = None
            logger.error(f"Failed to connect to Async Elasticsearch: {e}")
            raise e
    return _async_es_client

