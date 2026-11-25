from elasticsearch import Elasticsearch, AsyncElasticsearch
import logging
from config import ELASTICSEARCH_HOST, settings
from services.tls_manager import get_ssl_context

logger = logging.getLogger(__name__)

_es_client = None
_async_es_client = None


def _resolve_es_credentials() -> tuple[str, str]:
    try:
        from services.vault_loader import SecretStore
        user = SecretStore.get("elasticsearch.user") or settings.elastic_user
        pw = SecretStore.get("elasticsearch.password") or settings.elastic_password
        return user, pw
    except Exception:
        return settings.elastic_user, settings.elastic_password


def get_elasticsearch_client():
    global _es_client
    if _es_client is None:
        try:
            ssl_ctx = get_ssl_context()
            user, pw = _resolve_es_credentials()
            kwargs = {"hosts": [ELASTICSEARCH_HOST], "connections_per_node": 10, "request_timeout": 10.0}
            if pw:
                kwargs["basic_auth"] = (user, pw)
            if ssl_ctx:
                kwargs["ssl_context"] = ssl_ctx

            _es_client = Elasticsearch(**kwargs)
            if _es_client.ping():
                logger.info("Elasticsearch connection established.")
            else:
                logger.warning("Elasticsearch ping failed.")
        except Exception as e:
            _es_client = None
            logger.error("Failed to connect to Elasticsearch: %s", e)
            raise e
    return _es_client


async def get_async_elasticsearch_client():
    global _async_es_client
    if _async_es_client is None:
        try:
            ssl_ctx = get_ssl_context()
            user, pw = _resolve_es_credentials()
            kwargs = {"hosts": [ELASTICSEARCH_HOST], "connections_per_node": 10, "request_timeout": 10.0}
            if pw:
                kwargs["basic_auth"] = (user, pw)
            if ssl_ctx:
                kwargs["ssl_context"] = ssl_ctx

            _async_es_client = AsyncElasticsearch(**kwargs)
            if await _async_es_client.ping():
                logger.info("Async Elasticsearch connection established.")
            else:
                logger.warning("Async Elasticsearch ping failed.")
        except Exception as e:
            _async_es_client = None
            logger.error("Failed to connect to Async Elasticsearch: %s", e)
            raise e
    return _async_es_client


async def close_elasticsearch_clients():
    """Cleanly closes initialized sync and async Elasticsearch clients without reconnecting."""
    global _es_client, _async_es_client
    if _async_es_client is not None:
        try:
            await _async_es_client.close()
        except Exception:
            pass
        _async_es_client = None
    if _es_client is not None:
        try:
            _es_client.close()
        except Exception:
            pass
        _es_client = None
