from neo4j import GraphDatabase, AsyncGraphDatabase
import logging
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from services.tls_manager import get_ssl_context

logger = logging.getLogger(__name__)

_driver = None
_async_driver = None


def _resolve_neo4j_config() -> tuple[str, str, str]:
    try:
        from services.vault_loader import SecretStore
        uri = SecretStore.get("neo4j.uri") or NEO4J_URI
        user = SecretStore.get("neo4j.user") or NEO4J_USER
        pw = SecretStore.get("neo4j.password") or NEO4J_PASSWORD
        return uri, user, pw
    except Exception:
        return NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD


def _build_neo4j_kwargs(user: str, password: str) -> dict:
    ssl_ctx = get_ssl_context()
    kwargs = {
        "auth": (user, password),
        "connection_timeout": 5.0,
        "connection_acquisition_timeout": 10.0,
        "max_transaction_retry_time": 15.0,
        "max_connection_pool_size": 25,
        "max_connection_lifetime": 3600,
    }
    if ssl_ctx:
        kwargs["encrypted"] = True
        kwargs["ssl_context"] = ssl_ctx
    return kwargs


def get_neo4j_driver():
    global _driver
    if _driver is None:
        try:
            uri, user, pw = _resolve_neo4j_config()
            _driver = GraphDatabase.driver(uri, **_build_neo4j_kwargs(user, pw))
            logger.info("Neo4j driver initialized successfully.")
        except Exception as e:
            _driver = None
            logger.error("Failed to create Neo4j driver: %s", e)
            raise e
    return _driver


def close_neo4j_driver():
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
        logger.info("Neo4j driver closed.")


async def get_async_neo4j_driver():
    global _async_driver
    if _async_driver is None:
        try:
            uri, user, pw = _resolve_neo4j_config()
            _async_driver = AsyncGraphDatabase.driver(uri, **_build_neo4j_kwargs(user, pw))
            logger.info("Async Neo4j driver initialized successfully.")
        except Exception as e:
            _async_driver = None
            logger.error("Failed to create Async Neo4j driver: %s", e)
            raise e
    return _async_driver


async def close_async_neo4j_driver():
    global _async_driver
    if _async_driver is not None:
        await _async_driver.close()
        _async_driver = None
        logger.info("Async Neo4j driver closed.")
