from neo4j import GraphDatabase, AsyncGraphDatabase
import logging
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from services.tls_manager import get_ssl_context

logger = logging.getLogger(__name__)

_driver = None
_async_driver = None

def get_neo4j_driver():
    global _driver
    if _driver is None:
        try:
            ssl_ctx = get_ssl_context()
            kwargs = {
                "auth": (NEO4J_USER, NEO4J_PASSWORD),
                "connection_timeout": 5.0,
                "max_connection_lifetime": 3600
            }
            if ssl_ctx:
                kwargs["encrypted"] = True
                kwargs["ssl_context"] = ssl_ctx
            _driver = GraphDatabase.driver(NEO4J_URI, **kwargs)
            logger.info("Neo4j driver initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to create Neo4j driver: {e}")
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
            ssl_ctx = get_ssl_context()
            kwargs = {
                "auth": (NEO4J_USER, NEO4J_PASSWORD),
                "connection_timeout": 5.0,
                "max_connection_lifetime": 3600
            }
            if ssl_ctx:
                kwargs["encrypted"] = True
                kwargs["ssl_context"] = ssl_ctx
            _async_driver = AsyncGraphDatabase.driver(NEO4J_URI, **kwargs)
            logger.info("Async Neo4j driver initialized successfully.")
        except Exception as e:
            _async_driver = None
            logger.error(f"Failed to create Async Neo4j driver: {e}")
            raise e
    return _async_driver

async def close_async_neo4j_driver():
    global _async_driver
    if _async_driver is not None:
        await _async_driver.close()
        _async_driver = None
        logger.info("Async Neo4j driver closed.")

