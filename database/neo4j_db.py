from neo4j import GraphDatabase, AsyncGraphDatabase
import logging
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

logger = logging.getLogger(__name__)

_driver = None
_async_driver = None

def get_neo4j_driver():
    global _driver
    if _driver is None:
        try:
            _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
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
            _async_driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
            logger.info("Async Neo4j driver initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to create Async Neo4j driver: {e}")
            raise e
    return _async_driver

async def close_async_neo4j_driver():
    global _async_driver
    if _async_driver is not None:
        await _async_driver.close()
        _async_driver = None
        logger.info("Async Neo4j driver closed.")

