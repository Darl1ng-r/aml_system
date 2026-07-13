import pg8000
import queue
from contextlib import contextmanager
import logging
from config import POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD

logger = logging.getLogger(__name__)

class SimplePGPool:
    def __init__(self, size=10):
        self.pool = queue.Queue(maxsize=size)
        self.host = POSTGRES_HOST
        self.port = POSTGRES_PORT
        self.database = POSTGRES_DB
        self.user = POSTGRES_USER
        self.password = POSTGRES_PASSWORD
        
        for _ in range(size):
            try:
                conn = self._create_connection()
                self.pool.put(conn)
            except Exception as e:
                logger.error(f"Failed to create database connection during pool initialization: {e}")
                raise e

    def _create_connection(self):
        return pg8000.connect(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password
        )

    def getconn(self):
        # If pool is empty, block or create connection
        try:
            conn = self.pool.get(timeout=2.0)
            # Verify connection is active
            try:
                # pg8000 connection has a run/execute method or we can execute a simple query
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
            except Exception:
                # Connection is dead, create a new one
                logger.warning("Replacing dead connection in pool.")
                conn = self._create_connection()
            return conn
        except queue.Empty:
            logger.warning("Connection pool exhausted, creating ad-hoc connection.")
            return self._create_connection()

    def putconn(self, conn):
        try:
            self.pool.put_nowait(conn)
        except queue.Full:
            conn.close()

    def closeall(self):
        logger.info("Closing all pg8000 connections in pool.")
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
            except Exception:
                pass

# Initialize connection pool
connection_pool = None
try:
    connection_pool = SimplePGPool(size=10)
    logger.info("pg8000 connection pool initialized.")
except Exception as e:
    logger.error(f"Error initializing pg8000 connection pool: {e}")

@contextmanager
def get_db_connection():
    if not connection_pool:
        raise Exception("Database connection pool is not initialized.")
    conn = connection_pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        raise e
    finally:
        connection_pool.putconn(conn)

@contextmanager
def get_db_cursor():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            yield cursor
        finally:
            cursor.close()
