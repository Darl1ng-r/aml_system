from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    postgres_host: str = "localhost"
    postgres_port: int = 5433
    postgres_db: str = "aml_db"
    postgres_user: str = "postgres"
    postgres_password: str = "postgrespassword"
    
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "passwordpassword"
    
    redis_host: str = "localhost"
    redis_port: int = 6379
    
    kafka_bootstrap_servers: str = "localhost:9092"
    transactions_topic: str = "aml.transactions.scored"
    
    elasticsearch_host: str = "http://localhost:9200"
    sanctions_index: str = "sanctions_list"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

# PostgreSQL Config
POSTGRES_HOST = settings.postgres_host
POSTGRES_PORT = settings.postgres_port
POSTGRES_DB = settings.postgres_db
POSTGRES_USER = settings.postgres_user
POSTGRES_PASSWORD = settings.postgres_password
POSTGRES_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

# Neo4j Config
NEO4J_URI = settings.neo4j_uri
NEO4J_USER = settings.neo4j_user
NEO4J_PASSWORD = settings.neo4j_password

# Redis Config
REDIS_HOST = settings.redis_host
REDIS_PORT = settings.redis_port

# Redpanda/Kafka Config
KAFKA_BOOTSTRAP_SERVERS = settings.kafka_bootstrap_servers
TRANSACTIONS_TOPIC = settings.transactions_topic

# Elasticsearch Config
ELASTICSEARCH_HOST = settings.elasticsearch_host
SANCTIONS_INDEX = settings.sanctions_index

