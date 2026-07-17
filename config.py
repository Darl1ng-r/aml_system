from pydantic_settings import BaseSettings, SettingsConfigDict  #fix

class Settings(BaseSettings):
    postgres_host: str = "localhost"
    postgres_port: int = 5433
    postgres_replica_host: str = "localhost"
    postgres_replica_port: int = 5434
    postgres_db: str = "aml_db"
    postgres_user: str = "postgres"
    postgres_password: str = ""
    
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    
    redis_host: str = "localhost"
    redis_port: int = 6379
    
    kafka_bootstrap_servers: str = "localhost:9092"
    transactions_topic: str = "aml.transactions.scored"
    
    elasticsearch_host: str = "http://localhost:9200"
    sanctions_index: str = "sanctions_list"
    pep_index: str = "pep_list"
    # Set ELASTIC_USER / ELASTIC_PASSWORD in .env when xpack.security is enabled.
    # Leave empty for local dev running without security.
    elastic_user: str = "elastic"
    elastic_password: str = ""

    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    # Short-lived access token — 30 minutes.
    # Clients should use the refresh token to silently renew.
    access_token_expire_minutes: int = 30
    # Long-lived refresh token — 7 days.
    refresh_token_expire_days: int = 7

    supabase_url: str = "https://xzhsdffpnrlpcitiectz.supabase.co"
    supabase_key: str = ""

    # Comma-separated list of allowed frontend origins.
    # ⚠️  Do NOT include the API server itself (localhost:8000).
    # Override via ALLOWED_ORIGINS in .env for production.
    # Example: ALLOWED_ORIGINS=https://aml.yourdomain.com
    allowed_origins: str = "http://localhost:3000"

    # OpenTelemetry / Distributed Tracing
    otel_service_name: str = "aml-platform"
    otel_exporter_endpoint: str = "http://localhost:4317"

    # Mutual TLS (mTLS) & In-Transit Encryption Settings
    enable_tls: bool = False
    strict_mtls: bool = False
    tls_ca_cert: str | None = None
    tls_client_cert: str | None = None
    tls_client_key: str | None = None

    # ── HashiCorp Vault — secrets management ──────────────────────────────────
    # Non-sensitive connection config (addresses / IDs used to *retrieve* secrets).
    # Actual credentials (passwords, keys) are never stored in settings.
    #
    # vault_addr:      Full Vault server URL, e.g. http://vault:8200
    #                  Leave empty for local dev — falls back to env vars.
    # vault_role_id:   AppRole role_id for authentication.
    # vault_secret_id: AppRole secret_id for authentication.
    # vault_dev_token: Static dev root token (local vault -dev only; never prod).
    # vault_mount:     KV-v2 mount path (default: "secret").
    vault_addr: str = ""
    vault_role_id: str = ""
    vault_secret_id: str = ""
    vault_dev_token: str = ""
    vault_mount: str = "secret"
    vault_lease_renewal_seconds: int = 3600

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

# PostgreSQL Config
POSTGRES_HOST = settings.postgres_host
POSTGRES_PORT = settings.postgres_port
POSTGRES_REPLICA_HOST = settings.postgres_replica_host
POSTGRES_REPLICA_PORT = settings.postgres_replica_port
POSTGRES_DB = settings.postgres_db
POSTGRES_USER = settings.postgres_user
POSTGRES_PASSWORD = settings.postgres_password
POSTGRES_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
POSTGRES_REPLICA_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_REPLICA_HOST}:{POSTGRES_REPLICA_PORT}/{POSTGRES_DB}"

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
PEP_INDEX = settings.pep_index

