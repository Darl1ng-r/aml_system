from dotenv import load_dotenv
load_dotenv()

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict  #fix

class Settings(BaseSettings):
    environment: str = "development"
    allow_offline_dev: bool = True
    postgres_host: str = "localhost"
    postgres_port: int = 5433
    postgres_replica_host: str = "localhost"
    postgres_replica_port: int = 5434
    postgres_db: str = "aml_db"
    postgres_user: str = "aml_app"
    postgres_password: str = ""
    aml_app_password: str = ""
    run_migrations_on_startup: bool = False
    
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    metrics_secret: str = ""
    
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
    jwt_algorithm: str = "RS256"
    # Short-lived access token — 15 minutes.
    # Clients should use the refresh token to silently renew.
    access_token_expire_minutes: int = 15
    # Long-lived refresh token — 7 days.
    refresh_token_expire_days: int = 7

    supabase_url: str = ""
    supabase_key: str = ""

    # Public self-registration switch (forced False in production)
    allow_public_signup: bool = True

    # Datastore Consolidation Feature Flags (PostgreSQL pg_trgm + CTEs are primary)
    enable_neo4j: bool = False
    enable_elasticsearch: bool = False

    # Embedded background worker toggle (set False in multi-pod K8s where dedicated worker runs)
    run_embedded_worker: bool = True

    # P0-1: Multi-Currency FX Normalization
    base_currency: str = "USD"
    fx_rates_url: str = "https://api.frankfurter.app/latest"

    # P0-3: Pluggable Evidence Storage (local | s3) & ClamAV Scanning
    evidence_storage_backend: str = "local"
    evidence_s3_bucket: str = ""
    evidence_s3_endpoint: str = ""
    evidence_s3_region: str = "us-east-1"
    evidence_s3_access_key: str = ""
    evidence_s3_secret_key: str = ""
    evidence_kms_key_id: str = ""
    evidence_worm_enabled: bool = False
    clamav_enabled: bool = False
    clamav_host: str = "localhost"
    clamav_port: int = 3310

    # P0-4: FinCEN / FIU Transport (sandbox | sftp | rest)
    fincen_transport: str = "sandbox"
    fincen_sftp_host: str = ""
    fincen_sftp_port: int = 22
    fincen_sftp_username: str = ""
    fincen_sftp_remote_dir: str = "/incoming/bsa"

    # Comma-separated list of allowed frontend origins.
    # ⚠️  Do NOT include the API server itself (localhost:8000).
    # Override via ALLOWED_ORIGINS in .env for production.
    # Example: ALLOWED_ORIGINS=https://aml.yourdomain.com
    allowed_origins: str = "http://localhost:3000"

    # OpenTelemetry / Distributed Tracing
    otel_service_name: str = "aml-platform"
    otel_exporter_endpoint: str = "http://localhost:4317"

    # Sentry APM & Real-Time Error Tracking
    sentry_dsn: str | None = None
    sentry_traces_sample_rate: float = 0.1

    # Mutual TLS (mTLS) & In-Transit Encryption Settings
    enable_tls: bool = False
    strict_mtls: bool = False
    tls_ca_cert: str | None = None
    tls_client_cert: str | None = None
    tls_client_key: str | None = None

    # Internal API Gateway verification secret
    internal_gateway_secret: str = "aml-internal-gateway-secret-dev-only"

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

    # P2-2: Optional External LLM Co-Pilot (receives PII-tokenized payloads only)
    llm_copilot_api_url: str = ""
    llm_copilot_api_key: str = ""
    llm_copilot_model: str = "gpt-4o-mini"

    # P2-5: Live Adverse Media OSINT Connector (GDELT 2.0 default, free/no-key)
    adverse_media_api_url: str = "https://api.gdeltproject.org/api/v2/doc/doc"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def _check_insecure_passwords(self) -> None:
        insecure_defaults = {
            "postgrespassword",
            "passwordpassword",
            "changeme_in_production",
            "change_me_in_production_jwt_secret_key_256bit",
            "aml_app_secure_pass_2026",
        }
        passwords = [
            ("postgres_password", self.postgres_password),
            ("neo4j_password", self.neo4j_password),
            ("elastic_password", self.elastic_password),
            ("aml_app_password", self.aml_app_password),
        ]
        for name, pw in passwords:
            if pw in insecure_defaults:
                raise ValueError(f"CRITICAL: Default {name} is forbidden in production environment!")

        if self.internal_gateway_secret in {"aml-internal-gateway-secret-dev-only", ""}:
            raise ValueError("CRITICAL: Default internal_gateway_secret is forbidden in production environment!")

    def _check_production_origins_and_metrics(self) -> None:
        # PRR Enforcement: In production, metrics_secret must be set and high-entropy
        if not self.metrics_secret or len(self.metrics_secret.strip()) < 16:
            raise ValueError("CRITICAL: METRICS_SECRET must be configured with >= 16 characters in production environment!")

        # PRR Enforcement: In production, allowed_origins cannot contain localhost or wildcard
        origins = [o.strip().lower() for o in self.allowed_origins.split(",") if o.strip()]
        for origin in origins:
            if origin == "*" or "localhost" in origin or "127.0.0.1" in origin:
                raise ValueError(f"CRITICAL: Insecure ALLOWED_ORIGINS entry '{origin}' is forbidden in production! Must be explicit HTTPS domain.")

    @model_validator(mode="after")
    def validate_production_settings(self):
        if str(self.environment).lower() != "production":
            return self

        self._check_insecure_passwords()
        self._check_production_origins_and_metrics()

        # Fail-Closed: Production must NEVER run in offline development mode or allow public signup
        self.allow_offline_dev = False
        self.allow_public_signup = False
        return self

settings = Settings()

RUN_MIGRATIONS_ON_STARTUP = settings.run_migrations_on_startup

# PostgreSQL Config
POSTGRES_HOST = settings.postgres_host
POSTGRES_PORT = settings.postgres_port
POSTGRES_REPLICA_HOST = settings.postgres_replica_host
POSTGRES_REPLICA_PORT = settings.postgres_replica_port
POSTGRES_DB = settings.postgres_db
POSTGRES_USER = settings.postgres_user
POSTGRES_PASSWORD = (
    settings.aml_app_password
    if settings.postgres_user == "aml_app" and settings.aml_app_password
    else settings.postgres_password
)
POSTGRES_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
POSTGRES_REPLICA_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_REPLICA_HOST}:{POSTGRES_REPLICA_PORT}/{POSTGRES_DB}"

# Neo4j Config
NEO4J_URI = settings.neo4j_uri
NEO4J_USER = settings.neo4j_user
NEO4J_PASSWORD = settings.neo4j_password

# Redis Config
REDIS_HOST = settings.redis_host
REDIS_PORT = settings.redis_port
REDIS_PASSWORD = settings.redis_password

# Redpanda/Kafka Config
KAFKA_BOOTSTRAP_SERVERS = settings.kafka_bootstrap_servers
TRANSACTIONS_TOPIC = settings.transactions_topic

# Elasticsearch Config
ELASTICSEARCH_HOST = settings.elasticsearch_host
SANCTIONS_INDEX = settings.sanctions_index
PEP_INDEX = settings.pep_index

