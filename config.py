from urllib.parse import quote_plus
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
    postgres_pool_min_size: int = 2
    postgres_pool_max_size: int = 15
    postgres_replica_pool_max_size: int = 4
    postgres_acquire_timeout_seconds: float = 5.0
    replica_max_lag_seconds: float = 2.0
    read_after_write_window_seconds: int = 5
    run_migrations_on_startup: bool = False
    
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    
    # State Redis (noeviction: locks, idempotency, token revocations, rate limits)
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""

    # Dedicated Cache Redis (allkeys-lfu: volatile read caches; empty host falls back to redis_host DB 1 in single-node dev)
    redis_cache_host: str = ""
    redis_cache_port: int = 6380
    redis_cache_password: str = ""
    redis_cache_db: int = 1
    redis_cache_socket_timeout_seconds: float = 0.20
    redis_cache_connect_timeout_seconds: float = 0.15
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
    jwt_issuer: str = "aml-sentinel"
    jwt_audience: str = "aml-sentinel-api"
    # Canonical public base URL for OIDC SSO redirect_uri construction (prevents Host header poisoning)
    public_base_url: str = ""
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

    # Embedded background worker toggle (overridden to False in K8s/Compose multi-pod configs)
    run_embedded_worker: bool = True

    # Cloudflare Turnstile bot mitigation secret key (required in hardened envs when Turnstile enabled)
    turnstile_secret_key: str = ""

    # Central outbound egress kill-switch for non-production isolation
    outbound_egress_enabled: bool = True

    # Explicit Host header allowlist for TrustedHostMiddleware in hardened environments
    allowed_hosts: str = ""

    # Kafka / Redpanda SASL credentials (for SASL_SSL in production)
    kafka_sasl_username: str = ""
    kafka_sasl_password: str = ""
    kafka_sasl_mechanism: str = "SCRAM-SHA-512"

    # P0-1: Multi-Currency FX Normalization
    base_currency: str = "USD"
    fx_rates_url: str = "https://api.frankfurter.dev/v1/latest"

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
    fincen_sandbox_mode: bool = True
    fincen_sftp_host: str = ""
    fincen_sftp_port: int = 22
    fincen_sftp_username: str = ""
    fincen_sftp_remote_dir: str = "/incoming/bsa"
    fincen_known_hosts_path: str = "/etc/aml/fincen_known_hosts"

    # Comma-separated list of allowed frontend origins.
    # ⚠️  Do NOT include the API server itself (localhost:8000).
    # Override via ALLOWED_ORIGINS in .env for production.
    # Example: ALLOWED_ORIGINS=https://aml.example.com
    allowed_origins: str = "http://localhost:3000"

    # OpenTelemetry / Distributed Tracing
    otel_service_name: str = "aml-platform"
    otel_exporter_endpoint: str = "http://localhost:4317"
    otel_trace_sample_rate: float = 0.1

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

    @staticmethod
    def _is_placeholder_secret(value: str) -> bool:
        v = (value or "").strip()
        if not v:
            return False
        upper = v.upper()
        return (
            upper.startswith("REPLACE_WITH_")
            or upper.startswith("CHANGE_ME_")
            or v.lower().startswith("your_")
            or v == "1x0000000000000000000000000000000AA"
        )

    def _check_insecure_passwords(self) -> None:
        insecure_defaults = {
            "postgrespassword",
            "passwordpassword",
            "redispassword",
            "changeme_in_production",
            "change_me_in_production_jwt_secret_key_256bit",
            "aml_app_secure_pass_2026",
            "1x0000000000000000000000000000000AA",
        }
        passwords = [
            ("postgres_password", self.postgres_password),
            ("neo4j_password", self.neo4j_password),
            ("elastic_password", self.elastic_password),
            ("aml_app_password", self.aml_app_password),
            ("redis_password", self.redis_password),
            ("turnstile_secret_key", self.turnstile_secret_key),
        ]
        for name, pw in passwords:
            if pw in insecure_defaults or self._is_placeholder_secret(pw):
                raise ValueError(f"CRITICAL: Default {name} is forbidden in production environment!")

        if not self.postgres_password.strip() and not self.aml_app_password.strip():
            raise ValueError(
                "CRITICAL: Either POSTGRES_PASSWORD or AML_APP_PASSWORD must be non-empty in hardened environments!"
            )

        if self.internal_gateway_secret in {"aml-internal-gateway-secret-dev-only", ""} or self._is_placeholder_secret(
            self.internal_gateway_secret
        ):
            raise ValueError("CRITICAL: Default internal_gateway_secret is forbidden in production environment!")

        if self.vault_dev_token.strip():
            raise ValueError("CRITICAL: VAULT_DEV_TOKEN is strictly forbidden in hardened environments!")

    @property
    def is_production(self) -> bool:
        """Canonical production check recognizing both 'production' and 'prod' (HARD-03)."""
        return str(self.environment).strip().lower() in {"production", "prod"}

    @property
    def is_hardened(self) -> bool:
        """True for production, prod, AND staging so staging enforces identical security parity (P1-01)."""
        return str(self.environment).strip().lower() in {"production", "prod", "staging"}

    def _check_production_origins_and_metrics(self) -> None:
        # PRR Enforcement: In hardened envs, metrics_secret must be set, high-entropy, and non-placeholder
        if (
            not self.metrics_secret
            or len(self.metrics_secret.strip()) < 16
            or self._is_placeholder_secret(self.metrics_secret)
        ):
            raise ValueError("CRITICAL: METRICS_SECRET must be configured with >= 16 characters in production environment!")

        # PRR Enforcement: In hardened envs, allowed_origins must be explicit HTTPS domains (no wildcard, localhost, or plain HTTP)
        origins = [o.strip().lower() for o in self.allowed_origins.split(",") if o.strip()]
        if not origins:
            raise ValueError("CRITICAL: ALLOWED_ORIGINS must define at least one explicit HTTPS origin in production!")
        for origin in origins:
            if (
                origin == "*"
                or "localhost" in origin
                or "127.0.0.1" in origin
                or not origin.startswith("https://")
            ):
                raise ValueError(
                    f"CRITICAL: Insecure ALLOWED_ORIGINS entry '{origin}' is forbidden in production! Must be explicit HTTPS domain."
                )

    @model_validator(mode="after")
    def validate_production_settings(self):
        if not self.is_hardened:
            return self

        self._check_insecure_passwords()
        self._check_production_origins_and_metrics()

        # Fail-Closed: Production & staging must NEVER run in offline development mode or allow public signup
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
_PG_USER_ENC = quote_plus(POSTGRES_USER)
_PG_PASS_ENC = quote_plus(POSTGRES_PASSWORD)
_PG_SSL_SUFFIX = "?sslmode=require" if settings.enable_tls else ""
POSTGRES_URL = f"postgresql://{_PG_USER_ENC}:{_PG_PASS_ENC}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}{_PG_SSL_SUFFIX}"
POSTGRES_REPLICA_URL = f"postgresql://{_PG_USER_ENC}:{_PG_PASS_ENC}@{POSTGRES_REPLICA_HOST}:{POSTGRES_REPLICA_PORT}/{POSTGRES_DB}{_PG_SSL_SUFFIX}"

# Neo4j Config
NEO4J_URI = settings.neo4j_uri
NEO4J_USER = settings.neo4j_user
NEO4J_PASSWORD = settings.neo4j_password

# Redis Config (State vs. Dedicated Cache)
REDIS_HOST = settings.redis_host
REDIS_PORT = settings.redis_port
REDIS_PASSWORD = settings.redis_password
REDIS_CACHE_HOST = settings.redis_cache_host
REDIS_CACHE_PORT = settings.redis_cache_port
REDIS_CACHE_PASSWORD = settings.redis_cache_password
REDIS_CACHE_DB = settings.redis_cache_db

# Redpanda/Kafka Config
KAFKA_BOOTSTRAP_SERVERS = settings.kafka_bootstrap_servers
TRANSACTIONS_TOPIC = settings.transactions_topic

# Elasticsearch Config
ELASTICSEARCH_HOST = settings.elasticsearch_host
SANCTIONS_INDEX = settings.sanctions_index
PEP_INDEX = settings.pep_index

