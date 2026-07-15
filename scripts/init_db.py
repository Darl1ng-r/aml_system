import sys
import os
import time
import asyncio
import asyncpg

# Add parent directory to sys.path to import local modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.neo4j_db import get_neo4j_driver
from database.elasticsearch_db import get_elasticsearch_client
from config import SANCTIONS_INDEX, POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD

async def init_postgres():
    print("Initializing PostgreSQL tables...")
    create_tables_sql = """
    -- Clean Reset for Local Dev
    DROP TABLE IF EXISTS alerts CASCADE;
    DROP TABLE IF EXISTS transactions CASCADE;
    DROP TABLE IF EXISTS customer_profiles CASCADE;
    DROP TABLE IF EXISTS accounts CASCADE;
    DROP TABLE IF EXISTS tenants CASCADE;
    DROP TABLE IF EXISTS users CASCADE;

    -- Create Tenants Table
    CREATE TABLE IF NOT EXISTS tenants (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Create Accounts Table
    CREATE TABLE IF NOT EXISTS accounts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
        account_number VARCHAR(50) UNIQUE NOT NULL,
        swift_bic VARCHAR(20),
        owner_name VARCHAR(255) NOT NULL,
        risk_score NUMERIC(5, 2) DEFAULT 0.00,
        status VARCHAR(20) DEFAULT 'ACTIVE',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Create Customer Profiles Table (Phase 2 Baseline Cache)
    CREATE TABLE IF NOT EXISTS customer_profiles (
        account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
        avg_amount NUMERIC(15, 2) DEFAULT 0.00,
        median_amount NUMERIC(15, 2) DEFAULT 0.00,
        variance_amount NUMERIC(15, 2) DEFAULT 0.00,
        daily_frequency NUMERIC(10, 4) DEFAULT 0.00,
        weekly_frequency NUMERIC(10, 4) DEFAULT 0.00,
        monthly_frequency INT DEFAULT 0,
        unique_receivers_count INT DEFAULT 0,
        unique_receiver_countries_count INT DEFAULT 0,
        avg_hour NUMERIC(4, 2) DEFAULT 0.00,
        variance_hour NUMERIC(6, 2) DEFAULT 0.00,
        top_countries TEXT[],
        top_merchants TEXT[],
        top_devices TEXT[],
        top_channels TEXT[],
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Create Transactions Table
    CREATE TABLE IF NOT EXISTS transactions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
        sender_account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
        receiver_account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
        amount NUMERIC(15, 2) NOT NULL,
        currency VARCHAR(3) NOT NULL,
        status VARCHAR(20) DEFAULT 'COMPLETED',
        timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
        country VARCHAR(3),
        merchant VARCHAR(100),
        device VARCHAR(100),
        channel VARCHAR(50)
    );

    -- Create Indexes for transactions
    CREATE INDEX IF NOT EXISTS idx_transactions_sender_timestamp ON transactions(sender_account_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_transactions_receiver_timestamp ON transactions(receiver_account_id, timestamp DESC);

    -- Create Alerts Table
    CREATE TABLE IF NOT EXISTS alerts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
        transaction_id UUID REFERENCES transactions(id) ON DELETE CASCADE,
        rule_name VARCHAR(100) NOT NULL,
        threat_level VARCHAR(20) NOT NULL,
        ai_risk_score NUMERIC(5, 2),
        explainability_payload JSONB,
        status VARCHAR(20) DEFAULT 'NEW',
        assigned_officer_id UUID,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

    -- Create Alerts Index
    CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status) WHERE status IN ('NEW', 'UNDER_INVESTIGATION');

    -- Create Users Table
    CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        role VARCHAR(50) DEFAULT 'ANALYST',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
    """

    conn = await asyncpg.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        database=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD
    )
    try:
        async with conn.transaction():
            await conn.execute(create_tables_sql)
            
            # Seed Default Tenant
            tenant = await conn.fetchrow("SELECT id FROM tenants WHERE name = 'Default Tenant' LIMIT 1;")
            if not tenant:
                tenant_id = await conn.fetchval("INSERT INTO tenants (name) VALUES ('Default Tenant') RETURNING id;")
                print(f"Default tenant created with ID: {tenant_id}")
            else:
                tenant_id = tenant[0]
                print(f"Default tenant found: {tenant_id}")

            # Seed some mock accounts if table is empty
            count = await conn.fetchval("SELECT COUNT(*) FROM accounts;")
            if count == 0:
                accounts_data = [
                    ("DE12003400567890111100", "DBANKDEFXXX", "Alice Schmidt", 0.10),
                    ("US99887766554433221100", "CHASEUS3XXX", "Bob Jones", 0.15),
                    ("GB44332211009988776655", "BARCGB22XXX", "Charlie Smith", 0.65), # higher risk
                    ("RU11223344556677889900", "SBERRU88XXX", "Vladimir Smirnov", 0.90)  # high risk/sanctions-sounding name
                ]
                for acc_num, bic, owner, risk in accounts_data:
                    await conn.execute(
                        "INSERT INTO accounts (tenant_id, account_number, swift_bic, owner_name, risk_score) VALUES ($1, $2, $3, $4, $5);",
                        tenant_id, acc_num, bic, owner, risk
                    )
                print("PostgreSQL seeded with test accounts.")

            # Seed Default Users
            user_count = await conn.fetchval("SELECT COUNT(*) FROM users;")
            if user_count == 0:
                import uuid
                analysts = [
                    ("sarah_jenkins", "ANALYST"),
                    ("alex_rivera", "ANALYST"),
                    ("david_chen", "ANALYST"),
                    ("emma_watson", "ANALYST"),
                ]
                for username, role in analysts:
                    user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{username}.aml.com"))
                    await conn.execute(
                        "INSERT INTO users (id, username, role) VALUES ($1, $2, $3);",
                        user_id, username, role
                    )
                print("PostgreSQL seeded with compliance analyst users.")
    finally:
        await conn.close()
    print("PostgreSQL initialization complete.")

def init_neo4j():
    print("Initializing Neo4j unique constraints...")
    driver = get_neo4j_driver()
    
    constraints = [
        "CREATE CONSTRAINT account_id_unique IF NOT EXISTS FOR (a:Account) REQUIRE a.id IS UNIQUE;",
        "CREATE CONSTRAINT person_tax_id_unique IF NOT EXISTS FOR (p:Person) REQUIRE p.tax_id IS UNIQUE;",
        "CREATE CONSTRAINT company_reg_unique IF NOT EXISTS FOR (c:Company) REQUIRE c.registration_number IS UNIQUE;"
    ]
    
    with driver.session() as session:
        for constraint in constraints:
            try:
                session.run(constraint)
            except Exception as e:
                print(f"Constraint execution warning (can be ignored if already exists): {e}")
    print("Neo4j unique constraints initialized.")

def init_elasticsearch():
    print("Initializing Elasticsearch indexes...")
    es = get_elasticsearch_client()
    
    # Check if index exists
    if es.indices.exists(index=SANCTIONS_INDEX):
        print(f"Elasticsearch index '{SANCTIONS_INDEX}' already exists.")
        return
        
    # Create index with Double Metaphone analyzer
    # Standard Elasticsearch double_metaphone requires the phonetic analysis plugin.
    # To be safe and compatible with standard out-of-the-box Elasticsearch images without plugins,
    # we will declare a custom phonetic filter, but fall back if the plugin is not installed, or
    # we configure standard fuzzy ngram analyzer which does excellent spelling tolerance.
    # Let's configure it with standard analyzers + phonetic filters.
    settings = {
        "settings": {
            "analysis": {
                "filter": {
                    "phonetic_filter": {
                        "type": "phonetic",
                        "encoder": "doublemetaphone",
                        "replace": False
                    }
                },
                "analyzer": {
                    "phonetic_analyzer": {
                        "tokenizer": "standard",
                        "filter": [
                            "lowercase",
                            "phonetic_filter"
                        ]
                    }
                }
            }
        },
        "mappings": {
            "properties": {
                "name": {
                    "type": "text",
                    "fields": {
                        "phonetic": {
                            "type": "text",
                            "analyzer": "phonetic_analyzer"
                        },
                        "keyword": {
                            "type": "keyword"
                        }
                    }
                },
                "source_list": {
                    "type": "keyword"
                },
                "date_of_birth": {
                    "type": "date",
                    "format": "yyyy-MM-dd"
                }
            }
        }
    }

    try:
        es.indices.create(index=SANCTIONS_INDEX, body=settings)
        print(f"Elasticsearch index '{SANCTIONS_INDEX}' created successfully with phonetic configuration.")
    except Exception as e:
        print(f"Phonetic plugin might be missing; creating fallback fuzzy index... ({e})")
        # Fallback without phonetic analysis plugin (using standard text search + fuzzy queries)
        fallback_settings = {
            "mappings": {
                "properties": {
                    "name": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword"
                            }
                        }
                    },
                    "source_list": {
                        "type": "keyword"
                    },
                    "date_of_birth": {
                        "type": "date",
                        "format": "yyyy-MM-dd"
                    }
                }
            }
        }
        es.indices.create(index=SANCTIONS_INDEX, body=fallback_settings)
        print(f"Fallback Elasticsearch index '{SANCTIONS_INDEX}' created successfully.")

    # Seed PEP/Sanction dataset
    mock_sanctions = [
        {"name": "Wladimir Smirnow", "source_list": "OFAC Specially Designated Nationals (SDN)", "date_of_birth": "1974-05-12"},
        {"name": "Ivan Petrov", "source_list": "EU Consolidated Sanctions List", "date_of_birth": "1980-09-20"},
        {"name": "John Doe", "source_list": "UK Sanctions List", "date_of_birth": "1965-01-01"}
    ]
    
    for i, entry in enumerate(mock_sanctions):
        es.index(index=SANCTIONS_INDEX, id=str(i+1), document=entry)
    es.indices.refresh(index=SANCTIONS_INDEX)
    print("Elasticsearch seeded with sample sanction entries.")

async def async_main():
    print("Starting database initialization...")
    # Wait for databases to be up (if docker compose is starting them)
    await asyncio.sleep(3)
    
    try:
        await init_postgres()
    except Exception as e:
        print(f"Error initializing PostgreSQL: {e}")
        
    try:
        init_neo4j()
    except Exception as e:
        print(f"Error initializing Neo4j: {e}")
        
    try:
        init_elasticsearch()
    except Exception as e:
        print(f"Error initializing Elasticsearch: {e}")
        
    print("Database initialization finished.")

if __name__ == "__main__":
    asyncio.run(async_main())
