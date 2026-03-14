"""
Recon Sentinel — Tech Context Intelligence
Shared module providing tech-aware context to all agents.

Two sources:
  1. Dynamic: tech detected by earlier agents in this scan (from DB)
  2. Static: common tech stacks and their associated leak/vuln patterns

Agents import get_scan_tech_context() to get adaptive patterns.
"""

import logging
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.models import Finding

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# DEFAULT TECH STACKS — common in modern organizations
# ═══════════════════════════════════════════════════════════════════════

# These represent what most orgs use in 2024-2026.
# Even if we can't detect specific tech, these patterns are worth checking
# because the probability of finding them is high across the industry.

DEFAULT_TECH_STACK = {
    # --- AI / LLM (assume every org experiments with these now) ---
    "ai_llm": {
        "keywords": ["openai", "anthropic", "claude", "chatgpt", "langchain", "llama", "huggingface", "cohere", "gemini"],
        "env_vars": ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "HUGGINGFACE_TOKEN", "COHERE_API_KEY", "GOOGLE_AI_KEY", "AZURE_OPENAI_KEY", "LANGCHAIN_API_KEY", "REPLICATE_API_TOKEN"],
        "github_dorks": [
            ('"{domain}" OPENAI_API_KEY', "openai_key", "CRITICAL"),
            ('"{domain}" ANTHROPIC_API_KEY', "anthropic_key", "CRITICAL"),
            ('"{domain}" sk-ant-', "anthropic_secret", "CRITICAL"),
            ('"{domain}" sk-proj-', "openai_project_key", "CRITICAL"),
            ('"{domain}" HUGGINGFACE_TOKEN', "hf_token", "HIGH"),
            ('"{domain}" LANGCHAIN_API_KEY', "langchain_key", "HIGH"),
            ('"{domain}" REPLICATE_API_TOKEN', "replicate_key", "HIGH"),
        ],
        "js_patterns": {
            "openai_key": r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
            "anthropic_key": r"sk-ant-[a-zA-Z0-9\-_]{40,}",
        },
        "sensitive_paths": [".env", "config/ai.yml", "config/llm.json", ".langchain", "prompts/"],
    },

    # --- Cloud Providers ---
    "aws": {
        "keywords": ["aws", "amazon", "s3", "ec2", "lambda", "cloudfront", "dynamodb", "sqs", "sns", "ecs", "ecr", "cognito", "amplify", "ses", "iam", "eks", "fargate", "elasticache", "secretsmanager"],
        "env_vars": [
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AWS_DEFAULT_REGION", "AWS_ACCOUNT_ID", "AWS_ROLE_ARN",
            # SES
            "AWS_SES_ACCESS_KEY", "AWS_SES_SECRET_KEY", "SES_SMTP_PASSWORD",
            # Cognito
            "COGNITO_USER_POOL_ID", "COGNITO_CLIENT_ID", "COGNITO_CLIENT_SECRET",
            # Amplify / AppSync
            "AWS_APPSYNC_API_KEY", "AMPLIFY_APP_ID",
            # ECR / ECS / EKS
            "ECR_REGISTRY", "ECS_CLUSTER",
            # Secrets Manager / SSM
            "AWS_SM_SECRET_ARN",
        ],
        "github_dorks": [
            ('"{domain}" AWS_SECRET_ACCESS_KEY', "aws_secret", "CRITICAL"),
            ('"{domain}" AKIA', "aws_access_key", "CRITICAL"),
            ('"{domain}" ASIA', "aws_temp_key", "CRITICAL"),      # Temp STS creds
            ('"{domain}" s3.amazonaws.com', "s3_bucket", "HIGH"),
            ('"{domain}" .s3.amazonaws.com filetype:json OR filetype:yml', "s3_config", "HIGH"),
            ('"{domain}" rds.amazonaws.com', "rds_endpoint", "HIGH"),
            ('"{domain}" execute-api', "api_gateway", "MEDIUM"),   # API Gateway URLs
            ('"{domain}" lambda.amazonaws.com', "lambda_url", "MEDIUM"),
            ('"{domain}" cognito-idp', "cognito_pool", "HIGH"),
            ('"{domain}" COGNITO_CLIENT_SECRET', "cognito_secret", "CRITICAL"),
            ('"{domain}" SES_SMTP_PASSWORD', "ses_password", "CRITICAL"),
            ('"{domain}" secretsmanager', "secrets_mgr_ref", "HIGH"),
            ('"{domain}" elasticache', "elasticache_ref", "MEDIUM"),
            ('"{domain}" filename:.env AWS_', "aws_env_file", "CRITICAL"),
            ('"{domain}" filename:credentials aws_access_key_id', "aws_creds_file", "CRITICAL"),
        ],
        "js_patterns": {
            "aws_access_key": r"(?:AKIA|ASIA)[A-Z0-9]{16}",
            "aws_secret": r"(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
            "aws_account_id": r"(?:account.?id|aws.?account)\s*[:=]\s*['\"](\d{12})['\"]",
            "cognito_pool": r"(?:us|eu|ap)-\w+-\d+_[A-Za-z0-9]+",
            "s3_bucket_url": r"https?://[a-z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com",
            "api_gateway_url": r"https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com",
        },
        "sensitive_paths": [
            ".aws/credentials", ".aws/config", "aws-exports.js", "amplify/",
            "aws-exports.json", "cdk.json", "cdk.out/", "samconfig.toml",
            ".elasticbeanstalk/config.yml", "buildspec.yml",
        ],
    },

    "gcp": {
        "keywords": ["gcp", "google cloud", "gke", "firebase", "firestore", "bigquery", "cloud run", "cloud functions", "pub/sub", "vertex", "cloud sql", "cloud storage"],
        "env_vars": [
            "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT", "FIREBASE_TOKEN",
            "GCLOUD_PROJECT", "GCP_PROJECT_ID", "GOOGLE_API_KEY",
            # Firebase
            "FIREBASE_API_KEY", "FIREBASE_AUTH_DOMAIN", "FIREBASE_MESSAGING_SENDER_ID",
            "FIREBASE_PRIVATE_KEY", "FIREBASE_PROJECT_ID",
            # Vertex AI / Cloud AI
            "VERTEX_AI_KEY",
            # Cloud SQL
            "CLOUD_SQL_CONNECTION_NAME", "DB_SOCKET_PATH",
            # GCS
            "GCS_BUCKET_NAME", "GOOGLE_STORAGE_BUCKET",
        ],
        "github_dorks": [
            ('"{domain}" GOOGLE_APPLICATION_CREDENTIALS', "gcp_creds", "CRITICAL"),
            ('"{domain}" AIzaSy', "google_api_key", "HIGH"),
            ('"{domain}" firebaseio.com', "firebase_url", "MEDIUM"),
            ('"{domain}" type "service_account"', "gcp_service_account", "CRITICAL"),
            ('"{domain}" "private_key" "client_email"', "gcp_json_key", "CRITICAL"),
            ('"{domain}" storage.googleapis.com', "gcs_bucket", "HIGH"),
            ('"{domain}" FIREBASE_PRIVATE_KEY', "firebase_private_key", "CRITICAL"),
            ('"{domain}" FIREBASE_API_KEY', "firebase_api_key", "HIGH"),
            ('"{domain}" cloudsql', "cloud_sql_ref", "MEDIUM"),
            ('"{domain}" filename:service-account.json', "gcp_sa_file", "CRITICAL"),
        ],
        "js_patterns": {
            "google_api": r"AIza[0-9A-Za-z\-_]{35}",
            "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
            "firebase_config": r"(?:apiKey|messagingSenderId|appId)\s*:\s*['\"]([A-Za-z0-9\-_:]+)['\"]",
            "gcs_url": r"https://storage\.googleapis\.com/[a-z0-9._-]+",
            "gcp_project": r"(?:project.?id|projectId)\s*[:=]\s*['\"]([a-z][a-z0-9-]{4,28}[a-z0-9])['\"]",
        },
        "sensitive_paths": [
            "firebase.json", ".firebaserc", "google-services.json",
            "service-account.json", "gcp-key.json", "firestore.rules",
            "storage.rules", "remoteconfig.template.json", "app.yaml",
            ".gcloudignore",
        ],
    },

    "azure": {
        "keywords": ["azure", "microsoft cloud", "cosmos", "azure devops", "azure functions", "blob storage", "azure ad", "entra", "key vault", "app service", "aks"],
        "env_vars": [
            "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
            "AZURE_STORAGE_CONNECTION_STRING", "AZURE_OPENAI_KEY",
            "AZURE_OPENAI_ENDPOINT",
            # Cosmos DB
            "COSMOS_DB_KEY", "COSMOS_DB_CONNECTION_STRING",
            # Service Bus / Event Hub
            "AZURE_SERVICEBUS_CONNECTION_STRING", "AZURE_EVENTHUB_CONNECTION_STRING",
            # Key Vault
            "AZURE_KEY_VAULT_URI",
            # App insights
            "APPLICATIONINSIGHTS_CONNECTION_STRING", "APPINSIGHTS_INSTRUMENTATIONKEY",
            # Container Registry
            "AZURE_ACR_PASSWORD",
            # DevOps
            "AZURE_DEVOPS_PAT", "SYSTEM_ACCESSTOKEN",
        ],
        "github_dorks": [
            ('"{domain}" AZURE_CLIENT_SECRET', "azure_secret", "CRITICAL"),
            ('"{domain}" DefaultEndpointsProtocol=https AccountName=', "azure_storage", "CRITICAL"),
            ('"{domain}" blob.core.windows.net', "azure_blob", "HIGH"),
            ('"{domain}" COSMOS_DB_KEY', "cosmos_key", "CRITICAL"),
            ('"{domain}" AZURE_DEVOPS_PAT', "azure_devops_pat", "CRITICAL"),
            ('"{domain}" AZURE_OPENAI_KEY', "azure_openai_key", "CRITICAL"),
            ('"{domain}" AZURE_OPENAI_ENDPOINT', "azure_openai_endpoint", "MEDIUM"),
            ('"{domain}" vault.azure.net', "azure_keyvault", "HIGH"),
            ('"{domain}" servicebus.windows.net', "azure_servicebus", "HIGH"),
            ('"{domain}" database.windows.net', "azure_sql", "HIGH"),
            ('"{domain}" APPINSIGHTS_INSTRUMENTATIONKEY', "azure_appinsights", "MEDIUM"),
            ('"{domain}" filename:.env AZURE_', "azure_env_file", "CRITICAL"),
        ],
        "js_patterns": {
            "azure_storage_conn": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44,};",
            "azure_cosmos_key": r"[A-Za-z0-9+/=]{44,}==",
            "azure_instrumentation_key": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        },
        "sensitive_paths": [
            "azure-pipelines.yml", ".azure/", "local.settings.json",
            "appsettings.json", "appsettings.Development.json",
            "web.config", "host.json", "proxies.json",
        ],
    },

    # --- CI/CD & DevOps ---
    "cicd": {
        "keywords": ["github actions", "gitlab", "jenkins", "circleci", "travis", "docker", "kubernetes", "terraform", "ansible"],
        "env_vars": ["CI_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN", "DOCKER_PASSWORD", "KUBECONFIG", "TF_VAR_"],
        "github_dorks": [
            ('"{domain}" GITHUB_TOKEN', "github_token_leak", "CRITICAL"),
            ('"{domain}" GITLAB_TOKEN', "gitlab_token", "CRITICAL"),
            ('"{domain}" DOCKER_PASSWORD', "docker_creds", "HIGH"),
            ('"{domain}" filename:Dockerfile', "dockerfile", "LOW"),
            ('"{domain}" filename:terraform.tfstate', "tf_state", "CRITICAL"),
            ('"{domain}" filename:.github/workflows', "gh_actions", "LOW"),
        ],
        "js_patterns": {},
        "sensitive_paths": [".github/workflows/", ".gitlab-ci.yml", "Jenkinsfile", "terraform.tfstate", ".kube/config", "docker-compose.yml"],
    },

    # --- Payments & SaaS ---
    "payments": {
        "keywords": ["stripe", "paypal", "braintree", "adyen", "square"],
        "env_vars": ["STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "PAYPAL_CLIENT_SECRET", "BRAINTREE_PRIVATE_KEY"],
        "github_dorks": [
            ('"{domain}" sk_live_', "stripe_live_key", "CRITICAL"),
            ('"{domain}" STRIPE_SECRET', "stripe_secret", "CRITICAL"),
            ('"{domain}" PAYPAL_CLIENT_SECRET', "paypal_secret", "HIGH"),
        ],
        "js_patterns": {
            "stripe_secret": r"sk_live_[0-9a-zA-Z]{24,}",
            "stripe_publishable": r"pk_live_[0-9a-zA-Z]{24,}",
        },
        "sensitive_paths": [],
    },

    # --- Communication ---
    "comms": {
        "keywords": ["slack", "discord", "twilio", "sendgrid", "mailgun", "postmark"],
        "env_vars": ["SLACK_TOKEN", "SLACK_WEBHOOK", "DISCORD_TOKEN", "TWILIO_AUTH_TOKEN", "SENDGRID_API_KEY", "MAILGUN_API_KEY"],
        "github_dorks": [
            ('"{domain}" xoxb-', "slack_bot_token", "HIGH"),
            ('"{domain}" hooks.slack.com', "slack_webhook", "HIGH"),
            ('"{domain}" SENDGRID_API_KEY', "sendgrid_key", "HIGH"),
            ('"{domain}" TWILIO_AUTH_TOKEN', "twilio_token", "HIGH"),
            ('"{domain}" DISCORD_TOKEN', "discord_token", "HIGH"),
        ],
        "js_patterns": {
            "slack_token": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
            "slack_webhook": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
            "discord_webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        },
        "sensitive_paths": [],
    },

    # --- Databases ---
    "databases": {
        "keywords": ["postgresql", "mysql", "mongodb", "redis", "elasticsearch", "supabase", "planetscale", "neon"],
        "env_vars": ["DATABASE_URL", "MONGO_URI", "REDIS_URL", "ELASTICSEARCH_URL", "SUPABASE_KEY", "SUPABASE_URL"],
        "github_dorks": [
            ('"{domain}" DATABASE_URL', "db_url", "CRITICAL"),
            ('"{domain}" mongodb+srv://', "mongo_conn", "CRITICAL"),
            ('"{domain}" redis://', "redis_conn", "HIGH"),
            ('"{domain}" SUPABASE_KEY', "supabase_key", "HIGH"),
        ],
        "js_patterns": {
            "mongo_uri": r"mongodb(?:\+srv)?://[^\s'\"]+",
            "postgres_uri": r"postgres(?:ql)?://[^\s'\"]+",
            "redis_uri": r"redis://[^\s'\"]+",
        },
        "sensitive_paths": [".pgpass", "mongod.conf", "redis.conf", "database.yml"],
    },

    # --- Auth Providers ---
    "auth": {
        "keywords": ["auth0", "okta", "firebase auth", "cognito", "clerk", "supertokens", "keycloak"],
        "env_vars": ["AUTH0_CLIENT_SECRET", "AUTH0_DOMAIN", "OKTA_CLIENT_SECRET", "NEXTAUTH_SECRET", "CLERK_SECRET_KEY"],
        "github_dorks": [
            ('"{domain}" AUTH0_CLIENT_SECRET', "auth0_secret", "CRITICAL"),
            ('"{domain}" NEXTAUTH_SECRET', "nextauth_secret", "CRITICAL"),
            ('"{domain}" CLERK_SECRET_KEY', "clerk_secret", "HIGH"),
            ('"{domain}" OKTA_CLIENT_SECRET', "okta_secret", "CRITICAL"),
        ],
        "js_patterns": {},
        "sensitive_paths": [],
    },

    # --- Frameworks (detected by web_recon / httpx) ---
    "nextjs": {
        "keywords": ["next.js", "nextjs", "vercel", "_next/"],
        "env_vars": ["NEXT_PUBLIC_", "NEXTAUTH_URL", "NEXTAUTH_SECRET"],
        "github_dorks": [
            ('"{domain}" NEXT_PUBLIC_ filename:.env', "nextjs_env", "HIGH"),
            ('"{domain}" NEXTAUTH_SECRET', "nextauth_secret", "CRITICAL"),
        ],
        "js_patterns": {},
        "sensitive_paths": [".next/", "next.config.js", ".vercel/"],
    },

    "laravel": {
        "keywords": ["laravel", "artisan", "blade", "eloquent"],
        "env_vars": ["APP_KEY", "APP_DEBUG", "DB_PASSWORD", "MAIL_PASSWORD", "PUSHER_APP_KEY"],
        "github_dorks": [
            ('"{domain}" APP_KEY=base64:', "laravel_app_key", "CRITICAL"),
            ('"{domain}" APP_DEBUG=true', "laravel_debug", "HIGH"),
            ('"{domain}" DB_PASSWORD filename:.env', "laravel_db_pass", "CRITICAL"),
        ],
        "js_patterns": {},
        "sensitive_paths": [".env", "storage/logs/laravel.log", "artisan", "config/app.php"],
    },

    "django": {
        "keywords": ["django", "wsgi", "asgi", "manage.py"],
        "env_vars": ["DJANGO_SECRET_KEY", "DJANGO_SETTINGS_MODULE", "SECRET_KEY"],
        "github_dorks": [
            ('"{domain}" DJANGO_SECRET_KEY', "django_secret", "CRITICAL"),
            ('"{domain}" SECRET_KEY filename:settings.py', "django_settings_secret", "CRITICAL"),
            ('"{domain}" DEBUG = True filename:settings.py', "django_debug", "HIGH"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["settings.py", "manage.py", "requirements.txt", "Pipfile"],
    },

    "rails": {
        "keywords": ["ruby on rails", "rails", "rack", "bundler", "activerecord"],
        "env_vars": ["SECRET_KEY_BASE", "RAILS_MASTER_KEY", "DATABASE_URL"],
        "github_dorks": [
            ('"{domain}" SECRET_KEY_BASE', "rails_secret", "CRITICAL"),
            ('"{domain}" RAILS_MASTER_KEY', "rails_master_key", "CRITICAL"),
            ('"{domain}" filename:credentials.yml.enc', "rails_credentials", "HIGH"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["config/master.key", "config/credentials.yml.enc", "Gemfile", "config/database.yml"],
    },

    "spring": {
        "keywords": ["spring", "spring boot", "java", "tomcat", "maven", "gradle"],
        "env_vars": ["SPRING_DATASOURCE_PASSWORD", "SPRING_SECURITY_OAUTH2_CLIENT_SECRET", "JWT_SECRET"],
        "github_dorks": [
            ('"{domain}" SPRING_DATASOURCE_PASSWORD', "spring_db_pass", "CRITICAL"),
            ('"{domain}" filename:application.properties password', "spring_props_pass", "CRITICAL"),
            ('"{domain}" filename:application.yml secret', "spring_yml_secret", "HIGH"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["application.properties", "application.yml", "actuator/", "actuator/env"],
    },

    # --- Analytics & Tracking ---
    "analytics": {
        "keywords": ["mixpanel", "amplitude", "segment", "posthog", "datadog", "google analytics", "gtm", "hotjar", "heap"],
        "env_vars": ["MIXPANEL_TOKEN", "AMPLITUDE_API_KEY", "SEGMENT_WRITE_KEY", "POSTHOG_API_KEY", "DD_API_KEY", "DD_APP_KEY", "GA_TRACKING_ID"],
        "github_dorks": [
            ('"{domain}" SEGMENT_WRITE_KEY', "segment_key", "HIGH"),
            ('"{domain}" MIXPANEL_TOKEN', "mixpanel_token", "MEDIUM"),
            ('"{domain}" DD_API_KEY', "datadog_key", "HIGH"),
            ('"{domain}" POSTHOG_API_KEY', "posthog_key", "MEDIUM"),
        ],
        "js_patterns": {
            "segment_key": r"(?:write_key|writeKey)\s*[:=]\s*['\"]([A-Za-z0-9]{20,})['\"]",
        },
        "sensitive_paths": [],
    },

    # --- Observability & Logging ---
    "observability": {
        "keywords": ["sentry", "new relic", "grafana", "prometheus", "elastic", "splunk", "pagerduty", "opsgenie"],
        "env_vars": ["SENTRY_DSN", "SENTRY_AUTH_TOKEN", "NEW_RELIC_LICENSE_KEY", "GRAFANA_API_KEY", "ELASTIC_APM_SECRET_TOKEN", "PAGERDUTY_API_KEY", "SPLUNK_HEC_TOKEN"],
        "github_dorks": [
            ('"{domain}" SENTRY_DSN', "sentry_dsn", "MEDIUM"),
            ('"{domain}" SENTRY_AUTH_TOKEN', "sentry_auth", "HIGH"),
            ('"{domain}" NEW_RELIC_LICENSE_KEY', "newrelic_key", "HIGH"),
            ('"{domain}" GRAFANA_API_KEY', "grafana_key", "HIGH"),
            ('"{domain}" SPLUNK_HEC_TOKEN', "splunk_token", "HIGH"),
        ],
        "js_patterns": {
            "sentry_dsn": r"https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+",
        },
        "sensitive_paths": ["sentry.properties", "newrelic.yml", "newrelic.js"],
    },

    # --- CMS / WordPress / Headless ---
    "cms": {
        "keywords": ["wordpress", "wp-admin", "strapi", "contentful", "sanity", "ghost", "drupal", "shopify"],
        "env_vars": ["WORDPRESS_DB_PASSWORD", "WP_DB_PASSWORD", "CONTENTFUL_ACCESS_TOKEN", "CONTENTFUL_SPACE_ID", "SANITY_TOKEN", "STRAPI_ADMIN_JWT_SECRET", "SHOPIFY_API_SECRET"],
        "github_dorks": [
            ('"{domain}" WORDPRESS_DB_PASSWORD', "wp_db_pass", "CRITICAL"),
            ('"{domain}" CONTENTFUL_ACCESS_TOKEN', "contentful_token", "HIGH"),
            ('"{domain}" SANITY_TOKEN', "sanity_token", "HIGH"),
            ('"{domain}" SHOPIFY_API_SECRET', "shopify_secret", "CRITICAL"),
            ('"{domain}" STRAPI_ADMIN_JWT_SECRET', "strapi_jwt", "CRITICAL"),
            ('"{domain}" wp-config.php DB_PASSWORD', "wp_config_pass", "CRITICAL"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["wp-config.php", "wp-config.php.bak", "wp-admin/", "wp-login.php", ".wp-config.php.swp", "strapi/"],
    },

    # --- Mobile / React Native / Flutter ---
    "mobile": {
        "keywords": ["react native", "flutter", "expo", "ionic", "swift", "kotlin", "android", "ios", "capacitor"],
        "env_vars": ["EXPO_TOKEN", "APPLE_API_KEY", "GOOGLE_SERVICES_JSON", "ANDROID_KEYSTORE_PASSWORD"],
        "github_dorks": [
            ('"{domain}" EXPO_TOKEN', "expo_token", "HIGH"),
            ('"{domain}" filename:google-services.json', "google_services", "HIGH"),
            ('"{domain}" filename:GoogleService-Info.plist', "apple_services", "HIGH"),
            ('"{domain}" ANDROID_KEYSTORE_PASSWORD', "android_keystore", "CRITICAL"),
            ('"{domain}" filename:app.json "expo"', "expo_config", "LOW"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["google-services.json", "GoogleService-Info.plist", "app.json", "eas.json"],
    },

    # --- Crypto / Web3 / Blockchain ---
    "crypto": {
        "keywords": ["ethereum", "web3", "solana", "hardhat", "truffle", "metamask", "ethers", "alchemy", "infura", "moralis"],
        "env_vars": ["PRIVATE_KEY", "MNEMONIC", "INFURA_API_KEY", "ALCHEMY_API_KEY", "ETHERSCAN_API_KEY", "MORALIS_API_KEY", "WALLET_PRIVATE_KEY"],
        "github_dorks": [
            ('"{domain}" PRIVATE_KEY 0x', "eth_private_key", "CRITICAL"),
            ('"{domain}" MNEMONIC', "wallet_mnemonic", "CRITICAL"),
            ('"{domain}" INFURA_API_KEY', "infura_key", "HIGH"),
            ('"{domain}" ALCHEMY_API_KEY', "alchemy_key", "HIGH"),
            ('"{domain}" ETHERSCAN_API_KEY', "etherscan_key", "MEDIUM"),
        ],
        "js_patterns": {
            "eth_private_key": r"0x[a-fA-F0-9]{64}",
            "mnemonic_phrase": r"(?:mnemonic|seed)\s*[:=]\s*['\"]([a-z]+(?: [a-z]+){11,23})['\"]",
        },
        "sensitive_paths": ["hardhat.config.js", "truffle-config.js", ".secret", "secrets.json"],
    },

    # --- Object Storage / CDN ---
    "storage": {
        "keywords": ["cloudflare", "cloudinary", "imgix", "uploadthing", "minio", "backblaze", "r2", "bunny"],
        "env_vars": ["CLOUDFLARE_API_TOKEN", "CF_API_KEY", "CLOUDINARY_URL", "CLOUDINARY_API_SECRET", "MINIO_SECRET_KEY", "BACKBLAZE_APP_KEY", "UPLOADTHING_SECRET"],
        "github_dorks": [
            ('"{domain}" CLOUDFLARE_API_TOKEN', "cf_token", "CRITICAL"),
            ('"{domain}" CLOUDINARY_API_SECRET', "cloudinary_secret", "HIGH"),
            ('"{domain}" MINIO_SECRET_KEY', "minio_secret", "CRITICAL"),
            ('"{domain}" UPLOADTHING_SECRET', "uploadthing_secret", "HIGH"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["wrangler.toml", ".wrangler/"],
    },

    # --- AI Agents / MCP / LLM Tooling (2025-2026 wave) ---
    "ai_agents": {
        "keywords": ["mcp", "model context protocol", "langsmith", "langgraph", "crewai", "autogen", "dify", "flowise", "n8n"],
        "env_vars": ["LANGSMITH_API_KEY", "LANGCHAIN_TRACING_V2", "TAVILY_API_KEY", "SERPAPI_KEY", "BROWSERLESS_TOKEN", "COMPOSIO_API_KEY"],
        "github_dorks": [
            ('"{domain}" LANGSMITH_API_KEY', "langsmith_key", "HIGH"),
            ('"{domain}" TAVILY_API_KEY', "tavily_key", "MEDIUM"),
            ('"{domain}" SERPAPI_KEY', "serpapi_key", "MEDIUM"),
            ('"{domain}" BROWSERLESS_TOKEN', "browserless_token", "HIGH"),
            ('"{domain}" COMPOSIO_API_KEY', "composio_key", "MEDIUM"),
            ('"{domain}" filename:mcp.json', "mcp_config", "HIGH"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["mcp.json", ".langsmith/", "langgraph.json", "flows/"],
    },

    # --- Secrets Managers (ironic but real — people leak the keys to their vault) ---
    "secrets_mgmt": {
        "keywords": ["vault", "hashicorp", "doppler", "1password", "bitwarden", "infisical"],
        "env_vars": ["VAULT_TOKEN", "VAULT_ADDR", "DOPPLER_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN", "INFISICAL_TOKEN"],
        "github_dorks": [
            ('"{domain}" VAULT_TOKEN', "vault_token", "CRITICAL"),
            ('"{domain}" DOPPLER_TOKEN', "doppler_token", "CRITICAL"),
            ('"{domain}" OP_SERVICE_ACCOUNT_TOKEN', "1password_sa_token", "CRITICAL"),
            ('"{domain}" INFISICAL_TOKEN', "infisical_token", "CRITICAL"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["vault.hcl", ".vault-token"],
    },

    # --- Testing / Staging Leaks ---
    "testing": {
        "keywords": ["playwright", "cypress", "selenium", "puppeteer", "jest", "postman"],
        "env_vars": ["TEST_USER_PASSWORD", "CYPRESS_RECORD_KEY", "PLAYWRIGHT_TOKEN", "BROWSERSTACK_ACCESS_KEY"],
        "github_dorks": [
            ('"{domain}" TEST_USER_PASSWORD', "test_password", "HIGH"),
            ('"{domain}" CYPRESS_RECORD_KEY', "cypress_key", "MEDIUM"),
            ('"{domain}" BROWSERSTACK_ACCESS_KEY', "browserstack_key", "MEDIUM"),
            ('"{domain}" filename:postman_collection', "postman_collection", "MEDIUM"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["cypress.env.json", "playwright.config.ts", ".postman/"],
    },

    # --- Infrastructure as Code ---
    "iac": {
        "keywords": ["terraform", "pulumi", "ansible", "cloudformation", "cdk"],
        "env_vars": ["TF_VAR_", "PULUMI_ACCESS_TOKEN", "ANSIBLE_VAULT_PASSWORD", "AWS_CLOUDFORMATION_ROLE_ARN"],
        "github_dorks": [
            ('"{domain}" filename:terraform.tfstate', "tf_state", "CRITICAL"),
            ('"{domain}" PULUMI_ACCESS_TOKEN', "pulumi_token", "CRITICAL"),
            ('"{domain}" ANSIBLE_VAULT_PASSWORD', "ansible_vault_pass", "CRITICAL"),
            ('"{domain}" filename:*.tfvars', "tf_vars", "HIGH"),
        ],
        "js_patterns": {},
        "sensitive_paths": ["terraform.tfstate", "terraform.tfstate.backup", "*.tfvars", "ansible/vault.yml", "pulumi.*.yaml"],
    },
}


# ═══════════════════════════════════════════════════════════════════════
# TECH CONTEXT DATACLASS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class TechContext:
    """Aggregated tech intelligence for an agent to use."""
    # What was detected by earlier agents
    detected_techs: list[str] = field(default_factory=list)
    # Which default stacks matched (by keyword in detected_techs)
    matched_stacks: list[str] = field(default_factory=list)
    # Always include these (high probability across all orgs)
    always_check: list[str] = field(default_factory=lambda: [
        "ai_llm",       # Every org uses AI tools now
        "ai_agents",    # MCP/LangSmith/agent tooling — 2025-2026 wave
        "cicd",         # GitHub Actions / Docker / Terraform everywhere
        "databases",    # Every app has a DB
        "comms",        # Slack/Discord webhooks in every org
        "observability", # Sentry/Datadog/New Relic — near-universal
        "secrets_mgmt", # Ironic but real: people leak their vault keys
    ])

    @property
    def all_active_stacks(self) -> list[str]:
        """All tech stacks that should be checked: matched + always-check."""
        return list(set(self.matched_stacks + self.always_check))

    def _get_stack(self, name: str) -> dict:
        """Get a stack definition by name."""
        return DEFAULT_TECH_STACK.get(name, {})

    def get_github_dorks(self) -> list[tuple[str, str, str]]:
        """Get tech-specific GitHub dork templates."""
        dorks = []
        seen = set()
        for stack_name in self.all_active_stacks:
            stack = DEFAULT_TECH_STACK.get(stack_name, {})
            for dork in stack.get("github_dorks", []):
                key = dork[0]  # template string
                if key not in seen:
                    seen.add(key)
                    dorks.append(dork)
        return dorks

    def get_js_patterns(self) -> dict[str, str]:
        """Get tech-specific JS secret regex patterns."""
        patterns = {}
        for stack_name in self.all_active_stacks:
            stack = DEFAULT_TECH_STACK.get(stack_name, {})
            patterns.update(stack.get("js_patterns", {}))
        return patterns

    def get_sensitive_paths(self) -> list[str]:
        """Get tech-specific sensitive file paths for dir discovery."""
        paths = set()
        for stack_name in self.all_active_stacks:
            stack = DEFAULT_TECH_STACK.get(stack_name, {})
            paths.update(stack.get("sensitive_paths", []))
        return sorted(paths)

    def get_env_vars(self) -> list[str]:
        """Get env var names to search for in leaks."""
        env_vars = set()
        for stack_name in self.all_active_stacks:
            stack = DEFAULT_TECH_STACK.get(stack_name, {})
            env_vars.update(stack.get("env_vars", []))
        return sorted(env_vars)


# ═══════════════════════════════════════════════════════════════════════
# CONTEXT BUILDER
# ═══════════════════════════════════════════════════════════════════════

async def get_scan_tech_context(scan_id: str) -> TechContext:
    """
    Build tech context for a scan by:
      1. Reading findings from earlier agents (tech_detected, tags)
      2. Matching detected tech against known stack patterns
      3. Always including high-probability stacks (AI, CI/CD, DBs, comms)

    Call this from any agent's execute() to get adaptive patterns.
    """
    ctx = TechContext()

    # Step 1: Read what earlier agents discovered
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Finding.raw_data, Finding.tags)
                .where(Finding.scan_id == uuid.UUID(scan_id))
            )
            for raw_data, tags in result.all():
                if tags:
                    for tag in tags:
                        ctx.detected_techs.append(tag.lower())
                if raw_data and isinstance(raw_data, dict):
                    for tech in raw_data.get("tech_detected", []):
                        ctx.detected_techs.append(tech.lower())
                    # Also check for specific indicators
                    for key in ["service_name", "http_server", "framework"]:
                        val = raw_data.get(key, "")
                        if val:
                            ctx.detected_techs.append(str(val).lower())
    except Exception as e:
        logger.warning(f"Failed to load tech context from DB: {e}")

    # Deduplicate
    ctx.detected_techs = list(set(ctx.detected_techs))

    # Step 2: Match against known stacks
    for stack_name, stack_def in DEFAULT_TECH_STACK.items():
        keywords = stack_def.get("keywords", [])
        for keyword in keywords:
            keyword_lower = keyword.lower()
            if any(keyword_lower in tech for tech in ctx.detected_techs):
                ctx.matched_stacks.append(stack_name)
                break

    logger.info(
        f"Tech context for scan {scan_id}: "
        f"{len(ctx.detected_techs)} techs detected, "
        f"{len(ctx.matched_stacks)} stacks matched ({ctx.matched_stacks}), "
        f"{len(ctx.all_active_stacks)} active stacks total"
    )

    return ctx
