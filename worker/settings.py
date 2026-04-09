"""
Centralized configuration for Zovark worker.
Reads from environment variables with ZOVARK_ prefix, falls back to .env file.
SecretStr prevents accidental logging of credentials.
"""
import os
from pydantic_settings import BaseSettings
from pydantic import SecretStr


class ZovarkSettings(BaseSettings):
    # Database
    db_host: str = "pgbouncer"
    db_port: int = 5432
    db_user: str = "zovark"
    db_password: SecretStr = SecretStr("zovark_dev_2026")
    db_name: str = "zovark"

    # Valkey (Redis-API-compatible BSD fork)
    valkey_host: str = "valkey"
    valkey_port: int = 6379
    valkey_password: SecretStr = SecretStr("zovark_valkey_dev_2026")

    # LLM inference — llama-server in zovark-inference container
    llm_base_url: str = "http://zovark-inference:8080"
    llm_endpoint: str = "http://zovark-inference:8080/v1/chat/completions"
    llm_fast_model: str = "gemma-4-e4b-it"
    llm_quality_model: str = "gemma-4-e4b-it"
    llm_key: str = "sk-zovark-dev-2026"

    # Execution
    execution_mode: str = "tools"
    path_d_fallback_enabled: bool = True
    mode: str = "full"  # "full" or "templates-only"

    # Governance
    default_autonomy_level: str = "observe"

    # Operational
    max_investigation_timeout_seconds: int = 300
    max_concurrent_activities: int = 8

    # Parallel tool execution (Feature C)
    parallel_tools_enabled: bool = False  # ZOVARK_PARALLEL_TOOLS_ENABLED
    max_parallel_tools: int = 4  # ZOVARK_MAX_PARALLEL_TOOLS (1-8)

    # Observability
    otel_enabled: bool = True
    otel_endpoint: str = "http://zovark-signoz-collector:4318"

    model_config = {
        "env_prefix": "ZOVARK_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",  # ignore legacy ZOVARK_REDIS_PASSWORD
    }

    @property
    def database_url(self) -> str:
        return f"postgresql://{self.db_user}:{self.db_password.get_secret_value()}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def valkey_url(self) -> str:
        # URL scheme stays redis:// — Valkey accepts it (wire-compatible)
        return f"redis://:{self.valkey_password.get_secret_value()}@{self.valkey_host}:{self.valkey_port}/0"

    # Backwards-compat alias for code that still uses redis_url
    @property
    def redis_url(self) -> str:
        return self.valkey_url

    @property
    def redis_password(self) -> SecretStr:
        return self.valkey_password


# Singleton — import this everywhere
try:
    settings = ZovarkSettings()
except Exception:
    # Fallback for test environments without .env
    settings = ZovarkSettings(
        db_password=SecretStr("zovark_dev_2026"),
        valkey_password=SecretStr("zovark_valkey_dev_2026"),
    )
