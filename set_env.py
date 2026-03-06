"""
Centralized environment setup module for PCP Manager.
Handles environment configuration, .env section loading, and Azure Key Vault integration.

Usage in app.py (must be first, before config import):
    import set_env
    set_env.setup()
"""
import argparse
import configparser
import logging
import os
from enum import Enum
from typing import Any, Dict, Optional

# ── Logging ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Reduce Azure SDK noise
logging.getLogger('azure').setLevel(logging.WARNING)
logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)
logging.getLogger('azure.identity').setLevel(logging.WARNING)


# ── Enums & data classes ──────────────────────────────────────────────────
class Environment(Enum):
    DEV     = "dev"
    STAGING = "staging"
    PROD    = "prod"


class EnvironmentConfig:
    def __init__(self,
                 key_vault_url: str,
                 secret_prefix: Optional[str] = None,
                 use_managed_identity: bool = False,
                 tenant_id: Optional[str] = None):
        self.key_vault_url        = key_vault_url
        self.secret_prefix        = secret_prefix or ""
        self.use_managed_identity = use_managed_identity
        self.tenant_id            = tenant_id


import sys


# ── .env file loader ──────────────────────────────────────────────────────
def load_env_config(environment: str = "dev", env_file: str = ".env") -> Dict[str, str]:
    """
    Load configuration from INI-style .env file.
    Merges [COMMON] first, then the environment-specific section on top.
    """
    if not os.path.exists(env_file):
        logger.warning(f"Environment file '{env_file}' not found – skipping")
        return {}

    parser = configparser.ConfigParser()
    parser.read(env_file)

    # Normalise aliases
    env_aliases = {"development": "dev", "production": "prod"}
    environment = env_aliases.get(environment.lower(), environment.lower())
    section     = environment.upper()

    merged: Dict[str, str] = {}

    # COMMON first (lower priority)
    if parser.has_section("COMMON"):
        merged.update({k.upper(): v for k, v in parser.items("COMMON")})

    # Environment-specific section (higher priority)
    if parser.has_section(section):
        merged.update({k.upper(): v for k, v in parser.items(section)})
    else:
        logger.warning(f".env has no [{section}] section – only COMMON values loaded")

    return merged


def set_env_variables(config_dict: Dict[str, str]) -> None:
    """Push config dict into os.environ (only if not already set – allows CI override)."""
    for key, value in config_dict.items():
        env_key = key.upper()
        if env_key not in os.environ:
            os.environ[env_key] = value
    logger.debug(f"Loaded {len(config_dict)} settings into environment")

    # For local development: default DB_SSLMODE to 'disable' if not set
    if (
        os.getenv('ENVIRONMENT', 'dev').lower() == 'dev'
        and 'DB_SSLMODE' not in os.environ
    ):
        os.environ['DB_SSLMODE'] = 'disable'
        print('[set_env] Defaulted DB_SSLMODE=disable for local development', file=sys.stderr)


# ── Azure Key Vault client ────────────────────────────────────────────────
class AzureKeyVaultConfig:
    """
    Environment-aware Azure Key Vault client.
    Falls back to local environment variables when Key Vault is unavailable.
    """

    # PCP Manager secrets (without env prefix)
    SECRET_NAMES = [
        "WEB-SECRET",
        "DB-PASSWORD",
        "PCP-GMAIL-PWD",
    ]

    def __init__(self, environment: Optional[str] = None):
        self.environment  = self._resolve_environment(environment)
        self.env_config   = self._build_env_config(self.environment)
        self.client       = None
        self.azure_available = False
        self._secret_cache: Dict[str, str] = {}

        self._init_client()

    # ── internal helpers ──────────────────────────────────────────────────
    def _resolve_environment(self, environment: Optional[str]) -> str:
        raw = environment or os.getenv("ENVIRONMENT", "dev")
        env = raw.lower()
        valid = {e.value for e in Environment}
        if env not in valid:
            logger.warning(f"Unknown environment '{env}', defaulting to 'dev'")
            env = "dev"
        return env

    def _build_env_config(self, environment: str) -> EnvironmentConfig:
        kv_url = (
            os.getenv("AZURE_KEY_VAULT_URL") or
            os.getenv(f"AZURE_KEY_VAULT_URL_{environment.upper()}") or
            os.getenv("AZURE_KEY_VAULT_URL_FALLBACK") or
            os.getenv("KEYVAULT_URL", "")          # legacy name
        )
        if not kv_url:
            raise ValueError(
                "No Key Vault URL found. Set AZURE_KEY_VAULT_URL in .env or environment."
            )

        # Remove all environment-based secret prefixes
        use_mi_default = "true" if environment == "prod" else "false"
        use_mi      = os.getenv("USE_MANAGED_IDENTITY", use_mi_default).lower() == "true"

        if environment == "prod" and not use_mi:
            logger.warning("Managed Identity is DISABLED in production – not recommended!")

        return EnvironmentConfig(
            key_vault_url        = kv_url,
            secret_prefix        = "",  # No prefix for any environment
            use_managed_identity = use_mi,
            tenant_id            = os.getenv("AZURE_TENANT_ID"),
        )

    def _init_client(self) -> None:
        try:
            if self.env_config.use_managed_identity:
                from azure.identity import ManagedIdentityCredential
                credential = ManagedIdentityCredential()
            else:
                from azure.identity import DefaultAzureCredential
                kwargs = {}
                if self.env_config.tenant_id:
                    kwargs["tenant_id"] = self.env_config.tenant_id
                credential = DefaultAzureCredential(**kwargs)

            from azure.keyvault.secrets import SecretClient
            self.client = SecretClient(
                vault_url  = self.env_config.key_vault_url,
                credential = credential,
            )
            # Probe auth (a 404 means auth is good; 401/403 means it isn't)
            try:
                self.client.get_secret("__auth-probe__")
            except Exception as probe_err:
                msg = str(probe_err).lower()
                if any(x in msg for x in ("401", "403", "unauthorized", "authentication")):
                    raise probe_err
            self.azure_available = True
            logger.debug("Azure Key Vault authenticated successfully")
        except ImportError:
            logger.warning("Azure SDK not installed – using local env vars only")
        except Exception as exc:
            logger.warning(f"Azure Key Vault auth failed: {exc} – falling back to env vars")
            self.client = None

    # ── public interface ──────────────────────────────────────────────────
    def get_secret(self, secret_name: str, use_cache: bool = True) -> Optional[str]:
        """
        Retrieve a secret, trying:
          1. Cache
          2. Key Vault with env prefix  (e.g. dev-DB-PASSWORD)
          3. Key Vault without prefix   (fallback / backward compat)
          4. Local environment variable (DB_PASSWORD or ENVIRONMENT_DB_PASSWORD)
        """
        prefixed = f"{self.env_config.secret_prefix}{secret_name}"
        cache_key = prefixed

        if use_cache and cache_key in self._secret_cache:
            return self._secret_cache[cache_key]

        if not (self.azure_available and self.client):
            return self._from_env(secret_name, cache_key, use_cache)

        try:
            try:
                secret = self.client.get_secret(prefixed)
            except Exception:
                if self.env_config.secret_prefix:
                    secret = self.client.get_secret(secret_name)   # unprefixed fallback
                else:
                    raise

            value = secret.value if secret else None
            if use_cache and value:
                self._secret_cache[cache_key] = value
            return value

        except Exception as exc:
            logger.warning(f"Key Vault lookup failed for '{prefixed}': {exc} – using env vars")
            return self._from_env(secret_name, cache_key, use_cache)

    def _from_env(self, secret_name: str, cache_key: str, use_cache: bool) -> Optional[str]:
        env_name = secret_name.replace("-", "_")
        candidates = [
            env_name,
            f"{self.environment.upper()}_{env_name}",
        ]
        print(f"[DEBUG _from_env] candidates: {candidates}")
        for name in candidates:
            value = os.getenv(name)
            print(f"[DEBUG _from_env] {name} -> {value}")
            if value:
                if use_cache:
                    self._secret_cache[cache_key] = value
                return value
        return None

    def load_all_secrets(self) -> Dict[str, str]:
        """Load all PCP Manager secrets and return as {ENV_VAR_NAME: value}."""
        result = {}
        for name in self.SECRET_NAMES:
            value = self.get_secret(name)
            if value:
                result[name.replace("-", "_")] = value
            else:
                logger.warning(f"Secret not found: {name}")
        return result

    def set_environment_variables(self) -> None:
        """Push all PCP Manager secrets into os.environ."""
        for key, value in self.load_all_secrets().items():
            os.environ[key] = value

    def get_info(self) -> Dict[str, Any]:
        return {
            "environment":          self.environment,
            "key_vault_url":        self.env_config.key_vault_url,
            "secret_prefix":        self.env_config.secret_prefix,
            "use_managed_identity": self.env_config.use_managed_identity,
            "azure_available":      self.azure_available,
            "cached_secrets":       len(self._secret_cache),
        }


# ── Module-level singleton ────────────────────────────────────────────────
_kv_instance: Optional[AzureKeyVaultConfig] = None


def get_kv_config(environment: Optional[str] = None) -> AzureKeyVaultConfig:
    """Return (or create) the module-level AzureKeyVaultConfig singleton."""
    global _kv_instance
    if _kv_instance is None:
        _kv_instance = AzureKeyVaultConfig(environment)
    return _kv_instance


# ── EnvironmentSetup class (matches PCPTokenServer pattern) ───────────────
class EnvironmentSetup:
    """Centralised environment bootstrap for PCP Manager."""

    def __init__(self, script_name: str = "pcp_manager", description: str = None):
        self.script_name = script_name
        self.description = description or f"{script_name} – PCP Manager Flask app"
        self.args        = None
        self.environment: Optional[str] = None

    def create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description=self.description)
        parser.add_argument(
            "environment_pos", nargs="?",
            choices=["dev", "development", "staging", "prod", "production"],
            help="Environment (dev | staging | prod)",
        )
        parser.add_argument(
            "--environment", "-e", dest="environment_flag",
            choices=["dev", "development", "staging", "prod", "production"],
            help="Environment flag (alternative to positional)",
        )
        return parser

    @staticmethod
    def _normalise(env: str) -> str:
        return {"development": "dev", "production": "prod"}.get(env, env)

    def parse_and_setup(
        self,
        parser: Optional[argparse.ArgumentParser] = None,
        argv: Optional[list] = None,
    ) -> argparse.Namespace:
        if parser is None:
            parser = self.create_parser()

        # ignore_unknown so Flask CLI args don't cause errors
        self.args, _ = parser.parse_known_args(argv)

        environment = self.args.environment_flag or self.args.environment_pos
        if environment:
            environment = self._normalise(environment)
            os.environ["ENVIRONMENT"] = environment
            self.environment = environment
            logger.warning(f"Environment set to: {environment}")
        else:
            self.environment = self._normalise(os.getenv("ENVIRONMENT", "dev"))
            logger.warning(f"Using environment: {self.environment} (from env var / default)")

        # 1 – load .env sections into os.environ
        try:
            cfg = load_env_config(self.environment)
            if cfg:
                set_env_variables(cfg)
                logger.warning(f"Loaded .env config for '{self.environment}'")
        except Exception as exc:
            logger.warning(f"Could not load .env config: {exc}")

        # 2 – pull secrets from Azure Key Vault
        try:
            kv = get_kv_config(self.environment)
            kv.set_environment_variables()
            logger.warning(
                f"Azure Key Vault secrets loaded  "
                f"(vault={kv.env_config.key_vault_url}, no prefix used)"
            )
        except Exception as exc:
            print(f"Warning: could not load Key Vault secrets: {exc}")
            print("  Ensure 'az login' is run or managed identity is configured.")

        return self.args

    def get_environment(self) -> str:
        return self.environment or self._normalise(os.getenv("ENVIRONMENT", "dev"))


# ── Convenience entry-point called from app.py ────────────────────────────
_setup_done = False

def setup(environment: Optional[str] = None) -> str:
    """
    Bootstrap environment for PCP Manager.
    Call once at the very top of app.py, before importing config.

    Returns the active environment name.
    """
    global _setup_done
    if _setup_done:
        return os.getenv("ENVIRONMENT", "dev")

    env_setup = EnvironmentSetup()
    # Build a minimal parser (no --host/--port – Flask handles those)
    parser = env_setup.create_parser()
    env_setup.parse_and_setup(parser)

    _setup_done = True
    return env_setup.get_environment()
