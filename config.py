import os
import time

# In-process cache: { (vault_url, secret_name): (value, expires_at) }
_secret_cache: dict = {}
_CACHE_TTL = 3600  # seconds – re-fetch from Key Vault at most once per hour


def _get_keyvault_secret(vault_url: str, secret_name: str) -> str:
    """Fetch a secret from Azure Key Vault.

    Uses ManagedIdentityCredential when USE_MANAGED_IDENTITY=true (prod),
    otherwise DefaultAzureCredential (dev/staging).

    Results are cached in-process for _CACHE_TTL seconds so that the
    Key Vault round-trip only happens once per hour rather than on
    every database connection or email send.
    """
    cache_key = (vault_url, secret_name)
    now = time.monotonic()
    if cache_key in _secret_cache:
        value, expires_at = _secret_cache[cache_key]
        if now < expires_at:
            return value

    use_mi = os.getenv('USE_MANAGED_IDENTITY', 'false').lower() == 'true'
    if use_mi:
        from azure.identity import ManagedIdentityCredential
        credential = ManagedIdentityCredential()
    else:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()

    from azure.keyvault.secrets import SecretClient
    client = SecretClient(vault_url=vault_url, credential=credential)
    value = client.get_secret(secret_name).value
    _secret_cache[cache_key] = (value, now + _CACHE_TTL)
    return value


class Config:
	DB_HOST = os.getenv('DB_HOST', 'localhost')
	DB_PORT = os.getenv('DB_PORT', '5432')
	DB_NAME = os.getenv('DB_NAME', 'PCP')
	DB_USER = os.getenv('DB_USER', 'postgres')
	# WEB_SECRET is set by set_env from Azure Key Vault (secret name: WEB-SECRET)
	SECRET_KEY = os.getenv('WEB_SECRET') or os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

	# Email (Gmail SMTP) for MFA one-time codes
	MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
	MAIL_PORT = int(os.getenv('MAIL_PORT', '587'))
	MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
	MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
	MAIL_FROM = os.getenv('MAIL_FROM', os.getenv('MAIL_USERNAME', ''))

	# Timezone used when storing naive datetimes in the DB (PostgreSQL server TZ)
	STORED_TZ = os.getenv('STORED_TZ', 'America/Los_Angeles')

	# Azure Key Vault – prefer the name set by set_env, fall back to legacy name
	_KEYVAULT_URL = os.getenv('AZURE_KEY_VAULT_URL') or os.getenv('KEYVAULT_URL', '')
	_KEYVAULT_WEB_SECRET  = os.getenv('KEYVAULT_WEB_SECRET',  'WEB-SECRET')
	_KEYVAULT_MAIL_SECRET = os.getenv('KEYVAULT_MAIL_SECRET', 'PCP-GMAIL-PWD')
	_KEYVAULT_DB_SECRET   = os.getenv('KEYVAULT_DB_SECRET',   'DB-PASSWORD')

	@classmethod
	def _get_keyvault_secret(cls, secret_name: str) -> str:
		if not cls._KEYVAULT_URL:
			raise RuntimeError(
				'KEYVAULT_URL is not set in .env. '
				'Set it to https://<vault-name>.vault.azure.net/'
			)
		return _get_keyvault_secret(cls._KEYVAULT_URL, secret_name)

	@classmethod
	def get_secret_key(cls) -> str:
		"""Retrieve the Flask SECRET_KEY from Azure Key Vault."""
		return cls._get_keyvault_secret(cls._KEYVAULT_WEB_SECRET)

	@classmethod
	def get_mail_password(cls) -> str:
		"""Retrieve the Gmail App Password from Azure Key Vault."""
		return cls._get_keyvault_secret(cls._KEYVAULT_MAIL_SECRET)

	@classmethod
	def get_db_password(cls) -> str:
		"""Retrieve the database password from Azure Key Vault."""
		return cls._get_keyvault_secret(cls._KEYVAULT_DB_SECRET)

