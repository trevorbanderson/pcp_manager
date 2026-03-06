import os
from unittest import mock

import pytest

import set_env


def test_load_env_config_missing_file(tmp_path, monkeypatch):
    # Should warn and return empty dict if .env missing
    monkeypatch.chdir(tmp_path)
    result = set_env.load_env_config('dev', '.env')
    assert result == {}

def test_get_kv_config_returns_singleton(monkeypatch):
    monkeypatch.setenv('AZURE_KEY_VAULT_URL', 'https://test.vault.azure.net/')
    monkeypatch.setattr(set_env.AzureKeyVaultConfig, '_init_client', lambda self: None)
    monkeypatch.setattr(set_env.AzureKeyVaultConfig, 'load_all_secrets', lambda self: {})
    monkeypatch.setattr(set_env.AzureKeyVaultConfig, 'set_environment_variables', lambda self: None)
    set_env._kv_instance = None
    kv1 = set_env.get_kv_config('dev')
    kv2 = set_env.get_kv_config('dev')
    assert kv1 is kv2

def test_kv_from_env(monkeypatch):
        # Print cache before clearing
        # Print cache before clearing
        print('Before clearing, kv._secret_cache:', getattr(set_env.AzureKeyVaultConfig, '_secret_cache', None))
        # Ensure no previous value interferes
        if 'WEB-SECRET' in os.environ:
            print('Pre-test os.environ[WEB-SECRET]:', os.environ['WEB-SECRET'])
            del os.environ['WEB-SECRET']
        print('After delete, os.environ.get:', os.environ.get('WEB-SECRET'))
        monkeypatch.setenv('WEB_SECRET', 'testsecret')
        monkeypatch.setenv('AZURE_KEY_VAULT_URL', 'https://test.vault.azure.net/')
        print('After setenv, os.environ[WEB-SECRET]:', os.environ.get('WEB-SECRET'))
        monkeypatch.setattr(set_env.AzureKeyVaultConfig, '_init_client', lambda self: None)
        # Patch load_all_secrets and set_environment_variables to do nothing
        monkeypatch.setattr(set_env.AzureKeyVaultConfig, 'load_all_secrets', lambda self: {})
        monkeypatch.setattr(set_env.AzureKeyVaultConfig, 'set_environment_variables', lambda self: None)
        # Reset singleton and all caches
        set_env._kv_instance = None
        if hasattr(set_env.AzureKeyVaultConfig, '_secret_cache'):
            set_env.AzureKeyVaultConfig._secret_cache = {}
        kv = set_env.AzureKeyVaultConfig('dev')
        kv.azure_available = False
        kv.client = None
        kv.env_config.use_managed_identity = False
        kv._secret_cache.clear()
        print('After clearing, kv._secret_cache:', kv._secret_cache)
        # Remove from os.environ to force env fetch
        if 'WEB-SECRET' in kv._secret_cache:
            del kv._secret_cache['WEB-SECRET']
        print('Before assertion, kv._secret_cache:', kv._secret_cache)
        assert kv.get_secret('WEB-SECRET') == 'testsecret'
