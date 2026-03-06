"""Unit tests for app.py helper / utility functions."""
from datetime import datetime
from unittest.mock import patch

import pytest

FAKE_USER_ROW = {
    'id': 1,
    'username': 'testuser',
    'full_name': 'Test User',
    'email': 'test@test.com',
    'password_hash': 'hashed',
    'totp_secret': None,
    'is_active': True,
    'is_admin': False,
}


# ---------------------------------------------------------------------------
# fmt_dt Jinja2 filter
# ---------------------------------------------------------------------------
class TestFmtDt:
    def test_none_returns_empty(self):
        from app import fmt_dt
        assert fmt_dt(None) == ''

    def test_empty_string_returns_empty(self):
        from app import fmt_dt
        assert fmt_dt('') == ''

    def test_datetime_morning(self):
        from app import fmt_dt
        result = fmt_dt(datetime(2025, 3, 15, 9, 5))
        assert '15-Mar-2025' in result
        assert '9:05 AM' in result

    def test_datetime_afternoon(self):
        from app import fmt_dt
        result = fmt_dt(datetime(2025, 3, 15, 14, 30))
        assert '2:30 PM' in result

    def test_datetime_noon_is_pm(self):
        from app import fmt_dt
        result = fmt_dt(datetime(2025, 6, 1, 12, 0))
        assert '12:00 PM' in result

    def test_datetime_midnight_is_am(self):
        from app import fmt_dt
        result = fmt_dt(datetime(2025, 6, 1, 0, 0))
        assert '12:00 AM' in result

    def test_iso_string_parsed(self):
        from app import fmt_dt
        result = fmt_dt('2025-03-15T09:05:00')
        assert '15-Mar-2025' in result
        assert 'AM' in result

    def test_invalid_string_returned_as_is(self):
        from app import fmt_dt
        result = fmt_dt('not-a-date')
        assert result == 'not-a-date'


# ---------------------------------------------------------------------------
# _now
# ---------------------------------------------------------------------------
def test_now_returns_datetime():
    from app import _now
    assert isinstance(_now(), datetime)


# ---------------------------------------------------------------------------
# evaluate_dimension_formula
# ---------------------------------------------------------------------------
class TestEvaluateDimensionFormula:
    def test_none_returns_none(self):
        from app import evaluate_dimension_formula
        assert evaluate_dimension_formula(None, 10, 20, 30) is None

    def test_empty_string_returns_none(self):
        from app import evaluate_dimension_formula
        assert evaluate_dimension_formula('', 10, 20, 30) is None

    def test_numeric_string(self):
        from app import evaluate_dimension_formula
        assert evaluate_dimension_formula('42', 10, 20, 30) == 42.0

    def test_float_value(self):
        from app import evaluate_dimension_formula
        assert evaluate_dimension_formula(3.14, 10, 20, 30) == 3.14

    def test_simple_expression(self):
        from app import evaluate_dimension_formula
        assert evaluate_dimension_formula('=2 + 3', 10, 20, 30) == 5.0

    def test_uses_measurement(self):
        from app import evaluate_dimension_formula
        assert evaluate_dimension_formula('=measurement * 2', 5.0, 20, 30) == 10.0

    def test_uses_rows_per_4inch(self):
        from app import evaluate_dimension_formula
        assert evaluate_dimension_formula('=rows_per_4inch * 2', 5, 10, 30) == 20.0

    def test_uses_stitches_per_4inch(self):
        from app import evaluate_dimension_formula
        assert evaluate_dimension_formula('=stitches_per_4inch + measurement', 5, 10, 30) == 35.0

    def test_caret_becomes_pow(self):
        from app import evaluate_dimension_formula
        assert evaluate_dimension_formula('=2^3', 10, 20, 30) == 8.0

    def test_combined_variables(self):
        from app import evaluate_dimension_formula
        result = evaluate_dimension_formula(
            '=measurement * rows_per_4inch / stitches_per_4inch', 4.0, 20, 10
        )
        assert result == 8.0


# ---------------------------------------------------------------------------
# get_dmn_file_path
# ---------------------------------------------------------------------------
class TestGetDmnFilePath:
    def test_file_not_found_raises(self):
        from app import get_dmn_file_path
        with patch('app.os.path.exists', return_value=False):
            with pytest.raises(FileNotFoundError):
                get_dmn_file_path()

    def test_empty_file_raises(self):
        from app import get_dmn_file_path
        with patch('app.os.path.exists', return_value=True), \
             patch('app.os.path.getsize', return_value=0):
            with pytest.raises(ValueError):
                get_dmn_file_path()


# ---------------------------------------------------------------------------
# User helper functions / User model
# ---------------------------------------------------------------------------
class TestUserHelpers:
    def test_get_user_by_id_found(self, monkeypatch):
        import app as app_module
        from app import _get_user_by_id
        monkeypatch.setattr(app_module, 'execute_query', lambda *a, **kw: [FAKE_USER_ROW])
        user = _get_user_by_id(1)
        assert user is not None
        assert user.username == 'testuser'
        assert user.get_id() == '1'
        assert user.is_active is True

    def test_get_user_by_id_not_found(self, monkeypatch):
        import app as app_module
        from app import _get_user_by_id
        monkeypatch.setattr(app_module, 'execute_query', lambda *a, **kw: [])
        assert _get_user_by_id(999) is None

    def test_get_user_by_username_found(self, monkeypatch):
        import app as app_module
        from app import _get_user_by_username
        monkeypatch.setattr(app_module, 'execute_query', lambda *a, **kw: [FAKE_USER_ROW])
        user = _get_user_by_username('testuser')
        assert user.email == 'test@test.com'
        assert user.is_admin is False

    def test_get_user_by_username_not_found(self, monkeypatch):
        import app as app_module
        from app import _get_user_by_username
        monkeypatch.setattr(app_module, 'execute_query', lambda *a, **kw: [])
        assert _get_user_by_username('nobody') is None

    def test_user_no_full_name_falls_back_to_username(self, monkeypatch):
        import app as app_module
        from app import _get_user_by_id
        monkeypatch.setattr(app_module, 'execute_query',
                            lambda *a, **kw: [dict(FAKE_USER_ROW, full_name=None)])
        user = _get_user_by_id(1)
        assert user.full_name == 'testuser'

    def test_user_inactive(self, monkeypatch):
        import app as app_module
        from app import _get_user_by_id
        monkeypatch.setattr(app_module, 'execute_query',
                            lambda *a, **kw: [dict(FAKE_USER_ROW, is_active=False)])
        user = _get_user_by_id(1)
        assert user.is_active is False
