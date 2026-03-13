"""Integration tests for app.py Flask routes."""
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

FAKE_USER_ROW = {
    'id': 1,
    'username': 'testadmin',
    'full_name': 'Test Admin',
    'email': 'admin@test.com',
    'password_hash': 'placeholder',   # never used via session auth
    'totp_secret': None,
    'is_active': True,
    'is_admin': True,
}

NON_ADMIN_ROW = dict(FAKE_USER_ROW, id=2, username='plainuser', is_admin=False)


def _user_eq(row=None):
    """Return a mock execute_query that resolves user loads and returns [] for everything else."""
    if row is None:
        row = FAKE_USER_ROW

    def eq(sql, params=None, fetch=True):
        low = sql.lower()
        if (
            'from users where id' in low
            or 'from users where username' in low
            or 'full_name from users' in low
        ):
            return [row]
        return []

    return eq


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def auth_client(client, monkeypatch):
    """Client authenticated as admin; all DB calls mocked."""
    import app as app_module
    monkeypatch.setattr(app_module, 'execute_query', _user_eq())
    with client.session_transaction() as sess:
        sess['_user_id'] = '1'
    return client


@pytest.fixture
def non_admin_client(client, monkeypatch):
    """Client authenticated as a non-admin user."""
    import app as app_module
    monkeypatch.setattr(app_module, 'execute_query', _user_eq(NON_ADMIN_ROW))
    with client.session_transaction() as sess:
        sess['_user_id'] = '2'
    return client


# ---------------------------------------------------------------------------
# Unauthenticated access — protected routes redirect to login
# ---------------------------------------------------------------------------
class TestUnauthenticatedRedirects:
    def test_index(self, client):
        assert client.get('/').status_code == 302

    def test_age_list(self, client):
        assert client.get('/age').status_code == 302

    def test_pieces_list(self, client):
        assert client.get('/pieces').status_code == 302

    def test_users_list(self, client):
        assert client.get('/users').status_code == 302

    def test_measurements_list(self, client):
        assert client.get('/measurements').status_code == 302


# ---------------------------------------------------------------------------
# Favicon — public endpoint, but require_login endpoint name is 'favicon_ico'
# so it IS intercepted for unauthenticated clients; authenticated → 204
# ---------------------------------------------------------------------------
def test_favicon_unauthenticated_redirects(client):
    assert client.get('/favicon.ico').status_code == 302


def test_favicon_authenticated_returns_204(auth_client):
    assert auth_client.get('/favicon.ico').status_code == 204


# ---------------------------------------------------------------------------
# Authenticated GET list routes → 200
# ---------------------------------------------------------------------------
class TestAuthenticatedListRoutes:
    def test_index(self, auth_client):
        assert auth_client.get('/').status_code == 200

    def test_age_list(self, auth_client):
        assert auth_client.get('/age').status_code == 200

    def test_pieces_list(self, auth_client):
        assert auth_client.get('/pieces').status_code == 200

    def test_sizes_list(self, auth_client):
        assert auth_client.get('/sizes').status_code == 200

    def test_level_of_difficulty_list(self, auth_client):
        assert auth_client.get('/level_of_difficulty').status_code == 200

    def test_phases_list(self, auth_client):
        assert auth_client.get('/phases').status_code == 200

    def test_step_groups_list(self, auth_client):
        assert auth_client.get('/step_groups').status_code == 200

    def test_step_list(self, auth_client):
        assert auth_client.get('/step').status_code == 200

    def test_pcp_info_list(self, auth_client):
        assert auth_client.get('/pcp_info').status_code == 200

    def test_measurements_list(self, auth_client):
        assert auth_client.get('/measurements').status_code == 200

    def test_measurements_with_filters(self, auth_client):
        assert auth_client.get('/measurements?age_id=1&body_part_id=2&gender_id=1').status_code == 200

    def test_yarn_weights_list(self, auth_client):
        assert auth_client.get('/yarn_weights').status_code == 200

    def test_elements_list(self, auth_client):
        assert auth_client.get('/elements').status_code == 200

    def test_elements_list_with_filter(self, auth_client):
        assert auth_client.get('/elements?type_filter=stitch').status_code == 200

    def test_pattern_yarn_weights_list(self, auth_client):
        assert auth_client.get('/pattern_yarn_weights').status_code == 200

    def test_pattern_categories_list(self, auth_client):
        assert auth_client.get('/pattern_categories').status_code == 200

    def test_pattern_elements_list(self, auth_client):
        assert auth_client.get('/pattern_elements').status_code == 200

    def test_users_list(self, auth_client):
        assert auth_client.get('/users').status_code == 200


# ---------------------------------------------------------------------------
# Authenticated GET create forms → 200
# ---------------------------------------------------------------------------
class TestCreateForms:
    def test_age_create_form(self, auth_client):
        assert auth_client.get('/age/create').status_code == 200

    def test_pieces_create_form(self, auth_client):
        assert auth_client.get('/pieces/create').status_code == 200

    def test_sizes_create_form(self, auth_client):
        assert auth_client.get('/sizes/create').status_code == 200

    def test_phases_create_form(self, auth_client):
        assert auth_client.get('/phases/create').status_code == 200

    def test_step_groups_create_form(self, auth_client):
        assert auth_client.get('/step_groups/create').status_code == 200

    def test_step_create_form(self, auth_client):
        assert auth_client.get('/step/create').status_code == 200

    def test_pcp_info_create_form(self, auth_client):
        assert auth_client.get('/pcp_info/create').status_code == 200

    def test_level_of_difficulty_create_form(self, auth_client):
        assert auth_client.get('/level_of_difficulty/create').status_code == 200

    def test_users_create_form(self, auth_client):
        assert auth_client.get('/users/create').status_code == 200

    def test_elements_create_form(self, auth_client):
        assert auth_client.get('/elements/create').status_code == 200

    def test_measurements_create_form(self, auth_client):
        assert auth_client.get('/measurements/create').status_code == 200

    def test_pattern_yarn_weights_create_form(self, auth_client):
        assert auth_client.get('/pattern_yarn_weights/create').status_code == 200


# ---------------------------------------------------------------------------
# Edit routes — item not found (mock returns []) → redirect 302
# ---------------------------------------------------------------------------
class TestEditNotFound:
    def test_age_edit_not_found(self, auth_client):
        assert auth_client.get('/age/edit/9999').status_code == 302

    def test_pieces_edit_not_found(self, auth_client):
        assert auth_client.get('/pieces/9999/edit').status_code == 302

    def test_sizes_edit_not_found(self, auth_client):
        assert auth_client.get('/sizes/edit/9999').status_code == 302

    def test_phases_edit_not_found(self, auth_client):
        assert auth_client.get('/phases/edit/9999').status_code == 302

    def test_step_groups_edit_not_found(self, auth_client):
        assert auth_client.get('/step_groups/edit/9999').status_code == 302

    def test_step_edit_not_found(self, auth_client):
        assert auth_client.get('/step/edit/9999').status_code == 302

    def test_pcp_info_edit_not_found(self, auth_client):
        assert auth_client.get('/pcp_info/edit/9999').status_code == 302

    def test_users_edit_returns_form(self, auth_client):
        # Mock always returns FAKE_USER_ROW for user id lookups, so
        # the edit form is rendered regardless of the id value → 200
        assert auth_client.get('/users/9999/edit').status_code == 200

    def test_yarn_weights_edit_not_found(self, auth_client):
        assert auth_client.get('/yarn_weights/edit/9999').status_code == 302


# ---------------------------------------------------------------------------
# Admin-only routes (non-admin user → redirect)
# ---------------------------------------------------------------------------
class TestAdminOnlyRoutes:
    def test_users_list_rejected(self, non_admin_client):
        assert non_admin_client.get('/users').status_code == 302

    def test_users_create_get_rejected(self, non_admin_client):
        assert non_admin_client.get('/users/create').status_code == 302

    def test_users_create_post_rejected(self, non_admin_client):
        resp = non_admin_client.post('/users/create', data={
            'username': 'x', 'email': 'x@x.com', 'password': 'password123'
        })
        assert resp.status_code == 302

    def test_users_delete_rejected(self, non_admin_client):
        assert non_admin_client.post('/users/9999/delete').status_code == 302

    def test_users_reset_totp_rejected(self, non_admin_client):
        assert non_admin_client.post('/users/9999/reset_totp').status_code == 302


# ---------------------------------------------------------------------------
# POST create routes → 302 redirect on success
# ---------------------------------------------------------------------------
class TestCreatePost:
    def test_age_create(self, auth_client):
        resp = auth_client.post('/age/create', data={
            'name': 'Toddler', 'abbreviation': 'T', 'seq': '1'
        })
        assert resp.status_code == 302

    def test_pieces_create(self, auth_client):
        resp = auth_client.post('/pieces/create', data={'name': 'Body'})
        assert resp.status_code == 302

    def test_sizes_create(self, auth_client):
        resp = auth_client.post('/sizes/create', data={
            'name': 'XS', 'abbreviation': 'XS', 'seq': '1'
        })
        assert resp.status_code == 302

    def test_phases_create(self, auth_client):
        resp = auth_client.post('/phases/create', data={
            'seq': '1', 'description': 'Phase 1', 'is_active': 'true'
        })
        assert resp.status_code == 302

    def test_step_groups_create(self, auth_client):
        resp = auth_client.post('/step_groups/create', data={
            'phase_id': '1', 'seq': '1', 'description': 'Group A', 'is_active': 'true'
        })
        assert resp.status_code == 302

    def test_step_create(self, auth_client):
        resp = auth_client.post('/step/create', data={
            'phase_id': '1', 'step_group_id': '1',
            'seq': '1', 'description': 'Do something',
            'step_sql': '', 'is_active': 'true',
        })
        assert resp.status_code == 302

    def test_pcp_info_create(self, auth_client):
        resp = auth_client.post('/pcp_info/create', data={
            'type': 'note', 'text_to_display': 'Hello', 'is_active': 'true'
        })
        assert resp.status_code == 302

    def test_level_of_difficulty_create(self, auth_client):
        resp = auth_client.post('/level_of_difficulty/create', data={
            'name': 'Easy', 'seq': '1', 'symbol': 'E'
        })
        assert resp.status_code == 302

    def test_pattern_yarn_weights_create(self, auth_client):
        resp = auth_client.post('/pattern_yarn_weights/create', data={
            'pattern_id': '1', 'yarn_weight_id': '2'
        })
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# User create validation
# ---------------------------------------------------------------------------
class TestUserCreateValidation:
    def test_missing_fields(self, auth_client):
        resp = auth_client.post('/users/create', data={})
        assert resp.status_code == 200   # re-renders form

    def test_password_too_short(self, auth_client):
        resp = auth_client.post('/users/create', data={
            'username': 'newuser', 'full_name': 'New User', 'email': 'new@test.com', 'password': 'short'
        })
        assert resp.status_code == 200   # re-renders form with error

    def test_duplicate_user(self, auth_client, monkeypatch):
        import app as app_module

        def eq(sql, params=None, fetch=True):
            low = sql.lower()
            if 'from users where id' in low or 'full_name from users' in low:
                return [FAKE_USER_ROW]
            if 'from users where' in low:
                return [{'id': 99}]  # simulate duplicate
            return []

        monkeypatch.setattr(app_module, 'execute_query', eq)
        resp = auth_client.post('/users/create', data={
            'username': 'existing', 'full_name': 'Existing User', 'email': 'existing@test.com', 'password': 'password123'
        })
        assert resp.status_code == 200   # re-renders form with "already exists" error


# ---------------------------------------------------------------------------
# DELETE routes → 302
# ---------------------------------------------------------------------------
class TestDeleteRoutes:
    def test_age_delete(self, auth_client):
        assert auth_client.post('/age/delete/1').status_code == 302

    def test_pieces_delete(self, auth_client):
        assert auth_client.post('/pieces/delete/1').status_code == 302

    def test_sizes_delete(self, auth_client):
        assert auth_client.post('/sizes/delete/1').status_code == 302

    def test_phases_delete(self, auth_client):
        assert auth_client.post('/phases/delete/1').status_code == 302

    def test_step_groups_delete(self, auth_client):
        assert auth_client.post('/step_groups/delete/1').status_code == 302

    def test_step_delete(self, auth_client):
        assert auth_client.post('/step/delete/1').status_code == 302

    def test_level_of_difficulty_delete(self, auth_client):
        assert auth_client.post('/level_of_difficulty/1/delete').status_code == 302

    def test_pcp_info_delete(self, auth_client):
        assert auth_client.post('/pcp_info/delete/1').status_code == 302

    def test_elements_delete(self, auth_client):
        assert auth_client.post('/elements/1/delete').status_code == 302

    def test_measurements_delete(self, auth_client):
        assert auth_client.post('/measurements/delete/1').status_code == 302

    def test_yarn_weights_delete(self, auth_client):
        assert auth_client.post('/yarn_weights/delete/1').status_code == 302

    def test_pattern_yarn_weights_delete(self, auth_client):
        assert auth_client.post('/pattern_yarn_weights/1/delete').status_code == 302

    def test_patterns_delete(self, auth_client, monkeypatch):
        import app as app_module

        def eq(sql, params=None, fetch=True):
            low = sql.lower()
            if (
                'from users where id' in low
                or 'from users where username' in low
                or 'full_name from users' in low
            ):
                return [FAKE_USER_ROW]
            if 'select id, name from pattern where id' in low:
                return [{'id': 1, 'name': 'Alice Cowl'}]
            return []

        monkeypatch.setattr(app_module, 'execute_query', eq)
        assert auth_client.post('/patterns/1/delete').status_code == 302

    def test_patterns_delete_db_error_redirects(self, auth_client, monkeypatch):
        import app as app_module

        def eq(sql, params=None, fetch=True):
            low = sql.lower()
            if (
                'from users where id' in low
                or 'from users where username' in low
                or 'full_name from users' in low
            ):
                return [FAKE_USER_ROW]
            if 'select id, name from pattern where id' in low:
                return [{'id': 1, 'name': 'Alice Cowl'}]
            if 'update pattern set is_active = false where id' in low:
                raise RuntimeError('db failed')
            return []

        monkeypatch.setattr(app_module, 'execute_query', eq)

        resp = auth_client.post('/patterns/1/delete')
        assert resp.status_code == 302
        with auth_client.session_transaction() as sess:
            flashes = sess.get('_flashes', [])
        assert any('unable to delete pattern' in msg.lower() for _, msg in flashes)

    def test_users_delete_self_rejected(self, auth_client):
        # user id=1 cannot delete themselves
        resp = auth_client.post('/users/1/delete')
        assert resp.status_code == 302
        with auth_client.session_transaction() as sess:
            flashes = sess.get('_flashes', [])
        assert any('cannot delete' in msg.lower() for _, msg in flashes)

    def test_users_delete_other(self, auth_client):
        assert auth_client.post('/users/99/delete').status_code == 302

    def test_users_reset_totp(self, auth_client):
        assert auth_client.post('/users/99/reset_totp').status_code == 302


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------
def test_logout(auth_client):
    resp = auth_client.get('/logout')
    assert resp.status_code == 302
    assert '/login' in resp.headers['Location']


# ---------------------------------------------------------------------------
# Login route
# ---------------------------------------------------------------------------
class TestLoginRoute:
    def test_get_renders_form(self, client):
        resp = client.get('/login')
        assert resp.status_code == 200

    def test_invalid_credentials(self, client, monkeypatch):
        import app as app_module
        monkeypatch.setattr(app_module, 'execute_query', lambda *a, **kw: [])
        resp = client.post('/login', data={'username': 'nobody', 'password': 'bad'})
        assert resp.status_code == 200
        assert b'invalid' in resp.data.lower()

    def test_valid_credentials_trigger_email_otp(self, client, monkeypatch):
        from werkzeug.security import generate_password_hash

        import app as app_module
        row = dict(FAKE_USER_ROW, password_hash=generate_password_hash('secret123'))
        monkeypatch.setattr(app_module, 'execute_query',
                            lambda *a, **kw: [row] if 'from users' in a[0].lower() else [])
        monkeypatch.setattr(app_module, 'send_otp_email', lambda *a, **kw: None)
        resp = client.post('/login', data={'username': 'testadmin', 'password': 'secret123'})
        assert resp.status_code == 302
        assert '/mfa/verify' in resp.headers['Location']

    def test_already_authenticated_redirects_to_index(self, auth_client):
        resp = auth_client.get('/login')
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# MFA verify
# ---------------------------------------------------------------------------
class TestMfaVerify:
    def test_no_session_redirects_to_login(self, client):
        resp = client.get('/mfa/verify')
        assert resp.status_code == 302
        assert '/login' in resp.headers['Location']

    def test_get_with_session_renders_form(self, client):
        with client.session_transaction() as sess:
            sess['mfa_user_id'] = 1
            sess['mfa_method'] = 'email'
        assert client.get('/mfa/verify').status_code == 200

    def test_valid_email_otp_logs_in(self, client, monkeypatch):
        import app as app_module
        monkeypatch.setattr(app_module, 'execute_query', _user_eq())
        future = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        with client.session_transaction() as sess:
            sess['mfa_user_id'] = 1
            sess['mfa_method'] = 'email'
            sess['mfa_otp'] = '123456'
            sess['mfa_otp_expiry'] = future
        resp = client.post('/mfa/verify', data={'code': '123456'})
        assert resp.status_code == 302

    def test_invalid_email_otp_stays_on_page(self, client, monkeypatch):
        import app as app_module
        monkeypatch.setattr(app_module, 'execute_query', _user_eq())
        future = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        with client.session_transaction() as sess:
            sess['mfa_user_id'] = 1
            sess['mfa_method'] = 'email'
            sess['mfa_otp'] = '123456'
            sess['mfa_otp_expiry'] = future
        resp = client.post('/mfa/verify', data={'code': '000000'})
        assert resp.status_code == 200

    def test_expired_otp_redirects_to_login(self, client, monkeypatch):
        import app as app_module
        monkeypatch.setattr(app_module, 'execute_query', _user_eq())
        past = (datetime.utcnow() - timedelta(minutes=1)).isoformat()
        with client.session_transaction() as sess:
            sess['mfa_user_id'] = 1
            sess['mfa_method'] = 'email'
            sess['mfa_otp'] = '123456'
            sess['mfa_otp_expiry'] = past
        resp = client.post('/mfa/verify', data={'code': '123456'})
        assert resp.status_code == 302


# ---------------------------------------------------------------------------
# MFA TOTP setup
# ---------------------------------------------------------------------------
def test_mfa_setup_totp_get(auth_client):
    resp = auth_client.get('/mfa/setup/totp')
    assert resp.status_code == 200


def test_mfa_setup_totp_invalid_code(auth_client):
    import pyotp
    with auth_client.session_transaction() as sess:
        sess['totp_setup_secret'] = pyotp.random_base32()
    resp = auth_client.post('/mfa/setup/totp', data={'code': '000000'})
    assert resp.status_code == 200


def test_mfa_setup_totp_no_secret_in_session(auth_client):
    resp = auth_client.post('/mfa/setup/totp', data={'code': '123456'})
    assert resp.status_code == 302  # redirects back to setup with flash


# ---------------------------------------------------------------------------
# API — calculate_chart_dimensions
# ---------------------------------------------------------------------------
class TestApiCalculateChartDimensions:
    def test_missing_required_params(self, auth_client):
        resp = auth_client.post(
            '/api/calculate_chart_dimensions',
            json={'age_id': 1},
            content_type='application/json',
        )
        assert resp.status_code == 400
        assert b'missing' in resp.data.lower()

    def test_piece_not_found(self, auth_client, monkeypatch):
        import app as app_module

        def eq(sql, params=None, fetch=True):
            low = sql.lower()
            if 'from users where id' in low or 'full_name from users' in low:
                return [FAKE_USER_ROW]
            return []   # piece lookup returns nothing

        monkeypatch.setattr(app_module, 'execute_query', eq)
        resp = auth_client.post(
            '/api/calculate_chart_dimensions',
            json={'piece_id': 1, 'age_id': 1, 'pattern_id': 1, 'gender_id': 1},
            content_type='application/json',
        )
        assert resp.status_code == 404

    def test_dmn_file_missing_returns_400(self, auth_client, monkeypatch):
        import app as app_module

        def eq(sql, params=None, fetch=True):
            low = sql.lower()
            if 'from users where id' in low or 'full_name from users' in low:
                return [FAKE_USER_ROW]
            if 'from piece where id' in low:
                return [{'name': 'Front Body'}]
            return []

        monkeypatch.setattr(app_module, 'execute_query', eq)
        with patch('app.os.path.exists', return_value=False):
            resp = auth_client.post(
                '/api/calculate_chart_dimensions',
                json={'piece_id': 1, 'age_id': 1, 'pattern_id': 1, 'gender_id': 1},
                content_type='application/json',
            )
        assert resp.status_code == 400
