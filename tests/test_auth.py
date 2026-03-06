from unittest import mock

def test_login_requires_username_and_password(client):
    # Mock DB so the login route can render the form without a real DB connection
    with mock.patch('database.execute_query', return_value=[]):
        resp = client.post('/login', data={})
    assert resp.status_code == 200
    assert b'username' in resp.data.lower()
    assert b'password' in resp.data.lower()
