def test_login_requires_username_and_password(client):
    resp = client.post('/login', data={})
    assert resp.status_code == 200
    assert b'username' in resp.data.lower()
    assert b'password' in resp.data.lower()
