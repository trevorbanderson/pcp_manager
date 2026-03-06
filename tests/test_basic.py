def test_homepage(client):
    resp = client.get('/')
    assert resp.status_code in (200, 302)  # 302 if login required

def test_login_page(client):
    resp = client.get('/login')
    assert resp.status_code == 200
    assert b'login' in resp.data.lower()
