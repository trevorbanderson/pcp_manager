def test_404(client):
    resp = client.get('/nonexistent')
    assert resp.status_code == 404

def test_500(client, monkeypatch):
    # Log in as a test user to avoid redirect (Flask-Login uses _user_id)
    with client.session_transaction() as sess:
        sess['_user_id'] = '1'  # Use a valid user id string
    # Ensure exceptions are handled as 500 errors
    client.application.config['PROPAGATE_EXCEPTIONS'] = False
    resp = client.get('/fail')
    assert resp.status_code == 500
