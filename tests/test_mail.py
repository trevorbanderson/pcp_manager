from unittest import mock

import app
from config import Config


def test_send_otp_email(monkeypatch):
    # Patch smtplib.SMTP to avoid real email
    with mock.patch('smtplib.SMTP') as mock_smtp:
        monkeypatch.setattr(Config, 'get_mail_password', lambda: 'pw')
        monkeypatch.setattr(Config, 'MAIL_FROM', 'from@example.com')
        monkeypatch.setattr(Config, 'MAIL_SERVER', 'smtp.example.com')
        monkeypatch.setattr(Config, 'MAIL_PORT', 587)
        monkeypatch.setattr(Config, 'MAIL_USE_TLS', True)
        monkeypatch.setattr(Config, 'MAIL_USERNAME', 'user')
        app.send_otp_email('to@example.com', '123456')
        assert mock_smtp.called
        instance = mock_smtp.return_value.__enter__.return_value
        assert instance.sendmail.called
