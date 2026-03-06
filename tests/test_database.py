from unittest import mock

import pytest

import database


def test_get_db_connection(monkeypatch):
    # Patch psycopg.connect to avoid real DB connection
    with mock.patch('database.psycopg.connect') as mock_connect:
        conn = database.get_db_connection()
        assert mock_connect.called
        assert conn == mock_connect.return_value

def test_execute_query_select(monkeypatch):
    # Patch get_db_connection and cursor
    mock_conn = mock.MagicMock()
    mock_cursor = mock.MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.description = True
    mock_cursor.fetchall.return_value = [{'id': 1}]
    monkeypatch.setattr(database, 'get_db_connection', lambda: mock_conn)
    result = database.execute_query('SELECT 1', fetch=True)
    assert result == [{'id': 1}]
    assert mock_cursor.execute.called
    assert mock_cursor.close.called
    assert mock_conn.close.called
