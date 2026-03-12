import psycopg
from psycopg.rows import dict_row

import pcp_logger as _pcp_logger
from config import Config

_log = _pcp_logger.get_logger("database")

def get_db_connection():
    """Create and return a database connection."""
    import os
    sslmode = os.getenv('DB_SSLMODE', 'require')   # 'require' for Azure; 'disable' for local dev
    _log.debug(f"DB_SSLMODE at connect: {sslmode}")
    conn = psycopg.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        dbname=Config.DB_NAME,
        user=Config.DB_USER,
        password=Config.get_db_password(),
        sslmode=sslmode,
        row_factory=dict_row,
        autocommit=False,
    )
    return conn

def execute_query(query, params=None, fetch=True):
    """Execute a query and return results."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(query, params)
        # Only fetch rows when the statement produced a result set (SELECT).
        # INSERT/UPDATE/DELETE set cur.description to None.
        if fetch and cur.description is not None:
            result = cur.fetchall()
        else:
            result = None
        conn.commit()
        _log.debug(
            "Query executed",
            extra={
                "query_preview": (query[:120] + "…") if len(query) > 120 else query,
                "row_count":     len(result) if result is not None else None,
            },
        )
        return result
    except Exception as e:
        conn.rollback()
        _log.error(
            f"Database error: {e}",
            extra={
                "query_preview": (query[:120] + "…") if len(query) > 120 else query,
            },
            exc_info=True,
        )
        raise e
    finally:
        cur.close()
        conn.close()
