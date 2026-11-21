"""
DB Sentinel — Database Connection & Query Execution Helper
Uses mysql.connector with connection pooling for thread-safe high performance.
"""

import mysql.connector
from mysql.connector import pooling

_pool = None


def init_db(app):
    """Initialize the connection pool from Flask app config."""
    global _pool
    # If already initialized and connected, return existing pool
    if _pool is not None:
        return
    _pool = pooling.MySQLConnectionPool(
        pool_name="db_sentinel_pool",
        pool_size=5,
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB'],
        port=app.config['MYSQL_PORT'],
        autocommit=True,
    )


def get_db():
    """Return a connection from the pool."""
    global _pool
    if _pool is None:
        try:
            from flask import current_app
            if current_app:
                init_db(current_app)
        except Exception as e:
            raise RuntimeError(
                f"Database connection failed: {e}. "
                "Ensure MySQL is running (e.g., 'net start MySQL80') and run 'python database/setup.py --reset'."
            ) from e
    if _pool is None:
        raise RuntimeError(
            "Database pool not initialized. "
            "Ensure MySQL is running (e.g., 'net start MySQL80') and run 'python database/setup.py --reset'."
        )
    return _pool.get_connection()


def close_db(conn):
    """Return a connection to the pool."""
    if conn and conn.is_connected():
        conn.close()


def execute_query(query, params=None, fetch=True):
    """Execute a query and optionally fetch results as list of dicts."""
    conn = get_db()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        if fetch:
            result = cursor.fetchall()
        else:
            conn.commit()
            result = cursor.lastrowid
        cursor.close()
        return result
    finally:
        close_db(conn)
