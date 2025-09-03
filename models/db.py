from flask import current_app, g
import mysql.connector

def get_db_connection():
    cfg = current_app.config

    # Coerce/ensure sane defaults so mysql.connector never sees None
    host = cfg.get("MYSQL_HOST") or "127.0.0.1"
    user = cfg.get("MYSQL_USER") or "root"
    password = cfg.get("MYSQL_PASSWORD") or ""
    database = cfg.get("MYSQL_DB") or "khepgaming"
    port = cfg.get("MYSQL_PORT") or 3306

    conn = mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        port=int(port),   # <= make sure it’s an int
        autocommit=True,
    )
    return conn

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass
