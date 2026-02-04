import os
import psycopg2
from psycopg2.extras import execute_values

def pg_conn():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=os.getenv("POSTGRES_DB", "cyber"),
        user=os.getenv("POSTGRES_USER", "cyber_user"),
        password=os.getenv("POSTGRES_PASSWORD", "cyber_pass"),
    )

def upsert_rows(conn, table, columns, rows, conflict_cols):
    """
    Generic UPSERT helper. rows is list of tuples matching columns.
    """
    if not rows:
        return 0
    cols_sql = ", ".join(columns)
    conflict_sql = ", ".join(conflict_cols)
    update_sql = ", ".join([f"{c}=EXCLUDED.{c}" for c in columns if c not in conflict_cols])

    sql = f"""
        INSERT INTO {table} ({cols_sql})
        VALUES %s
        ON CONFLICT ({conflict_sql})
        DO UPDATE SET {update_sql}
    """
    with conn.cursor() as cur:
        execute_values(cur, sql, rows, page_size=1000)
    conn.commit()
    return len(rows)
