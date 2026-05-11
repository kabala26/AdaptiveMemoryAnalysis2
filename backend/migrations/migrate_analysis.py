#!/usr/bin/env python3
"""
Migration: add analysis pipeline tables (memory_dumps, features, ml_models, results).

Safe to run multiple times — all CREATE TABLE statements use IF NOT EXISTS.
The existing users table is never touched.

Usage:
    python backend/migrations/migrate_analysis.py
"""

import os
import re
import sys
import psycopg2
from dotenv import load_dotenv

load_dotenv()

SQL_FILE = os.path.join(os.path.dirname(__file__), 'add_analysis_tables.sql')

EXPECTED_TABLES = ['memory_dumps', 'features', 'ml_models', 'results']


def parse_database_url(url: str):
    match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', url)
    if not match:
        raise ValueError(
            f'DATABASE_URL format not recognised. '
            f'Expected postgresql://user:pass@host:port/dbname, got: {url!r}'
        )
    user, password, host, port, database = match.groups()
    return dict(host=host, port=int(port), database=database, user=user, password=password)


def table_exists(cursor, table_name: str) -> bool:
    cursor.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = 'public' AND table_name = %s",
        (table_name,)
    )
    return cursor.fetchone() is not None


def run_migration():
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print('ERROR: DATABASE_URL environment variable is not set.')
        sys.exit(1)

    try:
        conn_params = parse_database_url(db_url)
    except ValueError as exc:
        print(f'ERROR: {exc}')
        sys.exit(1)

    print(f"Connecting to PostgreSQL at {conn_params['host']}:{conn_params['port']} "
          f"/ {conn_params['database']} ...")

    try:
        conn = psycopg2.connect(**conn_params)
        conn.autocommit = False
        cursor = conn.cursor()
    except psycopg2.OperationalError as exc:
        print(f'ERROR: Could not connect to database: {exc}')
        sys.exit(1)

    # Verify the users table exists before proceeding so FKs won't fail
    if not table_exists(cursor, 'users'):
        print('ERROR: users table not found. Run the main schema migration first.')
        conn.close()
        sys.exit(1)

    # Report pre-migration state
    print('\nPre-migration table status:')
    for tbl in EXPECTED_TABLES:
        exists = table_exists(cursor, tbl)
        print(f'  {tbl:<20} {"already exists — will skip" if exists else "missing — will create"}')

    # Load and execute the SQL file
    with open(SQL_FILE, 'r') as f:
        sql = f.read()

    try:
        cursor.execute(sql)
        conn.commit()
    except psycopg2.Error as exc:
        conn.rollback()
        print(f'\nERROR: Migration failed, transaction rolled back.\n{exc}')
        cursor.close()
        conn.close()
        sys.exit(1)

    # Report post-migration state
    print('\nPost-migration table status:')
    all_ok = True
    for tbl in EXPECTED_TABLES:
        exists = table_exists(cursor, tbl)
        status = 'OK' if exists else 'MISSING (unexpected)'
        print(f'  {tbl:<20} {status}')
        if not exists:
            all_ok = False

    cursor.close()
    conn.close()

    if all_ok:
        print('\nMigration completed successfully.')
    else:
        print('\nWARNING: One or more tables are still missing after migration.')
        sys.exit(1)


if __name__ == '__main__':
    run_migration()
