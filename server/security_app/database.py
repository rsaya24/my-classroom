"""SQLite locally; PostgreSQL for persistent multi-instance deployments.

This adapter supports only this application's fixed SQL, not arbitrary SQLite SQL.
The global transaction lock preserves the demo's SQLite writer serialization for
deduplication/queue claims. It is intentionally a low-volume prototype design.
"""
import re
import sqlite3


class Row(dict):
    def __getitem__(self, key):
        return tuple(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


class Result:
    def __init__(self, cursor, lastrowid=None):
        self.cursor = cursor
        self.lastrowid = lastrowid

    def fetchone(self):
        row = self.cursor.fetchone()
        return Row(row) if row is not None else None

    def fetchall(self):
        return [Row(row) for row in self.cursor.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


def postgres_sql(sql):
    # All SQL statements originate in source code; values remain bound parameters.
    sql = re.sub(r'\bid INTEGER PRIMARY KEY\b', 'id BIGSERIAL PRIMARY KEY', sql)
    sql = re.sub(r'\bREAL\b', 'DOUBLE PRECISION', sql)
    return sql.replace('?', '%s')


class Postgres:
    def __init__(self, url):
        import psycopg
        from psycopg.rows import dict_row
        self.driver = psycopg
        self.connection = psycopg.connect(url, autocommit=True, row_factory=dict_row,
                                         connect_timeout=10)
        self.in_transaction = False

    def begin(self):
        if not self.in_transaction:
            self.connection.execute('BEGIN')
            self.in_transaction = True
            self.connection.execute("SET LOCAL lock_timeout = '10s'")
            self.connection.execute("SET LOCAL statement_timeout = '20s'")
            self.connection.execute('SELECT pg_advisory_xact_lock(74190263)')

    def execute(self, sql, params=()):
        if sql.strip().upper() == 'BEGIN IMMEDIATE':
            self.begin()
            return None
        write = sql.lstrip().split()[0].upper() in {'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER'}
        if write:
            self.begin()
        converted = postgres_sql(sql)
        returning = bool(re.match(r'\s*INSERT INTO (users|alerts)\b', sql, re.I))
        if returning:
            converted = converted.rstrip(';') + ' RETURNING id'
        try:
            cursor = self.connection.execute(converted, params)
        except self.driver.IntegrityError as error:
            raise sqlite3.IntegrityError('Database constraint failed') from error
        return Result(cursor, cursor.fetchone()['id'] if returning else None)

    def executescript(self, script):
        for sql in script.split(';'):
            if sql.strip():
                self.execute(sql)

    def commit(self):
        if self.in_transaction:
            self.connection.execute('COMMIT')
            self.in_transaction = False

    def rollback(self):
        if self.in_transaction:
            self.connection.execute('ROLLBACK')
            self.in_transaction = False

    def close(self):
        self.connection.close()  # PostgreSQL rolls back any unfinished transaction.


def connect(config):
    if config.get('DATABASE_URL'):
        return Postgres(config['DATABASE_URL'])
    connection = sqlite3.connect(config['DATABASE'], timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA journal_mode=WAL')
    return connection


def initialize(connection, script, postgres=False):
    connection.executescript(script)
    if postgres:
        connection.execute('ALTER TABLE notifications ADD COLUMN IF NOT EXISTS claim_token TEXT')
        connection.execute('ALTER TABLE notifications ADD COLUMN IF NOT EXISTS lease_until DOUBLE PRECISION DEFAULT 0')
    else:
        columns = {row['name'] for row in connection.execute('PRAGMA table_info(notifications)')}
        for column, kind in [('claim_token', 'TEXT'), ('lease_until', 'REAL DEFAULT 0')]:
            if column not in columns:
                connection.execute(f'ALTER TABLE notifications ADD COLUMN {column} {kind}')
    connection.commit()
