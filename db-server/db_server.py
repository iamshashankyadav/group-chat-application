"""
SQLite REST Database Server
===========================
Exposes a thin HTTP API around a local SQLite database.
All 3 chat backends point to this server via DB_SERVER_URL.

Endpoints:
  POST   /messages               — upsert a message (dedup by id)
  GET    /messages?room=&limit=  — retrieve messages (oldest-first)
  PUT    /user_keys/{username}   — upsert a user's Ed25519 public key
  GET    /user_keys/{username}   — fetch a user's public key

Environment variables:
  SQLITE_DB_PATH   — path to the SQLite file  (default: chat.db)
  DB_SERVER_PORT   — port to listen on        (default: 5500)
"""

import os
import sqlite3
import threading
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_PATH = os.environ.get('SQLITE_DB_PATH', 'chat.db')
PORT    = int(os.environ.get('DB_SERVER_PORT', '5500'))

# ---------------------------------------------------------------------------
# Database — single shared connection with WAL mode for concurrent reads
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_conn: sqlite3.Connection = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        # WAL mode: allows concurrent readers while a writer is active
        _conn.execute('PRAGMA journal_mode=WAL')
        _conn.execute('PRAGMA synchronous=NORMAL')
        _conn.execute('PRAGMA cache_size=-32000')   # 32 MB page cache
        _conn.commit()
    return _conn


def _init_schema() -> None:
    with _lock:
        conn = _get_conn()
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS messages (
                id          TEXT PRIMARY KEY,
                room_id     TEXT    NOT NULL DEFAULT "general",
                sender      TEXT    NOT NULL DEFAULT "anonymous",
                ciphertext  TEXT    NOT NULL DEFAULT "",
                nonce       TEXT    NOT NULL DEFAULT "",
                signature   TEXT    NOT NULL DEFAULT "",
                timestamp   INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_room_ts
                ON messages (room_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_ts
                ON messages (timestamp DESC);

            CREATE TABLE IF NOT EXISTS user_keys (
                username    TEXT PRIMARY KEY,
                public_key  TEXT NOT NULL
            );
        ''')
        conn.commit()
    print(f'[db_server] SQLite database ready: {os.path.abspath(DB_PATH)}')


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title='SQLite DB Server', version='1.0')


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class MessageIn(BaseModel):
    id:         str
    room_id:    str  = 'general'
    sender:     str  = 'anonymous'
    ciphertext: str  = ''
    nonce:      str  = ''
    signature:  str  = ''
    timestamp:  int  = 0


class UserKeyIn(BaseModel):
    public_key: str


# ---------------------------------------------------------------------------
# Routes — Messages
# ---------------------------------------------------------------------------
@app.post('/messages', status_code=201)
def upsert_message(msg: MessageIn):
    """Insert or replace a message (deduplication on primary key `id`)."""
    with _lock:
        conn = _get_conn()
        conn.execute(
            '''
            INSERT OR REPLACE INTO messages
                (id, room_id, sender, ciphertext, nonce, signature, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (msg.id, msg.room_id, msg.sender,
             msg.ciphertext, msg.nonce, msg.signature, msg.timestamp),
        )
        conn.commit()
    return {'ok': True, 'id': msg.id}


@app.get('/messages')
def get_messages(room: Optional[str] = None, limit: int = 50):
    """
    Return up to `limit` messages, oldest-first.
    Optionally filter by `room`.
    """
    with _lock:
        conn = _get_conn()
        if room:
            cursor = conn.execute(
                '''
                SELECT * FROM messages
                WHERE room_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                ''',
                (room, limit),
            )
        else:
            cursor = conn.execute(
                '''
                SELECT * FROM messages
                ORDER BY timestamp DESC
                LIMIT ?
                ''',
                (limit,),
            )
        rows = [dict(r) for r in cursor.fetchall()]

    # Reverse so that response is oldest → newest
    return list(reversed(rows))


# ---------------------------------------------------------------------------
# Routes — User Keys
# ---------------------------------------------------------------------------
@app.put('/user_keys/{username}', status_code=200)
def upsert_user_key(username: str, body: UserKeyIn):
    """Insert or replace the Ed25519 public key for a user."""
    uname = username.lower()
    with _lock:
        conn = _get_conn()
        conn.execute(
            'INSERT OR REPLACE INTO user_keys (username, public_key) VALUES (?, ?)',
            (uname, body.public_key),
        )
        conn.commit()
    return {'ok': True, 'username': uname}


@app.get('/user_keys/{username}')
def get_user_key(username: str):
    """Fetch the Ed25519 public key for a user."""
    uname = username.lower()
    with _lock:
        conn = _get_conn()
        row = conn.execute(
            'SELECT public_key FROM user_keys WHERE username = ?',
            (uname,),
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail='Key not found')
    return {'username': uname, 'public_key': row['public_key']}


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get('/health')
def health():
    return {'status': 'ok', 'db': os.path.abspath(DB_PATH)}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    _init_schema()
    print(f'[db_server] Listening on 0.0.0.0:{PORT}')
    uvicorn.run('db_server:app', host='0.0.0.0', port=PORT, log_level='warning')
