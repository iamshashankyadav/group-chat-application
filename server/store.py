"""
store.py — Message & Key Storage via SQLite REST DB Server
==========================================================
All persistence is delegated to a lightweight SQLite REST server
running on the LAN (db_server.py).  No direct MongoDB dependency.

Configuration (env vars):
  DB_SERVER_URL  — base URL of the db_server  (default: http://127.0.0.1:5500)

The HTTP client uses keep-alive connection pooling, so the per-request
overhead is just one round-trip (~1-5 ms on LAN vs ~100-200 ms for Atlas).
"""

import os
from typing import Dict, Any, List, Optional

import httpx
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519

from server import crypto

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DB_SERVER_URL: str = os.environ.get('DB_SERVER_URL', 'http://127.0.0.1:5500')

# Persistent HTTP client — connection-pooled, keep-alive, thread-safe
_http = httpx.Client(base_url=DB_SERVER_URL, timeout=10.0)

# In-process public-key cache — avoids a round-trip for repeat senders
_user_keys_cache: Dict[str, ed25519.Ed25519PublicKey] = {}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _to_bytes(val) -> bytes:
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        try:
            return bytes.fromhex(val)
        except ValueError:
            return val.encode('utf-8')
    return bytes(val)


def _to_hex(val) -> str:
    if isinstance(val, bytes):
        return val.hex()
    return str(val)


def _decode_row(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decrypt + verify a raw message row returned by the DB server.
    Returns a dict suitable for /feed and /history responses.
    """
    msg_id    = doc['id']
    sender    = doc.get('sender', 'Anonymous')
    r_id      = doc.get('room_id', 'general')
    timestamp = doc.get('timestamp', 0)
    ciphertext = _to_bytes(doc.get('ciphertext', ''))
    nonce      = _to_bytes(doc.get('nonce', ''))
    signature  = _to_bytes(doc.get('signature', ''))

    pub_key = get_user_public_key(sender)
    signable_payload = crypto.make_signable_payload(
        msg_id, r_id, sender, timestamp, nonce, ciphertext
    )

    # Verify Ed25519 signature
    signature_valid = False
    if pub_key:
        signature_valid = crypto.verify_signature(pub_key, signature, signable_payload)

    # Decrypt AES-GCM ciphertext
    decrypted_text = None
    decryption_valid = False
    try:
        decrypted_text = crypto.decrypt_message(ciphertext, nonce)
        decryption_valid = True
    except InvalidTag:
        decrypted_text = '[TAMPERED: AES-GCM Integrity Check Failed]'
    except Exception as exc:
        decrypted_text = f'[DECRYPTION ERROR: {exc}]'

    if not signature_valid and decryption_valid:
        decrypted_text = f'[UNVERIFIED SIGNATURE] {decrypted_text}'

    is_tampered = not (signature_valid and decryption_valid)

    return {
        'id':          msg_id,
        'client-name': sender,
        'username':    sender,
        'msg':         decrypted_text,
        'text':        decrypted_text,
        'room':        r_id,
        'timestamp':   timestamp,
        'verified':    not is_tampered,
        'tampered':    is_tampered,
    }


# ---------------------------------------------------------------------------
# User public keys
# ---------------------------------------------------------------------------
def save_user_public_key(username: str, public_key_bytes: bytes) -> None:
    """Upsert a user's Ed25519 public key into the DB server and local cache."""
    uname = username.lower()
    # Update in-process cache first
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        _user_keys_cache[uname] = pub
    except Exception:
        pass

    try:
        _http.put(f'/user_keys/{uname}', json={'public_key': _to_hex(public_key_bytes)})
    except Exception:
        pass  # Non-fatal — cache will still serve future lookups


def get_user_public_key(username: str) -> Optional[ed25519.Ed25519PublicKey]:
    """
    Lookup priority:
      1. In-process cache
      2. DB server  (GET /user_keys/{username})
      3. Local disk keystore via crypto module (fallback / generates new key)
    """
    uname = username.lower()

    # 1. Cache hit
    if uname in _user_keys_cache:
        return _user_keys_cache[uname]

    # 2. DB server lookup
    try:
        resp = _http.get(f'/user_keys/{uname}')
        if resp.status_code == 200:
            data = resp.json()
            raw_bytes = _to_bytes(data['public_key'])
            pub = ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)
            _user_keys_cache[uname] = pub
            return pub
    except Exception:
        pass

    # 3. Fallback: generate / load from local disk keystore
    _, pub = crypto.get_or_create_sender_keys(username)
    _user_keys_cache[uname] = pub
    return pub


# ---------------------------------------------------------------------------
# Message storage
# ---------------------------------------------------------------------------
def save_message(
    msg_id: str,
    room_id: str,
    sender: str,
    ciphertext: bytes,
    nonce: bytes,
    signature: bytes,
    timestamp: int,
) -> None:
    """POST a message to the DB server (upsert — dedup on `id`)."""
    _http.post('/messages', json={
        'id':         msg_id,
        'room_id':    room_id,
        'sender':     sender,
        'ciphertext': _to_hex(ciphertext),
        'nonce':      _to_hex(nonce),
        'signature':  _to_hex(signature),
        'timestamp':  timestamp,
    })


def append_message(
    room_id: str,
    msg: Dict[str, Any],
    sender_private_key: Optional[ed25519.Ed25519PrivateKey] = None,
) -> Dict[str, Any]:
    """
    Encrypt, sign, and durably store a message.
    Returns a dict that the API can return directly to the caller.
    """
    msg_id    = msg['id']
    sender    = msg.get('username') or msg.get('from')
    text      = msg['text']
    timestamp = msg['timestamp']

    # Resolve sender keys
    if sender_private_key is None:
        sender_private_key, sender_pub = crypto.get_or_create_sender_keys(sender)
    else:
        sender_pub = sender_private_key.public_key()

    save_user_public_key(sender, sender_pub.public_bytes_raw())

    # 1. Encrypt (AES-GCM 256)
    ciphertext, nonce = crypto.encrypt_message(text)

    # 2. Sign (Ed25519)
    signable_payload = crypto.make_signable_payload(
        msg_id, room_id, sender, timestamp, nonce, ciphertext
    )
    signature = crypto.sign_message(sender_private_key, signable_payload)

    # 3. Store via DB server (POST /messages)
    save_message(msg_id, room_id, sender, ciphertext, nonce, signature, timestamp)

    return {
        'id':        msg_id,
        'room':      room_id,
        'username':  sender,
        'text':      text,
        'timestamp': timestamp,
        'verified':  True,
    }


# ---------------------------------------------------------------------------
# Message retrieval
# ---------------------------------------------------------------------------
def get_history(room_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Fetch the last `limit` messages for a room, decrypted and verified."""
    try:
        resp = _http.get('/messages', params={'room': room_id, 'limit': limit})
        rows = resp.json()
    except Exception:
        return []

    return [_decode_row(doc) for doc in rows]


def get_feed(room_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Fetch the last `limit` messages across all rooms (or a specific room),
    decrypted and signature-verified, returned oldest-first.
    """
    params: Dict[str, Any] = {'limit': limit}
    if room_id:
        params['room'] = room_id

    try:
        resp = _http.get('/messages', params=params)
        rows = resp.json()
    except Exception:
        return []

    return [_decode_row(doc) for doc in rows]