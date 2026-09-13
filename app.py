import asyncio
import mimetypes
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket
from fastapi.responses import FileResponse, Response

from server import config, logger, store
from server.rooms import RoomManager
from server.ws_server import WSServer
room_manager = RoomManager(logger)
ws_server = WSServer(room_manager, logger)


@asynccontextmanager
async def lifespan(application: FastAPI):
    # startup
    logger.log(
        'server_start',
        port=config.PORT,
        rooms=config.DEFAULT_ROOMS,
        admins=config.ADMIN_USERNAMES,
    )
    print('\nGroup Chat server running (FastAPI):')
    print(f'  Local:   http://localhost:{config.PORT}')
    print(f'  Network: http://<this-machine-IP>:{config.PORT}  (use for other lab machines)')
    print(f'  Admins:  {", ".join(config.ADMIN_USERNAMES)} (set ADMIN_USERNAMES env var to change)\n')

    yield  # application runs here

    #  shutdown 
    logger.log('servr_shutdown', signal='lifespan')
    ws_server.shutdown()
    # Give in-flight sends a moment to complete before uvicorn closes sockets.
    await asyncio.sleep(0.5)


#inializaing the app here
app = FastAPI(lifespan=lifespan, title='Group Chat')

# Enable CORS for all origins
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
import time
import uuid

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# ---------------------------------------------------------------------------
# Required API Routes
# ---------------------------------------------------------------------------

@app.post('/message')
async def post_message(request: Request):
    """
    Accepts 'client-name' and 'msg' as input and submits a message.
    Supports JSON, Form Data, or Query Parameters.
    Enforces deduplication on message ID, stores encrypted & signed in MongoDB,
    and broadcasts to active WebSocket clients.
    """
    data = {}
    content_type = request.headers.get('content-type', '')
    if 'application/json' in content_type:
        try:
            data = await request.json()
        except Exception:
            data = {}
    elif 'application/x-www-form-urlencoded' in content_type or 'multipart/form-data' in content_type:
        form = await request.form()
        data = dict(form)
    else:
        # Fallback: try parsing JSON, if fail ignore
        try:
            data = await request.json()
        except Exception:
            data = {}

    client_name = (
        data.get('client-name')
        or data.get('client_name')
        or data.get('username')
        or data.get('sender')
        or request.query_params.get('client-name')
        or request.query_params.get('client_name')
        or request.query_params.get('username')
        or 'Anonymous'
    )
    msg_text = (
        data.get('msg')
        or data.get('text')
        or data.get('message')
        or request.query_params.get('msg')
        or request.query_params.get('text')
        or request.query_params.get('message')
        or ''
    )

    if not msg_text:
        return JSONResponse({'error': 'Message content cannot be empty'}, status_code=400)

    msg_id = data.get('id') or data.get('msg_id') or request.query_params.get('id') or str(uuid.uuid4())
    room = data.get('room') or request.query_params.get('room') or config.DEFAULT_ROOMS[0]
    
    try:
        timestamp = int(data.get('timestamp') or request.query_params.get('timestamp') or int(time.time() * 1000))
    except Exception:
        timestamp = int(time.time() * 1000)

    msg_obj = {
        'id': msg_id,
        'username': str(client_name).strip()[:config.MAX_USERNAME_LEN],
        'text': str(msg_text).strip()[:config.MAX_MESSAGE_LEN],
        'room': room,
        'timestamp': timestamp,
    }

    # Encrypt (AES-GCM), Sign (Ed25519), and Store in MongoDB (dedup on _id)
    saved = store.append_message(room, msg_obj)

    # Real-time WebSocket broadcast to room
    room_manager.broadcast(room, {'type': 'message', **msg_obj})

    return {
        'status': 'ok',
        'id': msg_id,
        'client-name': msg_obj['username'],
        'username': msg_obj['username'],
        'msg': msg_obj['text'],
        'text': msg_obj['text'],
        'room': room,
        'timestamp': msg_obj['timestamp'],
        'verified': saved.get('verified', True),
    }


@app.get('/feed')
async def get_feed_route(room: str = None, limit: int = 50):
    """
    Retrieves the last `limit` messages (default 50), decrypted and verified.
    Optionally filter by `room`. Results are returned oldest-first.
    """
    return store.get_feed(room_id=room, limit=limit)


# ---------------------------------------------------------------------------
# WebSocket route
# ---------------------------------------------------------------------------
@app.websocket('/ws')
async def ws_route(ws: WebSocket):
    await ws_server.handle_connection(ws)

_PUBLIC = Path(__file__).parent / 'public'

#routes for frintend laoding
@app.get('/')
async def index():
    return FileResponse(_PUBLIC / 'index.html')


@app.get('/{filename:path}')
async def static_file(filename: str):
    """Serve any file under public/; path traversal is prevented
    by resolving the full path and confirming it stays inside _PUBLIC."""
    target = (_PUBLIC / filename).resolve()
    # Guard against path traversal (e.g. ../../etc/passwd)
    if not str(target).startswith(str(_PUBLIC.resolve())):
        return Response(status_code=403)
    if target.is_file():
        mime, _ = mimetypes.guess_type(str(target))
        return FileResponse(target, media_type=mime or 'application/octet-stream')
    # Fall back to index.html for unknown paths (SPA-style)
    return FileResponse(_PUBLIC / 'index.html')

# Entry point

if __name__ == '__main__':
    uvicorn.run(
        'app:app',
        host='0.0.0.0',
        port=config.PORT,
        # ws_ping_interval / ws_ping_timeout: uvicorn sends WebSocket
        # ping frames automatically — replaces flask-sock's
        # SOCK_SERVER_OPTIONS ping_interval.
        ws_ping_interval=config.HEARTBEAT_INTERVAL_MS / 1000,
        ws_ping_timeout=config.HEARTBEAT_INTERVAL_MS / 1000,
        log_level='warning',   # suppress uvicorn access logs; we have our own
    )