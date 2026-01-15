import os
import secrets
import json
import aiofiles
import sqlite3
import hashlib
from datetime import datetime, timedelta
from aiohttp import web
from aiohttp.web import WSMsgType
import pandas as pd
import base64

# --- FOLDERS ---
STATIC_DIR = "static"
UPLOAD_DIR = "uploads"
RECORDING_DIR = "recordings"
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RECORDING_DIR, exist_ok=True)

# --- DATABASE SETUP ---
DB_FILE = "database.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        session_token TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS meetings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        host_id INTEGER,
        start_time DATETIME,
        end_time DATETIME,
        title TEXT,
        host_password_hash TEXT,  -- NEW: Store hashed host password
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(host_id) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS participants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        meeting_id INTEGER,
        name TEXT,
        join_time DATETIME,
        role TEXT DEFAULT 'participant',
        FOREIGN KEY(meeting_id) REFERENCES meetings(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT,
        expires DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS recordings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        meeting_id INTEGER,
        filename TEXT,
        uploaded_at DATETIME,
        FOREIGN KEY(meeting_id) REFERENCES meetings(id))''')
    conn.commit()
    conn.close()


init_db()

# --- GLOBAL VARIABLES ---
rooms = {}  # active WebSocket rooms
registered_rooms = {}  # meetings created (code → info)


# --- HELPERS ---
def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def get_user_by_email(email):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, full_name, password_hash FROM users WHERE email=?", (email,))
    row = c.fetchone()
    conn.close()
    return row  # (id, full_name, password_hash) or None


def get_user_by_token(token):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, full_name FROM users WHERE session_token=?", (token,))
    row = c.fetchone()
    conn.close()
    return row  # (id, full_name) or None


def get_meeting_by_code(code):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, start_time, title, end_time, host_id, host_password_hash FROM meetings WHERE code=?", (code,))
    row = c.fetchone()
    conn.close()
    return row  # (id, start_time, title, end_time, host_id, host_password_hash) or None


def get_user_meetings(user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        """SELECT code, title, start_time, end_time, created_at FROM meetings WHERE host_id=? ORDER BY created_at DESC""",
        (user_id,))
    rows = c.fetchall()
    conn.close()
    return rows


# --- ROUTES ---
async def index(request):
    return web.FileResponse(os.path.join(STATIC_DIR, "index.html"))


async def signup_handler(request):
    data = await request.json()
    email = data.get('email', '').strip().lower()
    password = data.get('password')
    full_name = data.get('full_name', '').strip()
    if not all([email, password, full_name]):
        return web.json_response({"error": "All fields required"}, status=400)
    if get_user_by_email(email):
        return web.json_response({"error": "Email already exists"}, status=400)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO users (email, password_hash, full_name) VALUES (?, ?, ?)",
              (email, hash_password(password), full_name))
    conn.commit()
    conn.close()
    return web.json_response({"success": True, "message": "Account created!"})


async def login_handler(request):
    data = await request.json()
    email = data.get('email', '').strip().lower()
    password = data.get('password')
    user = get_user_by_email(email)
    if not user or user[2] != hash_password(password):
        return web.json_response({"error": "Invalid credentials"}, status=401)
    token = secrets.token_hex(32)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE users SET session_token = ? WHERE id = ?", (token, user[0]))
    conn.commit()
    conn.close()
    return web.json_response({"success": True, "token": token, "name": user[1], "user_id": user[0]})


async def forgot_password_handler(request):
    data = await request.json()
    email = data.get('email', '').strip().lower()
    user = get_user_by_email(email)
    if not user:
        return web.json_response({"error": "Email not found"}, status=404)
    token = secrets.token_hex(16)
    expires = datetime.now() + timedelta(hours=1)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO password_resets (user_id, token, expires) VALUES (?, ?, ?)", (user[0], token, expires))
    conn.commit()
    conn.close()
    return web.json_response({"success": True, "reset_token": token})


async def reset_password_handler(request):
    data = await request.json()
    token = data.get('token')
    new_pw = data.get('new_password')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT user_id FROM password_resets WHERE token=? AND expires > DATETIME('now')", (token,))
    row = c.fetchone()
    if not row:
        conn.close()
        return web.json_response({"error": "Invalid or expired token"}, status=400)
    c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_pw), row[0]))
    c.execute("DELETE FROM password_resets WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return web.json_response({"success": True, "message": "Password reset successful!"})


async def create_meeting(request):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return web.json_response({"error": "Unauthorized"}, status=401)
    token = auth_header.split(' ')[1]
    user = get_user_by_token(token)
    if not user:
        return web.json_response({"error": "Invalid session"}, status=401)

    data = await request.json()
    date_str = data.get('date')
    start_time_str = data.get('startTime')
    end_time_str = data.get('endTime')
    title = data.get('title', '').strip()
    host_password = data.get('hostPassword', '').strip()  # Required

    # Validate inputs
    if not title:
        return web.json_response({"error": "Meeting title is required"}, status=400)
    if not date_str or not start_time_str or not end_time_str:
        return web.json_response({"error": "Date, start time, and end time are required"}, status=400)
    if not host_password:
        return web.json_response({"error": "Host password is required"}, status=400)

    try:
        start_time = datetime.strptime(f"{date_str} {start_time_str}", "%Y-%m-%d %H:%M")
        end_time = datetime.strptime(f"{date_str} {end_time_str}", "%Y-%m-%d %H:%M")
        if end_time <= start_time:
            return web.json_response({"error": "End time must be after start time"}, status=400)
    except ValueError:
        return web.json_response({"error": "Invalid date/time format"}, status=400)

    code = secrets.token_hex(3).upper()
    password_hash = hash_password(host_password)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT INTO meetings 
                 (code, host_id, start_time, end_time, title, host_password_hash) 
                 VALUES (?, ?, ?, ?, ?, ?)""",
              (code, user[0], start_time, end_time, title, password_hash))
    meeting_id = c.lastrowid
    conn.commit()
    conn.close()

    registered_rooms[code] = {
        'start_time': start_time,
        'end_time': end_time,
        'meeting_id': meeting_id,
        'host_id': user[0],
        'host_password_hash': password_hash
    }

    link = f"http://localhost:8080/?meeting={code}"
    return web.json_response({
        "code": code,
        "link": link,
        "title": title,
        "scheduled": start_time.isoformat(),
        "endTime": end_time.isoformat()
    })


async def get_user_meetings_handler(request):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return web.json_response({"error": "Unauthorized"}, status=401)
    token = auth_header.split(' ')[1]
    user = get_user_by_token(token)
    if not user:
        return web.json_response({"error": "Invalid session"}, status=401)
    meetings = get_user_meetings(user[0])
    meeting_list = []
    for meeting in meetings:
        code, title, start_time_str, end_time_str, created_at = meeting
        start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00')) if isinstance(start_time_str,
                                                                                                 str) else start_time_str
        end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00')) if isinstance(end_time_str,
                                                                                             str) and end_time_str else end_time_str
        meeting_list.append({
            "code": code,
            "title": title,
            "startTime": start_time.isoformat() if start_time else None,
            "endTime": end_time.isoformat() if end_time else None,
            "createdAt": created_at,
            "link": f"http://localhost:8080/?meeting={code}"
        })
    return web.json_response({"meetings": meeting_list})


async def meeting_info(request):
    code = request.match_info['code']
    meeting = get_meeting_by_code(code)
    if not meeting:
        return web.json_response({"error": "Meeting not found"}, status=404)

    meeting_id, start_time_str, title, end_time_str, host_id, password_hash = meeting
    start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00')) if isinstance(start_time_str,
                                                                                             str) else start_time_str
    end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00')) if isinstance(end_time_str,
                                                                                         str) and end_time_str else end_time_str
    now = datetime.now()
    has_ended = end_time and now > end_time

    return web.json_response({
        "title": title,
        "scheduledTime": start_time.isoformat() if start_time else None,
        "endTime": end_time.isoformat() if end_time else None,
        "hostId": host_id,
        "hasEnded": has_ended,
        "requiresHostPassword": bool(password_hash)  # Always True since required
    })


async def list_recordings(request):
    code = request.query.get('code')
    if not code:
        return web.json_response({"error": "Code required"}, status=400)
    meeting = get_meeting_by_code(code)
    if not meeting:
        return web.json_response({"error": "Meeting not found"}, status=404)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT filename, uploaded_at FROM recordings WHERE meeting_id = ? ORDER BY uploaded_at DESC",
              (meeting[0],))
    rows = c.fetchall()
    conn.close()
    recordings = [{"filename": r[0], "uploaded_at": str(r[1])[:19].replace("T", " ")} for r in rows]
    return web.json_response({"recordings": recordings})


async def upload_handler(request):
    reader = await request.multipart()
    field = await reader.next()
    if not field or field.name != 'file':
        return web.json_response({'error': 'no file'}, status=400)
    original_filename = field.filename
    ext = os.path.splitext(original_filename)[1]
    token = secrets.token_hex(8)
    saved_name = f"{token}{ext}"
    saved_path = os.path.join(UPLOAD_DIR, saved_name)
    async with aiofiles.open(saved_path, 'wb') as f:
        while True:
            chunk = await field.read_chunk()
            if not chunk:
                break
            await f.write(chunk)
    file_url = f"/uploads/{saved_name}"
    return web.json_response({'url': file_url, 'filename': original_filename})


async def upload_recording(request):
    data = await request.json()
    code = data.get('code')
    blob = data.get('blob')
    meeting = get_meeting_by_code(code)
    if not meeting:
        return web.json_response({"error": "Invalid meeting"}, status=404)
    filename = f"{code}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.webm"
    filepath = os.path.join(RECORDING_DIR, filename)
    try:
        with open(filepath, "wb") as f:
            f.write(base64.b64decode(blob))
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO recordings (meeting_id, filename, uploaded_at) VALUES (?, ?, ?)",
                  (meeting[0], filename, datetime.now()))
        conn.commit()
        conn.close()
        return web.json_response({"success": True, "filename": filename})
    except Exception as e:
        return web.json_response({"error": f"Failed to save recording: {str(e)}"}, status=500)


async def export_participants(request):
    code = request.query.get('code')
    if not code:
        return web.json_response({"error": "Code required"}, status=400)
    meeting = get_meeting_by_code(code)
    if not meeting:
        return web.json_response({"error": "Meeting not found"}, status=404)
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        """SELECT p.name, p.join_time, p.role FROM participants p JOIN meetings m ON p.meeting_id = m.id WHERE m.code = ?""",
        conn, params=(code,))
    conn.close()
    excel_path = f"participants_{code}.xlsx"
    df.to_excel(excel_path, index=False)
    return web.FileResponse(excel_path,
                            headers={"Content-Disposition": f"attachment; filename=participants_{code}.xlsx"})


async def download_recording(request):
    filename = request.query.get('file')
    if not filename:
        return web.json_response({"error": "File required"}, status=400)
    path = os.path.join(RECORDING_DIR, filename)
    if not os.path.exists(path):
        return web.json_response({"error": "File not found"}, status=404)
    return web.FileResponse(path, headers={"Content-Disposition": f"attachment; filename={filename}"})


# --- WEBSOCKET ---
async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    room = request.match_info['room']

    # Validate meeting exists
    meeting = get_meeting_by_code(room)
    if not meeting:
        await ws.close(code=1008, message="Invalid meeting code")
        return ws

    meeting_id, start_time_str, title, end_time_str, host_id, password_hash = meeting
    start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00')) if isinstance(start_time_str,
                                                                                             str) else start_time_str
    end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00')) if isinstance(end_time_str,
                                                                                         str) and end_time_str else end_time_str
    now = datetime.now()

    # Check if meeting has ended
    if end_time and now > end_time:
        await ws.close(code=1008, message="Meeting has ended")
        return ws

    # Initialize room
    if room not in registered_rooms:
        registered_rooms[room] = {
            'start_time': start_time,
            'end_time': end_time,
            'meeting_id': meeting_id,
            'host_id': host_id,
            'host_password_hash': password_hash
        }

    if room not in rooms:
        rooms[room] = {'websockets': set(), 'users': {}, 'host': None, 'meeting_id': meeting_id}

    rooms[room]['websockets'].add(ws)
    ws_id = str(id(ws))

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                data = json.loads(msg.data)
                msg_type = data.get("type")
                payload = data.get("payload", {})

                if msg_type == "join":
                    username = payload.get("username")
                    join_as_host = payload.get("joinAsHost", False)
                    provided_host_id = payload.get("hostId")
                    provided_password = payload.get("host_password", "")
                    role = payload.get("role", "participant")

                    # === HOST PASSWORD VERIFICATION ===
                    is_valid_host = False
                    if role in ["host", "cohost"]:
                        if not password_hash:
                            await ws.send_json({"type": "error", "payload": {"message": "Host password required",
                                                                             "code": "PASSWORD_REQUIRED"}})
                            return ws
                        if not provided_password:
                            await ws.send_json({"type": "error", "payload": {"message": "Host password required",
                                                                             "code": "PASSWORD_REQUIRED"}})
                            return ws
                        if hash_password(provided_password) != password_hash:
                            await ws.send_json({"type": "error", "payload": {"message": "Invalid host password",
                                                                             "code": "INVALID_PASSWORD"}})
                            return ws
                        is_valid_host = True

                    # Set role
                    final_role = "participant"
                    if role == "host" and is_valid_host and provided_host_id == host_id:
                        final_role = "host"
                        rooms[room]['host'] = ws_id
                    elif role == "cohost" and is_valid_host:
                        final_role = "cohost"

                    rooms[room]['users'][ws_id] = {'name': username, 'role': final_role}

                    # Store in DB
                    conn = sqlite3.connect(DB_FILE)
                    c = conn.cursor()
                    c.execute("INSERT INTO participants (meeting_id, name, join_time, role) VALUES (?, ?, ?, ?)",
                              (rooms[room]['meeting_id'], username, datetime.now(), final_role))
                    conn.commit()
                    conn.close()

                    await broadcast_user_list(room)
                    await broadcast_participant_count(room)

                elif msg_type == "chat-message":
                    sender_name = rooms[room]['users'].get(ws_id, {}).get('name', 'Unknown')
                    sender_role = rooms[room]['users'].get(ws_id, {}).get('role', 'participant')

                    # Broadcast chat message to all participants
                    chat_payload = {
                        "message": payload.get("message", ""),
                        "sender": sender_name,
                        "role": sender_role,
                        "timestamp": datetime.now().isoformat(),
                        "senderId": ws_id
                    }

                    for peer in rooms[room]['websockets']:
                        await peer.send_json({"type": "chat-message", "payload": chat_payload})

                elif msg_type == "file-share":
                    sender_name = rooms[room]['users'].get(ws_id, {}).get('name', 'Unknown')
                    sender_role = rooms[room]['users'].get(ws_id, {}).get('role', 'participant')

                    # Broadcast file share to all participants
                    file_payload = {
                        "fileUrl": payload.get("fileUrl", ""),
                        "fileName": payload.get("fileName", ""),
                        "sender": sender_name,
                        "role": sender_role,
                        "timestamp": datetime.now().isoformat(),
                        "senderId": ws_id
                    }

                    for peer in rooms[room]['websockets']:
                        await peer.send_json({"type": "file-share", "payload": file_payload})

                # === FIXED: SCREEN SHARING MESSAGES ===
                elif msg_type == "screen-share-start":
                    # Add sender info to payload
                    sender_name = rooms[room]['users'].get(ws_id, {}).get('name', 'Unknown')
                    screen_payload = payload.copy()
                    screen_payload['from'] = sender_name
                    
                    # Broadcast screen share start to all other participants
                    for peer in rooms[room]['websockets']:
                        if peer != ws:
                            await peer.send_json({"type": "screen-share-start", "payload": screen_payload})
                        else:
                            # Also send confirmation to sender
                            await ws.send_json({"type": "screen-share-start", "payload": {**screen_payload, "self": True}})

                elif msg_type == "screen-share-stop":
                    # Add sender info to payload
                    sender_name = rooms[room]['users'].get(ws_id, {}).get('name', 'Unknown')
                    screen_payload = payload.copy()
                    screen_payload['from'] = sender_name
                    
                    # Broadcast screen share stop to all other participants
                    for peer in rooms[room]['websockets']:
                        if peer != ws:
                            await peer.send_json({"type": "screen-share-stop", "payload": screen_payload})
                        else:
                            # Also send confirmation to sender
                            await ws.send_json({"type": "screen-share-stop", "payload": {**screen_payload, "self": True}})

                elif msg_type in ["offer", "answer", "ice-candidate"]:
                    target = payload.get("target")
                    if target:
                        for pws, pid in [(p, str(id(p))) for p in rooms[room]['websockets']]:
                            if pid == target:
                                await pws.send_json({"type": msg_type, "payload": payload})
                                break

                elif msg_type == "mute-user":
                    if rooms[room]['host'] == ws_id or rooms[room]['users'].get(ws_id, {}).get('role') == 'cohost':
                        target = payload.get("target")
                        for pws, pid in [(p, str(id(p))) for p in rooms[room]['websockets']]:
                            if pid == target:
                                await pws.send_json({"type": "mute-request", "payload": {}})
                                break

                # === FIXED: BROADCAST ALL OTHER MESSAGE TYPES ===
                else:
                    # Broadcast all other message types (reactions, etc.) to all participants
                    for peer in rooms[room]['websockets']:
                        if peer != ws:
                            await peer.send_json({"type": msg_type, "payload": payload})

    finally:
        if ws_id in rooms[room]['users']:
            del rooms[room]['users'][ws_id]
        if rooms[room]['host'] == ws_id:
            rooms[room]['host'] = None
        rooms[room]['websockets'].remove(ws)
        await broadcast_user_list(room)
        await broadcast_participant_count(room)
        if not rooms[room]['websockets']:
            del rooms[room]

    return ws


async def broadcast_user_list(room):
    users = [{"id": uid, "name": user_data['name'], "role": user_data['role']} for uid, user_data in
             rooms[room]['users'].items()]
    host_id = rooms[room]['host']
    for ws in rooms[room]['websockets']:
        await ws.send_json({"type": "user-list", "payload": {"users": users, "host": host_id}})


async def broadcast_participant_count(room):
    count = len(rooms[room]['websockets'])
    for ws in rooms[room]['websockets']:
        await ws.send_json({"type": "participants", "payload": {"count": count}})


# --- APP SETUP ---
app = web.Application()
app.add_routes([
    web.get("/", index),
    web.get("/ws/{room}", websocket_handler),
    web.post("/signup", signup_handler),
    web.post("/login", login_handler),
    web.post("/forgot_password", forgot_password_handler),
    web.post("/reset_password", reset_password_handler),
    web.post("/create_meeting", create_meeting),
    web.get("/user_meetings", get_user_meetings_handler),
    web.get("/meeting_info/{code}", meeting_info),
    web.get("/recordings", list_recordings),
    web.post("/upload", upload_handler),
    web.post("/upload_recording", upload_recording),
    web.get("/export_participants", export_participants),
    web.get("/download_recording", download_recording),
    web.static("/static", STATIC_DIR),
    web.static("/uploads", UPLOAD_DIR),
    web.static("/recordings", RECORDING_DIR),
])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    web.run_app(app, host="0.0.0.0", port=port)
