import os
import threading
import time
import sqlite3
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'edrsaiweb-secret'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# ── Database (minimal, ephemeral in Render) ──────────────────────────────────
def _get_data_dir():
    """Use local directory, handle permission errors gracefully."""
    candidate = os.environ.get('EDR_DATA_DIR') or os.path.dirname(__file__)
    try:
        os.makedirs(os.path.join(candidate, 'backups'), exist_ok=True)
        return candidate
    except (PermissionError, OSError):
        return os.path.dirname(__file__)

APP_BASE_DIR = _get_data_dir()
DB_PATH = os.path.join(APP_BASE_DIR, 'edr_log.db')

def _db_init():
    """Initialize minimal database for web history."""
    con = sqlite3.connect(DB_PATH)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('''
        CREATE TABLE IF NOT EXISTS log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            hole_depth REAL,
            gamma REAL,
            gamma_depth REAL,
            incl REAL,
            azim REAL
        )
    ''')
    con.commit()
    con.close()

# ── Global state ──────────────────────────────────────────────────────────────
_lock = threading.Lock()
_latest = {
    'hole_depth': None,
    'gamma': None,
    'gamma_depth': None,
    'incl': None,
    'azim': None,
    'gTFA': None,
    'mTFA': None,
    'compass_points': [],
    'ts': 0,
}

_config = {'gamma_offset': 15.0}
_history = []          # in-memory history: list of web_payload dicts, newest last
HISTORY_MAX = 2000     # keep last 2000 records in RAM

# ── Helper functions ──────────────────────────────────────────────────────────
def _fallback_compass_points(latest: dict):
    """Build minimal compass points from toolface values when explicit points are absent."""
    points = latest.get('compass_points') or []
    if points:
        return points
    
    out = []
    gtfa = latest.get('gTFA')
    mtfa = latest.get('mTFA')
    if gtfa is not None:
        out.append({'az': round(gtfa % 360.0, 2), 'r': 0.95})
    if mtfa is not None:
        out.append({'az': round(mtfa % 360.0, 2), 'r': 0.55})
    return out

def _web_payload_snapshot(latest: dict):
    """Minimal read-only payload for EDRsaiWeb visualizations."""
    return {
        'ts': latest.get('ts'),
        'hole_depth': latest.get('hole_depth'),
        'gamma_depth': latest.get('gamma_depth'),
        'gamma_offset': _config.get('gamma_offset', 15.0),
        'gamma': latest.get('gamma'),
        'incl': latest.get('incl'),
        'azim': latest.get('azim'),
        'gTFA': latest.get('gTFA'),
        'mTFA': latest.get('mTFA'),
        'compass_points': _fallback_compass_points(latest),
    }

# ── Broadcaster (Socket.IO updates) ───────────────────────────────────────────
def _broadcaster():
    """Emit periodic socket updates with current state."""
    while True:
        time.sleep(1)
        with _lock:
            web_payload = _web_payload_snapshot(_latest)
        socketio.emit('web_update', web_payload)

# ── Flask routes ──────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('web.html')

@app.route('/web')
def web_page():
    return render_template('web.html')

@app.route('/api/web/state')
def api_web_state():
    """Current state snapshot for web UI."""
    with _lock:
        payload = _web_payload_snapshot(_latest)
    return jsonify(payload)

@app.route('/api/web/history')
def api_web_history():
    """Last N samples — served from in-memory history (survives page refresh)."""
    limit = int(request.args.get('limit', 1200))
    with _lock:
        rows = list(_history[-limit:])
    return jsonify(rows)

@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    """Receive telemetry data from EDRsai desktop application."""
    data = request.get_json(force=True) or {}
    
    with _lock:
        # Update latest state
        for key in ['hole_depth', 'gamma', 'gamma_depth', 'incl', 'azim', 'gTFA', 'mTFA']:
            if key in data and data[key] is not None:
                try:
                    _latest[key] = float(data[key])
                except (ValueError, TypeError):
                    pass
        
        if 'compass_points' in data and isinstance(data['compass_points'], list):
            _latest['compass_points'] = data['compass_points']
        
        _latest['ts'] = time.time()

        # Store snapshot in memory history
        snap = _web_payload_snapshot(_latest)
        _history.append(snap)
        if len(_history) > HISTORY_MAX:
            del _history[:-HISTORY_MAX]

        # Also persist to DB when gamma is available
        if _latest.get('gamma') is not None:
            try:
                con = sqlite3.connect(DB_PATH)
                con.execute('''
                    INSERT INTO log (ts, hole_depth, gamma, gamma_depth, incl, azim)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    _latest['ts'],
                    _latest.get('hole_depth'),
                    _latest.get('gamma'),
                    _latest.get('gamma_depth'),
                    _latest.get('incl'),
                    _latest.get('azim')
                ))
                con.commit()
                con.close()
            except Exception:
                pass
    
    return jsonify({'ok': True})

@app.after_request
def add_web_cors_headers(resp):
    """Allow CORS for web API endpoints."""
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    _db_init()
    t = threading.Thread(target=_broadcaster, daemon=True)
    t.start()
    port_env = os.environ.get('PORT') or os.environ.get('EDR_PORT', '5051')
    socketio.run(app, host='0.0.0.0', port=int(port_env), debug=False, allow_unsafe_werkzeug=True)
