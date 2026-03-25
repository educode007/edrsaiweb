import os
import io
import re
import csv
import threading
import time
import sqlite3
from datetime import datetime
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('EDR_SECRET_KEY', 'edrsaiweb-secret-2026')
app.config['SESSION_COOKIE_HTTPONLY'] = True
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# ── Auth ──────────────────────────────────────────────────────────────────────
# Credentials: set EDR_USER / EDR_PASSWORD env vars, defaults below
_AUTH_USER = os.environ.get('EDR_USER', 'admin')
_AUTH_PASS = os.environ.get('EDR_PASSWORD', 'edrsai2026')

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

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
    'tfa_ts': 0,   # increments only when a new gTFA/mTFA value arrives via ingest
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
        'tfa_ts': latest.get('tfa_ts', 0),
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
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if username == _AUTH_USER and password == _AUTH_PASS:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('index'))
        error = 'Usuario o contraseña incorrectos.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/')
@login_required
def index():
    return render_template('web.html')

@app.route('/web')
@login_required
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
        had_tfa = 'gTFA' in data or 'mTFA' in data
        for key in ['hole_depth', 'gamma', 'gamma_depth', 'incl', 'azim', 'gTFA', 'mTFA']:
            if key in data and data[key] is not None:
                try:
                    _latest[key] = float(data[key])
                except (ValueError, TypeError):
                    pass
        if had_tfa:
            _latest['tfa_ts'] = _latest['tfa_ts'] + 1
        
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

@app.route('/log')
@login_required
def log_page():
    return render_template('log.html')


# ── LAS / CSV helpers ──────────────────────────────────────────────────────────
def _parse_las(text):
    lines = text.splitlines()
    columns = []
    in_curve = False
    data_start = None
    null_val = -9999.25
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith('~C'):
            in_curve = True
            continue
        if in_curve:
            if s.startswith('~'):
                in_curve = False
                if s.upper().startswith('~A'):
                    data_start = i + 1
                continue
            if s and not s.startswith('#'):
                col = re.split(r'[\s.:]', s)[0].strip().upper()
                if col:
                    columns.append(col)
        if s.upper().startswith('~A'):
            data_start = i + 1
        if s.upper().startswith('NULL') and '.' in s:
            for p in s.split():
                try:
                    null_val = float(p)
                    break
                except ValueError:
                    pass
    if not columns or data_start is None:
        return [], []
    rows = []
    for line in lines[data_start:]:
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        vals = s.split()
        if len(vals) != len(columns):
            continue
        row = {}
        for col, val in zip(columns, vals):
            try:
                f = float(val.replace(',', '.'))
                row[col] = None if abs(f - null_val) < 0.1 else f
            except ValueError:
                row[col] = None
        rows.append(row)
    return columns, rows


def _parse_csv_file(text):
    sample = text[:2000]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    columns = [c.strip().upper() for c in (reader.fieldnames or [])]
    rows = []
    for raw in reader:
        row = {}
        for k, v in raw.items():
            col = k.strip().upper() if k else ''
            try:
                row[col] = float(v.strip().replace(',', '.')) if v and v.strip() not in ('', 'NA', 'NaN', 'NULL', '-9999', '-9999.25') else None
            except (ValueError, AttributeError):
                row[col] = None
        rows.append(row)
    return columns, rows


def _to_float_safe(v):
    if v is None:
        return None
    try:
        return round(float(v), 3)
    except (ValueError, TypeError):
        return None


@app.route('/api/log/parse', methods=['POST'])
@login_required
def api_log_parse():
    f = request.files.get('file')
    if not f:
        return jsonify({'ok': False, 'error': 'No file'}), 400
    text = f.read().decode('utf-8', errors='ignore')
    fname = f.filename.lower()
    if fname.endswith('.las'):
        columns, rows = _parse_las(text)
    else:
        columns, rows = _parse_csv_file(text)
    if not columns:
        return jsonify({'ok': False, 'error': 'No se pudieron leer columnas'}), 400
    return jsonify({'ok': True, 'columns': columns, 'preview': rows[:5]})


@app.route('/api/log/import', methods=['POST'])
@login_required
def api_log_import():
    f = request.files.get('file')
    if not f:
        return jsonify({'ok': False, 'error': 'No file'}), 400
    text = f.read().decode('utf-8', errors='ignore')
    fname = f.filename.lower()
    col_depth    = request.form.get('col_depth', '').upper()
    col_gamma    = request.form.get('col_gamma', '').upper()
    col_gas      = request.form.get('col_gas', '').upper()
    col_oil_show = request.form.get('col_oil_show', '').upper()
    col_gas_show = request.form.get('col_gas_show', '').upper()
    if fname.endswith('.las'):
        _, rows = _parse_las(text)
    else:
        _, rows = _parse_csv_file(text)
    if not rows:
        return jsonify({'ok': False, 'error': 'Archivo vacío'}), 400
    if not col_depth:
        return jsonify({'ok': False, 'error': 'col_depth requerido'}), 400
    mapped = []
    for r in rows:
        d = r.get(col_depth)
        if d is None:
            continue
        # oil_show / gas_show: accept numeric (>0 = show) or bool
        def _to_show(v):
            if v is None:
                return 0
            try:
                return 1 if float(v) > 0 else 0
            except (ValueError, TypeError):
                return 0

        mapped.append({
            'depth':    round(float(d), 3),
            'gamma':    _to_float_safe(r.get(col_gamma)) if col_gamma else None,
            'gas':      _to_float_safe(r.get(col_gas))   if col_gas   else None,
            'oil_show': _to_show(r.get(col_oil_show)) if col_oil_show else 0,
            'gas_show': _to_show(r.get(col_gas_show)) if col_gas_show else 0,
            # extra: raw rastros value for intensity visualization
            'rastros':  _to_float_safe(r.get(col_oil_show)) if col_oil_show else None,
        })
    if not mapped:
        return jsonify({'ok': False, 'error': 'Sin filas válidas'}), 400
    mapped.sort(key=lambda x: x['depth'])
    return jsonify({'ok': True, 'rows': mapped, 'inserted': len(mapped)})


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
