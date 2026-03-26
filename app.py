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
# Admin credentials
_AUTH_USER = os.environ.get('EDR_USER', 'admin')
_AUTH_PASS = os.environ.get('EDR_PASSWORD', 'edrsai2026')
# Viewer credentials (read-only)
_VIEWER_USER = os.environ.get('EDR_VIEWER_USER', 'viewer')
_VIEWER_PASS = os.environ.get('EDR_VIEWER_PASSWORD', 'viewer2026')

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Restrict endpoint to admin role only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login_page'))
        if session.get('role') != 'admin':
            return jsonify({'ok': False, 'error': 'Permiso denegado'}), 403
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
    con.execute('''
        CREATE TABLE IF NOT EXISTS las_data (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            depth    REAL NOT NULL,
            gas      REAL,
            rastros  REAL,
            oil_show INTEGER DEFAULT 0,
            gas_show INTEGER DEFAULT 0,
            arcilita INTEGER DEFAULT 0,
            limoarci INTEGER DEFAULT 0,
            arngrsa  INTEGER DEFAULT 0,
            arncong  INTEGER DEFAULT 0,
            conglom  INTEGER DEFAULT 0,
            mudstone INTEGER DEFAULT 0,
            wacstone INTEGER DEFAULT 0,
            pacstone INTEGER DEFAULT 0,
            grastone INTEGER DEFAULT 0,
            evaptas  INTEGER DEFAULT 0,
            rocavolc INTEGER DEFAULT 0
        )
    ''')
    # Add lito columns to existing DBs that lack them
    _LITO_COLS = ['arcilita','limoarci','arngrsa','arncong','conglom','mudstone','wacstone','pacstone','grastone','evaptas','rocavolc']
    for col in _LITO_COLS:
        try:
            con.execute(f'ALTER TABLE las_data ADD COLUMN {col} INTEGER DEFAULT 0')
        except Exception:
            pass
    con.commit()
    con.close()


_LITO_KEYS = ['arcilita','limoarci','arngrsa','arncong','conglom','mudstone','wacstone','pacstone','grastone','evaptas','rocavolc']

def _las_db_load():
    """Load las_data rows from SQLite."""
    try:
        lito_ph = ','.join(_LITO_KEYS)
        con = sqlite3.connect(DB_PATH)
        cur = con.execute(f'SELECT depth,gas,rastros,oil_show,gas_show,{lito_ph} FROM las_data ORDER BY depth')
        rows = []
        for r in cur.fetchall():
            row = {'depth': r[0], 'gas': r[1], 'rastros': r[2], 'oil_show': r[3], 'gas_show': r[4]}
            for i, k in enumerate(_LITO_KEYS):
                row[k] = r[5 + i]
            rows.append(row)
        con.close()
        return rows
    except Exception:
        return []


def _las_db_save(rows):
    """Replace all las_data rows with new data."""
    try:
        lito_ph = ','.join(_LITO_KEYS)
        lito_q  = ','.join(['?'] * len(_LITO_KEYS))
        con = sqlite3.connect(DB_PATH)
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('DELETE FROM las_data')
        con.executemany(
            f'INSERT INTO las_data (depth,gas,rastros,oil_show,gas_show,{lito_ph}) VALUES (?,?,?,?,?,{lito_q})',
            [(r['depth'], r.get('gas'), r.get('rastros'), r.get('oil_show', 0), r.get('gas_show', 0))
             + tuple(r.get(k, 0) for k in _LITO_KEYS)
             for r in rows]
        )
        con.commit()
        con.close()
    except Exception:
        pass



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
_las_data = []         # LAS/CSV imported rows: [{depth, gas, rastros, oil_show, gas_show}]
LAS_MAX   = 20000      # max rows to keep in RAM

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
            session['role'] = 'admin'
            return redirect(url_for('index'))
        elif username == _VIEWER_USER and password == _VIEWER_PASS:
            session['logged_in'] = True
            session['username'] = username
            session['role'] = 'viewer'
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
    return render_template('web.html', role=session.get('role', 'viewer'))

@app.route('/web')
@login_required
def web_page():
    return render_template('web.html', role=session.get('role', 'viewer'))

@app.route('/api/web/state')
def api_web_state():
    """Current state snapshot for web UI."""
    with _lock:
        payload = _web_payload_snapshot(_latest)
    return jsonify(payload)

@app.route('/api/web/history')
def api_web_history():
    """Gamma history from SQLite DB — survives server restarts."""
    limit = int(request.args.get('limit', 5000))
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.execute(
            'SELECT hole_depth, gamma, gamma_depth FROM log '
            'WHERE gamma IS NOT NULL '
            'ORDER BY id DESC LIMIT ?', (limit,)
        )
        rows = []
        for r in cur.fetchall():
            rows.append({
                'hole_depth':  r[0],
                'gamma':       r[1],
                'gamma_depth': r[2],
            })
        con.close()
        rows.reverse()  # oldest first
        return jsonify(rows)
    except Exception as e:
        return jsonify([])

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

        # Persist to DB when gamma arrives — deduplicate by gamma_depth
        if _latest.get('gamma') is not None:
            gd_new = _latest.get('gamma_depth') or _latest.get('hole_depth')
            try:
                con = sqlite3.connect(DB_PATH)
                # Check if this gamma_depth already exists
                if gd_new is not None:
                    cur = con.execute(
                        'SELECT COUNT(*) FROM log WHERE ABS(gamma_depth - ?) < 0.01',
                        (gd_new,)
                    )
                    already = cur.fetchone()[0] > 0
                else:
                    already = False
                if not already:
                    con.execute('''
                        INSERT INTO log (ts, hole_depth, gamma, gamma_depth, incl, azim)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        _latest['ts'],
                        _latest.get('hole_depth'),
                        _latest.get('gamma'),
                        gd_new,
                        _latest.get('incl'),
                        _latest.get('azim')
                    ))
                    con.commit()
                con.close()
            except Exception:
                pass
    
    return jsonify({'ok': True})

@app.route('/api/ingest/bulk', methods=['POST'])
def api_ingest_bulk():
    """Receive full gamma history from EDRsai — replaces all existing gamma data."""
    rows = request.get_json(force=True) or []
    if not isinstance(rows, list):
        return jsonify({'ok': False, 'error': 'Expected array'}), 400
    inserted = 0
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('DELETE FROM log')  # full replace — no mixing of sessions
        for row in rows:
            gamma = row.get('gamma')
            if gamma is None:
                continue
            gd = row.get('gamma_depth') or row.get('hole_depth')
            hd = row.get('hole_depth')
            ts = row.get('ts') or 0
            if gd is None:
                continue
            con.execute(
                'INSERT INTO log (ts, hole_depth, gamma, gamma_depth) VALUES (?,?,?,?)',
                (ts, hd, gamma, gd)
            )
            inserted += 1
        con.commit()
        con.close()
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500
    return jsonify({'ok': True, 'inserted': inserted})


@app.route('/log')
@login_required
def log_page():
    return render_template('log.html', role=session.get('role', 'viewer'))


# ── LAS / CSV helpers ──────────────────────────────────────────────────────────
def _decode_bytes(raw):
    """Decode bytes trying UTF-8, latin-1, cp1252 in order."""
    for enc in ('utf-8', 'latin-1', 'cp1252'):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, Exception):
            continue
    return raw.decode('utf-8', errors='ignore')

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
        su = s.upper()
        if su.startswith('NULL'):
            for p in s.split():
                try:
                    null_val = float(p.replace(',', '.'))
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
@admin_required
def api_log_parse():
    f = request.files.get('file')
    if not f:
        return jsonify({'ok': False, 'error': 'No file'}), 400
    try:
        raw = f.read()
        text = _decode_bytes(raw)
        fname = f.filename.lower()
        if fname.endswith('.las'):
            columns, rows = _parse_las(text)
        else:
            columns, rows = _parse_csv_file(text)
        if not columns:
            return jsonify({'ok': False, 'error': 'No se pudieron detectar columnas. Verificar formato LAS/CSV'}), 400
        return jsonify({'ok': True, 'columns': columns, 'preview': rows[:5]})
    except Exception as e:
        return jsonify({'ok': False, 'error': 'Error al parsear: ' + str(e)}), 500


@app.route('/api/log/import', methods=['POST'])
@admin_required
def api_log_import():
    f = request.files.get('file')
    if not f:
        return jsonify({'ok': False, 'error': 'No file'}), 400
    text = _decode_bytes(f.read())
    fname = f.filename.lower()
    col_depth    = request.form.get('col_depth', '').upper()
    col_gamma    = request.form.get('col_gamma', '').upper()
    col_gas      = request.form.get('col_gas', '').upper()
    col_oil_show = request.form.get('col_oil_show', '').upper()
    col_gas_show = request.form.get('col_gas_show', '').upper()
    # Lithology columns
    _lito_cols = {
        'arcilita': request.form.get('col_arcilita', '').upper(),
        'limoarci': request.form.get('col_limoarci', '').upper(),
        'arngrsa':  request.form.get('col_arngrsa',  '').upper(),
        'arncong':  request.form.get('col_arncong',  '').upper(),
        'conglom':  request.form.get('col_conglom',  '').upper(),
        'mudstone': request.form.get('col_mudstone', '').upper(),
        'wacstone': request.form.get('col_wacstone', '').upper(),
        'pacstone': request.form.get('col_pacstone', '').upper(),
        'grastone': request.form.get('col_grastone', '').upper(),
        'evaptas':  request.form.get('col_evaptas',  '').upper(),
        'rocavolc': request.form.get('col_rocavolc', '').upper(),
    }
    if fname.endswith('.las'):
        _, rows = _parse_las(text)
    else:
        _, rows = _parse_csv_file(text)
    if not rows:
        return jsonify({'ok': False, 'error': 'Archivo vacío'}), 400
    if not col_depth:
        return jsonify({'ok': False, 'error': 'col_depth requerido'}), 400

    def _to_show(v):
        if v is None:
            return 0
        try:
            return 1 if float(v) > 0 else 0
        except (ValueError, TypeError):
            return 0

    mapped = []
    for r in rows:
        d = r.get(col_depth)
        if d is None:
            continue
        row = {
            'depth':    round(float(d), 3),
            'gamma':    _to_float_safe(r.get(col_gamma)) if col_gamma else None,
            'gas':      _to_float_safe(r.get(col_gas))   if col_gas   else None,
            'oil_show': _to_show(r.get(col_oil_show)) if col_oil_show else 0,
            'gas_show': _to_show(r.get(col_gas_show)) if col_gas_show else 0,
            'rastros':  _to_float_safe(r.get(col_oil_show)) if col_oil_show else None,
        }
        for lito_key, lito_col in _lito_cols.items():
            row[lito_key] = _to_show(r.get(lito_col)) if lito_col else 0
        mapped.append(row)
    global _las_data
    if not mapped:
        return jsonify({'ok': False, 'error': 'Sin filas válidas'}), 400
    mapped.sort(key=lambda x: x['depth'])
    mapped = mapped[:LAS_MAX]
    # Persist to SQLite (survives process restart) AND RAM cache
    _las_db_save(mapped)
    with _lock:
        _las_data = mapped
    return jsonify({'ok': True, 'rows': mapped, 'inserted': len(mapped)})


@app.route('/api/log/data', methods=['GET'])
@login_required
def api_log_data_get():
    """Return stored LAS data — RAM cache first, fallback to SQLite."""
    global _las_data
    with _lock:
        rows = list(_las_data)
    if not rows:
        # RAM cache empty (process restarted) — load from SQLite
        rows = _las_db_load()
        with _lock:
            _las_data = rows
    return jsonify({'ok': True, 'rows': rows, 'count': len(rows)})


@app.route('/api/log/data', methods=['DELETE'])
@admin_required
def api_log_data_delete():
    """Clear stored LAS data from RAM and SQLite."""
    global _las_data
    _las_db_save([])   # wipe SQLite
    with _lock:
        _las_data = []
    return jsonify({'ok': True})


@app.after_request
def add_web_cors_headers(resp):
    """Allow CORS for web API endpoints."""
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp

# ── Startup (runs under both Gunicorn and direct execution) ───────────────────
_db_init()
threading.Thread(target=_broadcaster, daemon=True).start()

# ── Main (direct execution only) ──────────────────────────────────────────────
if __name__ == '__main__':
    port_env = os.environ.get('PORT') or os.environ.get('EDR_PORT', '5051')
    socketio.run(app, host='0.0.0.0', port=int(port_env), debug=False, allow_unsafe_werkzeug=True)
