import os
import shutil
import socket
import threading
import time
import math
import random
import sqlite3
import csv
import io
import json
import atexit
import signal
from datetime import datetime
import serial
import serial.tools.list_ports
import requests
from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'edrsai-secret'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# ── Database ──────────────────────────────────────────────────────────────────────────────
# In packaged desktop installs, app folder can be read-only (e.g., Program Files).
# Use EDR_DATA_DIR when provided by launcher; fallback to script folder for dev runs.
APP_BASE_DIR = os.environ.get('EDR_DATA_DIR') or os.path.dirname(__file__)
DB_PATH      = os.path.join(APP_BASE_DIR, 'edr_log.db')
BACKUP_DIR   = os.path.join(APP_BASE_DIR, 'backups')
BACKUP_KEEP = 48          # keep last 48 backup files (~2 hours at 2.5-min interval)
BACKUP_INTERVAL = 120     # seconds between backups

# PIN stored as plain string; change here to customize
DB_CLEAR_PIN = '1234'

CONFIG_PATH = os.path.join(APP_BASE_DIR, 'edr_config.json')

def _config_load():
    """Load persisted config from disk, merging into _config defaults."""
    if not os.path.exists(CONFIG_PATH):
        return
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            saved = json.load(f)
        for key in ('gamma_offset', 'tcp_port', 'render_url', 'port', 'baud'):
            if key in saved:
                _config[key] = saved[key]
        if 'wits_map' in saved and isinstance(saved['wits_map'], dict):
            _config['wits_map'].update(saved['wits_map'])
        if 'source_map' in saved and isinstance(saved['source_map'], dict):
            _config['source_map'].update(saved['source_map'])
        print(f'[CONFIG] Loaded from {CONFIG_PATH}')
    except Exception as e:
        print(f'[CONFIG] Error loading: {e}')

def _config_save():
    """Persist current config to disk."""
    try:
        data = {
            'gamma_offset': _config.get('gamma_offset', 15.0),
            'tcp_port':     _config.get('tcp_port', 5000),
            'render_url':   _config.get('render_url', ''),
            'port':         _config.get('port', ''),
            'baud':         _config.get('baud', 19200),
            'wits_map':     _config.get('wits_map', {}),
            'source_map':   _config.get('source_map', {}),
        }
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f'[CONFIG] Error saving: {e}')

def _db_init():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute('PRAGMA journal_mode=WAL')   # WAL mode: safer on power loss
    con.execute('''
        CREATE TABLE IF NOT EXISTS log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL    NOT NULL,
            hole_depth  REAL,
            bit_depth   REAL,
            wob         REAL,
            rpm         REAL,
            flow        REAL,
            rop         REAL,
            spp         REAL,
            gamma       REAL,
            gamma_depth REAL
        )
    ''')
    # Migration: add gamma_depth if column missing (existing DB)
    try:
        con.execute('ALTER TABLE log ADD COLUMN gamma_depth REAL')
        con.commit()
    except Exception:
        pass
    con.commit()
    con.close()

def _db_backup():
    """Copy DB to backups/ with timestamp filename, then prune old files."""
    if not os.path.exists(DB_PATH):
        return
    ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
    dst = os.path.join(BACKUP_DIR, f'edr_log_{ts}.db')
    try:
        # Use SQLite backup API for consistent snapshot while DB is in use
        src_con = sqlite3.connect(DB_PATH)
        dst_con = sqlite3.connect(dst)
        src_con.backup(dst_con)
        dst_con.close()
        src_con.close()
    except Exception as e:
        print(f'[BACKUP] Error: {e}')
        return
    # Prune: keep only the newest BACKUP_KEEP files
    files = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.startswith('edr_log_') and f.endswith('.db')]
    )
    for old in files[:-BACKUP_KEEP]:
        try:
            os.remove(os.path.join(BACKUP_DIR, old))
        except OSError:
            pass
    print(f'[BACKUP] Saved {dst}')

def _backup_thread():
    """Background thread: run a backup every BACKUP_INTERVAL seconds."""
    while True:
        time.sleep(BACKUP_INTERVAL)
        _db_backup()

def _db_insert(row: dict):
    con = sqlite3.connect(DB_PATH)
    con.execute('''
        INSERT INTO log (ts, hole_depth, bit_depth, wob, rpm, flow, rop, spp, gamma, gamma_depth)
        VALUES (:ts, :hole_depth, :bit_depth, :wob, :rpm, :flow, :rop, :spp, :gamma, :gamma_depth)
    ''', row)
    con.commit()
    con.close()

def _db_fetch_all():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        'SELECT * FROM log ORDER BY ts ASC'
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]

def _fallback_compass_points(latest: dict):
    """Build minimal compass points from toolface values when explicit points are absent."""
    points = latest.get('compass_points') or []
    if points:
        return points

    out = []
    gtfa = _to_float(latest.get('gTFA'))
    mtfa = _to_float(latest.get('mTFA'))
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
        'gamma_ts': _tcp_last_ts,
    }

def _db_fetch_range(depth_from, depth_to):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        'SELECT * FROM log WHERE hole_depth >= ? AND hole_depth <= ? ORDER BY ts ASC',
        (depth_from, depth_to)
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]

# ── Global state ──────────────────────────────────────────────────────────────
_lock = threading.Lock()
_latest = {
    'hole_depth': None,
    'bit_depth':  None,
    'wob':        None,
    'rpm':        None,
    'flow':       None,
    'rop':        None,
    'spp':        None,
    'gamma':        None,
    'gamma_depth':  None,
    'incl':         None,
    'azim':         None,
    'gTFA':         None,
    'mTFA':         None,
    'compass_points': [],
    'ts':           0,
}

# source_map: field -> 'sim' | 'serial' | 'tcp'
# Controls which data source is authoritative for each parameter.
_DEFAULT_SOURCE_MAP = {
    'hole_depth': 'serial',
    'bit_depth':  'serial',
    'wob':        'sim',
    'rpm':        'sim',
    'rop':        'sim',
    'spp':        'sim',
    'flow':       'sim',
    'gamma':      'tcp',
}

_config = {
    'port': '', 'baud': 19200, 'gamma_offset': 15.0, 'tcp_port': 5000,
    'render_url': '',  # URL de EDRsaiweb en Render (ej: https://edrsaiweb.onrender.com)
    'source_map': dict(_DEFAULT_SOURCE_MAP),
    'wits_map': {
        '0108': 'hole_depth',
        '0110': 'bit_depth',
        '0117': 'wob',
        '0120': 'rpm',
        '0113': 'rop',
        '0121': 'spp',
        '0126': 'flow',
        '0160': 'gamma',
    }
}

_serial_thread  = None
_serial_stop    = threading.Event()

_sim_thread     = None
_sim_stop       = threading.Event()
_sim_running    = False

_tcp_thread     = None
_tcp_stop       = threading.Event()
_tcp_running    = False
_tcp_last_gamma    = None   # last gamma value received via TCP
_tcp_last_ts       = None   # timestamp of last TCP reception (local)
_tcp_last_wdtt_ts  = None   # parsed WDTT as unix timestamp (sender time)
_tcp_time_skew     = None   # seconds: sender_time - local_time, best estimate (positive = sender ahead)
_tcp_last_wdtt_raw = None   # raw WDTT string as received
_tcp_skew_samples  = []     # recent skew samples for min-latency estimation (max 20)
_tcp_gamma_consumed = True  # True = gamma already recorded in DB, waiting for next TCP packet
_tcp_last_incl      = None
_tcp_last_azim      = None
_tcp_last_points_count = 0
_last_gamma_hd      = None  # last hole_depth at which gamma was recorded in DB
_last_hd_sample     = None  # last observed hole_depth sample (HD1) for advance check (HD2 > HD1)
_gamma_fresh        = False # True for exactly one broadcaster cycle after new gamma arrives

# ── TCP Gamma Receiver ───────────────────────────────────────────────────────
def _parse_wdtt(wdtt_str):
    """Parse YYMMDDHHMMSS string → unix timestamp. Returns None on error."""
    s = wdtt_str.strip()
    if len(s) != 12 or not s.isdigit():
        return None
    try:
        from datetime import datetime as _dt
        return _dt.strptime(s, '%y%m%d%H%M%S').timestamp()
    except Exception:
        return None

def _to_float(v):
    try:
        return float(v)
    except Exception:
        return None

def _pick_part(parts: dict, keys, contains=None):
    """Return first matching string value from parsed TCP tokens."""
    for k in keys:
        if k in parts and parts[k] != '':
            return parts[k]
    if contains:
        for k, v in parts.items():
            ku = str(k).upper()
            if any(token in ku for token in contains) and v != '':
                return v
    return None

def _parse_compass_points(raw):
    """Parse compass points into [{'az': deg, 'r': radius}, ...].

    Accepted formats:
      - JSON list: [{"az":252.3,"r":1.0}, [252.3, 1.0], ...]
      - Text list: "252.3:1,251.7:0.8,250.9:0.6"
      - Separators between az/r: ':', '|', '/'
    """
    if raw is None:
        return None

    s = str(raw).strip()
    if not s:
        return []

    def _build(az, rr):
        azf = _to_float(az)
        rf = _to_float(rr)
        if azf is None or rf is None:
            return None
        return {'az': round(azf % 360.0, 2), 'r': round(max(0.0, rf), 4)}

    # 1) JSON payload support
    try:
        obj = json.loads(s)
        if isinstance(obj, list):
            out = []
            for item in obj:
                point = None
                if isinstance(item, dict):
                    point = _build(item.get('az', item.get('angle')), item.get('r', item.get('radius')))
                elif isinstance(item, (list, tuple)) and len(item) >= 2:
                    point = _build(item[0], item[1])
                if point is not None:
                    out.append(point)
            if out:
                return out
    except Exception:
        pass

    # 2) Compact text payload support
    out = []
    for token in s.split(','):
        tok = token.strip()
        if not tok:
            continue
        az = rr = None
        for sep in (':', '|', '/'):
            if sep in tok:
                az, rr = tok.split(sep, 1)
                break
        if az is None:
            continue
        point = _build(az, rr)
        if point is not None:
            out.append(point)
    return out

def _handle_tcp_client(conn, addr):
    """Handle a single TCP connection: parse key-value telemetry from EDRsender."""
    global _tcp_last_gamma, _tcp_last_ts, _tcp_last_wdtt_ts, _tcp_time_skew
    global _tcp_last_wdtt_raw, _tcp_gamma_consumed, _tcp_last_incl, _tcp_last_azim, _tcp_last_points_count
    try:
        conn.settimeout(5.0)
        buf = ''
        while True:
            chunk = conn.recv(256)
            if not chunk:
                break
            buf += chunk.decode('utf-8', errors='ignore')
            while '\n' in buf:
                line, buf = buf.split('\n', 1)
                line = line.strip()
                if not line:
                    continue
                parts = {}
                for token in line.split(';'):
                    if '=' in token:
                        k, v = token.split('=', 1)
                        parts[k.strip().upper()] = v.strip()
                if not parts:
                    continue
                try:
                    local_ts  = time.time()
                    skew      = None
                    sender_ts = None
                    if 'WDTT' in parts:
                        sender_ts = _parse_wdtt(parts['WDTT'])
                        if sender_ts is not None:
                            skew = round(sender_ts - local_ts, 1)

                    gamma    = _to_float(_pick_part(parts, ['GAMA', 'GAMMA']))
                    incl     = _to_float(_pick_part(parts, ['INCL', 'INC', 'INCLINATION']))
                    azim     = _to_float(_pick_part(parts, ['AZIM', 'AZM', 'AZIMUTH', 'TAZM']))
                    tcp_hd   = _to_float(_pick_part(parts, ['HOLE_DEPTH', 'HD', 'HOLE_D', 'HOLEDEPTH']))
                    tcp_bd   = _to_float(_pick_part(parts, ['BIT_DEPTH', 'BD', 'BIT_D', 'BITDEPTH']))
                    gtfa  = _to_float(_pick_part(parts, ['GTFA', 'G_TFA', 'TOOLFACE_G', 'GTF', 'TFG'], contains=['GTFA', 'TOOLFACE_G']))
                    mtfa  = _to_float(_pick_part(parts, ['MTFA', 'M_TFA', 'TOOLFACE_M', 'MTF', 'TFM'], contains=['MTFA', 'TOOLFACE_M']))

                    raw_points = _pick_part(
                        parts,
                        ['COMPASS_POINTS', 'POINTS', 'PTS', 'COMPASS', 'CPTS'],
                        contains=['COMPASS', 'POINTS', 'PTS']
                    )
                    points = _parse_compass_points(raw_points) if raw_points is not None else None

                    # Ignore lines with no telemetry data payload
                    if gamma is None and incl is None and azim is None and gtfa is None and mtfa is None and points is None and sender_ts is None and tcp_hd is None and tcp_bd is None:
                        continue

                    with _lock:
                        _latest['ts'] = local_ts

                        src_map = _config.get('source_map', _DEFAULT_SOURCE_MAP)
                        if tcp_hd is not None and src_map.get('hole_depth', 'serial') == 'tcp':
                            _latest['hole_depth'] = round(tcp_hd, 2)
                        if tcp_bd is not None and src_map.get('bit_depth', 'serial') == 'tcp':
                            _latest['bit_depth'] = round(tcp_bd, 2)

                        if gamma is not None:
                            _latest['gamma']   = round(gamma, 2)
                            _tcp_last_gamma    = round(gamma, 2)
                            _tcp_last_ts       = local_ts
                            _tcp_gamma_consumed = False  # new packet ready to be recorded

                        if incl is not None:
                            _latest['incl'] = round(incl, 2)
                            _tcp_last_incl = round(incl, 2)

                        if azim is not None:
                            _latest['azim'] = round(azim, 2)
                            _tcp_last_azim = round(azim, 2)

                        if gtfa is not None:
                            _latest['gTFA'] = round(gtfa % 360.0, 2)

                        if mtfa is not None:
                            _latest['mTFA'] = round(mtfa % 360.0, 2)

                        if points is not None:
                            _latest['compass_points'] = points
                            _tcp_last_points_count = len(points)

                        if sender_ts is not None:
                            _tcp_last_wdtt_ts = sender_ts
                        if skew is not None:
                            _tcp_skew_samples.append(skew)
                            if len(_tcp_skew_samples) > 20:
                                _tcp_skew_samples.pop(0)
                            sorted_s = sorted(_tcp_skew_samples)
                            mid = len(sorted_s) // 2
                            _tcp_time_skew = sorted_s[mid]
                        _tcp_last_wdtt_raw = parts.get('WDTT')
                    print(
                        f'[TCP] gamma={gamma} incl={incl} azim={azim} gtfa={gtfa} mtfa={mtfa} '
                        f'pts={len(points) if points is not None else "-"} skew={skew}s de {addr[0]}'
                    )
                except Exception as _ex:
                    print(f'[TCP] Error procesando "{line}": {_ex}')
    except Exception as _ex:
        print(f'[TCP] Error en handler: {_ex}')
    finally:
        try:
            conn.close()
        except Exception:
            pass

def _tcp_server(tcp_port):
    """TCP server thread: accept connections and spawn handler threads."""
    global _tcp_running
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(('0.0.0.0', tcp_port))
        srv.listen(5)
        srv.settimeout(1.0)
        _tcp_running = True
        print(f'[TCP] Escuchando en 0.0.0.0:{tcp_port}')
        while not _tcp_stop.is_set():
            try:
                conn, addr = srv.accept()
                t = threading.Thread(target=_handle_tcp_client, args=(conn, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
    except Exception as e:
        print(f'[TCP] Error: {e}')
    finally:
        try:
            srv.close()
        except Exception:
            pass
        _tcp_running = False
        print('[TCP] Servidor detenido.')

def _start_tcp(tcp_port):
    global _tcp_thread
    _tcp_stop.set()
    if _tcp_thread and _tcp_thread.is_alive():
        _tcp_thread.join(timeout=3)
    _tcp_stop.clear()
    _tcp_thread = threading.Thread(target=_tcp_server, args=(tcp_port,), daemon=True)
    _tcp_thread.start()

def _stop_tcp():
    _tcp_stop.set()

# ── WITS parser ───────────────────────────────────────────────────────────────
def _parse_wits_line(line: str):
    line = line.strip()
    if len(line) < 6:
        return None, None
    code  = line[:4]
    value = line[4:].strip()
    if value and value[0] in ',:;=':
        value = value[1:].strip()
    with _lock:
        wits_map = _config.get('wits_map', {})
    key = wits_map.get(code)
    if key is None:
        return None, None
    try:
        return key, float(value)
    except ValueError:
        return None, None

# ── Serial reader ─────────────────────────────────────────────────────────────
def _serial_reader(port, baud):
    global _tcp_gamma_consumed, _last_gamma_hd, _last_hd_sample, _gamma_fresh
    try:
        ser = serial.Serial(port, baud, timeout=2)
    except Exception as e:
        print(f'[SERIAL] Error abriendo {port}: {e}')
        return
    print(f'[SERIAL] Leyendo {port} @ {baud}')
    buf = ''
    while not _serial_stop.is_set():
        try:
            raw = ser.read(256)
            if not raw:
                continue
            # Accept CR or LF terminated records from different WITS senders.
            buf += raw.decode('ascii', errors='ignore').replace('\r', '\n')
            while '\n' in buf:
                line, buf = buf.split('\n', 1)
                key, val = _parse_wits_line(line)
                if key is None:
                    continue
                # Only accept fields whose source_map entry is 'serial'
                with _lock:
                    src_map = _config.get('source_map', _DEFAULT_SOURCE_MAP)
                if src_map.get(key, 'serial' if key in ('hole_depth','bit_depth') else 'sim') != 'serial':
                    continue
                with _lock:
                    _latest[key] = val
                    _latest['ts'] = time.time() + (_tcp_time_skew or 0.0)
                    # Insert a DB row whenever depth arrives (one full WITS cycle)
                    if key in ('hole_depth', 'bit_depth'):
                        gamma_offset = _config.get('gamma_offset', 15.0)
                        hd    = _latest.get('hole_depth')
                        bd    = _latest.get('bit_depth')
                        # Record gamma only when depth advances (HD2 > HD1) and a new TCP packet arrived
                        hd_advancing = (
                            hd is not None and
                            _last_hd_sample is not None and
                            hd > _last_hd_sample
                        )
                        if not _tcp_gamma_consumed and _tcp_last_gamma is not None and hd_advancing:
                            gamma = _tcp_last_gamma
                            _tcp_gamma_consumed = True
                            _last_gamma_hd = hd
                            _gamma_fresh = True
                        else:
                            gamma = None
                        if hd is not None:
                            _last_hd_sample = hd
                        gamma_depth = round((bd or 0) - gamma_offset, 2) if gamma is not None else None
                        if gamma_depth is not None:
                            _latest['gamma_depth'] = gamma_depth
                        db_row = {
                            'ts':          _latest['ts'],
                            'hole_depth':  hd,
                            'bit_depth':   bd,
                            'wob':         _latest.get('wob'),
                            'rpm':         _latest.get('rpm'),
                            'flow':        _latest.get('flow'),
                            'rop':         _latest.get('rop'),
                            'spp':         _latest.get('spp'),
                            'gamma':       gamma,
                            'gamma_depth': gamma_depth,
                        }
                        try:
                            _db_insert(db_row)
                        except Exception as e:
                            print(f'[SERIAL] Error DB: {e}')
        except Exception as e:
            print(f'[SERIAL] Error leyendo: {e}')
            time.sleep(1)
    try:
        ser.close()
    except Exception:
        pass
    print('[SERIAL] Hilo serial detenido.')

def _start_serial(port, baud):
    global _serial_thread
    _serial_stop.set()
    if _serial_thread and _serial_thread.is_alive():
        _serial_thread.join(timeout=3)
    _serial_stop.clear()
    _serial_thread = threading.Thread(target=_serial_reader, args=(port, baud), daemon=True)
    _serial_thread.start()

# ── Simulator ─────────────────────────────────────────────────────────────────
def _simulator():
    """
    Simulates progressive drilling.
    - hole_depth / bit_depth increase ~0.3 m per second (variable ROP)
    - wob: 3–8 t, random walk
    - spp: 1600–2100 psi, correlated with wob
    - rpm: 50–80, slow random walk
    - flow: 460–510 gpm, slow random walk
    - rop: derived from wob
    - gamma: valor recibido por TCP (GAMA=valor)
    """
    global _tcp_gamma_consumed, _last_gamma_hd, _last_hd_sample, _gamma_fresh
    hd        = 0.0
    bd        = 0.0
    wob       = 5.0
    rpm       = 65.0
    flow      = 485.0
    spp       = 1850.0
    TICK      = 1.0   # seconds between ticks

    _db_init()

    while not _sim_stop.is_set():
        # Random walk parameters
        wob  = max(3.0, min(8.0,  wob  + random.uniform(-0.3, 0.3)))
        rpm  = max(50.0, min(80.0, rpm  + random.uniform(-1.0, 1.0)))
        flow = max(460.0, min(510.0, flow + random.uniform(-2.0, 2.0)))

        # SPP correlates with WOB: higher WOB → higher SPP
        spp_target = 1600.0 + (wob - 3.0) / 5.0 * 500.0
        spp = max(1600.0, min(2100.0, spp + (spp_target - spp) * 0.15 + random.uniform(-20, 20)))

        # ROP: random walk around 60 m/hr, range 40-80
        rop = max(40.0, min(80.0, 60.0 + (wob - 5.0) * 3.0 + random.uniform(-2, 2)))

        # Advance both depths simultaneously based on ROP
        depth_inc = rop / 3600.0 * TICK  # m per tick
        hd += depth_inc
        bd += depth_inc

        try:
            with _lock:
                gamma_offset  = _config.get('gamma_offset', 15.0)
                skew          = _tcp_time_skew or 0.0
                src_map       = _config.get('source_map', _DEFAULT_SOURCE_MAP)
                # Use real depths from _latest when source is serial or tcp
                hd_src = src_map.get('hole_depth', 'serial')
                bd_src = src_map.get('bit_depth',  'serial')
                final_hd = (_latest.get('hole_depth') or hd) if hd_src in ('serial', 'tcp') else hd
                final_bd = (_latest.get('bit_depth')  or bd) if bd_src in ('serial', 'tcp') else bd
                # Record gamma only when depth advances (HD2 > HD1) and a new TCP packet arrived
                hd_advancing = (
                    _last_hd_sample is not None and
                    final_hd > _last_hd_sample
                )
                if not _tcp_gamma_consumed and _tcp_last_gamma is not None and hd_advancing:
                    gamma = _tcp_last_gamma
                    _tcp_gamma_consumed = True
                    _last_gamma_hd = final_hd
                    _gamma_fresh = True
                else:
                    gamma = None
                _last_hd_sample = final_hd
            ts = time.time() + skew

            gamma_depth = round(final_bd - gamma_offset, 2) if gamma is not None else None

            db_row = {
                'ts':          ts,
                'hole_depth':  round(final_hd, 2),
                'bit_depth':   round(final_bd, 2),
                'wob':         round(wob,  2),
                'rpm':         round(rpm,  1),
                'flow':        round(flow, 1),
                'rop':         round(rop,  2),
                'spp':         round(spp,  0),
                'gamma':       round(gamma, 1) if gamma is not None else None,
                'gamma_depth': gamma_depth,
            }

            with _lock:
                src_map = _config.get('source_map', _DEFAULT_SOURCE_MAP)
                for k, v in db_row.items():
                    # Don't overwrite gamma/gamma_depth in _latest with None — keep last known value
                    if k in ('gamma', 'gamma_depth') and v is None:
                        continue
                    # Respect source_map: only write fields assigned to 'sim'
                    field_source = src_map.get(k, 'sim')
                    if field_source != 'sim':
                        continue
                    _latest[k] = v
                _latest['ts'] = ts

            try:
                _db_insert(db_row)
            except Exception as e:
                print(f'[DB] Error insertando: {e}')

        except Exception as e:
            print(f'[SIM] Error en tick: {e}')

        time.sleep(TICK)

    print('[SIM] Simulador detenido.')

def _start_simulator():
    global _sim_thread, _sim_running
    _sim_stop.set()
    if _sim_thread and _sim_thread.is_alive():
        _sim_thread.join(timeout=3)
    _sim_stop.clear()
    _sim_thread = threading.Thread(target=_simulator, daemon=True)
    _sim_thread.start()
    _sim_running = True

def _stop_simulator():
    global _sim_running
    _sim_stop.set()
    _sim_running = False

# ── Background broadcaster ────────────────────────────────────────────────────
def _send_to_render(payload):
    """Send telemetry data to EDRsaiweb in Render."""
    render_url = _config.get('render_url', '').strip()
    if not render_url:
        return
    
    try:
        url = f"{render_url}/api/ingest"
        requests.post(url, json=payload, timeout=2)
    except Exception as e:
        # Silent fail - no queremos bloquear la app local si Render no responde
        pass

def _broadcaster():
    while True:
        time.sleep(1)
        with _lock:
            payload = dict(_latest)
            payload['time_skew']     = _tcp_time_skew
            payload['serial_active'] = bool(_config.get('port', ''))
            payload['gamma_ts']      = _tcp_last_ts  # frontend detects new gamma by comparing this
            web_payload = _web_payload_snapshot(_latest)
        
        socketio.emit('data_update', payload)
        socketio.emit('web_update', web_payload)
        
        # Enviar a Render si está configurado
        _send_to_render(web_payload)

# ── Flask routes ──────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/web')
def web_page():
    return render_template('web.html')

@app.route('/export')
def export_page():
    return render_template('export.html')

@app.route('/config')
def config_page():
    return render_template('config.html')

@app.after_request
def add_web_cors_headers(resp):
    path = (request.path or '')
    if path.startswith('/api/web/'):
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp

@app.route('/api/state')
def api_state():
    with _lock:
        return jsonify(dict(_latest))

@app.route('/api/web/state')
def api_web_state():
    """Read-only reduced payload for web visualization clients."""
    with _lock:
        return jsonify(_web_payload_snapshot(_latest))

@app.route('/api/web/history')
def api_web_history():
    """Read-only gamma vs hole_depth history for web chart bootstrap."""
    limit = int(request.args.get('limit', 1200))
    limit = max(10, min(5000, limit))
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        'SELECT ts, hole_depth, gamma FROM log WHERE hole_depth IS NOT NULL AND gamma IS NOT NULL ORDER BY ts DESC LIMIT ?',
        (limit,)
    ).fetchall()
    con.close()
    rows = list(reversed([dict(r) for r in rows]))
    return jsonify(rows)

@app.route('/api/ports')
def api_ports():
    ports = [p.device for p in serial.tools.list_ports.comports()]
    return jsonify({'ports': ports})

@app.route('/api/config/serial', methods=['GET'])
def api_config_get():
    return jsonify(_config)

@app.route('/api/config/serial', methods=['POST'])
def api_config_set():
    data = request.get_json(force=True) or {}
    port = str(data.get('port', '') or '')
    baud = int(data.get('baud', 19200) or 19200)
    _config['port'] = port
    _config['baud'] = baud
    if port:
        _stop_simulator()
        _start_serial(port, baud)
    return jsonify({'ok': True})

@app.route('/api/config/app', methods=['GET'])
def api_config_app_get():
    return jsonify({
        'gamma_offset': _config.get('gamma_offset', 15.0),
        'tcp_port':     _config.get('tcp_port', 5000),
        'render_url':   _config.get('render_url', ''),
    })

@app.route('/api/config/app', methods=['POST'])
def api_config_app_set():
    data = request.get_json(force=True) or {}
    try:
        _config['gamma_offset'] = float(data.get('gamma_offset', _config.get('gamma_offset', 15.0)))
    except (ValueError, TypeError):
        pass
    try:
        new_tcp = int(data.get('tcp_port', _config.get('tcp_port', 5000)))
        if new_tcp != _config['tcp_port']:
            _config['tcp_port'] = new_tcp
            _start_tcp(new_tcp)
    except (ValueError, TypeError):
        pass
    if 'render_url' in data:
        _config['render_url'] = str(data['render_url']).strip()
    _config_save()
    return jsonify({'ok': True, 'gamma_offset': _config['gamma_offset'], 'tcp_port': _config['tcp_port'], 'render_url': _config.get('render_url', '')})

@app.route('/api/time')
def api_time():
    """Returns EDRsai current time so EDRsender can calculate clock offset."""
    now = time.time()
    return jsonify({
        'unix':   now,
        'wdtt':   datetime.fromtimestamp(now).strftime('%y%m%d%H%M%S'),
        'iso':    datetime.fromtimestamp(now).strftime('%Y-%m-%dT%H:%M:%S'),
    })

@app.route('/api/tcp/status')
def api_tcp_status():
    return jsonify({
        'running':    _tcp_running,
        'port':       _config.get('tcp_port', 5000),
        'last_gamma': _tcp_last_gamma,
        'last_incl':  _tcp_last_incl,
        'last_azim':  _tcp_last_azim,
        'last_points_count': _tcp_last_points_count,
        'last_ts':    _tcp_last_ts,
        'time_skew':  _tcp_time_skew,
        'last_wdtt':  _tcp_last_wdtt_raw,
        'local_time': datetime.now().strftime('%y%m%d%H%M%S'),
    })

@app.route('/api/config/source', methods=['GET'])
def api_config_source_get():
    return jsonify({'source_map': _config.get('source_map', dict(_DEFAULT_SOURCE_MAP))})

@app.route('/api/config/source', methods=['POST'])
def api_config_source_set():
    data = request.get_json(force=True) or {}
    src = data.get('source_map', {})
    valid_fields  = {'hole_depth','bit_depth','wob','rpm','rop','spp','flow','gamma','incl','azim'}
    valid_sources = {'sim', 'serial', 'tcp'}
    for field, source in src.items():
        if field in valid_fields and source in valid_sources:
            _config['source_map'][field] = source
    _config_save()
    return jsonify({'ok': True, 'source_map': _config['source_map']})

@app.route('/api/config/wits', methods=['GET'])
def api_config_wits_get():
    return jsonify({'wits_map': _config.get('wits_map', {})})

@app.route('/api/config/wits', methods=['POST'])
def api_config_wits_set():
    data = request.get_json(force=True) or {}
    wits_map = data.get('wits_map', {})
    valid_keys = {'hole_depth','bit_depth','wob','rpm','rop','spp','flow','gamma'}
    cleaned = {}
    for code, field in wits_map.items():
        code = str(code).strip().zfill(4)[:4]
        if field in valid_keys:
            cleaned[code] = field
    _config['wits_map'] = cleaned
    _config_save()
    return jsonify({'ok': True, 'wits_map': _config['wits_map']})

@app.route('/api/inject', methods=['POST'])
def api_inject():
    data = request.get_json(force=True) or {}
    with _lock:
        for k, v in data.items():
            if k == 'compass_points' and isinstance(v, list):
                _latest['compass_points'] = v
                continue
            if k in _latest and v is not None:
                try:
                    _latest[k] = float(v)
                except (ValueError, TypeError):
                    pass
        _latest['ts'] = time.time()
    return jsonify({'ok': True})

@app.route('/api/simulator', methods=['POST'])
def api_simulator():
    data   = request.get_json(force=True) or {}
    action = data.get('action', 'start')
    if action == 'start':
        _start_simulator()
        return jsonify({'ok': True, 'running': True})
    else:
        _stop_simulator()
        return jsonify({'ok': True, 'running': False})

@app.route('/api/simulator/status')
def api_sim_status():
    return jsonify({'running': _sim_running})

@app.route('/api/history')
def api_history():
    """Returns last N rows from DB for chart scroll."""
    limit = int(request.args.get('limit', 500))
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        'SELECT * FROM log ORDER BY ts DESC LIMIT ?', (limit,)
    ).fetchall()
    con.close()
    rows = list(reversed([dict(r) for r in rows]))
    return jsonify(rows)

def _fmt_tcp_date(ts_value):
    """Format TCP-aligned row timestamp as dd/mm/yy for export."""
    if ts_value is None:
        return ''
    try:
        return datetime.fromtimestamp(float(ts_value)).strftime('%d/%m/%y')
    except Exception:
        return ''

@app.route('/api/export/csv')
def api_export_csv():
    """Export selected columns as CSV download."""
    cols_param = request.args.get('cols', '')
    depth_from = request.args.get('from', None)
    depth_to   = request.args.get('to',   None)

    all_cols = ['tcp_date', 'id', 'ts', 'hole_depth', 'bit_depth', 'wob', 'rpm', 'flow', 'rop', 'spp', 'gamma', 'gamma_depth']
    if cols_param:
        selected = [c for c in cols_param.split(',') if c in all_cols]
    else:
        selected = all_cols

    if not selected:
        selected = all_cols

    # tcp_date must always be present and first in the export
    if 'tcp_date' not in selected:
        selected = ['tcp_date'] + selected
    else:
        selected = ['tcp_date'] + [c for c in selected if c != 'tcp_date']

    try:
        df  = float(depth_from) if depth_from else None
        dt  = float(depth_to)   if depth_to   else None
    except (ValueError, TypeError):
        df, dt = None, None

    if df is not None and dt is not None:
        rows = _db_fetch_range(df, dt)
    else:
        rows = _db_fetch_all()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=selected, extrasaction='ignore', lineterminator='\n')
    writer.writeheader()
    for r in rows:
        row = dict(r)
        row['tcp_date'] = _fmt_tcp_date(row.get('ts'))
        for depth_col in ('hole_depth', 'bit_depth'):
            if row.get(depth_col) is not None:
                try:
                    row[depth_col] = round(float(row[depth_col]), 1)
                except Exception:
                    pass
        if 'ts' in selected and row.get('ts') is not None:
            try:
                row['ts'] = datetime.fromtimestamp(float(row['ts'])).strftime('%H:%M:%S')
            except Exception:
                pass
        writer.writerow(row)

    csv_content = output.getvalue()
    return Response(
        csv_content,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=edr_export.csv'}
    )

@app.route('/api/export/preview')
def api_export_preview():
    """Returns first 50 rows for preview table."""
    cols_param = request.args.get('cols', '')
    depth_from = request.args.get('from', None)
    depth_to   = request.args.get('to',   None)

    all_cols = ['tcp_date', 'id', 'ts', 'hole_depth', 'bit_depth', 'wob', 'rpm', 'flow', 'rop', 'spp', 'gamma', 'gamma_depth']
    if cols_param:
        selected = [c for c in cols_param.split(',') if c in all_cols]
    else:
        selected = all_cols

    # tcp_date must always be present and first in the preview/export schema
    if 'tcp_date' not in selected:
        selected = ['tcp_date'] + selected
    else:
        selected = ['tcp_date'] + [c for c in selected if c != 'tcp_date']

    try:
        df  = float(depth_from) if depth_from else None
        dt  = float(depth_to)   if depth_to   else None
    except (ValueError, TypeError):
        df, dt = None, None

    if df is not None and dt is not None:
        rows = _db_fetch_range(df, dt)
    else:
        rows = _db_fetch_all()

    def fmt_row(r):
        row = {c: r.get(c) for c in selected}
        row['tcp_date'] = _fmt_tcp_date(r.get('ts'))
        for depth_col in ('hole_depth', 'bit_depth'):
            if row.get(depth_col) is not None:
                try:
                    row[depth_col] = round(float(row[depth_col]), 1)
                except Exception:
                    pass
        if 'ts' in selected and row.get('ts') is not None:
            try:
                row['ts'] = datetime.fromtimestamp(float(row['ts'])).strftime('%H:%M:%S')
            except Exception:
                pass
        return row
    preview = [fmt_row(r) for r in rows[:50]]
    total   = len(rows)
    return jsonify({'cols': selected, 'rows': preview, 'total': total})

@app.route('/api/db/clear', methods=['POST'])
def api_db_clear():
    data = request.get_json(force=True) or {}
    if str(data.get('pin', '')) != DB_CLEAR_PIN:
        return jsonify({'ok': False, 'error': 'PIN incorrecto'}), 403
    # Take a backup before clearing
    _db_backup()
    con = sqlite3.connect(DB_PATH)
    con.execute('DELETE FROM log')
    con.commit()
    con.close()
    return jsonify({'ok': True})

@app.route('/api/backup/now', methods=['POST'])
def api_backup_now():
    """Trigger an immediate manual backup."""
    _db_backup()
    files = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.startswith('edr_log_') and f.endswith('.db')]
    )
    return jsonify({'ok': True, 'files': len(files), 'latest': files[-1] if files else None})

@app.route('/api/backup/list')
def api_backup_list():
    files = sorted(
        [f for f in os.listdir(BACKUP_DIR) if f.startswith('edr_log_') and f.endswith('.db')]
    , reverse=True)
    return jsonify({'backups': files})

@app.route('/api/build')
def api_build():
    return jsonify({'is_local': True, 'version': '0.2.0'})

# ── SocketIO events ───────────────────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    with _lock:
        payload = dict(_latest)
    emit('data_update', payload)

def _graceful_shutdown(*_):
    """Backup DB and save config before exit."""
    print('[SHUTDOWN] Guardando backup final y config...')
    _db_backup()
    _config_save()
    print('[SHUTDOWN] Listo.')

atexit.register(_graceful_shutdown)
for _sig in (signal.SIGTERM, signal.SIGINT):
    try:
        signal.signal(_sig, _graceful_shutdown)
    except (OSError, ValueError):
        pass

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    _db_init()
    _config_load()          # restore persisted settings before starting
    _db_backup()            # snapshot DB state at startup
    t = threading.Thread(target=_broadcaster, daemon=True)
    t.start()
    tb = threading.Thread(target=_backup_thread, daemon=True)
    tb.start()
    _start_tcp(_config['tcp_port'])
    _start_simulator()
    port_env = os.environ.get('EDR_PORT', '5051')
    socketio.run(app, host='0.0.0.0', port=int(port_env), debug=False)
