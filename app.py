from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory, Response
import json
import os
import subprocess
import random
import string
import uuid
from datetime import datetime, timedelta
import sys
import shutil
import threading
import time
import zipfile
import hashlib
import secrets
import re
import traceback
import base64
import hmac
import socket

# ============================================
# Optional imports (Termux-friendly)
# ============================================
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[WARN] psutil not available.")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[WARN] 'requests' not installed. Run: pip install requests")

try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    print("[WARN] 'pyjwt' not installed. Using HMAC fallback.")

app = Flask(__name__)

# ============================================
# Config
# ============================================
app.secret_key = os.environ.get('SECRET_KEY', 'alamin-hosting-CHANGE-ME-IN-PRODUCTION')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_DEBUG', '0') != '1'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

JWT_MASTER_SECRET = os.environ.get('JWT_SECRET', 'alamin-jwt-master-secret-key-change-me')
SUBDOMAIN_BASE = os.environ.get('SUBDOMAIN_BASE', '').strip()
AUTOFIX_ENABLED = os.environ.get('AUTOFIX', '1') == '1'

# ============================================
# Paths
# ============================================
if os.path.exists('/data') and os.access('/data', os.W_OK):
    DATA_DIR = os.environ.get('DATA_DIR', '/data')
else:
    DATA_DIR = os.environ.get('DATA_DIR', os.path.abspath('.'))

os.makedirs(DATA_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, 'users.json')
BOTS_DIR = os.path.join(DATA_DIR, 'bots')
NETLIFY_DIR = os.path.join(DATA_DIR, 'netlify_sites')
NETLIFY_USERS_FILE = os.path.join(DATA_DIR, 'netlify_users.json')
DEPLOY_DIR = os.path.join(DATA_DIR, 'deployed_apis')
API_UPLOAD_DIR = os.path.join(DATA_DIR, 'api_uploads')
DEPLOY_DB = os.path.join(DATA_DIR, 'deployed_apis.json')
APP_LOGS_DIR = os.path.join(DATA_DIR, 'app_logs')

for d in [NETLIFY_DIR, BOTS_DIR, DEPLOY_DIR, API_UPLOAD_DIR, APP_LOGS_DIR]:
    os.makedirs(d, exist_ok=True)

NETLIFY_LOGS = {}
NETLIFY_DOMAIN = os.environ.get('NETLIFY_DOMAIN', '').strip()
CPU_HISTORY = {}
CRASH_COUNT = {}
running_api_containers = {}
IS_WINDOWS = sys.platform == 'win32'

DEFAULT_ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'mdalaminmmmnnn037@gmail.com')
DEFAULT_ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'ALAMIN@DD')

_users_lock = threading.Lock()
_netlify_users_lock = threading.Lock()
_deploy_lock = threading.Lock()

# ============================================
# Termux environment detection
# ============================================
TERMUX_PREFIX = '/data/data/com.termux/files/usr'
IS_TERMUX = os.path.exists(TERMUX_PREFIX)

# Build environment with proper PATH
def build_env(extra=None):
    env = os.environ.copy()
    base_paths = []
    if IS_TERMUX:
        base_paths.append(f'{TERMUX_PREFIX}/bin')
    base_paths.extend(['/usr/local/bin', '/usr/bin', '/bin'])
    current = env.get('PATH', '')
    for p in base_paths:
        if p not in current:
            current = p + ':' + current
    env['PATH'] = current
    env['NODE_ENV'] = 'production'
    env['PYTHONUNBUFFERED'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'
    if extra:
        env.update(extra)
    return env

# ============================================
# System detection
# ============================================
def check_command_exists(cmd):
    try:
        result = subprocess.run([cmd, '--version'], capture_output=True, text=True, timeout=15, shell=IS_WINDOWS)
        if result.returncode == 0:
            return True
    except Exception:
        pass
    try:
        which_cmd = ['where', cmd] if IS_WINDOWS else ['which', cmd]
        result = subprocess.run(which_cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            return True
    except Exception:
        pass
    return False

DOCKER_AVAILABLE = False  # Docker not supported on Termux
NODE_AVAILABLE = check_command_exists('node')
NPM_AVAILABLE = check_command_exists('npm')
PYTHON_AVAILABLE = check_command_exists('python') or check_command_exists('python3')
PHP_AVAILABLE = check_command_exists('php')

# ============================================
# Password hashing
# ============================================
def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return f"{salt}${hashed}"

def verify_password(password, stored):
    if not stored:
        return False
    if '$' not in stored:
        return password == stored
    try:
        salt, hashed = stored.split('$', 1)
        check = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
        return check == hashed
    except Exception:
        return False

# ============================================
# JWT
# ============================================
def generate_jwt_token(app_id, expires_days=30):
    if not JWT_AVAILABLE:
        payload = f"{app_id}:{int(time.time()) + expires_days * 86400}"
        sig = hmac.new(JWT_MASTER_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        raw = f"{payload}:{sig}"
        return base64.urlsafe_b64encode(raw.encode()).decode()
    payload = {'app_id': app_id, 'iat': int(time.time()), 'exp': int(time.time()) + expires_days * 86400, 'iss': 'alamin-hosting'}
    return pyjwt.encode(payload, JWT_MASTER_SECRET, algorithm='HS256')

def verify_jwt_token(token):
    try:
        if not JWT_AVAILABLE:
            decoded = base64.urlsafe_b64decode(token.encode()).decode()
            parts = decoded.rsplit(':', 2)
            if len(parts) != 3:
                return None
            app_id, ts, sig = parts
            payload = f"{app_id}:{ts}"
            expected = hmac.new(JWT_MASTER_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            if int(ts) < int(time.time()):
                return None
            return app_id
        data = pyjwt.decode(token, JWT_MASTER_SECRET, algorithms=['HS256'])
        return data.get('app_id')
    except Exception:
        return None

# ============================================
# Deploy DB
# ============================================
def load_deploy_db():
    if not os.path.exists(DEPLOY_DB):
        return {"apps": {}}
    try:
        with open(DEPLOY_DB, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {"apps": {}}

def save_deploy_db(data):
    with _deploy_lock:
        tmp = DEPLOY_DB + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, DEPLOY_DB)

# ============================================
# Project detection
# ============================================
def detect_project_type(app_dir):
    if os.path.exists(os.path.join(app_dir, 'package.json')):
        return 'node'
    if os.path.exists(os.path.join(app_dir, 'requirements.txt')) or \
       os.path.exists(os.path.join(app_dir, 'main.py')) or \
       os.path.exists(os.path.join(app_dir, 'app.py')):
        return 'python'
    if os.path.exists(os.path.join(app_dir, 'index.php')):
        return 'php'
    if os.path.exists(os.path.join(app_dir, 'index.html')):
        return 'static'
    for f in os.listdir(app_dir):
        if f.endswith('.js'):
            return 'node'
        if f.endswith('.py'):
            return 'python'
        if f.endswith('.php'):
            return 'php'
    return 'unknown'

def auto_detect_build_cmd(app_dir):
    ptype = detect_project_type(app_dir)
    if ptype == 'node':
        return 'npm install --no-audit --no-fund --legacy-peer-deps'
    elif ptype == 'python':
        req = os.path.join(app_dir, 'requirements.txt')
        if os.path.exists(req):
            return f'{sys.executable} -m pip install -r requirements.txt --disable-pip-version-check'
        return ''
    return ''

def auto_detect_start_cmd(app_dir, port):
    ptype = detect_project_type(app_dir)
    if ptype == 'node':
        if NPM_AVAILABLE:
            return 'npm start'
        for f in os.listdir(app_dir):
            if f.endswith('.js'):
                return f'node {f}'
        return ''
    elif ptype == 'python':
        for name in ['main.py', 'app.py', 'server.py', 'index.py']:
            if os.path.exists(os.path.join(app_dir, name)):
                return f'{sys.executable} {name}'
        for f in os.listdir(app_dir):
            if f.endswith('.py'):
                return f'{sys.executable} {f}'
        return ''
    elif ptype == 'php':
        if os.path.exists(os.path.join(app_dir, 'index.php')):
            return f'php -S 127.0.0.1:{port} -t .'
        return ''
    elif ptype == 'static':
        return f'{sys.executable} -m http.server {port} --bind 127.0.0.1'
    return ''

# ============================================
# AUTO-FIX ENGINE
# ============================================
def _read_file_safe(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ''

def _write_file_safe(path, content):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception:
        return False

def _log_autofix(log_fn, msg):
    try:
        if log_fn:
            log_fn(f"[AUTOFIX] {msg}")
    except Exception:
        pass

def autofix_python_app(app_dir, log_fn=None):
    fixes = []
    py_files = []
    for name in ['main.py', 'app.py', 'server.py', 'index.py', 'run.py', 'bot.py']:
        p = os.path.join(app_dir, name)
        if os.path.exists(p):
            py_files.append(p)
    if not py_files:
        for f in os.listdir(app_dir):
            if f.endswith('.py') and not f.startswith('_'):
                py_files.append(os.path.join(app_dir, f))
    if not py_files:
        return fixes

    for py_file in py_files:
        content = _read_file_safe(py_file)
        if not content.strip():
            continue
        original = content
        fname = os.path.basename(py_file)

        is_web_app = any(kw in content for kw in ['Flask(', 'FastAPI(', 'from flask', 'from fastapi', 'app.run(', 'uvicorn.run(', 'bottle.run'])
        if not is_web_app:
            continue

        needs_os = ('os.environ' in content or 'app.run(' in content)
        if needs_os and not re.search(r'^\s*import\s+os\b', content, re.MULTILINE) and not re.search(r'^\s*from\s+os\s+import', content, re.MULTILINE):
            lines = content.split('\n')
            insert_at = 0
            for i, line in enumerate(lines):
                if line.strip().startswith(('import ', 'from ')):
                    insert_at = i
                    break
            lines.insert(insert_at, 'import os')
            content = '\n'.join(lines)
            fixes.append(f"{fname}: added 'import os'")
            _log_autofix(log_fn, f"Added 'import os' to {fname}")

        def fix_flask_run(match):
            original_call = match.group(0)
            if 'os.environ' in original_call or 'os.getenv' in original_call:
                if "host='127.0.0.1'" in original_call or 'host="127.0.0.1"' in original_call:
                    return original_call.replace("127.0.0.1", "0.0.0.0")
                return original_call
            fn_name = match.group(1)
            return f"{fn_name}(\n        host='0.0.0.0',\n        port=int(os.environ.get('PORT', 5000)),\n        debug=False\n    )"

        new_content = re.sub(r'(\b\w+\.run)\s*\(\s*[^)]*\)', fix_flask_run, content, flags=re.DOTALL)
        if new_content == content:
            new_content = re.sub(r'^(\s*)(\w+\.run)\s*\(\s*\)\s*$', r"\1\2(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)", content, flags=re.MULTILINE)

        if new_content != content:
            fixes.append(f"{fname}: fixed app.run()")
            _log_autofix(log_fn, f"Fixed app.run() in {fname}")
            content = new_content

        if "host='127.0.0.1'" in content:
            content = content.replace("host='127.0.0.1'", "host='0.0.0.0'")
        if 'host="127.0.0.1"' in content:
            content = content.replace('host="127.0.0.1"', 'host="0.0.0.0"')
        content = re.sub(r'debug\s*=\s*True', 'debug=False', content)

        if content != original:
            _write_file_safe(py_file, content)

    req_path = os.path.join(app_dir, 'requirements.txt')
    if not os.path.exists(req_path):
        detected = set()
        for f in os.listdir(app_dir):
            if not f.endswith('.py'):
                continue
            c = _read_file_safe(os.path.join(app_dir, f))
            if 'from flask' in c or 'import flask' in c:
                detected.add('flask')
            if 'from fastapi' in c or 'import fastapi' in c:
                detected.add('fastapi')
                detected.add('uvicorn')
            if 'import requests' in c:
                detected.add('requests')
            if 'import telebot' in c or 'from telebot' in c:
                detected.add('pyTelegramBotAPI')
            if 'import telegram' in c and 'telebot' not in c:
                detected.add('python-telegram-bot')
            if 'from dotenv' in c or 'import dotenv' in c:
                detected.add('python-dotenv')
            if 'import pymongo' in c:
                detected.add('pymongo')
        if detected:
            _write_file_safe(req_path, '\n'.join(sorted(detected)) + '\n')
            fixes.append(f"created requirements.txt with {len(detected)} packages")
    return fixes

def autofix_node_app(app_dir, log_fn=None):
    fixes = []
    js_files = []
    for name in ['index.js', 'server.js', 'app.js', 'main.js', 'bot.js']:
        p = os.path.join(app_dir, name)
        if os.path.exists(p):
            js_files.append(p)
    if not js_files:
        for f in os.listdir(app_dir):
            if f.endswith('.js') and not f.startswith('_'):
                js_files.append(os.path.join(app_dir, f))

    for js_file in js_files:
        content = _read_file_safe(js_file)
        if not content.strip():
            continue
        original = content
        fname = os.path.basename(js_file)

        def fix_listen(match):
            var_name = match.group(1)
            port = match.group(2)
            if 'process.env.PORT' in match.group(0):
                return match.group(0)
            return f"{var_name}.listen(process.env.PORT || {port}, '0.0.0.0'"

        new_content = re.sub(r'(\w+)\.listen\s*\(\s*(\d{2,5})', fix_listen, content)
        if new_content != content:
            content = new_content
            fixes.append(f"{fname}: fixed listen() to use PORT")

        content = re.sub(r"\.listen\s*\(\s*process\.env\.PORT\s*\|\|\s*\d+\s*\)", ".listen(process.env.PORT || 3000, '0.0.0.0')", content)

        if content != original:
            _write_file_safe(js_file, content)

    # package.json fix
    pkg_path = os.path.join(app_dir, 'package.json')
    if os.path.exists(pkg_path):
        try:
            with open(pkg_path, 'r', encoding='utf-8') as pf:
                pkg_data = json.load(pf)

            needs_fix = False
            if pkg_data.get('type') == 'module':
                uses_require = False
                for js_f in js_files:
                    js_content = _read_file_safe(js_f)
                    if 'require(' in js_content:
                        uses_require = True
                        break
                if uses_require:
                    del pkg_data['type']
                    needs_fix = True
                    fixes.append("removed 'type: module' (using require())")

            if 'type' not in pkg_data:
                uses_import = False
                for js_f in js_files:
                    js_content = _read_file_safe(js_f)
                    if re.search(r'^\s*import\s+', js_content, re.MULTILINE):
                        uses_import = True
                        break
                if not uses_import:
                    pkg_data['type'] = 'commonjs'
                    needs_fix = True
                    fixes.append("added 'type: commonjs'")

            if needs_fix:
                _write_file_safe(pkg_path, json.dumps(pkg_data, indent=2))
        except Exception:
            pass

    if not os.path.exists(pkg_path) and js_files:
        entry = os.path.basename(js_files[0])
        deps = set()
        for f in js_files:
            c = _read_file_safe(f)
            if 'express' in c:
                deps.add('express')
            if 'cors' in c:
                deps.add('cors')
            if 'dotenv' in c:
                deps.add('dotenv')
            if 'node-telegram-bot-api' in c:
                deps.add('node-telegram-bot-api')
        if not deps:
            deps.add('express')
        pkg_json = {
            "name": "deployed-app",
            "version": "1.0.0",
            "main": entry,
            "type": "commonjs",
            "scripts": {"start": f"node {entry}"},
            "dependencies": {d: "latest" for d in sorted(deps)}
        }
        _write_file_safe(pkg_path, json.dumps(pkg_json, indent=2))
        fixes.append(f"created package.json")
    return fixes

def autofix_php_app(app_dir, log_fn=None):
    fixes = []
    if not os.path.exists(os.path.join(app_dir, 'index.php')):
        for f in os.listdir(app_dir):
            if f.endswith('.php'):
                try:
                    shutil.copy(os.path.join(app_dir, f), os.path.join(app_dir, 'index.php'))
                    fixes.append(f"copied {f} -> index.php")
                except Exception:
                    pass
                break
    return fixes

def autofix_static_app(app_dir, log_fn=None):
    fixes = []
    if not os.path.exists(os.path.join(app_dir, 'index.html')):
        for f in os.listdir(app_dir):
            if f.endswith(('.html', '.htm')):
                try:
                    shutil.copy(os.path.join(app_dir, f), os.path.join(app_dir, 'index.html'))
                    fixes.append(f"copied {f} -> index.html")
                except Exception:
                    pass
                break
        else:
            _write_file_safe(os.path.join(app_dir, 'index.html'), '<!DOCTYPE html>\n<html><body><h1>App Deployed!</h1></body></html>')
            fixes.append("created default index.html")
    return fixes

def autofix_app(app_dir, log_fn=None):
    results = {'fixes': [], 'project_type': 'unknown'}
    try:
        ptype = detect_project_type(app_dir)
        results['project_type'] = ptype
        _log_autofix(log_fn, f"Detected project type: {ptype}")
        if ptype == 'python':
            results['fixes'].extend(autofix_python_app(app_dir, log_fn))
        elif ptype == 'node':
            results['fixes'].extend(autofix_node_app(app_dir, log_fn))
        elif ptype == 'php':
            results['fixes'].extend(autofix_php_app(app_dir, log_fn))
        elif ptype == 'static':
            results['fixes'].extend(autofix_static_app(app_dir, log_fn))
    except Exception as e:
        _log_autofix(log_fn, f"AutoFix error: {e}")
    return results

# ============================================
# PORT CHECK
# ============================================
def _port_is_open(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

# ============================================
# NODE.JS INSTALL - MULTI-STRATEGY
# ============================================
def install_node_deps(app_dir, log_handle, env):
    """Multi-strategy npm install with verification."""
    pkg_path = os.path.join(app_dir, 'package.json')
    node_modules = os.path.join(app_dir, 'node_modules')
    lock_file = os.path.join(app_dir, 'package-lock.json')

    if not os.path.exists(pkg_path):
        log_handle.write("[NODE] No package.json - skipping\n")
        log_handle.flush()
        return False

    # Read package.json
    try:
        with open(pkg_path, 'r', encoding='utf-8') as pf:
            pkg_data = json.load(pf)
    except Exception as e:
        log_handle.write(f"[NODE] Cannot read package.json: {e}\n")
        log_handle.flush()
        return False

    deps = {}
    deps.update(pkg_data.get('dependencies', {}) or {})
    deps.update(pkg_data.get('devDependencies', {}) or {})

    log_handle.write(f"[NODE] package.json declares {len(deps)} dependencies\n")
    log_handle.flush()

    # Check if install needed
    need_install = False
    missing_deps = []

    if not os.path.exists(node_modules):
        need_install = True
        log_handle.write("[NODE] node_modules missing\n")
    else:
        for dep_name in deps.keys():
            dep_path = os.path.join(node_modules, dep_name)
            if not os.path.exists(dep_path):
                need_install = True
                missing_deps.append(dep_name)
        if missing_deps:
            log_handle.write(f"[NODE] Missing: {', '.join(missing_deps[:8])}\n")

    log_handle.flush()

    if not need_install:
        log_handle.write("[NODE] All dependencies already installed\n")
        log_handle.flush()
        return True

    # CLEAN if partially broken
    if os.path.exists(node_modules) and missing_deps:
        log_handle.write("[NODE] Cleaning broken node_modules...\n")
        log_handle.flush()
        shutil.rmtree(node_modules, ignore_errors=True)
        if os.path.exists(lock_file):
            try:
                os.remove(lock_file)
            except Exception:
                pass

    # ===== STRATEGY 1: Standard install =====
    log_handle.write("\n[NODE] Strategy 1: npm install --legacy-peer-deps\n")
    log_handle.flush()
    try:
        p1 = subprocess.Popen(
            'npm install --legacy-peer-deps --no-audit --no-fund --loglevel=warn',
            cwd=app_dir, env=env, shell=True,
            stdout=log_handle, stderr=subprocess.STDOUT, text=True
        )
        p1.wait(timeout=1200)
        log_handle.write(f"\n[NODE] Strategy 1 exit: {p1.returncode}\n")
        log_handle.flush()
        if p1.returncode == 0 and os.path.exists(node_modules):
            return True
    except Exception as e:
        log_handle.write(f"[NODE] Strategy 1 error: {e}\n")
        log_handle.flush()

    # ===== STRATEGY 2: Force install =====
    log_handle.write("\n[NODE] Strategy 2: npm install --force\n")
    log_handle.flush()
    try:
        p2 = subprocess.Popen(
            'npm install --legacy-peer-deps --force --no-audit --no-fund',
            cwd=app_dir, env=env, shell=True,
            stdout=log_handle, stderr=subprocess.STDOUT, text=True
        )
        p2.wait(timeout=1200)
        log_handle.write(f"\n[NODE] Strategy 2 exit: {p2.returncode}\n")
        log_handle.flush()
        if p2.returncode == 0 and os.path.exists(node_modules):
            return True
    except Exception as e:
        log_handle.write(f"[NODE] Strategy 2 error: {e}\n")
        log_handle.flush()

    # ===== STRATEGY 3: Install missing deps directly =====
    if missing_deps:
        log_handle.write(f"\n[NODE] Strategy 3: Direct install of missing packages\n")
        log_handle.flush()
        try:
            deps_str = ' '.join(missing_deps[:15])
            p3 = subprocess.Popen(
                f'npm install {deps_str} --legacy-peer-deps --force --no-audit --no-fund',
                cwd=app_dir, env=env, shell=True,
                stdout=log_handle, stderr=subprocess.STDOUT, text=True
            )
            p3.wait(timeout=1200)
            log_handle.write(f"\n[NODE] Strategy 3 exit: {p3.returncode}\n")
            log_handle.flush()
        except Exception as e:
            log_handle.write(f"[NODE] Strategy 3 error: {e}\n")
            log_handle.flush()

    return os.path.exists(node_modules)

# ============================================
# run_local_fallback
# ============================================
def run_local_fallback(app_id, app_dir, port, build_cmd=None, start_cmd=None):
    try:
        log_file = os.path.join(APP_LOGS_DIR, f"{app_id}.log")
        log_handle = open(log_file, 'a', encoding='utf-8', errors='replace')

        log_handle.write(f"\n\n{'='*60}\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Deploy start\n{'='*60}\n")
        log_handle.write(f"Project type: {detect_project_type(app_dir)}\n")
        log_handle.write(f"Node: {NODE_AVAILABLE}, npm: {NPM_AVAILABLE}, Python: {PYTHON_AVAILABLE}\n")
        log_handle.write(f"Termux: {IS_TERMUX}\n")
        log_handle.flush()

        # AUTO-FIX
        if AUTOFIX_ENABLED:
            log_handle.write("\n[AUTOFIX] Scanning...\n")
            log_handle.flush()
            def _fix_log(msg):
                log_handle.write(f"{msg}\n")
                log_handle.flush()
            try:
                fix_results = autofix_app(app_dir, log_fn=_fix_log)
                if fix_results['fixes']:
                    log_handle.write(f"\n[AUTOFIX] {len(fix_results['fixes'])} fix(es) applied\n")
                    log_handle.flush()
                else:
                    log_handle.write("[AUTOFIX] No fixes needed\n")
                    log_handle.flush()
            except Exception as e:
                log_handle.write(f"[AUTOFIX] Error: {e}\n")
                log_handle.flush()

        if not build_cmd:
            build_cmd = auto_detect_build_cmd(app_dir)
        if not start_cmd:
            start_cmd = auto_detect_start_cmd(app_dir, port)

        log_handle.write(f"Build: {build_cmd or '(none)'}\n")
        log_handle.write(f"Start: {start_cmd or '(none)'}\n")
        log_handle.flush()

        if not start_cmd:
            log_handle.close()
            return None, "No start command"

        env = build_env({'PORT': str(port)})
        ptype = detect_project_type(app_dir)

        # NODE.JS SETUP
        if ptype == 'node':
            log_handle.write(f"\n[NODE] ========== NODE.JS SETUP ==========\n")
            log_handle.write(f"[NODE] Using {NODE_AVAILABLE=} {NPM_AVAILABLE=}\n")
            log_handle.flush()
            install_node_deps(app_dir, log_handle, env)
            log_handle.write("[NODE] ========== SETUP DONE ==========\n\n")
            log_handle.flush()

        # Skip build for node (already done)
        if build_cmd and build_cmd.strip():
            skip = (ptype == 'node' and 'npm install' in build_cmd)
            if not skip:
                log_handle.write(f"\n[BUILD] $ {build_cmd}\n")
                log_handle.flush()
                try:
                    bp = subprocess.Popen(build_cmd, cwd=app_dir, env=env, stdout=log_handle, stderr=subprocess.STDOUT, shell=True, text=True)
                    bp.wait(timeout=600)
                    log_handle.write(f"[BUILD] Exit: {bp.returncode}\n")
                    log_handle.flush()
                except Exception as be:
                    log_handle.write(f"[BUILD] Error: {be}\n")
                    log_handle.flush()
            else:
                log_handle.write("\n[BUILD] Skipping (already installed)\n")
                log_handle.flush()

        # START
        log_handle.write(f"\n[START] $ {start_cmd}\n")
        log_handle.write(f"[START] Port: {port}\n")
        log_handle.write("=" * 60 + "\n\n")
        log_handle.flush()

        proc = subprocess.Popen(start_cmd, cwd=app_dir, env=env, stdout=log_handle, stderr=subprocess.STDOUT, shell=True, text=True)

        log_handle.write(f"\n[VERIFY] Waiting 3s...\n")
        log_handle.flush()
        time.sleep(3)

        if proc.poll() is not None:
            log_handle.write(f"\n[ERROR] Process exited! Code: {proc.returncode}\n")
            log_handle.flush()
            log_handle.close()
            return None, f"App crashed (exit {proc.returncode})"

        log_handle.write(f"[VERIFY] Checking port {port}...\n")
        log_handle.flush()

        port_ready = False
        for i in range(15):
            if _port_is_open('127.0.0.1', port):
                port_ready = True
                log_handle.write(f"[VERIFY] Port {port} is OPEN! ({i+1}s)\n")
                log_handle.flush()
                break
            time.sleep(1)

        if not port_ready:
            log_handle.write(f"\n[ERROR] Port {port} not opened!\n")
            log_handle.flush()
            try:
                proc.kill()
            except Exception:
                pass
            log_handle.close()
            return None, f"Port {port} not listening"

        log_handle.write(f"\n[SUCCESS] App running on port {port}\n")
        log_handle.flush()
        return proc, None
    except Exception as e:
        return None, str(e)

# ============================================
# Error handlers
# ============================================
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'status': 'error', 'msg': 'File too large! Max 500MB'}), 413

@app.errorhandler(500)
def internal_error(error):
    traceback.print_exc()
    return jsonify({'status': 'error', 'msg': f'Server error: {str(error)}'}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return e
    traceback.print_exc()
    return jsonify({'status': 'error', 'msg': f'Server error: {str(e)}'}), 500

# ============================================
# Rate limiter & helpers
# ============================================
class RateLimiter:
    def check_rate(self, server_id, limit_percent):
        if not PSUTIL_AVAILABLE:
            return False, 0
        if server_id not in CPU_HISTORY:
            CPU_HISTORY[server_id] = []
        server, _ = get_server_by_id(server_id)
        if not server or server.get('status') != 'running':
            return False, 0
        pid = server.get('pid')
        if not pid:
            return False, 0
        try:
            proc = psutil.Process(pid)
            cpu = proc.cpu_percent(interval=1)
            now = time.time()
            CPU_HISTORY[server_id].append({'time': now, 'cpu': cpu})
            CPU_HISTORY[server_id] = [h for h in CPU_HISTORY[server_id] if now - h['time'] < 30]
            recent = [h['cpu'] for h in CPU_HISTORY[server_id] if now - h['time'] < 10]
            if recent:
                avg_cpu = sum(recent) / len(recent)
                if avg_cpu > limit_percent:
                    return True, avg_cpu
        except Exception:
            pass
        return False, 0

rate_limiter = RateLimiter()

def should_auto_restart(server_id):
    if server_id not in CRASH_COUNT:
        CRASH_COUNT[server_id] = {'count': 0, 'last_crash': time.time()}
    crash_info = CRASH_COUNT[server_id]
    if time.time() - crash_info['last_crash'] < 60:
        if crash_info['count'] >= 3:
            return False
    else:
        crash_info['count'] = 0
    crash_info['count'] += 1
    crash_info['last_crash'] = time.time()
    return True

def generate_random_password(length=10):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

# ============================================
# User management
# ============================================
def load_users():
    if not os.path.exists(USERS_FILE):
        default = {"admin": {"email": DEFAULT_ADMIN_EMAIL, "password": hash_password(DEFAULT_ADMIN_PASSWORD), "role": "admin"}}
        save_users(default)
        return default
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        data = {}
    if 'admin' not in data:
        data['admin'] = {"email": DEFAULT_ADMIN_EMAIL, "password": hash_password(DEFAULT_ADMIN_PASSWORD), "role": "admin"}
        save_users(data)
    else:
        if 'email' not in data['admin']:
            data['admin']['email'] = DEFAULT_ADMIN_EMAIL
            save_users(data)
    return data

def save_users(data):
    with _users_lock:
        tmp = USERS_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        os.replace(tmp, USERS_FILE)

def get_server_dir(server_id):
    server_dir = os.path.join(BOTS_DIR, server_id)
    os.makedirs(server_dir, exist_ok=True)
    return server_dir

def check_server_valid(server_id):
    users = load_users()
    for uname, data in users.items():
        if uname == 'admin':
            continue
        servers = data.get('servers', [])
        if not isinstance(servers, list):
            continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                expiry = s.get('expiry', '')
                if expiry:
                    try:
                        exp_date = datetime.strptime(expiry, '%Y-%m-%d %H:%M:%S.%f')
                        if datetime.now() > exp_date:
                            return False, "expired"
                    except Exception:
                        pass
                return True, s
    return False, "deleted"

def get_server_by_id(server_id):
    users = load_users()
    for uname, data in users.items():
        if uname == 'admin':
            continue
        servers = data.get('servers', [])
        if not isinstance(servers, list):
            continue
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                return s, uname
    return None, None

def create_default_files(server_dir):
    main_py = os.path.join(server_dir, 'main.py')
    if not os.path.exists(main_py):
        with open(main_py, 'w', encoding='utf-8') as f:
            f.write('''import time
print("Bot running on ALAMIN HOSTING")
counter = 0
while True:
    counter += 1
    print(f"[{time.strftime('%H:%M:%S')}] Heartbeat #{counter}")
    time.sleep(10)
''')
    req_file = os.path.join(server_dir, 'requirements.txt')
    if not os.path.exists(req_file):
        with open(req_file, 'w', encoding='utf-8') as f:
            f.write('# Add packages here\n')

# ============================================
# Bot runner
# ============================================
def run_bot(server_id, main_file='main.py', requirements_file='requirements.txt'):
    server_dir = get_server_dir(server_id)
    main_path = os.path.join(server_dir, main_file)
    log_file = os.path.join(server_dir, 'output.log')
    python_exe = sys.executable

    def log(msg):
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(f"{msg}\n")
                f.flush()
        except Exception:
            pass

    if not os.path.exists(main_path):
        return None, f"ERROR: {main_file} not found!"

    if os.path.exists(log_file):
        try:
            os.remove(log_file)
        except Exception:
            open(log_file, 'w').close()

    ts = lambda: datetime.now().strftime('%I:%M:%S %p')
    server, _ = get_server_by_id(server_id)
    cpu_limit = server.get('cpu_limit', 80) if server else 80

    if requirements_file and requirements_file.strip():
        req_path = os.path.join(server_dir, requirements_file.strip())
        if os.path.exists(req_path):
            with open(req_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith('#')]
            if lines:
                try:
                    proc = subprocess.Popen([python_exe, '-m', 'pip', 'install', '-r', os.path.abspath(req_path), '--disable-pip-version-check'],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                    for line in iter(proc.stdout.readline, ''):
                        if line.strip():
                            log(f"[{ts()}] {line.rstrip()}")
                    proc.wait()
                except Exception as e:
                    log(f"[{ts()}] pip error: {e}")

    try:
        main_path_abs = os.path.abspath(main_path)
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUNBUFFERED'] = '1'

        proc = subprocess.Popen([python_exe, main_path_abs], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=server_dir, text=True, encoding='utf-8', errors='replace', bufsize=1, env=env)

        log(f"[{ts()}] PID: {proc.pid}")

        if PSUTIL_AVAILABLE:
            def rate_monitor():
                while proc.poll() is None:
                    time.sleep(5)
                    exceeded, avg_cpu = rate_limiter.check_rate(server_id, cpu_limit)
                    if exceeded:
                        proc.terminate()
                        time.sleep(2)
                        if proc.poll() is None:
                            proc.kill()
                        break
            threading.Thread(target=rate_monitor, daemon=True).start()

        def stream_output():
            try:
                with open(log_file, 'a', encoding='utf-8') as f:
                    for line in iter(proc.stdout.readline, ''):
                        if line:
                            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] {line.rstrip()}\n")
                            f.flush()
            except Exception:
                pass
        threading.Thread(target=stream_output, daemon=True).start()
        return proc.pid, None
    except Exception as e:
        log(f"[{ts()}] Error: {e}")
        return None, str(e)

def stop_bot_process(pid):
    try:
        if IS_WINDOWS:
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
        else:
            os.kill(pid, 15)
            time.sleep(1)
            try:
                os.kill(pid, 9)
            except Exception:
                pass
        return True
    except Exception:
        return False

def monitor_bot(server_id, pid):
    while True:
        try:
            os.kill(pid, 0)
        except Exception:
            break
        time.sleep(5)

    server, _ = get_server_by_id(server_id)
    if not server or server.get('stopped_by_user') or server.get('rate_limit_exceeded'):
        return

    if should_auto_restart(server_id):
        time.sleep(3)
        new_pid, error = run_bot(server_id, server.get('main_file', 'main.py'), server.get('requirements_file', 'requirements.txt'))
        if new_pid:
            users = load_users()
            for uname, data in users.items():
                if uname == 'admin':
                    continue
                for s in data.get('servers', []):
                    if isinstance(s, dict) and s.get('server_id') == server_id:
                        s['status'] = 'running'
                        s['pid'] = new_pid
                        s['started_at'] = str(datetime.now())
                        s['rate_limit_exceeded'] = False
                        s['stopped_by_user'] = False
                        save_users(users)
                        break
            threading.Thread(target=monitor_bot, args=(server_id, new_pid), daemon=True).start()

def get_process_stats(pid):
    if not PSUTIL_AVAILABLE:
        return {'cpu_percent': 0, 'ram_mb': 0, 'ram_display': '0 MB'}
    try:
        proc = psutil.Process(pid)
        cpu = proc.cpu_percent(interval=0.5)
        mem = proc.memory_info()
        ram = mem.rss / (1024 * 1024)
        return {'cpu_percent': round(cpu, 1), 'ram_mb': round(ram, 1),
                'ram_display': f"{ram:.1f} MB" if ram < 1024 else f"{ram/1024:.1f} GB"}
    except Exception:
        return {'cpu_percent': 0, 'ram_mb': 0, 'ram_display': '0 MB'}

def get_network_stats(psutil_pid):
    if not PSUTIL_AVAILABLE:
        return "0 KB", "0 KB"
    try:
        proc = psutil.Process(psutil_pid)
        io = proc.io_counters()
        if io:
            return format_bytes(io.read_bytes / 1024), format_bytes(io.write_bytes / 1024)
    except Exception:
        pass
    return "0 KB", "0 KB"

def format_bytes(kb):
    if kb < 1024:
        return f"{kb:.1f} KB"
    mb = kb / 1024
    if mb < 1024:
        return f"{mb:.1f} MB"
    gb = mb / 1024
    return f"{gb:.2f} GB"

# ============================================
# Routes
# ============================================
@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'docker': DOCKER_AVAILABLE, 'node': NODE_AVAILABLE,
                    'npm': NPM_AVAILABLE, 'python': PYTHON_AVAILABLE, 'php': PHP_AVAILABLE,
                    'psutil': PSUTIL_AVAILABLE, 'jwt': JWT_AVAILABLE, 'autofix': AUTOFIX_ENABLED,
                    'termux': IS_TERMUX, 'time': str(datetime.now())}), 200

@app.route('/')
def index():
    return render_template('landing.html')

@app.route('/landing')
def landing():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        users = load_users()
        admin_data = users.get('admin', {})
        admin_email = (admin_data.get('email') or DEFAULT_ADMIN_EMAIL).strip().lower()
        if email == admin_email and verify_password(password, admin_data.get('password', '')):
            session['user'] = 'admin'
            session['email'] = admin_email
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        return render_template('login.html', error="Invalid email or password!")
    return render_template('login.html', error=None)

@app.route('/<server_id>/login', methods=['GET', 'POST'])
def server_login(server_id):
    valid, result = check_server_valid(server_id)
    if not valid:
        return render_template('error.html', error_type=result if result else "deleted", server_link=server_id)
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        users = load_users()
        for uname, data in users.items():
            if uname == 'admin':
                continue
            for s in data.get('servers', []):
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    if username == uname and verify_password(password, data.get('password', '')):
                        session['user'] = uname
                        session['role'] = 'user'
                        session['current_server_id'] = server_id
                        return redirect(url_for('server_home', server_id=server_id))
                    else:
                        return render_template('server_login.html', error="Invalid credentials!")
        return render_template('server_login.html', error="Invalid login!")
    return render_template('server_login.html', error=None)

@app.route('/<server_id>/home')
def server_home(server_id):
    if 'user' not in session or session.get('role') != 'user':
        return redirect(url_for('server_login', server_id=server_id))
    if session.get('current_server_id') != server_id:
        session.clear()
        return redirect(url_for('server_login', server_id=server_id))
    valid, result = check_server_valid(server_id)
    if not valid:
        session.clear()
        return render_template('error.html', error_type=result if result else "deleted", server_link=server_id)
    return render_template('home.html', username=session['user'], current_server=result)

@app.route('/logout')
def logout():
    server_id = session.get('current_server_id')
    session.clear()
    if server_id:
        return redirect(url_for('server_login', server_id=server_id))
    return redirect(url_for('login'))

@app.route('/admin')
def admin_dashboard():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    users = load_users()
    admin_email = users.get('admin', {}).get('email', DEFAULT_ADMIN_EMAIL)
    user_list = []
    total_servers = 0
    total_running = 0
    for uname, data in users.items():
        if uname == 'admin':
            continue
        servers = data.get('servers', [])
        if not isinstance(servers, list):
            servers = []
        running = sum(1 for s in servers if isinstance(s, dict) and s.get('status') == 'running')
        total_servers += len(servers)
        total_running += running
        user_list.append({'username': uname, 'password': data.get('password_plain', '********'),
                         'servers': servers, 'server_count': len(servers), 'running_count': running})
    return render_template('admin.html', users=user_list, total_servers=total_servers,
                         total_running=total_running, admin_email=admin_email)

@app.route('/admin/create_server', methods=['POST'])
def create_server():
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    server_type = data.get('server_type', 'python')
    ram = data.get('ram', '512MB')
    disk = data.get('disk', '1GB')
    expiry_days = int(data.get('expiry_days', 30))
    cpu_limit = int(data.get('cpu_limit', 80))
    if not username or not password:
        return jsonify({'error': 'Required!'}), 400
    users = load_users()
    server_id = str(uuid.uuid4())[:8]
    expiry_date = datetime.now() + timedelta(days=expiry_days)
    create_default_files(get_server_dir(server_id))
    new_server = {
        'server_id': server_id, 'link': server_id,
        'login_url': f"/{server_id}/login",
        'dashboard_url': f"/{server_id}/home",
        'full_link': request.host_url.rstrip('/') + f"/{server_id}/home",
        'type': server_type, 'ram': ram, 'disk': disk,
        'status': 'stopped', 'pid': None,
        'created': str(datetime.now()), 'expiry': str(expiry_date),
        'main_file': 'main.py', 'requirements_file': 'requirements.txt',
        'cpu_limit': cpu_limit, 'rate_limit_exceeded': False, 'stopped_by_user': False
    }
    if username not in users:
        users[username] = {'password': hash_password(password), 'password_plain': password, 'role': 'user', 'servers': []}
    else:
        users[username]['password_plain'] = password
    users[username]['servers'].append(new_server)
    save_users(users)
    return jsonify({'success': True, 'username': username, 'password': password,
                    'login_url': new_server['login_url'], 'hostname': new_server['full_link'],
                    'server_id': server_id, 'cpu_limit': cpu_limit})

@app.route('/admin/delete_server/<username>/<server_id>', methods=['POST'])
def delete_server(username, server_id):
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    users = load_users()
    if username in users:
        servers = users[username].get('servers', [])
        for s in servers:
            if isinstance(s, dict) and s.get('server_id') == server_id:
                if s.get('pid'):
                    stop_bot_process(s['pid'])
                try:
                    shutil.rmtree(get_server_dir(server_id))
                except Exception:
                    pass
                break
        users[username]['servers'] = [s for s in servers if isinstance(s, dict) and s.get('server_id') != server_id]
        if len(users[username]['servers']) == 0:
            del users[username]
        save_users(users)
    return jsonify({'success': True})

@app.route('/admin/server_action/<username>/<server_id>', methods=['POST'])
def admin_server_action(username, server_id):
    if 'user' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    data = request.get_json() or {}
    action = data.get('action', '').lower()
    if action not in ['start', 'stop', 'restart']:
        return jsonify({'success': False, 'error': 'Invalid action'}), 400
    users = load_users()
    if username not in users:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    target = None
    for s in users[username].get('servers', []):
        if isinstance(s, dict) and s.get('server_id') == server_id:
            target = s
            break
    if not target:
        return jsonify({'success': False, 'error': 'Server not found'}), 404
    try:
        if action == 'stop':
            if target.get('pid'):
                stop_bot_process(target['pid'])
            target['status'] = 'stopped'
            target['pid'] = None
            target['stopped_by_user'] = True
            save_users(users)
            return jsonify({'success': True, 'message': 'Stopped'})
        elif action == 'start':
            if target.get('status') == 'running':
                return jsonify({'success': True, 'message': 'Already running'})
            pid, error = run_bot(server_id, target.get('main_file', 'main.py'), target.get('requirements_file', 'requirements.txt'))
            if pid:
                users_fresh = load_users()
                for s in users_fresh[username].get('servers', []):
                    if isinstance(s, dict) and s.get('server_id') == server_id:
                        s['status'] = 'running'
                        s['pid'] = pid
                        s['started_at'] = str(datetime.now())
                        break
                save_users(users_fresh)
                threading.Thread(target=monitor_bot, args=(server_id, pid), daemon=True).start()
                return jsonify({'success': True, 'message': 'Started'})
            return jsonify({'success': False, 'error': error or 'Failed'}), 500
        elif action == 'restart':
            if target.get('pid'):
                stop_bot_process(target['pid'])
            time.sleep(2)
            pid, error = run_bot(server_id, target.get('main_file', 'main.py'), target.get('requirements_file', 'requirements.txt'))
            if pid:
                users_fresh = load_users()
                for s in users_fresh[username].get('servers', []):
                    if isinstance(s, dict) and s.get('server_id') == server_id:
                        s['status'] = 'running'
                        s['pid'] = pid
                        s['started_at'] = str(datetime.now())
                        break
                save_users(users_fresh)
                threading.Thread(target=monitor_bot, args=(server_id, pid), daemon=True).start()
                return jsonify({'success': True, 'message': 'Restarted'})
            return jsonify({'success': False, 'error': error or 'Failed'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# DEPLOY API
# ============================================
def get_free_port():
    used = set()
    db = load_deploy_db()
    for app in db.get('apps', {}).values():
        if app.get('port'):
            used.add(app['port'])
    port = 5100
    while port in used and port < 65000:
        port += 1
    return port

@app.route('/api/deploy-api', methods=['POST'])
def api_deploy():
    tmp_path = None
    try:
        file = request.files.get('file')
        if not file:
            return jsonify({"status": "error", "message": "No file"}), 400

        app_name = request.form.get('app_name', '').strip()
        mem_limit = request.form.get('mem_limit', '256m')
        cpu_limit = request.form.get('cpu_limit', '0.5')
        build_cmd = request.form.get('build_cmd', '').strip()
        start_cmd = request.form.get('start_cmd', '').strip()

        app_id = uuid.uuid4().hex[:8]
        app_dir = os.path.join(DEPLOY_DIR, app_id)
        os.makedirs(app_dir, exist_ok=True)

        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', file.filename)
        tmp_path = os.path.join(API_UPLOAD_DIR, f"{app_id}_{filename}")
        file.save(tmp_path)

        if filename.lower().endswith('.zip'):
            with zipfile.ZipFile(tmp_path, 'r') as z:
                z.extractall(app_dir)
        elif filename.lower().endswith('.js'):
            shutil.copy(tmp_path, os.path.join(app_dir, 'index.js'))
        elif filename.lower().endswith('.py'):
            shutil.copy(tmp_path, os.path.join(app_dir, 'main.py'))
        elif filename.lower().endswith('.html'):
            shutil.copy(tmp_path, os.path.join(app_dir, 'index.html'))
        else:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            return jsonify({"status": "error", "message": "Only .zip, .js, .py, .html"}), 400

        # Flatten nested folder
        entries = [e for e in os.listdir(app_dir) if not e.startswith('.') and e != '__MACOSX']
        if len(entries) == 1 and os.path.isdir(os.path.join(app_dir, entries[0])):
            inner = os.path.join(app_dir, entries[0])
            inner_items = os.listdir(inner)
            if any(f in inner_items for f in ['package.json', 'index.js', 'main.py', 'app.py', 'index.html', 'index.php', 'requirements.txt']):
                for item in inner_items:
                    shutil.move(os.path.join(inner, item), os.path.join(app_dir, item))
                try:
                    os.rmdir(inner)
                except Exception:
                    pass

        # Ensure package.json for JS
        if not os.path.exists(os.path.join(app_dir, 'package.json')) and \
           os.path.exists(os.path.join(app_dir, 'index.js')) and \
           not any(f in os.listdir(app_dir) for f in ['main.py', 'index.html', 'index.php']):
            with open(os.path.join(app_dir, 'package.json'), 'w') as f:
                json.dump({"name": f"app-{app_id}", "version": "1.0.0", "main": "index.js",
                          "type": "commonjs", "scripts": {"start": "node index.js"},
                          "dependencies": {"express": "^4.18.2", "cors": "^2.8.5"}}, f, indent=2)

        ptype = detect_project_type(app_dir)

        # AUTO-FIX
        autofix_summary = []
        if AUTOFIX_ENABLED:
            try:
                fix_results = autofix_app(app_dir, log_fn=None)
                autofix_summary = fix_results.get('fixes', [])
                print(f"[AUTOFIX] {app_id}: {len(autofix_summary)} fix(es)")
                for f in autofix_summary:
                    print(f"  * {f}")
            except Exception as e:
                print(f"[AUTOFIX] Error: {e}")

        if not build_cmd:
            build_cmd = auto_detect_build_cmd(app_dir)
        if not start_cmd:
            start_cmd = auto_detect_start_cmd(app_dir, 3000)
            if ptype == 'static':
                start_cmd = None

        port = get_free_port()
        if ptype == 'static':
            start_cmd = f'{sys.executable} -m http.server {port} --bind 127.0.0.1'

        jwt_token = generate_jwt_token(app_id, expires_days=30)

        db = load_deploy_db()
        db['apps'][app_id] = {
            'id': app_id, 'app_name': app_name, 'project_type': ptype, 'port': port,
            'createdAt': int(time.time() * 1000), 'status': 'stopped', 'filename': filename,
            'mem_limit': mem_limit, 'cpu_limit': cpu_limit, 'build_cmd': build_cmd or '',
            'start_cmd': start_cmd or '', 'container_id': None, 'docker_mode': False,
            'jwt_token': jwt_token, 'autofix': autofix_summary,
            'subdomain': f"{app_id}.local", 'subdomain_url': None,
            'url': f"{request.host_url.rstrip('/')}/api-app/{app_id}"
        }
        save_deploy_db(db)

        # RUN
        proc, err = run_local_fallback(app_id, app_dir, port, build_cmd=build_cmd, start_cmd=start_cmd)
        if proc:
            running_api_containers[app_id] = {'port': port, 'process': proc, 'dir': app_dir, 'mode': 'local'}
            db['apps'][app_id]['status'] = 'running'
            db['apps'][app_id].pop('error', None)
            save_deploy_db(db)
            message = "App deployed and running"
        else:
            db['apps'][app_id]['status'] = 'stopped'
            db['apps'][app_id]['error'] = err
            save_deploy_db(db)
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            return jsonify({"status": "error", "appId": app_id,
                          "message": f"Deploy failed: {err}",
                          "hint": "Check logs for details",
                          "logs_url": f"/api/app-logs/{app_id}",
                          "autofix": autofix_summary}), 500

        try:
            os.remove(tmp_path)
        except Exception:
            pass

        return jsonify({"status": "success", "appId": app_id,
                      "url": db['apps'][app_id]['url'], "port": port,
                      "docker": "fallback", "project_type": ptype,
                      "message": message, "autofix": autofix_summary})

    except Exception as e:
        traceback.print_exc()
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/deployed-apis', methods=['GET'])
def api_list_deployed():
    db = load_deploy_db()
    apps = db.get('apps', {})
    for app_id, info in apps.items():
        if app_id in running_api_containers:
            proc = running_api_containers[app_id]['process']
            info['status'] = 'running' if proc.poll() is None else 'stopped'
        else:
            info['status'] = info.get('status', 'stopped')

        stats = None
        if info['status'] == 'running' and app_id in running_api_containers and PSUTIL_AVAILABLE:
            try:
                proc = running_api_containers[app_id]['process']
                ps = psutil.Process(proc.pid)
                stats = {'cpu_percent': ps.cpu_percent(interval=0.1),
                        'ram_mb': round(ps.memory_info().rss / (1024*1024), 1)}
            except Exception:
                stats = None
        info['cpu_percent'] = stats['cpu_percent'] if stats else 0
        info['ram_mb'] = stats['ram_mb'] if stats else 0

        started = info.get('createdAt')
        if started and info['status'] == 'running':
            diff = int(time.time() - started / 1000)
            h, m = diff // 3600, (diff % 3600) // 60
            info['uptime'] = f"{h}h {m}m" if h > 0 else f"{m}m"
        else:
            info['uptime'] = '0m'

        if 'build_cmd' not in info:
            info['build_cmd'] = ''
        if 'start_cmd' not in info:
            info['start_cmd'] = ''
        if 'project_type' not in info:
            info['project_type'] = 'unknown'
    return jsonify({"apps": apps})

@app.route('/api/start-api/<app_id>', methods=['POST'])
def api_start_deployed(app_id):
    try:
        db = load_deploy_db()
        if app_id not in db.get('apps', {}):
            return jsonify({"status": "error", "message": "App not found"}), 404
        app_info = db['apps'][app_id]
        app_dir = os.path.join(DEPLOY_DIR, app_id)
        if not os.path.exists(app_dir):
            return jsonify({"status": "error", "message": "Files missing"}), 404
        if app_id in running_api_containers:
            proc = running_api_containers[app_id]['process']
            if proc.poll() is None:
                return jsonify({"status": "success", "message": "Already running"})
        proc, err = run_local_fallback(app_id, app_dir, app_info['port'],
                                      build_cmd=app_info.get('build_cmd', ''),
                                      start_cmd=app_info.get('start_cmd', ''))
        if proc:
            running_api_containers[app_id] = {'port': app_info['port'], 'process': proc, 'dir': app_dir, 'mode': 'local'}
            app_info['status'] = 'running'
            app_info.pop('error', None)
            save_deploy_db(db)
            return jsonify({"status": "success", "message": "Started"})
        app_info['status'] = 'stopped'
        app_info['error'] = err
        save_deploy_db(db)
        return jsonify({"status": "error", "message": err}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/stop-api/<app_id>', methods=['POST'])
def api_stop_deployed(app_id):
    try:
        db = load_deploy_db()
        if app_id not in db.get('apps', {}):
            return jsonify({"status": "error", "message": "App not found"}), 404
        app_info = db['apps'][app_id]
        if app_id in running_api_containers:
            try:
                proc = running_api_containers[app_id]['process']
                proc.terminate()
                time.sleep(1)
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass
            del running_api_containers[app_id]
        app_info['status'] = 'stopped'
        save_deploy_db(db)
        return jsonify({"status": "success", "message": "Stopped"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/rebuild-api/<app_id>', methods=['POST'])
def api_rebuild_deployed(app_id):
    try:
        db = load_deploy_db()
        if app_id not in db.get('apps', {}):
            return jsonify({"status": "error", "message": "App not found"}), 404
        app_info = db['apps'][app_id]
        app_dir = os.path.join(DEPLOY_DIR, app_id)
        if not os.path.exists(app_dir):
            return jsonify({"status": "error", "message": "Files missing"}), 404
        if app_id in running_api_containers:
            try:
                running_api_containers[app_id]['process'].terminate()
                time.sleep(1)
            except Exception:
                pass
            del running_api_containers[app_id]
        proc, err = run_local_fallback(app_id, app_dir, app_info['port'],
                                      build_cmd=app_info.get('build_cmd', ''),
                                      start_cmd=app_info.get('start_cmd', ''))
        if proc:
            running_api_containers[app_id] = {'port': app_info['port'], 'process': proc, 'dir': app_dir, 'mode': 'local'}
            app_info['status'] = 'running'
            app_info.pop('error', None)
            save_deploy_db(db)
            return jsonify({"status": "success", "message": "Rebuilt"})
        app_info['status'] = 'stopped'
        app_info['error'] = err
        save_deploy_db(db)
        return jsonify({"status": "error", "message": err}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/delete-api/<app_id>', methods=['DELETE'])
def api_delete_deployed(app_id):
    try:
        if app_id in running_api_containers:
            try:
                running_api_containers[app_id]['process'].kill()
            except Exception:
                pass
            del running_api_containers[app_id]
        app_dir = os.path.join(DEPLOY_DIR, app_id)
        if os.path.exists(app_dir):
            shutil.rmtree(app_dir, ignore_errors=True)
        log_file = os.path.join(APP_LOGS_DIR, f"{app_id}.log")
        if os.path.exists(log_file):
            try:
                os.remove(log_file)
            except Exception:
                pass
        db = load_deploy_db()
        if app_id in db.get('apps', {}):
            del db['apps'][app_id]
            save_deploy_db(db)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/app-logs/<app_id>')
def api_app_logs(app_id):
    log_file = os.path.join(APP_LOGS_DIR, f"{app_id}.log")
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                logs = f.read()[-50000:]
        except Exception:
            logs = "> Error reading"
    else:
        logs = "> No logs"
    return jsonify({'logs': logs})

@app.route('/api/jwt/<app_id>')
def api_get_jwt(app_id):
    db = load_deploy_db()
    app_info = db.get('apps', {}).get(app_id)
    if not app_info:
        return jsonify({'status': 'error', 'message': 'App not found'}), 404
    token = app_info.get('jwt_token')
    if not token:
        token = generate_jwt_token(app_id, expires_days=30)
        app_info['jwt_token'] = token
        save_deploy_db(db)
    return jsonify({'status': 'success', 'token': token, 'app_id': app_id})

# ============================================
# API Proxy
# ============================================
@app.route('/api-app/<app_id>', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
@app.route('/api-app/<app_id>/<path:path>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
def proxy_deployed_api(app_id, path):
    if not REQUESTS_AVAILABLE:
        return "requests module missing", 500
    db = load_deploy_db()
    app_info = db.get('apps', {}).get(app_id)
    if not app_info:
        return jsonify({'error': 'App not found'}), 404
    if app_info.get('status') != 'running':
        return jsonify({'error': 'App not running'}), 503
    port = app_info.get('port')
    if not port:
        return jsonify({'error': 'Port not set'}), 500
    target = f"http://127.0.0.1:{port}/{path}"

    if request.method == 'OPTIONS':
        response = Response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,PATCH,OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = '*'
        return response

    try:
        headers = {k: v for k, v in request.headers if k.lower() not in ('host', 'connection')}
        resp = requests.request(method=request.method, url=target, headers=headers,
                              data=request.get_data(), params=request.args,
                              timeout=60, allow_redirects=False)
        excluded = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        resp_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
        resp_headers.append(('Access-Control-Allow-Origin', '*'))
        return Response(resp.content, status=resp.status_code, headers=resp_headers)
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Timeout'}), 504
    except requests.exceptions.ConnectionError:
        log_file = os.path.join(APP_LOGS_DIR, f"{app_id}.log")
        tail = ""
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', errors='replace') as f:
                    tail = ''.join(f.readlines()[-25:])
            except Exception:
                tail = "(error)"
        return jsonify({'error': 'Backend not reachable',
                      'hint': f'Not listening on port {port}',
                      'last_logs': tail}), 502
    except Exception as e:
        return jsonify({'error': f'Proxy: {str(e)}'}), 502

# ============================================
# File APIs (for bot files)
# ============================================
@app.route('/api/files/<server_id>')
def api_files(server_id):
    folder = request.args.get('folder', '')
    server_dir = get_server_dir(server_id)
    if folder:
        server_dir = os.path.join(server_dir, folder)
        if not os.path.abspath(server_dir).startswith(os.path.abspath(get_server_dir(server_id))):
            return jsonify({'files': []})
    if not os.path.exists(server_dir):
        return jsonify({'files': []})
    files = []
    try:
        for item in os.listdir(server_dir):
            item_path = os.path.join(server_dir, item)
            files.append({'name': item, 'is_dir': os.path.isdir(item_path),
                        'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0,
                        'modified': datetime.fromtimestamp(os.path.getmtime(item_path)).strftime('%Y-%m-%d %H:%M')})
    except Exception:
        pass
    return jsonify({'files': files})

@app.route('/api/file/<server_id>', methods=['GET'])
def api_get_file(server_id):
    filename = request.args.get('filename', '')
    filepath = os.path.join(get_server_dir(server_id), filename)
    if os.path.exists(filepath) and os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return jsonify({'content': f.read()})
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/file/<server_id>', methods=['POST'])
def api_save_file(server_id):
    data = request.get_json()
    filepath = os.path.join(get_server_dir(server_id), data.get('filename', ''))
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(data.get('content', ''))
    return jsonify({'success': True})

@app.route('/api/file/<server_id>', methods=['DELETE'])
def api_delete_file(server_id):
    data = request.get_json()
    filepath = os.path.join(get_server_dir(server_id), data.get('filename', ''))
    if os.path.exists(filepath):
        if os.path.isdir(filepath):
            shutil.rmtree(filepath)
        else:
            os.remove(filepath)
    return jsonify({'success': True})

@app.route('/api/upload/<server_id>', methods=['POST'])
def api_upload(server_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    folder = request.form.get('folder', '')
    server_dir = get_server_dir(server_id)
    if folder:
        server_dir = os.path.join(server_dir, folder)
        os.makedirs(server_dir, exist_ok=True)
    file = request.files['file']
    file.save(os.path.join(server_dir, file.filename))
    return jsonify({'success': True})

@app.route('/api/create_folder/<server_id>', methods=['POST'])
def api_create_folder(server_id):
    data = request.get_json()
    os.makedirs(os.path.join(get_server_dir(server_id), data.get('foldername', '')), exist_ok=True)
    return jsonify({'success': True})

@app.route('/api/rename/<server_id>', methods=['POST'])
def api_rename(server_id):
    d = request.get_json()
    server_dir = get_server_dir(server_id)
    old_path = os.path.join(server_dir, d.get('old_name', ''))
    new_path = os.path.join(server_dir, d.get('new_name', ''))
    if os.path.exists(old_path):
        os.rename(old_path, new_path)
        return jsonify({'success': True})
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/unzip/<server_id>', methods=['POST'])
def api_unzip(server_id):
    data = request.get_json()
    zip_path = os.path.join(get_server_dir(server_id), data.get('filename', ''))
    if os.path.exists(zip_path) and zip_path.endswith('.zip'):
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(os.path.dirname(zip_path))
            return jsonify({'status': 'success', 'msg': 'Extracted!'})
        except Exception as e:
            return jsonify({'status': 'error', 'msg': str(e)})
    return jsonify({'status': 'error', 'msg': 'Invalid zip'}), 400

@app.route('/api/get_startup/<server_id>')
def api_get_startup(server_id):
    server, _ = get_server_by_id(server_id)
    if server:
        return jsonify({'main_file': server.get('main_file', 'main.py'),
                      'requirements_file': server.get('requirements_file', 'requirements.txt')})
    return jsonify({'main_file': 'main.py', 'requirements_file': 'requirements.txt'})

@app.route('/api/set_startup/<server_id>', methods=['POST'])
def api_set_startup(server_id):
    d = request.get_json()
    users = load_users()
    for uname, udata in users.items():
        if uname == 'admin':
            continue
        for s in udata.get('servers', []):
            if isinstance(s, dict) and s.get('server_id') == server_id:
                s['main_file'] = d.get('main_file', 'main.py')
                s['requirements_file'] = d.get('requirements_file')
                save_users(users)
                return jsonify({'success': True})
    return jsonify({'error': 'Not found'}), 404

# ============================================
# Bot APIs
# ============================================
@app.route('/api/run/<server_id>', methods=['POST'])
def api_run(server_id):
    server, _ = get_server_by_id(server_id)
    if not server:
        return jsonify({'status': 'error', 'msg': 'Not found'})
    if server.get('status') == 'running':
        return jsonify({'status': 'error', 'msg': 'Already running!'})
    pid, error = run_bot(server_id, server.get('main_file', 'main.py'), server.get('requirements_file', 'requirements.txt'))
    if pid:
        users = load_users()
        for uname, data in users.items():
            if uname == 'admin':
                continue
            for s in data.get('servers', []):
                if isinstance(s, dict) and s.get('server_id') == server_id:
                    s['status'] = 'running'
                    s['pid'] = pid
                    s['started_at'] = str(datetime.now())
                    save_users(users)
                    break
        threading.Thread(target=monitor_bot, args=(server_id, pid), daemon=True).start()
        return jsonify({'status': 'success', 'msg': 'Started!'})
    return jsonify({'status': 'error', 'msg': error or 'Failed'})

@app.route('/api/stop/<server_id>', methods=['POST'])
def api_stop(server_id):
    server, _ = get_server_by_id(server_id)
    if not server:
        return jsonify({'status': 'error', 'msg': 'Not found'})
    if server.get('pid'):
        stop_bot_process(server['pid'])
    users = load_users()
    for uname, data in users.items():
        if uname == 'admin':
            continue
        for s in data.get('servers', []):
            if isinstance(s, dict) and s.get('server_id') == server_id:
                s['status'] = 'stopped'
                s['pid'] = None
                s['stopped_by_user'] = True
                save_users(users)
                break
    return jsonify({'status': 'success', 'msg': 'Stopped'})

@app.route('/api/logs/<server_id>')
def api_logs(server_id):
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    if os.path.exists(log_file):
        with open(log_file, 'r', encoding='utf-8') as f:
            logs = f.read()
    else:
        logs = ""
    return jsonify({'logs': logs})

@app.route('/api/clear_logs/<server_id>', methods=['POST'])
def api_clear_logs(server_id):
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    try:
        if os.path.exists(log_file):
            try:
                os.remove(log_file)
            except Exception:
                open(log_file, 'w').close()
        return jsonify({'status': 'success', 'msg': 'Cleared'})
    except Exception:
        return jsonify({'status': 'error'}), 500

@app.route('/api/command', methods=['POST'])
def api_command():
    data = request.get_json()
    cmd = data.get('cmd', '')
    server_id = data.get('server_id', '')
    log_file = os.path.join(get_server_dir(server_id), 'output.log')
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=get_server_dir(server_id), timeout=30)
        output = (result.stdout + result.stderr)[:2000]
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().strftime('%I:%M:%S %p')}] $ {cmd}\n{output}\n")
        return jsonify({'status': 'success', 'output': output})
    except Exception:
        return jsonify({'status': 'error', 'msg': 'Timeout'})

@app.route('/api/stats/<server_id>')
def api_stats(server_id):
    server, _ = get_server_by_id(server_id)
    if not server:
        return jsonify({'cpu': '0%', 'ram': '0 MB', 'uptime': '0h', 'status': 'unknown',
                      'cpu_limit': 80, 'net_in': '0 KB', 'net_out': '0 KB'})
    uptime, cpu, ram, net_in, net_out = "0h 0m", "0%", "0 MB", "0 KB", "0 KB"
    if server.get('status') == 'running' and server.get('pid'):
        stats = get_process_stats(server['pid'])
        cpu = f"{stats['cpu_percent']}%"
        ram = stats['ram_display']
        net_in, net_out = get_network_stats(server['pid'])
    if server.get('status') == 'running' and server.get('started_at'):
        try:
            start = datetime.strptime(server['started_at'], '%Y-%m-%d %H:%M:%S.%f')
            diff = datetime.now() - start
            if diff.days > 0:
                uptime = f"{diff.days}d {diff.seconds//3600}h"
            else:
                h, m, s = diff.seconds // 3600, (diff.seconds % 3600) // 60, diff.seconds % 60
                uptime = f"{h}h {m}m {s}s"
        except Exception:
            pass
    return jsonify({'cpu': cpu, 'ram': ram, 'uptime': uptime, 'net_in': net_in,
                  'net_out': net_out, 'cpu_limit': server.get('cpu_limit', 80),
                  'status': server.get('status', 'stopped')})

@app.route('/api/change_password/<server_id>', methods=['POST'])
def api_change_password(server_id):
    if 'user' not in session:
        return jsonify({'error': 'Not logged in!'}), 403
    data = request.get_json()
    new_password = data.get('new_password', '')
    if not new_password or len(new_password) < 4:
        return jsonify({'error': 'Password must be 4+ chars!'})
    users = load_users()
    username = session.get('user')
    if username in users:
        users[username]['password'] = hash_password(new_password)
        users[username]['password_plain'] = new_password
        save_users(users)
        return jsonify({'success': True, 'msg': 'Password changed!'})
    return jsonify({'error': 'User not found!'}), 404

# ============================================
# Public API - create server
# ============================================
@app.route('/api/create', methods=['GET'])
def api_create_server():
    username = request.args.get('username', '').strip()
    password = request.args.get('password', '').strip()
    server_type = request.args.get('type', 'python').strip()
    ram = request.args.get('ram', '1GB').strip()
    disk = request.args.get('disk', '1GB').strip()
    cpu_limit = int(request.args.get('cpu', '30'))
    days = int(request.args.get('days', '3'))
    if not password:
        password = generate_random_password(10)
    if not username:
        username = f"ALAMIN_CODEX{random.randint(10000, 99999)}"
    if len(username) < 3 or len(password) < 4:
        return jsonify({'status': 'error', 'message': 'Username 3+, password 4+'}), 400
    users = load_users()
    if username in users:
        return jsonify({'status': 'error', 'message': f"'{username}' exists!"}), 400
    server_id = str(uuid.uuid4())[:8]
    expiry_date = datetime.now() + timedelta(days=days)
    create_default_files(get_server_dir(server_id))
    host = request.host
    is_local = host.startswith('localhost') or host.startswith('127.0.0.1') or host.startswith('192.168')
    scheme = 'http' if is_local else 'https'
    full_url = f"{scheme}://{host}/{server_id}/login"
    new_server = {
        'server_id': server_id, 'login_url': f"/{server_id}/login",
        'dashboard_url': f"/{server_id}/home", 'full_link': full_url,
        'type': server_type, 'ram': ram, 'disk': disk,
        'status': 'stopped', 'pid': None,
        'created': str(datetime.now()), 'expiry': str(expiry_date),
        'main_file': 'main.py', 'requirements_file': 'requirements.txt',
        'cpu_limit': cpu_limit, 'rate_limit_exceeded': False, 'stopped_by_user': False
    }
    users[username] = {'password': hash_password(password), 'password_plain': password,
                      'role': 'user', 'servers': [new_server]}
    save_users(users)
    return jsonify({'status': 'success', 'message': 'Panel created!',
                  'username': username, 'password': password,
                  'server_type': server_type, 'ram': ram, 'disk': disk,
                  'cpu_limit': cpu_limit, 'validity': f'{days} days',
                  'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                  'full_url': full_url, 'server_id': server_id}), 200

# ============================================
# Startup
# ============================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    print("\n" + "=" * 60)
    print("ALAMIN HOSTING - PRO EDITION (Termux)")
    print("=" * 60)
    print(f"Port: {port}")
    print(f"Data dir: {DATA_DIR}")
    print(f"Termux: {'YES' if IS_TERMUX else 'NO'}")
    print(f"Node.js: {'YES' if NODE_AVAILABLE else 'NO'}  npm: {'YES' if NPM_AVAILABLE else 'NO'}")
    print(f"Python: {'YES' if PYTHON_AVAILABLE else 'NO'}")
    print(f"PHP: {'YES' if PHP_AVAILABLE else 'NO'}")
    print(f"psutil: {'YES' if PSUTIL_AVAILABLE else 'NO'}")
    print(f"JWT: {'pyjwt' if JWT_AVAILABLE else 'HMAC'}")
    print(f"AutoFix: {'ENABLED' if AUTOFIX_ENABLED else 'DISABLED'}")
    print(f"requests: {'YES' if REQUESTS_AVAILABLE else 'NO!'}")
    print(f"Admin: {DEFAULT_ADMIN_EMAIL}")
    print("=" * 60 + "\n")
    app.run(debug=debug_mode, host='0.0.0.0', port=port, threaded=True)