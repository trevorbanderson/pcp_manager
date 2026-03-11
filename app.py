# ── Environment must be bootstrapped before Config is imported ──────────────
import set_env

_active_env = set_env.setup()  # loads .env section + Azure Key Vault secrets into os.environ
# ────────────────────────────────────────────────────────────────────────────

import atexit

import pcp_logger as _pcp_logger

_log = _pcp_logger.setup(_active_env)
_log.setLevel('DEBUG')  # Force DEBUG for all environments

def _shutdown_log(_captured_log=_log):
    """Flush logging handlers on exit; avoids emit on already-closed streams."""
    for h in list(_captured_log.handlers):
        try:
            h.flush()
        except Exception:
            pass
atexit.register(_shutdown_log)

# Log startup config and environment
import base64
import io
import os
import platform
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pandas as pd
import pyDMNrules
import pyotp
import qrcode

from config import Config
from database import execute_query

# Log startup config and environment (after Config is imported)
_log.info(
    f"App startup: ENV={_active_env}, Python={platform.python_version()}, Host={platform.node()}",
    extra={
        "env": _active_env,
        "python_version": platform.python_version(),
        "host": platform.node(),
        "config": {k: getattr(Config, k) for k in dir(Config) if k.isupper()}
    }
)

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

# ---------------------------------------------------------------------------
# Test-only route for error handling tests (must be after app is defined)
# ---------------------------------------------------------------------------
@app.route('/fail')
def fail():
    raise Exception('fail!')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now():
    """Current local datetime (naive) for storing in the DB."""
    return datetime.now()


# ---------------------------------------------------------------------------
# Jinja2 template filter – format datetime as local 12-hour time
# ---------------------------------------------------------------------------
@app.template_filter('fmt_dt')
def fmt_dt(value, fmt=None):
    """Return dd-Mmm-yyyy h:mm AM/PM with no leading zero on hour.
    Stored datetimes are already in server local time – no TZ conversion needed."""
    if not value:
        return ''
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    hour = value.hour % 12 or 12
    ampm = 'AM' if value.hour < 12 else 'PM'
    return value.strftime('%d-%b-%Y ') + f'{hour}:{value.strftime("%M")} {ampm}'


@app.context_processor
def inject_helpers():
    """Make get_full_name(username) available in all templates."""
    _cache = {}
    def get_full_name(username):
        if not username:
            return ''
        if username not in _cache:
            rows = execute_query("SELECT full_name FROM users WHERE username = %s", (username,))
            _cache[username] = (rows[0].get('full_name') or username) if rows else username
        return _cache[username]
    return dict(get_full_name=get_full_name)

# ---------------------------------------------------------------------------
# Flask-Login setup
# ---------------------------------------------------------------------------
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


class User(UserMixin):
    """Wraps a users-table row for Flask-Login."""
    def __init__(self, row):
        self.id           = row['id']
        self.username     = row['username']
        self.full_name    = row.get('full_name') or row['username']
        self.email        = row['email']
        self.password_hash = row['password_hash']
        self.totp_secret  = row.get('totp_secret')
        self._is_active   = row['is_active']
        self.is_admin     = row['is_admin']

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return self._is_active


def _get_user_by_id(user_id):
    rows = execute_query("SELECT * FROM users WHERE id = %s", (int(user_id),))
    return User(rows[0]) if rows else None


def _get_user_by_username(username):
    rows = execute_query("SELECT * FROM users WHERE username = %s", (username,))
    return User(rows[0]) if rows else None


@login_manager.user_loader
def load_user(user_id):
    return _get_user_by_id(user_id)


# ---------------------------------------------------------------------------
# Email OTP helper
# ---------------------------------------------------------------------------
def send_otp_email(to_email, otp_code):
    _log.debug(f"send_otp_email called: to_email={to_email}, otp_code={otp_code}")
    msg = MIMEMultipart()
    msg['From']    = Config.MAIL_FROM
    msg['To']      = to_email
    msg['Subject'] = 'PCP Manager – Your Login Code'
    body = (
        f"Your one-time login code is:\n\n"
        f"    {otp_code}\n\n"
        f"This code expires in 10 minutes. Do not share it with anyone."
    )
    msg.attach(MIMEText(body, 'plain'))
    mail_password = Config.get_mail_password()
    with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
        server.ehlo()
        if Config.MAIL_USE_TLS:
            server.starttls()
        server.login(Config.MAIL_USERNAME, mail_password)
        server.sendmail(Config.MAIL_FROM, to_email, msg.as_string())


# ---------------------------------------------------------------------------
# Require login for every route except auth endpoints
# ---------------------------------------------------------------------------
@app.before_request
def require_login():
    public_endpoints = {'login', 'mfa_verify', 'logout', 'static', 'favicon_ico'}
    if request.endpoint and request.endpoint not in public_endpoints:
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))


@app.after_request
def log_request(response):
    """Log every HTTP request with method, path, status, and user."""
    # Skip static assets to keep logs clean
    if request.endpoint == 'static':
        return response
    user = getattr(current_user, 'username', None) if current_user.is_authenticated else 'anonymous'
    _log.info(
        f"{request.method} {request.path} -> {response.status_code}",
        extra={
            "http_method":   request.method,
            "path":          request.path,
            "status":        response.status_code,
            "user":          user,
            "ip":            request.remote_addr,
            "endpoint":      request.endpoint,
        },
    )
    return response


@app.errorhandler(Exception)
def handle_exception(exc):
    """Log unhandled exceptions (500-level errors)."""
    import traceback as _tb
    _log.error(
        f"Exception handler triggered: {exc}",
        extra={
            "path": request.path,
            "method": request.method,
            "ip": request.remote_addr,
            "traceback": _tb.format_exc(),
        },
        exc_info=True,
    )
    from werkzeug.exceptions import NotFound
    if isinstance(exc, NotFound):
        from flask import Response
        return Response("404 Not Found", status=404)
    # Only re-raise in debug mode; otherwise, return a 500 response
    from flask import Response, current_app
    if current_app.config.get('DEBUG', False):
        raise exc
    return Response("500 Internal Server Error", status=500)


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def login():
    _log.debug(f"Login route called: method={request.method}, data={request.form.to_dict()}")
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        next_url = request.form.get('next', '')

        user = _get_user_by_username(username)
        if not user or not user.is_active or not check_password_hash(user.password_hash, password):
            _log.warning(
                "Login failed – invalid credentials",
                extra={"username": username, "ip": request.remote_addr},
            )
            flash('Invalid username or password.', 'error')
            return render_template('auth/login.html', next=next_url)

        # Credentials valid — begin MFA step
        session['mfa_user_id'] = user.id
        session['mfa_next']    = next_url

        if user.totp_secret:
            session['mfa_method'] = 'totp'
            _log.info(
                "MFA initiated (TOTP)",
                extra={"username": username, "user_id": user.id, "ip": request.remote_addr},
            )
        else:
            otp = ''.join(secrets.choice('0123456789') for _ in range(6))
            session['mfa_method']      = 'email'
            session['mfa_otp']         = otp
            session['mfa_otp_expiry']  = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
            _is_dev = _active_env.lower() == 'dev'
            try:
                send_otp_email(user.email, otp)
                _log.info(
                    "MFA initiated (email OTP)",
                    extra={"username": username, "user_id": user.id, "ip": request.remote_addr},
                )
                if _is_dev:
                    flash(f'[DEV] OTP code: {otp}', 'warning')
                else:
                    flash(f'A 6-digit code has been sent to {user.email[:4]}***{user.email[user.email.index("@"):]}', 'info')
            except Exception as e:
                _log.error(
                    f"Failed to send email OTP: {e}",
                    extra={"username": username, "ip": request.remote_addr},
                )
                if _is_dev:
                    # In dev, show the code on screen even if email fails
                    flash(f'[DEV] Email send failed ({e}). OTP code: {otp}', 'warning')
                else:
                    flash(f'Could not send email OTP: {e}', 'error')
                    session.clear()
                    return render_template('auth/login.html', next=next_url)

        return redirect(url_for('mfa_verify'))

    return render_template('auth/login.html', next=request.args.get('next', ''))


@app.route('/mfa/verify', methods=['GET', 'POST'], endpoint='mfa_verify')
def mfa_verify():
    _log.debug(f"MFA verify route called: method={request.method}, data={request.form.to_dict()}")
    user_id = session.get('mfa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    method = session.get('mfa_method', 'totp')

    if request.method == 'POST':
        code = request.form.get('code', '').strip().replace(' ', '')
        user = _get_user_by_id(user_id)
        if not user:
            session.clear()
            return redirect(url_for('login'))

        valid = False
        if method == 'totp':
            totp = pyotp.TOTP(user.totp_secret)
            valid = totp.verify(code, valid_window=1)
        else:
            expiry_str = session.get('mfa_otp_expiry')
            stored_otp = session.get('mfa_otp', '')
            if expiry_str and datetime.utcnow() < datetime.fromisoformat(expiry_str):
                valid = secrets.compare_digest(code, stored_otp)
            else:
                flash('Code has expired. Please log in again.', 'error')
                session.clear()
                return redirect(url_for('login'))

        if valid:
            next_url = session.pop('mfa_next', None)
            session.pop('mfa_user_id', None)
            session.pop('mfa_method', None)
            session.pop('mfa_otp', None)
            session.pop('mfa_otp_expiry', None)
            login_user(user, remember=False)
            _log.info(
                "Login successful",
                extra={"username": user.username, "user_id": user.id,
                       "mfa_method": method, "ip": request.remote_addr},
            )
            if not user.totp_secret:
                flash('Login successful. Set up an authenticator app for stronger MFA.', 'info')
            return redirect(next_url or url_for('index'))
        else:
            _log.warning(
                "MFA failed – invalid code",
                extra={"user_id": user_id, "mfa_method": method, "ip": request.remote_addr},
            )
            flash('Invalid or expired code. Please try again.', 'error')

    return render_template('auth/mfa_verify.html', method=method)


@app.route('/logout', endpoint='logout')
def logout():
    username = getattr(current_user, 'username', 'unknown')
    user_id  = getattr(current_user, 'id', None)
    logout_user()
    session.clear()
    _log.info(
        "Logout",
        extra={"username": username, "user_id": user_id, "ip": request.remote_addr},
    )
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/mfa/setup/totp', methods=['GET', 'POST'], endpoint='mfa_setup_totp')
def mfa_setup_totp():
    if request.method == 'POST':
        code         = request.form.get('code', '').strip().replace(' ', '')
        setup_secret = session.get('totp_setup_secret')
        if not setup_secret:
            flash('Setup session expired. Please try again.', 'error')
            return redirect(url_for('mfa_setup_totp'))
        totp = pyotp.TOTP(setup_secret)
        if totp.verify(code, valid_window=1):
            execute_query("UPDATE users SET totp_secret = %s WHERE id = %s", (setup_secret, current_user.id))
            session.pop('totp_setup_secret', None)
            _log.info(
                "TOTP authenticator set up successfully",
                extra={"username": current_user.username, "user_id": current_user.id,
                       "ip": request.remote_addr},
            )
            flash('Authenticator app set up successfully! TOTP will now be required at every login.', 'success')
            return redirect(url_for('index'))
        else:
            _log.warning(
                "TOTP setup failed – invalid code",
                extra={"username": current_user.username, "user_id": current_user.id,
                       "ip": request.remote_addr},
            )
            flash('Invalid code — please scan the QR code again and try once more.', 'error')

    secret = pyotp.random_base32()
    session['totp_setup_secret'] = secret
    otp_uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name='PCP Manager')
    buf = io.BytesIO()
    qrcode.make(otp_uri).save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template('auth/totp_setup.html', qr_b64=qr_b64, secret=secret)


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------
@app.route('/users', endpoint='users_list')
def users_list():
    if not current_user.is_admin:
        flash('Admin access required.', 'error')
        return redirect(url_for('index'))
    users = execute_query(
        "SELECT id, username, email, is_active, is_admin, totp_secret, created_at "
        "FROM users ORDER BY username"
    )
    return render_template('users/list.html', users=users)


@app.route('/users/create', methods=['GET', 'POST'], endpoint='users_create')
def users_create():
    if not current_user.is_admin:
        flash('Admin access required.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        username  = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email     = request.form.get('email', '').strip()
        password  = request.form.get('password', '')
        is_admin  = request.form.get('is_admin') == 'on'
        if not username or not full_name or not email or not password:
            flash('Username, full name, email, and password are required.', 'error')
            return render_template('users/create.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('users/create.html')
        if execute_query("SELECT id FROM users WHERE username=%s OR email=%s", (username, email)):
            flash('A user with that username or email already exists.', 'error')
            return render_template('users/create.html')
        execute_query(
            "INSERT INTO users (username, full_name, email, password_hash, is_active, is_admin, created_by) "
            "VALUES (%s, %s, %s, %s, TRUE, %s, %s)",
            (username, full_name, email, generate_password_hash(password), is_admin, current_user.id)
        )
        flash(f"User '{username}' created.", 'success')
        return redirect(url_for('users_list'))
    return render_template('users/create.html')


@app.route('/users/<int:id>/edit', methods=['GET', 'POST'], endpoint='users_edit')
def users_edit(id):
    if not current_user.is_admin:
        flash('Admin access required.', 'error')
        return redirect(url_for('index'))
    rows = execute_query("SELECT * FROM users WHERE id = %s", (id,))
    if not rows:
        flash('User not found.', 'error')
        return redirect(url_for('users_list'))
    user_row = rows[0]
    if request.method == 'POST':
        full_name    = request.form.get('full_name', '').strip()
        email       = request.form.get('email', '').strip()
        is_admin    = request.form.get('is_admin') == 'on'
        is_active   = request.form.get('is_active') == 'on'
        new_password = request.form.get('new_password', '').strip()
        if new_password:
            if len(new_password) < 8:
                flash('New password must be at least 8 characters.', 'error')
                return render_template('users/edit.html', user=user_row)
            execute_query(
                "UPDATE users SET full_name=%s, email=%s, is_admin=%s, is_active=%s, password_hash=%s WHERE id=%s",
                (full_name, email, is_admin, is_active, generate_password_hash(new_password), id)
            )
        else:
            execute_query(
                "UPDATE users SET full_name=%s, email=%s, is_admin=%s, is_active=%s WHERE id=%s",
                (full_name, email, is_admin, is_active, id)
            )
        flash('User updated.', 'success')
        return redirect(url_for('users_list'))
    return render_template('users/edit.html', user=user_row)


@app.route('/users/<int:id>/reset_totp', methods=['POST'], endpoint='users_reset_totp')
def users_reset_totp(id):
    if not current_user.is_admin:
        flash('Admin access required.', 'error')
        return redirect(url_for('index'))
    execute_query("UPDATE users SET totp_secret = NULL WHERE id = %s", (id,))
    flash('TOTP reset — user will receive an email OTP on next login.', 'success')
    return redirect(url_for('users_list'))


@app.route('/users/<int:id>/delete', methods=['POST'], endpoint='users_delete')
def users_delete(id):
    if not current_user.is_admin:
        flash('Admin access required.', 'error')
        return redirect(url_for('index'))
    if id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('users_list'))
    execute_query("DELETE FROM users WHERE id = %s", (id,))
    flash('User deleted.', 'success')
    return redirect(url_for('users_list'))


def get_dmn_file_path():
    """Return the DMN workbook path for this app (local project file only)."""
    local_dmn_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'DMN.xlsx')
    if not os.path.exists(local_dmn_path):
        raise FileNotFoundError(f"DMN workbook not found: {local_dmn_path}")
    if os.path.getsize(local_dmn_path) == 0:
        raise ValueError(f"DMN workbook is empty: {local_dmn_path}")
    return local_dmn_path


def evaluate_dimension_formula(raw_formula, measurement, rows_per_4inch, stitches_per_4inch):
    """Safely evaluate supported numeric DMN formulas from Excel cells."""
    if raw_formula is None:
        return None

    formula = str(raw_formula).strip().strip('"')
    if not formula:
        return None

    # If already numeric, return directly.
    try:
        return float(formula)
    except ValueError:
        pass

    # Normalize Excel-style formulas to Python expression syntax.
    if formula.startswith('='):
        formula = formula[1:]
    formula = formula.replace('^', '**')

    safe_locals = {
        'measurement': float(measurement),
        'rows_per_4inch': float(rows_per_4inch),
        'stitches_per_4inch': float(stitches_per_4inch),
        'pi': 3.141592653589793,
    }
    # nosec B307 — eval is intentionally sandboxed: builtins are disabled and
    # the only names in scope are the four numeric safe_locals defined above.
    return float(eval(formula, {"__builtins__": {}}, safe_locals))  # nosec B307

# --- Age Maintenance ---
@app.route('/age', methods=['GET'], endpoint='age_list')
def age_list():
    ages = execute_query("SELECT * FROM age ORDER BY seq, id")
    return render_template('age/list.html', ages=ages)

@app.route('/age/create', methods=['GET', 'POST'], endpoint='age_create')
def age_create():
    if request.method == 'POST':
        query = """
            INSERT INTO age (id, name, abbreviation, seq)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM age), %s, %s, %s)
        """
        execute_query(query, (
            request.form['name'],
            request.form.get('abbreviation', ''),
            int(request.form.get('seq', 0))
        ), fetch=False)
        flash('Age created successfully!', 'success')
        return redirect(url_for('age_list'))
    return render_template('age/create.html')

@app.route('/age/edit/<int:id>', methods=['GET', 'POST'], endpoint='age_edit')
def age_edit(id):
    age = execute_query("SELECT * FROM age WHERE id = %s", (id,))
    age = age[0] if age else None
    if not age:
        flash('Age not found.', 'danger')
        return redirect(url_for('age_list'))
    if request.method == 'POST':
        query = 'UPDATE age SET name = %s, abbreviation = %s, seq = %s WHERE id = %s'
        execute_query(query, (
            request.form['name'],
            request.form.get('abbreviation', ''),
            int(request.form.get('seq', 0)),
            id
        ), fetch=False)
        flash('Age updated successfully!', 'success')
        return redirect(url_for('age_list'))
    return render_template('age/edit.html', age=age)


@app.route('/age/delete/<int:id>', methods=['POST'], endpoint='age_delete')
def age_delete(id):
    execute_query('DELETE FROM age WHERE id = %s', (id,), fetch=False)
    flash('Age deleted successfully!', 'success')
    return redirect(url_for('age_list'))

# ...existing code...

# Level of Difficulty edit route
@app.route('/level_of_difficulty/edit/<int:id>', methods=['GET', 'POST'], endpoint='level_of_difficulty_edit')
def level_of_difficulty_edit(id):
    level = execute_query("SELECT * FROM level_of_difficulty WHERE id = %s", (id,))
    level = level[0] if level else None
    if not level:
        flash('Level of Difficulty not found.', 'danger')
        return redirect(url_for('level_of_difficulty_list'))
    if request.method == 'POST':
        query = 'UPDATE level_of_difficulty SET name = %s, seq = %s, symbol = %s, created_at = %s WHERE id = %s'
        execute_query(query, (
            request.form['name'],
            int(request.form.get('seq', 0)),
            request.form.get('symbol'),
            _now(),
            id
        ), fetch=False)
        flash('Level of Difficulty updated successfully!', 'success')
        return redirect(url_for('level_of_difficulty_list'))

    return render_template('level_of_difficulty/edit.html', level=level)

def get_body_part_from_piece(piece_name):
    """Call DMN rule to get body_part from piece name"""
    try:
        print(f"[DMN] get_body_part_from_piece called: piece={piece_name}")
        dmn_file_path = get_dmn_file_path()
        print(f"[DMN] using file for body part lookup: {dmn_file_path}")
        dmn = pyDMNrules.DMN()

        load_result = dmn.load(dmn_file_path)
        if load_result.get('errors'):
            raise ValueError(f"DMN load failed: {load_result['errors']}")

        # Try decision even with warnings
        result = dmn.decide({'piece': piece_name})
        print(f"DMN decision result for {piece_name}: {result}")

        if isinstance(result, tuple) and len(result) >= 2:
            errors_part, result_part = result
            if errors_part and errors_part.get('errors'):
                print(f"[DMN] Non-fatal annotation errors: {errors_part['errors'][:2]}...")
            # result_part may be a list of result dicts or a single result dict
            results = result_part if isinstance(result_part, list) else [result_part] if isinstance(result_part, dict) else []
            for res in results:
                result_data = res.get('Result', {}) if isinstance(res, dict) else {}
                body_part = result_data.get('body_part')
                if body_part and body_part != 'Not found':
                    return body_part, 'dmn_decision'

        raise ValueError(f"DMN did not return body_part for piece={piece_name}")

    except Exception as e:
        print(f"Error in get_body_part_from_piece: {e}")
        return None, 'error'



def calculate_chart_dimensions(piece_name, measurement, rows_per_4inch, stitches_per_4inch):
    """Call DMN rule to calculate chart dimensions"""
    try:
        print(
            f"[DMN] calculate_chart_dimensions called: piece={piece_name}, measurement={measurement}, "
            f"rows_per_4inch={rows_per_4inch}, stitches_per_4inch={stitches_per_4inch}"
        )
        dmn_file_path = get_dmn_file_path()
        print(f"[DMN] using file for coordinate lookup: {dmn_file_path}")
        dmn = pyDMNrules.DMN()

        load_result = dmn.load(dmn_file_path)
        if load_result.get('errors'):
            raise ValueError(f"DMN load failed: {load_result['errors']}")

        data = {
            'piece': piece_name,
            'measurement': measurement,
            'rows_per_4inch': rows_per_4inch,
            'stitches_per_4inch': stitches_per_4inch
        }
        result = dmn.decide(data)
        print(f"DMN calculation result for {piece_name}: {result}")

        if isinstance(result, tuple) and len(result) >= 2:
            errors_part, result_part = result
            if errors_part and errors_part.get('errors'):
                print(f"[DMN] Non-fatal annotation errors: {errors_part['errors'][:2]}...")
            # result_part may be a list of result dicts or a single result dict
            results = result_part if isinstance(result_part, list) else [result_part] if isinstance(result_part, dict) else []
            for res in results:
                result_data = res.get('Result', {}) if isinstance(res, dict) else {}
                if result_data.get('num_rows') is not None and result_data.get('num_stitches') is not None:
                    return result_data['num_rows'], result_data['num_stitches'], 'dmn_decision'

        raise ValueError(f"DMN did not return num_rows/num_stitches for piece={piece_name}")

    except Exception as e:
        print(f"Error in calculate_chart_dimensions: {e}")
        raise


def resolve_chart_dimensions_from_ids(piece_id, age_id, size_id, gender_id, pattern_id):
    """Resolve chart dimensions using DMN/business rules from database IDs."""
    piece_result = execute_query("SELECT name FROM piece WHERE id = %s", (piece_id,))
    if not piece_result:
        raise ValueError(f"Piece not found for id={piece_id}")
    piece_name = piece_result[0]['name']

    body_part, body_part_source = get_body_part_from_piece(piece_name)
    if not body_part:
        raise ValueError(f"DMN could not determine body part for piece={piece_name}")

    measurement_query = """
        SELECT m.measurement
        FROM measurement m
        JOIN body_part bp ON m.body_part_id = bp.id
        JOIN age a ON m.age_id = a.id
        JOIN size s ON m.size_id = s.id
        JOIN gender g ON m.gender_id = g.id
        WHERE bp.name = %s AND a.id = %s AND s.id = %s AND g.id = %s AND m.is_active = TRUE
    """
    measurement_result = execute_query(measurement_query, (body_part, age_id, size_id, gender_id))
    if not measurement_result:
        raise ValueError(
            f"No measurement found for body_part={body_part}, age={age_id}, size={size_id}, gender={gender_id}"
        )
    measurement = measurement_result[0]['measurement']

    pattern_result = execute_query(
        "SELECT gauge_rows_p4inch, gauge_stitches_p4inch FROM pattern WHERE id = %s",
        (pattern_id,)
    )
    if not pattern_result:
        raise ValueError(f"Pattern not found for id={pattern_id}")
    rows_per_4inch = pattern_result[0]['gauge_rows_p4inch']
    stitches_per_4inch = pattern_result[0]['gauge_stitches_p4inch']
    if not rows_per_4inch or not stitches_per_4inch:
        raise ValueError(f"Pattern gauge missing for id={pattern_id}")

    num_rows, num_stitches, dimension_source = calculate_chart_dimensions(
        piece_name, measurement, rows_per_4inch, stitches_per_4inch
    )

    return {
        'num_rows': int(num_rows),
        'num_stitches': int(num_stitches),
        'piece_name': piece_name,
        'body_part': body_part,
        'body_part_source': body_part_source,
        'dimension_source': dimension_source
    }

@app.route('/favicon.ico')
def favicon():
    return '', 204

# Home page shows patterns list
@app.route('/')
def index():
    patterns = execute_query("SELECT * FROM pattern ORDER BY id")
    return render_template('patterns/list.html', patterns=patterns)

# Piece Routes
@app.route('/pieces')
def pieces_list():
    pieces = execute_query("SELECT * FROM piece ORDER BY name")
    return render_template('pieces/list.html', pieces=pieces)

@app.route('/pieces/create', methods=['GET', 'POST'])
def pieces_create():
    if request.method == 'POST':
        query = """
            INSERT INTO piece (id, name, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM piece), %s, %s)
        """
        execute_query(query, (
            request.form['name'],
            current_user.username
        ), fetch=False)
        flash('Piece created successfully!', 'success')
        return redirect(url_for('pieces_list'))
    return render_template('pieces/create.html')

@app.route('/pieces/<int:id>/edit', methods=['GET', 'POST'])
def pieces_edit(id):
    if request.method == 'POST':
        query = "UPDATE piece SET name = %s, created_at = %s WHERE id = %s"
        execute_query(query, (request.form['name'], _now(), id), fetch=False)
        flash('Piece updated successfully!', 'success')
        return redirect(url_for('pieces_list'))

    piece = execute_query("SELECT * FROM piece WHERE id = %s", (id,))
    if not piece:
        flash('Piece not found.', 'danger')
        return redirect(url_for('pieces_list'))
    return render_template('pieces/edit.html', piece=piece[0])

@app.route('/pieces/delete/<int:id>', methods=['POST'])
def pieces_delete(id):
    execute_query("DELETE FROM piece WHERE id = %s", (id,), fetch=False)
    flash('Piece deleted successfully!', 'success')
    return redirect(url_for('pieces_list'))

@app.route('/step/delete/<int:id>', methods=['POST'], endpoint='step_delete')
def step_delete(id):
    execute_query("DELETE FROM step WHERE id = %s", (id,), fetch=False)
    flash('Step deleted successfully!', 'success')
    return redirect(url_for('step_list'))

@app.route('/step', methods=['GET'], endpoint='step_list')
def step_list():
    steps = execute_query("SELECT * FROM step ORDER BY id")
    return render_template('step/list.html', steps=steps)

@app.route('/step/create', methods=['GET', 'POST'], endpoint='step_create')
def step_create():
    if request.method == 'POST':
        query = '''
            INSERT INTO step (id, phase_seq, phase_desc, group_seq, group_desc, step_seq, step_desc, step_sql, is_active, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM step), %s, %s, %s, %s, %s, %s, %s, %s, %s)
        '''
        execute_query(query, (
            int(request.form['phase_seq']),
            request.form['phase_desc'],
            int(request.form['group_seq']) if request.form.get('group_seq') else None,
            request.form.get('group_desc'),
            int(request.form['step_seq']),
            request.form.get('step_desc'),
            request.form.get('step_sql'),
            request.form.get('is_active', 'true').lower() == 'true',
            current_user.username
        ), fetch=False)
        flash('Step created successfully!', 'success')
        return redirect(url_for('step_list'))
    return render_template('step/create.html')

@app.route('/step/edit/<int:id>', methods=['GET', 'POST'], endpoint='step_edit')
def step_edit(id):
    step = execute_query("SELECT * FROM step WHERE id = %s", (id,))
    step = step[0] if step else None
    if not step:
        flash('Step not found.', 'danger')
        return redirect(url_for('step_list'))
    if request.method == 'POST':
        query = '''
            UPDATE step SET phase_seq=%s, phase_desc=%s, group_seq=%s, group_desc=%s, step_seq=%s, step_desc=%s, step_sql=%s, is_active=%s, created_by=%s, created_at=%s WHERE id=%s
        '''
        execute_query(query, (
            int(request.form['phase_seq']),
            request.form['phase_desc'],
            int(request.form['group_seq']) if request.form.get('group_seq') else None,
            request.form.get('group_desc'),
            int(request.form['step_seq']),
            request.form.get('step_desc'),
            request.form.get('step_sql'),
            request.form.get('is_active', 'true').lower() == 'true',
            current_user.username,
            _now(),
            id
        ), fetch=False)
        flash('Step updated successfully!', 'success')
        return redirect(url_for('step_list'))
    return render_template('step/edit.html', step=step)

@app.route('/pcp_info', methods=['GET'], endpoint='pcp_info_list')
def pcp_info_list():
    pcp_infos = execute_query("SELECT * FROM pcp_info ORDER BY id")
    return render_template('pcp_info/list.html', pcp_infos=pcp_infos)

@app.route('/pcp_info/edit/<int:id>', methods=['GET', 'POST'], endpoint='pcp_info_edit')
def pcp_info_edit(id):
    pcp_info = execute_query("SELECT * FROM pcp_info WHERE id = %s", (id,))
    pcp_info = pcp_info[0] if pcp_info else None
    if not pcp_info:
        flash('PCP Info not found.', 'danger')
        return redirect(url_for('pcp_info_list'))
    if request.method == 'POST':
        query = '''
            UPDATE pcp_info SET type=%s, text_to_display=%s, is_active=%s, created_by=%s, created_at=%s WHERE id=%s
        '''
        execute_query(query, (
            request.form['type'],
            request.form['text_to_display'],
            request.form.get('is_active', 'true').lower() == 'true',
            current_user.username,
            _now(),
            id
        ), fetch=False)
        flash('PCP Info updated successfully!', 'success')
        return redirect(url_for('pcp_info_list'))
    return render_template('pcp_info/edit.html', pcp_info=pcp_info)

@app.route('/pcp_info/delete/<int:id>', methods=['POST'], endpoint='pcp_info_delete')
def pcp_info_delete(id):
    execute_query("DELETE FROM pcp_info WHERE id = %s", (id,), fetch=False)
    flash('PCP Info deleted successfully!', 'success')
    return redirect(url_for('pcp_info_list'))

@app.route('/pcp_info/create', methods=['GET', 'POST'], endpoint='pcp_info_create')
def pcp_info_create():
    if request.method == 'POST':
        query = '''
            INSERT INTO pcp_info (id, type, text_to_display, is_active, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM pcp_info), %s, %s, %s, %s)
        '''
        execute_query(query, (
            request.form['type'],
            request.form['text_to_display'],
            request.form.get('is_active', 'true').lower() == 'true',
            current_user.username
        ), fetch=False)
        flash('PCP Info created successfully!', 'success')
        return redirect(url_for('pcp_info_list'))
    return render_template('pcp_info/create.html')


# Add base64 encoding filter for templates

@app.route('/sizes')
def size_list():
    sizes = execute_query("SELECT * FROM size ORDER BY seq, id")
    return render_template('size/list.html', sizes=sizes)

@app.route('/sizes/create', methods=['GET', 'POST'])
def size_create():
    if request.method == 'POST':
        query = """
            INSERT INTO size (id, name, abbreviation, seq)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM size), %s, %s, %s)
        """
        execute_query(query, (
            request.form['name'],
            request.form['abbreviation'],
            int(request.form['seq']) if request.form.get('seq') else None
        ), fetch=False)
        flash('Size created successfully!', 'success')
        return redirect(url_for('size_list'))
    return render_template('size/create.html')

@app.route('/sizes/edit/<int:id>', methods=['GET', 'POST'])
def size_edit(id):
    size = execute_query('SELECT * FROM size WHERE id = %s', (id,))
    size = size[0] if size else None
    if not size:
        flash('Size not found.', 'danger')
        return redirect(url_for('size_list'))
    if request.method == 'POST':
        query = 'UPDATE size SET name = %s, abbreviation = %s, seq = %s WHERE id = %s'
        execute_query(query, (
            request.form['name'],
            request.form['abbreviation'],
            int(request.form['seq']) if request.form.get('seq') else None,
            id
        ), fetch=False)
        flash('Size updated successfully!', 'success')
        return redirect(url_for('size_list'))
    return render_template('size/edit.html', size=size)

@app.route('/sizes/delete/<int:id>', methods=['POST'])
def size_delete(id):
    execute_query('DELETE FROM size WHERE id = %s', (id,), fetch=False)
    flash('Size deleted successfully!', 'success')
    return redirect(url_for('size_list'))



# Level of Difficulty list route
@app.route('/level_of_difficulty')
def level_of_difficulty_list():
    levels = execute_query("SELECT * FROM level_of_difficulty WHERE is_active = TRUE ORDER BY seq, id")
    return render_template('level_of_difficulty/list.html', levels=levels)

# Level of Difficulty create route
@app.route('/level_of_difficulty/create', methods=['GET', 'POST'], endpoint='level_of_difficulty_create')
def level_of_difficulty_create():
    if request.method == 'POST':
        query = """
            INSERT INTO level_of_difficulty (id, name, seq, symbol, is_active, created_by, created_at)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM level_of_difficulty), %s, %s, %s, TRUE, %s, %s)
        """
        execute_query(query, (
            request.form['name'],
            int(request.form.get('seq', 0)),
            request.form.get('symbol'),
            current_user.username,
            _now()
        ), fetch=False)
        flash('Level of Difficulty created successfully!', 'success')
        return redirect(url_for('level_of_difficulty_list'))
    return render_template('level_of_difficulty/create.html')

# Level of Difficulty delete route
@app.route('/level_of_difficulty/<int:id>/delete', methods=['POST'])
def level_of_difficulty_delete(id):
    execute_query('UPDATE level_of_difficulty SET is_active = FALSE WHERE id = %s', (id,), fetch=False)
    flash('Level of Difficulty deleted.', 'success')
    return redirect(url_for('level_of_difficulty_list'))

# Pattern Categories Routes


# Pattern Category Create Route
@app.route('/pattern_categories/create', methods=['GET', 'POST'], endpoint='pattern_categories_create')
def pattern_categories_create():
    if request.method == 'POST':
        query = """
            INSERT INTO pattern_category (id, category, is_active, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM pattern_category), %s, TRUE, %s)
        """
        execute_query(query, (
            request.form['category'],
            current_user.username
        ), fetch=False)
        flash('Pattern category created successfully!', 'success')
        return redirect(url_for('pattern_categories_list'))
    return render_template('pattern_categories/create.html')

# Pattern Category List Route
@app.route('/pattern_categories', endpoint='pattern_categories_list')
def pattern_categories_list():
    categories = execute_query("SELECT * FROM pattern_category WHERE is_active = TRUE ORDER BY category")
    return render_template('pattern_categories/list.html', categories=categories)


@app.template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return ''


# Pattern Category Routes
@app.route('/pattern_categories')

# Add routes to serve pattern pictures (must be at top level)
    # ...existing code...

@app.route('/patterns/<int:id>/delete', methods=['POST'])
def patterns_delete(id):
    execute_query("UPDATE pattern SET is_active = FALSE WHERE id = %s", (id,), fetch=False)
    flash('Pattern deleted successfully!', 'success')
    return redirect(url_for('patterns_list'))

@app.route('/patterns/<int:id>/schematic')
def pattern_schematic(id):
    import io

    from flask import send_file
    pattern = execute_query("SELECT name, schematic FROM pattern WHERE id = %s", (id,))
    if pattern and pattern[0]['schematic']:
        return send_file(
            io.BytesIO(pattern[0]['schematic']),
            mimetype='image/jpeg',
            as_attachment=False,
            download_name=f"{pattern[0]['name']}_schematic.jpg"
        )
    return "No schematic available", 404

@app.route('/patterns/<int:id>/delete_image', methods=['POST'])
def pattern_delete_image(id):
    """NULL out a single image field on a pattern (schematic, picture1-3, gauge_measurement)."""
    from flask import jsonify
    allowed = {'schematic', 'picture1', 'picture2', 'picture3', 'gauge_measurement'}
    field = request.form.get('field', '').strip()
    if field not in allowed:
        return jsonify(ok=False, error='Invalid image field.'), 400
    # nosec B608 — field is validated against a fixed allowlist above
    execute_query(f'UPDATE pattern SET {field} = NULL WHERE id = %s', (id,), fetch=False)  # nosec B608
    return jsonify(ok=True)

@app.route('/patterns/<int:id>/picture/<int:pic>')
def pattern_picture(id, pic):
    import io

    from flask import send_file
    # Validate pic parameter (1, 2, or 3)
    if pic not in [1, 2, 3]:
        return "Invalid picture number", 404

    picture_column = f"picture{pic}"
    # nosec B608 — column name is constructed from pic which is validated to be 1, 2, or 3 above
    pattern = execute_query(f"SELECT name, {picture_column} FROM pattern WHERE id = %s", (id,))  # nosec B608
    if pattern and pattern[0][picture_column]:
        return send_file(
            io.BytesIO(pattern[0][picture_column]),
            mimetype='image/jpeg',
            as_attachment=False,
            download_name=f"{pattern[0]['name']}_picture{pic}.jpg"
        )
    return "No picture available", 404




# Measurement Routes
@app.route('/measurements')
def measurements_list():
    # Get filter values from query params
    age_id = request.args.get('age_id')
    body_part_id = request.args.get('body_part_id')
    gender_id = request.args.get('gender_id')

    # Build filter query
    query = '''
        SELECT m.*, a.name AS age_name, s.name AS size_name, s.abbreviation AS size_abbreviation, s.seq AS size_seq,
               bp.name AS body_part_name, g.name AS gender_name
        FROM measurement m
        LEFT JOIN age a ON m.age_id = a.id
        LEFT JOIN size s ON m.size_id = s.id
        LEFT JOIN body_part bp ON m.body_part_id = bp.id
        LEFT JOIN gender g ON m.gender_id = g.id
        WHERE m.is_active = TRUE
    '''
    params = []
    if age_id:
        query += ' AND m.age_id = %s'
        params.append(age_id)
    if body_part_id:
        query += ' AND m.body_part_id = %s'
        params.append(body_part_id)
    if gender_id:
        query += ' AND m.gender_id = %s'
        params.append(gender_id)
    query += ' ORDER BY bp.name, a.seq'
    measurements = execute_query(query, tuple(params))

    # Get filter options
    ages = execute_query('SELECT id, name FROM age ORDER BY seq, id')
    body_parts = execute_query('SELECT id, name FROM body_part ORDER BY name')
    genders = execute_query('SELECT id, name FROM gender ORDER BY name')

    sizes = execute_query('SELECT id, name, abbreviation FROM size ORDER BY seq, id')
    return render_template('measurements/list.html', measurements=measurements, ages=ages, body_parts=body_parts, genders=genders, sizes=sizes, selected_age_id=age_id, selected_body_part_id=body_part_id, selected_gender_id=gender_id)

@app.route('/measurements/create', methods=['GET', 'POST'])
def measurements_create():
    ages = execute_query("SELECT id, name FROM age ORDER BY name")
    sizes = execute_query("SELECT id, name, abbreviation FROM size ORDER BY seq, id")
    body_parts = execute_query('SELECT id, name FROM body_part ORDER BY name')
    genders = execute_query('SELECT id, name FROM gender ORDER BY name')
    if request.method == 'POST':
        # Check for duplicate measurement
        duplicate = execute_query("""
            SELECT id FROM measurement WHERE body_part_id = %s AND age_id = %s AND size_id = %s AND gender_id = %s
        """, (
            int(request.form['body_part_id']),
            int(request.form['age_id']),
            int(request.form['size_id']),
            int(request.form['gender_id'])
        ))
        if duplicate:
            flash('A measurement for this body part, age group, size, and gender already exists.', 'danger')
            return render_template('measurements/create.html', ages=ages, sizes=sizes, body_parts=body_parts, genders=genders)
        query = """
            INSERT INTO measurement (id, body_part_id, age_id, size_id, gender_id, measurement, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM measurement), %s, %s, %s, %s, %s, %s)
        """
        execute_query(query, (
            int(request.form['body_part_id']),
            int(request.form['age_id']),
            int(request.form['size_id']),
            int(request.form['gender_id']),
            request.form['measurement'],
            current_user.username
        ), fetch=False)
        flash('Measurement created successfully!', 'success')
        return redirect(url_for('measurements_list'))
    return render_template('measurements/create.html', ages=ages, sizes=sizes, body_parts=body_parts, genders=genders)

@app.route('/measurements/edit/<int:id>', methods=['GET', 'POST'])
def measurements_edit(id):
    ages = execute_query("SELECT id, name FROM age ORDER BY name")
    sizes = execute_query("SELECT id, name, abbreviation FROM size ORDER BY seq, id")
    body_parts = execute_query('SELECT id, name FROM body_part ORDER BY name')
    genders = execute_query('SELECT id, name FROM gender ORDER BY name')
    if request.method == 'POST':
        # Check for duplicate measurement (excluding current id)
        duplicate = execute_query("""
            SELECT id FROM measurement WHERE body_part_id = %s AND age_id = %s AND size_id = %s AND gender_id = %s AND id != %s
        """, (
            int(request.form['body_part_id']),
            int(request.form['age_id']),
            int(request.form['size_id']),
            int(request.form['gender_id']),
            id
        ))
        if duplicate:
            flash('A measurement for this body part, age group, size, and gender already exists.', 'danger')
            measurement = execute_query("SELECT * FROM measurement WHERE id = %s", (id,), fetch=True)
            if measurement:
                measurement = measurement[0]
            else:
                measurement = None
            return render_template('measurements/edit.html', measurement=measurement, ages=ages, sizes=sizes, body_parts=body_parts, genders=genders)
        query = """
            UPDATE measurement
            SET body_part_id = %s, age_id = %s, size_id = %s, gender_id = %s, measurement = %s
            WHERE id = %s
        """
        execute_query(query, (
            int(request.form['body_part_id']),
            int(request.form['age_id']),
            int(request.form['size_id']),
            int(request.form['gender_id']),
            request.form['measurement'],
            id
        ), fetch=False)
        flash('Measurement updated successfully!', 'success')
        return redirect(url_for('measurements_list'))
    measurement = execute_query("SELECT * FROM measurement WHERE id = %s", (id,), fetch=True)
    if measurement:
        measurement = measurement[0]
    else:
        measurement = None
    return render_template('measurements/edit.html', measurement=measurement, ages=ages, sizes=sizes, body_parts=body_parts, genders=genders)

@app.route('/measurements/delete/<int:id>', methods=['POST'])
def measurements_delete(id):
    execute_query("DELETE FROM measurement WHERE id = %s", (id,), fetch=False)
    flash('Measurement deleted successfully!', 'success')
    return redirect(url_for('measurements_list'))

# Yarn Weight Routes
@app.route('/yarn_weights')
def yarn_weights_list():
    yarn_weights = execute_query("SELECT * FROM yarn_weight WHERE is_active = TRUE ORDER BY weight_id")
    return render_template('yarn_weights/list.html', yarn_weights=yarn_weights)

# Add edit route for yarn weights
@app.route('/yarn_weights/edit/<int:id>', methods=['GET', 'POST'])
def yarn_weights_edit(id):
    yarn_weight = execute_query("SELECT * FROM yarn_weight WHERE weight_id = %s", (id,))
    yarn_weight = yarn_weight[0] if yarn_weight else None
    if not yarn_weight:
        flash('Yarn weight not found.', 'danger')
        return redirect(url_for('yarn_weights_list'))
    if request.method == 'POST':
        symbol_file = request.files.get('symbol')
        symbol_data = None
        if symbol_file and symbol_file.filename:
            symbol_file.stream.seek(0)
            symbol_data = symbol_file.stream.read() or None
        common_params = (
            request.form['weight_name'],
            int(float(request.form['lower_stitches_p4inch'])),
            int(float(request.form['upper_stitches_p4inch'])),
            float(request.form['lower_needle_size_mm']),
            float(request.form['upper_needle_size_mm']),
            int(float(request.form['lower_needle_size_us'])),
            int(float(request.form['upper_needle_size_us'])),
            int(float(request.form['wraps_per_inch_lower'])),
            int(float(request.form['wraps_per_inch_upper'])),
            request.form.get('inexpensive_yarn_type', ''),
            request.form.get('mid_range_yarn_type', ''),
            request.form.get('premium_yarn_type', ''),
            request.form.get('is_active', 'true').lower() == 'true',
            current_user.username,
            _now(),
        )
        if symbol_data:
            execute_query('''
                    UPDATE yarn_weight
                    SET weight_name=%s, lower_stitches_p4inch=%s, upper_stitches_p4inch=%s,
                        lower_needle_size_mm=%s, upper_needle_size_mm=%s,
                        lower_needle_size_us=%s, upper_needle_size_us=%s,
                        wraps_per_inch_lower=%s, wraps_per_inch_upper=%s,
                        inexpensive_yarn_type=%s, mid_range_yarn_type=%s, premium_yarn_type=%s,
                        is_active=%s, created_by=%s, created_at=%s, symbol=%s
                    WHERE weight_id=%s
                ''', common_params + (symbol_data, id), fetch=False)
        else:
            execute_query('''
                UPDATE yarn_weight
                SET weight_name=%s, lower_stitches_p4inch=%s, upper_stitches_p4inch=%s,
                    lower_needle_size_mm=%s, upper_needle_size_mm=%s,
                    lower_needle_size_us=%s, upper_needle_size_us=%s,
                    wraps_per_inch_lower=%s, wraps_per_inch_upper=%s,
                    inexpensive_yarn_type=%s, mid_range_yarn_type=%s, premium_yarn_type=%s,
                    is_active=%s, created_by=%s, created_at=%s
                WHERE weight_id=%s
            ''', common_params + (id,), fetch=False)
        flash('Yarn weight updated successfully!', 'success')
        return redirect(url_for('yarn_weights_list'))
    return render_template('yarn_weights/edit.html', yarn_weight=yarn_weight)

# Add delete route for yarn weights
@app.route('/yarn_weights/delete/<int:id>', methods=['POST'])
def yarn_weights_delete(id):
    execute_query("DELETE FROM yarn_weight WHERE weight_id = %s", (id,), fetch=False)
    flash('Yarn weight deleted successfully!', 'success')
    return redirect(url_for('yarn_weights_list'))

# Pattern Yarn Weight Routes
@app.route('/pattern_yarn_weights')
def pattern_yarn_weights_list():
    pattern_yarn_weights = execute_query("""
        SELECT pyw.*, p.name as pattern_name, yw.weight_name
        FROM pattern_yarn_weight pyw
        JOIN pattern p ON pyw.pattern_id = p.id
        JOIN yarn_weight yw ON pyw.yarn_weight_id = yw.weight_id
        ORDER BY p.name, yw.weight_name
    """)
    return render_template('pattern_yarn_weights/list.html', pattern_yarn_weights=pattern_yarn_weights)

@app.route('/pattern_yarn_weights/create', methods=['GET', 'POST'])
def pattern_yarn_weights_create():
    if request.method == 'POST':
        query = """
            INSERT INTO pattern_yarn_weight (id, pattern_id, yarn_weight_id, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM pattern_yarn_weight), %s, %s, %s)
        """
        execute_query(query, (
            int(request.form['pattern_id']),
            int(request.form['yarn_weight_id']),
            current_user.username
        ), fetch=False)
        flash('Pattern yarn weight created successfully!', 'success')
        return redirect(url_for('pattern_yarn_weights_list'))

    patterns = execute_query("SELECT id, name FROM pattern WHERE is_active = TRUE ORDER BY name")
    yarn_weights = execute_query("SELECT weight_id, weight_name FROM yarn_weight WHERE is_active = TRUE ORDER BY weight_name")
    return render_template('pattern_yarn_weights/create.html', patterns=patterns, yarn_weights=yarn_weights)

@app.route('/pattern_yarn_weights/<int:id>/edit', methods=['GET', 'POST'])
def pattern_yarn_weights_edit(id):
    if request.method == 'POST':
        query = "UPDATE pattern_yarn_weight SET pattern_id = %s, yarn_weight_id = %s, created_at = %s WHERE id = %s"
        execute_query(query, (
            int(request.form['pattern_id']),
            int(request.form['yarn_weight_id']),
            _now(),
            id
        ), fetch=False)
        flash('Pattern yarn weight updated successfully!', 'success')
        return redirect(url_for('pattern_yarn_weights_list'))

    pattern_yarn_weight = execute_query("SELECT * FROM pattern_yarn_weight WHERE id = %s", (id,))
    if not pattern_yarn_weight:
        flash('Pattern yarn weight not found.', 'danger')
        return redirect(url_for('pattern_yarn_weights_list'))

    patterns = execute_query("SELECT id, name FROM pattern WHERE is_active = TRUE ORDER BY name")
    yarn_weights = execute_query("SELECT weight_id, weight_name FROM yarn_weight WHERE is_active = TRUE ORDER BY weight_name")
    return render_template('pattern_yarn_weights/edit.html', pattern_yarn_weight=pattern_yarn_weight[0], patterns=patterns, yarn_weights=yarn_weights)

@app.route('/pattern_yarn_weights/<int:id>/delete', methods=['POST'])
def pattern_yarn_weights_delete(id):
    execute_query("DELETE FROM pattern_yarn_weight WHERE id = %s", (id,), fetch=False)
    flash('Pattern yarn weight deleted successfully!', 'success')
    return redirect(url_for('pattern_yarn_weights_list'))

# Element Routes
@app.route('/elements')
def elements_list():
    type_filter = request.args.get('type_filter', '')
    type_options = execute_query("SELECT DISTINCT type FROM element WHERE is_active = TRUE ORDER BY type")
    if type_filter:
        elements = execute_query("SELECT * FROM element WHERE is_active = TRUE AND type = %s ORDER BY id", (type_filter,))
    else:
        elements = execute_query("SELECT * FROM element WHERE is_active = TRUE ORDER BY id")
    return render_template('elements/list.html', elements=elements, type_options=type_options, type_filter=type_filter)

# Excel export for elements
@app.route('/elements/export_excel')
def elements_export_excel():
    from flask import send_file
    type_filter = request.args.get('type_filter', '')
    if type_filter:
        elements = execute_query("SELECT * FROM element WHERE is_active = TRUE AND type = %s ORDER BY id", (type_filter,))
    else:
        elements = execute_query("SELECT * FROM element WHERE is_active = TRUE ORDER BY id")
    if not elements:
        elements = []
    df = pd.DataFrame(elements)
    # Optional: drop symbol (bytea) column from export
    if 'symbol' in df.columns:
        df = df.drop(columns=['symbol'])
    # Format created_at as string if present
    if 'created_at' in df.columns:
        df['created_at'] = df['created_at'].astype(str)
    import io
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Elements')
    output.seek(0)
    return send_file(output, as_attachment=True, download_name='elements_export.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/elements/<int:id>/symbol')
def element_symbol(id):
    """Serve the element symbol as a PNG image"""

    from flask import Response

    result = execute_query("SELECT symbol, description FROM element WHERE id = %s", (id,))
    if not result or not result[0]['symbol']:
        return Response("No symbol found", status=404)

    try:
        # The symbol data is raw bitmap from freetype
        # We need to convert it to a proper image format
        symbol_data = result[0]['symbol']

        # Create a simple PNG from the raw bytes
        # For now, just return the raw bytes as image/png
        # (The actual rendering would depend on the bitmap format)
        return Response(symbol_data, mimetype='image/png')
    except Exception as e:
        return Response(f"Error rendering symbol: {e}", status=500)

@app.route('/elements/create', methods=['GET', 'POST'])
def elements_create():
    if request.method == 'POST':
        # Handle file upload for symbol (bytea)
        symbol_file = request.files.get('symbol')
        symbol_data = symbol_file.read() if symbol_file and symbol_file.filename else None

        query = """
            INSERT INTO element (id, type, symbol, ascii_symbol, description, abbrieviation, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM element), %s, %s, %s, %s, %s, %s)
        """
        execute_query(query, (
            request.form['type'],
            symbol_data,
            request.form['ascii_symbol'],
            request.form.get('description'),
            request.form.get('abbrieviation'),
            current_user.username
        ), fetch=False)
        flash('Element created successfully!', 'success')
        return redirect(url_for('elements_list'))
    return render_template('elements/create.html')

@app.route('/elements/<int:id>/edit', methods=['GET', 'POST'])
def elements_edit(id):
    if request.method == 'POST':
        # Handle file upload for symbol (bytea)
        symbol_file = request.files.get('symbol')

        if symbol_file and symbol_file.filename:
            symbol_data = symbol_file.read()
            query = """
                UPDATE element
                SET type = %s, symbol = %s, ascii_symbol = %s, description = %s, abbrieviation = %s
                WHERE id = %s
            """
            execute_query(query, (
                request.form['type'],
                symbol_data,
                request.form['ascii_symbol'],
                request.form.get('description'),
                request.form.get('abbrieviation'),
                id
            ), fetch=False)
        else:
            query = """
                UPDATE element
                SET type = %s, ascii_symbol = %s, description = %s, abbrieviation = %s
                WHERE id = %s
            """
            execute_query(query, (
                request.form['type'],
                request.form['ascii_symbol'],
                request.form.get('description'),
                request.form.get('abbrieviation'),
                id
            ), fetch=False)

        flash('Element updated successfully!', 'success')
        return redirect(url_for('elements_list'))

    element = execute_query("SELECT * FROM element WHERE id = %s", (id,))
    if not element:
        flash('Element not found!', 'error')
        return redirect(url_for('elements_list'))
    return render_template('elements/edit.html', element=element[0])

@app.route('/elements/<int:id>/delete', methods=['POST'])
def elements_delete(id):
    execute_query("UPDATE element SET is_active = FALSE WHERE id = %s", (id,), fetch=False)
    flash('Element deleted successfully!', 'success')
    return redirect(url_for('elements_list'))

# Pattern Elements Routes
@app.route('/pattern_elements')
def pattern_elements_list():
    pattern_elements = execute_query("""
        SELECT pe.*, p.name as pattern_name, e.description as element_description
        FROM pattern_element pe
        JOIN pattern p ON pe.pattern_id = p.id
        JOIN element e ON pe.element_id = e.id
        ORDER BY p.name, e.description
    """)
    return render_template('pattern_elements/list.html', pattern_elements=pattern_elements)

@app.route('/pattern_elements/create', methods=['GET', 'POST'])
def pattern_elements_create():
    if request.method == 'POST':
        query = """
            INSERT INTO pattern_element (id, pattern_id, element_id, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM pattern_element), %s, %s, %s)
        """
        execute_query(query, (
            int(request.form['pattern_id']),
            int(request.form['element_id']),
            current_user.username
        ), fetch=False)
        flash('Pattern element created successfully!', 'success')
        return redirect(url_for('pattern_elements_list'))

    patterns = execute_query("SELECT id, name FROM pattern WHERE is_active = TRUE ORDER BY name")
    elements = execute_query("SELECT id, description FROM element WHERE is_active = TRUE ORDER BY description")
    return render_template('pattern_elements/create.html', patterns=patterns, elements=elements)

@app.route('/pattern_elements/<int:id>/edit', methods=['GET', 'POST'])
def pattern_elements_edit(id):
    if request.method == 'POST':
        query = "UPDATE pattern_element SET pattern_id = %s, element_id = %s WHERE id = %s"
        execute_query(query, (
            int(request.form['pattern_id']),
            int(request.form['element_id']),
            id
        ), fetch=False)
        flash('Pattern element updated successfully!', 'success')
        return redirect(url_for('pattern_elements_list'))

    pattern_element = execute_query("SELECT * FROM pattern_element WHERE id = %s", (id,))
    if not pattern_element:
        flash('Pattern element not found.', 'danger')
        return redirect(url_for('pattern_elements_list'))

    patterns = execute_query("SELECT id, name FROM pattern WHERE is_active = TRUE ORDER BY name")
    elements = execute_query("SELECT id, description FROM element WHERE is_active = TRUE ORDER BY description")
    return render_template('pattern_elements/edit.html', pattern_element=pattern_element[0], patterns=patterns, elements=elements)

@app.route('/pattern_elements/<int:id>/delete', methods=['POST'])
def pattern_elements_delete(id):
    execute_query("DELETE FROM pattern_element WHERE id = %s", (id,), fetch=False)
    flash('Pattern element deleted successfully!', 'success')
    return redirect(url_for('pattern_elements_list'))

@app.route('/charts')
def charts_list():
    pattern_id = request.args.get('pattern_id')
    pattern_name = ''

    if pattern_id:
        # Get pattern name for context
        pattern = execute_query('SELECT name FROM pattern WHERE id = %s', (pattern_id,))
        pattern_name = pattern[0]['name'] if pattern else ''

        # Get charts for specific pattern
        charts = execute_query('''
            SELECT chart.*, piece.name AS piece_name, age.name AS age_name, size.name AS size_name
            FROM chart
            LEFT JOIN piece ON chart.piece_id = piece.id
            LEFT JOIN age ON chart.age_id = age.id
            LEFT JOIN size ON chart.size_id = size.id
            WHERE chart.id IN (SELECT chart_id FROM pattern_chart WHERE pattern_id = %s)
            ORDER BY chart.name
        ''', (pattern_id,))
    else:
        # Get all charts
        charts = execute_query('''
            SELECT chart.*, piece.name AS piece_name, age.name AS age_name, size.name AS size_name
            FROM chart
            LEFT JOIN piece ON chart.piece_id = piece.id
            LEFT JOIN age ON chart.age_id = age.id
            LEFT JOIN size ON chart.size_id = size.id
            ORDER BY chart.name
        ''')

    return render_template('charts/list.html', charts=charts, pattern_id=pattern_id, pattern_name=pattern_name)

@app.route('/api/calculate_chart_dimensions', methods=['POST'])
def api_calculate_chart_dimensions():
    """API endpoint to calculate chart dimensions using DMN rules"""
    _log.debug(f"API /api/calculate_chart_dimensions called: method={request.method}, json={request.get_json()}")
    try:
        data = request.get_json()
        print(f"[API] /api/calculate_chart_dimensions payload: {data}")

        # Extract required parameters
        piece_id = data.get('piece_id')
        age_id = data.get('age_id')
        size_id = data.get('size_id', 0)  # Default to 0 (NA)
        gender_id = data.get('gender_id')
        pattern_id = data.get('pattern_id')

        if not piece_id or not age_id or not pattern_id:
            return jsonify({'error': 'Missing required parameters'}), 400

        # Get piece name
        piece_result = execute_query("SELECT name FROM piece WHERE id = %s", (piece_id,))
        if not piece_result:
            return jsonify({'error': 'Piece not found'}), 404
        piece_name = piece_result[0]['name']

        dmn_file_path = get_dmn_file_path()
        dmn_file_modified = datetime.fromtimestamp(os.path.getmtime(dmn_file_path)).isoformat()
        dmn_file_size = os.path.getsize(dmn_file_path)

        # Step 1: Get body_part from piece using DMN
        body_part, body_part_source = get_body_part_from_piece(piece_name)
        print(f"[DMN] body_part result: value={body_part}, source={body_part_source}")

        # Step 2: Get measurement from database
        measurement_query = """
            SELECT m.measurement
            FROM measurement m
            JOIN body_part bp ON m.body_part_id = bp.id
            JOIN age a ON m.age_id = a.id
            JOIN size s ON m.size_id = s.id
            JOIN gender g ON m.gender_id = g.id
            WHERE bp.name = %s AND a.id = %s AND s.id = %s AND g.id = %s AND m.is_active = TRUE
        """
        measurement_result = execute_query(measurement_query, (body_part, age_id, size_id, gender_id))

        if not measurement_result:
            return jsonify({'error': f'No measurement found for body_part={body_part}, age={age_id}, size={size_id}, gender={gender_id}'}), 404
        measurement = measurement_result[0]['measurement']

        # Step 3: Get pattern gauge
        pattern_result = execute_query("SELECT gauge_rows_p4inch, gauge_stitches_p4inch FROM pattern WHERE id = %s", (pattern_id,))
        if not pattern_result:
            return jsonify({'error': 'Pattern not found'}), 404

        pattern_data = pattern_result[0]
        rows_per_4inch = pattern_data['gauge_rows_p4inch']
        stitches_per_4inch = pattern_data['gauge_stitches_p4inch']

        if not rows_per_4inch or not stitches_per_4inch:
            return jsonify({'error': 'Pattern gauge data missing'}), 400

        # Step 4: Call DMN decision PieceCoordinates
        num_rows, num_stitches, dimension_source = calculate_chart_dimensions(
            piece_name, measurement, rows_per_4inch, stitches_per_4inch
        )
        print(
            f"[DMN] dimension result: rows={num_rows}, stitches={num_stitches}, source={dimension_source}, "
            f"dmn_file={dmn_file_path}"
        )

        return jsonify({
            'success': True,
            'num_rows': round(num_rows),
            'num_stitches': round(num_stitches),
            'body_part': body_part,
            'measurement': measurement,
            'body_part_source': body_part_source,
            'dimension_source': dimension_source,
            'dmn_file_path': dmn_file_path,
            'dmn_file_modified': dmn_file_modified,
            'dmn_file_size': dmn_file_size,
            'calculation_info': f'Piece: {piece_name}, Body Part: {body_part}, Measurement: {measurement}, Pattern Gauge: {rows_per_4inch}r/{stitches_per_4inch}s per 4", DMN Source: {dimension_source}'
        })

    except Exception as e:
        return jsonify({'error': f'DMN calculation failed: {str(e)}'}), 400

@app.route('/charts/create', methods=['GET', 'POST'])
def charts_create():
    pattern_id = request.args.get('pattern_id') or request.form.get('pattern_id')

    if request.method == 'POST':
        piece_id = int(request.form['piece_id'])
        age_id = int(request.form['age_id'])
        size_id = int(request.form['size_id']) if request.form.get('size_id') else 0
        gender_id = int(request.form['gender_id']) if request.form.get('gender_id') else 0
        calc_rows = int(request.form.get('num_rows', 1))
        calc_cols = int(request.form.get('num_columns', 1))

        if not pattern_id:
            flash('Pattern context is required for DMN dimension calculation.', 'danger')
            return redirect(request.url)

        dim = resolve_chart_dimensions_from_ids(piece_id, age_id, size_id, gender_id, int(pattern_id))
        # Use form-submitted values so the user can override DMN defaults.
        # Fall back to DMN only when the form values are absent or zero.
        form_rows = int(request.form.get('num_rows', 0))
        form_cols = int(request.form.get('num_columns', 0))
        calc_rows = form_rows if form_rows > 0 else dim['num_rows']
        calc_cols = form_cols if form_cols > 0 else dim['num_stitches']
        print(
            f"[DMN] charts_create rows={calc_rows} (form={form_rows}, dmn={dim['num_rows']}), "
            f"cols={calc_cols} (form={form_cols}, dmn={dim['num_stitches']}), "
            f"piece={dim['piece_name']}, source={dim['dimension_source']}"
        )

        # Create new chart
        query = """
            INSERT INTO chart (id, name, num_rows, num_columns, description, instructions, piece_id, age_id, size_id, gender_id, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM chart), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """

        execute_query(query, (
            request.form['name'],
            calc_rows,
            calc_cols,
            request.form.get('description', ''),
            request.form.get('instructions', ''),
            piece_id,
            age_id,
            size_id,  # Use size ID 0 (NA) if no size selected
            int(request.form['gender_id']) if request.form.get('gender_id') else None,
            current_user.username
        ), fetch=False)

        # Link to pattern if pattern_id provided
        if pattern_id:
            chart_id = execute_query("SELECT MAX(id) as id FROM chart")[0]['id']
            execute_query(
                "INSERT INTO pattern_chart (id, pattern_id, chart_id, created_by) VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM pattern_chart), %s, %s, %s)",
                (pattern_id, chart_id, current_user.username),
                fetch=False
            )

        # Insert chart_coordinate for each cell with symbols
        chart_id = execute_query("SELECT MAX(id) as id FROM chart")[0]['id']
        num_rows = calc_rows
        num_cols = calc_cols
        created_by = current_user.username
        coordinates = []
        for r in range(1, num_rows + 1):  # 1-based indexing for display
            for c in range(1, num_cols + 1):  # 1-based indexing for display
                element_id = request.form.get(f'cell_symbol_{r}_{c}')
                if element_id:
                    # Convert to 0-based for storage (x=col-1, y=row-1)
                    coordinates.append((chart_id, c-1, r-1, int(element_id), True, _now(), created_by))

        if coordinates:
            # nosec B608 — only integer counter i+1 is interpolated, never user input
            values_str = ','.join([
                f"((SELECT COALESCE(MAX(id), 0) + {i+1} FROM chart_coordinate), %s, %s, %s, %s, %s, %s, %s)"  # nosec B608
                for i in range(len(coordinates))
            ])
            insert_query = f"""
                INSERT INTO chart_coordinate (id, chart_id, x, y, element_id, is_active, created_at, created_by)
                VALUES {values_str}
            """  # nosec B608"
            params = []
            for tup in coordinates:
                params.extend(tup)
            execute_query(insert_query, tuple(params), fetch=False)

        # Insert chart sections (three-level hierarchy: row sections, row subsections, column sections)
        section_idx = 0
        while True:
            start_row_key = f'section_{section_idx}_start_row'
            if start_row_key not in request.form:
                break

            # Insert row section and get its ID
            row_section_query = """
                INSERT INTO chart_row_section (chart_id, start_row, end_row, repeat_count, instructions, label, include_in_pdf, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """
            row_section_id = execute_query(
                row_section_query,
                (
                    chart_id,
                    int(request.form[f'section_{section_idx}_start_row']),
                    int(request.form[f'section_{section_idx}_end_row']),
                    int(request.form[f'section_{section_idx}_repeat_count']),
                    request.form.get(f'section_{section_idx}_instructions', '') or None,
                    request.form.get(f'section_{section_idx}_label', '') or None,
                    request.form.get(f'section_{section_idx}_include_in_pdf', '1') == '1',
                    created_by
                ),
                fetch=True
            )[0]['id']

            # Check for row subsections within this row section
            subsec_idx = 0
            while True:
                subsec_start_key = f'section_{section_idx}_subsec_{subsec_idx}_start_row'
                if subsec_start_key not in request.form:
                    break

                # Insert row subsection and get its ID
                row_subsection_query = """
                    INSERT INTO chart_row_subsection (row_section_id, start_row, end_row, instructions, label, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """
                row_subsection_id = execute_query(
                    row_subsection_query,
                    (
                        row_section_id,
                        int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_start_row']),
                        int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_end_row']),
                        request.form.get(f'section_{section_idx}_subsec_{subsec_idx}_instructions', '') or None,
                        request.form.get(f'section_{section_idx}_subsec_{subsec_idx}_label', '') or None,
                        created_by
                    ),
                    fetch=True
                )[0]['id']

                # Check for column sections within this row subsection
                col_idx = 0
                while True:
                    col_start_key = f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_start_col'
                    if col_start_key not in request.form:
                        break

                    col_section_query = """
                        INSERT INTO chart_column_section (row_subsection_id, start_col, end_col, repeat_count, instructions, created_by)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """
                    execute_query(
                        col_section_query,
                        (
                            row_subsection_id,
                            int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_start_col']),
                            int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_end_col']),
                            int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_repeat_count']),
                            request.form.get(f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_instructions', '') or None,
                            created_by
                        ),
                        fetch=False
                    )
                    col_idx += 1

                subsec_idx += 1

            section_idx += 1

        flash('Chart created successfully!', 'success')

        if pattern_id:
            return redirect(url_for('charts_list', pattern_id=pattern_id))
        else:
            return redirect(url_for('charts_list'))

    # GET request - show create form
    pieces = execute_query("SELECT id, name, is_human_part FROM piece WHERE is_active = TRUE ORDER BY name")
    ages = execute_query("SELECT * FROM age WHERE is_active = TRUE ORDER BY seq, id")
    all_sizes = execute_query("SELECT * FROM size WHERE is_active = TRUE ORDER BY seq, id")
    # Filter out NA size for the dropdown (but keep it available for backend logic)
    sizes = [size for size in all_sizes if size['id'] != 0]  # Remove NA from dropdown
    genders = execute_query("SELECT * FROM gender WHERE is_active = TRUE ORDER BY name")
    elements = execute_query("SELECT id, description, symbol, type, abbrieviation FROM element WHERE is_active = TRUE ORDER BY (symbol IS NULL), description")

    # Get pattern gauge info if pattern_id provided
    pattern_gauge = None
    pattern_name = None
    if pattern_id:
        pattern_result = execute_query("SELECT name, gauge_stitches_p4inch, gauge_rows_p4inch FROM pattern WHERE id = %s", (pattern_id,))
        if pattern_result:
            pattern_name = pattern_result[0]['name']
            pattern_gauge = pattern_result[0]
        else:
            pattern_gauge = {'gauge_stitches_p4inch': None, 'gauge_rows_p4inch': None}

    # Get measurements data for width calculation
    measurements = execute_query("""
        SELECT m.*, bp.name as body_part_name, a.name as age_name, s.name as size_name, g.name as gender_name
        FROM measurement m
        JOIN body_part bp ON m.body_part_id = bp.id
        JOIN age a ON m.age_id = a.id
        JOIN size s ON m.size_id = s.id
        JOIN gender g ON m.gender_id = g.id
        WHERE m.is_active = TRUE
    """)

    return render_template('charts/create_clean.html', pieces=pieces, ages=ages, sizes=sizes, genders=genders, elements=elements, pattern_id=pattern_id, pattern_name=pattern_name, pattern_gauge=pattern_gauge, measurements=measurements)

@app.route('/charts/test')
def charts_test():
    return render_template('charts/test_simple.html')

@app.route('/charts/create_simple_test')
def charts_create_simple_test():
    pieces = execute_query("SELECT id, name FROM piece WHERE is_active = TRUE ORDER BY name")
    return render_template('charts/create_simple_test.html', pieces=pieces)

@app.route('/charts/create_standalone')
def charts_create_standalone():
    pieces = execute_query("SELECT id, name FROM piece WHERE is_active = TRUE ORDER BY name")
    return render_template('charts/create_standalone.html', pieces=pieces)

@app.route('/charts/edit/<int:id>', methods=['GET', 'POST'])
def charts_edit(id):
    # Get pattern_id from form (POST), query param (GET), or pattern_chart linkage
    pattern_id = request.form.get('pattern_id') or request.args.get('pattern_id')
    if not pattern_id:
        # Try to get from pattern_chart
        result = execute_query('SELECT pattern_id FROM pattern_chart WHERE chart_id = %s', (id,))
        pattern_id = str(result[0]['pattern_id']) if result else None
    if not pattern_id:
        flash('Pattern context required for editing chart.', 'danger')
        return redirect(url_for('patterns_list'))

    # Get pattern name for context
    pattern = execute_query('SELECT name FROM pattern WHERE id = %s', (pattern_id,))
    pattern_name = pattern[0]['name'] if pattern else ''

    # Get chart with piece, age, size names
    result = execute_query('''
        SELECT chart.*, piece.name AS piece_name, age.name AS age_name, size.name AS size_name, gender.name AS gender_name
        FROM chart
        LEFT JOIN piece ON chart.piece_id = piece.id
        LEFT JOIN age ON chart.age_id = age.id
        LEFT JOIN size ON chart.size_id = size.id
        LEFT JOIN gender ON chart.gender_id = gender.id
        WHERE chart.id = %s
    ''', (id,))
    chart = result[0] if result else None
    if not chart:
        flash('Chart not found.', 'danger')
        return redirect(url_for('charts_list', pattern_id=pattern_id))

    if request.method == 'POST':
        piece_id = int(request.form['piece_id']) if request.form.get('piece_id') else None
        age_id = int(request.form['age_id']) if request.form.get('age_id') else None
        size_id = int(request.form['size_id']) if request.form.get('size_id') else 0
        gender_id = int(request.form['gender_id']) if request.form.get('gender_id') else 0
        calc_rows = int(request.form.get('num_rows', 1))
        calc_cols = int(request.form.get('num_columns', 1))

        if not (pattern_id and piece_id and age_id):
            flash('Pattern, piece, and age are required for DMN dimension calculation.', 'danger')
            return redirect(request.url)

        dim = resolve_chart_dimensions_from_ids(piece_id, age_id, size_id, gender_id, int(pattern_id))
        calc_rows = dim['num_rows']
        calc_cols = dim['num_stitches']
        print(
            f"[DMN] charts_edit using DMN dimensions rows={calc_rows}, cols={calc_cols}, "
            f"piece={dim['piece_name']}, source={dim['dimension_source']}"
        )

        query = '''
            UPDATE chart SET name=%s, num_rows=%s, num_columns=%s, description=%s, instructions=%s, created_by=%s, created_at=%s, piece_id=%s, age_id=%s, size_id=%s, gender_id=%s WHERE id=%s
        '''
        execute_query(query, (
            request.form['name'],
            calc_rows,
            calc_cols,
            request.form.get('description'),
            request.form.get('instructions'),
            current_user.username,
            _now(),
            piece_id,
            age_id,
            size_id,  # Use size ID 0 (NA) if no size selected
            int(request.form['gender_id']) if request.form.get('gender_id') else None,
            id
        ), fetch=False)

        # Maintain pattern_chart linkage: ensure only one pattern_chart entry for this chart
        execute_query('DELETE FROM pattern_chart WHERE chart_id = %s', (id,), fetch=False)
        # Insert new linkage
        insert_query = '''
            INSERT INTO pattern_chart (id, pattern_id, chart_id, chart_order, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM pattern_chart), %s, %s, 1, %s)
        '''
        execute_query(insert_query, (pattern_id, id, current_user.username), fetch=False)

        # Delete existing chart_coordinate rows for this chart
        execute_query('DELETE FROM chart_coordinate WHERE chart_id = %s', (id,), fetch=False)

        # Delete existing row sections (cascade will delete subsections and column sections)
        execute_query('UPDATE chart_row_section SET is_active = FALSE WHERE chart_id = %s', (id,), fetch=False)

        # Insert chart_coordinate for each cell (mirroring create logic)
        num_rows = calc_rows
        num_cols = calc_cols
        created_by = current_user.username
        coordinates = []
        for r in range(1, num_rows + 1):  # 1-based indexing to match form field names
            for c in range(1, num_cols + 1):  # 1-based indexing to match form field names
                element_id = request.form.get(f'cell_symbol_{r}_{c}')
                if element_id:
                    # Convert to 0-based for storage (x=col-1, y=row-1)
                    coordinates.append((id, c-1, r-1, int(element_id), True, _now(), created_by))
        if coordinates:
            # nosec B608 — only integer counter i+1 is interpolated, never user input
            values_str = ','.join([
                f"((SELECT COALESCE(MAX(id), 0) + {i+1} FROM chart_coordinate), %s, %s, %s, %s, %s, %s, %s)"  # nosec B608
                for i in range(len(coordinates))
            ])
            insert_query = f"""
                INSERT INTO chart_coordinate (id, chart_id, x, y, element_id, is_active, created_at, created_by)
                VALUES {values_str}
            """  # nosec B608
            params = []
            for tup in coordinates:
                params.extend(tup)
            execute_query(insert_query, tuple(params), fetch=False)

        # Insert chart sections (three-level hierarchy: row sections, row subsections, column sections)
        section_idx = 0
        while True:
            start_row_key = f'section_{section_idx}_start_row'
            if start_row_key not in request.form:
                break

            # Insert row section and get its ID
            row_section_query = """
                INSERT INTO chart_row_section (chart_id, start_row, end_row, repeat_count, instructions, label, include_in_pdf, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """
            row_section_id = execute_query(
                row_section_query,
                (
                    id,
                    int(request.form[f'section_{section_idx}_start_row']),
                    int(request.form[f'section_{section_idx}_end_row']),
                    int(request.form[f'section_{section_idx}_repeat_count']),
                    request.form.get(f'section_{section_idx}_instructions', '') or None,
                    request.form.get(f'section_{section_idx}_label', '') or None,
                    request.form.get(f'section_{section_idx}_include_in_pdf', '1') == '1',
                    created_by
                ),
                fetch=True
            )[0]['id']

            # Check for row subsections within this row section
            subsec_idx = 0
            while True:
                subsec_start_key = f'section_{section_idx}_subsec_{subsec_idx}_start_row'
                if subsec_start_key not in request.form:
                    break

                # Insert row subsection and get its ID
                row_subsection_query = """
                    INSERT INTO chart_row_subsection (row_section_id, start_row, end_row, instructions, label, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """
                row_subsection_id = execute_query(
                    row_subsection_query,
                    (
                        row_section_id,
                        int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_start_row']),
                        int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_end_row']),
                        request.form.get(f'section_{section_idx}_subsec_{subsec_idx}_instructions', '') or None,
                        request.form.get(f'section_{section_idx}_subsec_{subsec_idx}_label', '') or None,
                        created_by
                    ),
                    fetch=True
                )[0]['id']

                # Check for column sections within this row subsection
                col_idx = 0
                while True:
                    col_start_key = f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_start_col'
                    if col_start_key not in request.form:
                        break

                    col_section_query = """
                        INSERT INTO chart_column_section (row_subsection_id, start_col, end_col, repeat_count, instructions, created_by)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """
                    execute_query(
                        col_section_query,
                        (
                            row_subsection_id,
                            int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_start_col']),
                            int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_end_col']),
                            int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_repeat_count']),
                            request.form.get(f'section_{section_idx}_subsec_{subsec_idx}_col_{col_idx}_instructions', '') or None,
                            created_by
                        ),
                        fetch=False
                    )
                    col_idx += 1

                subsec_idx += 1

            section_idx += 1

        flash('Chart updated successfully!', 'success')
        return redirect(url_for('charts_list', pattern_id=pattern_id))

    elements = execute_query("SELECT id, description, symbol, type, abbrieviation FROM element WHERE is_active = TRUE ORDER BY (symbol IS NULL), description")
    pieces = execute_query("SELECT id, name, is_human_part FROM piece ORDER BY name")
    ages = execute_query("SELECT id, name FROM age ORDER BY seq, id")
    all_sizes = execute_query("SELECT id, name, abbreviation FROM size WHERE is_active = TRUE ORDER BY seq, id")
    # Filter out NA size for the dropdown (but keep it available for backend logic)
    sizes = [size for size in all_sizes if size['id'] != 0]  # Remove NA from dropdown
    genders = execute_query("SELECT * FROM gender WHERE is_active = TRUE ORDER BY name")

    # Get pattern gauge data for width calculation
    pattern_gauge = execute_query("SELECT gauge_stitches_p4inch, gauge_rows_p4inch FROM pattern WHERE id = %s", (pattern_id,))
    if pattern_gauge:
        pattern_gauge = pattern_gauge[0]
    else:
        pattern_gauge = {'gauge_stitches_p4inch': None, 'gauge_rows_p4inch': None}

    # Get measurements and ratios for width calculation
    measurements = execute_query("""
        SELECT m.measurement, bp.name as body_part_name, a.name as age_name,
               s.name as size_name, g.name as gender_name
        FROM measurement m
        JOIN body_part bp ON m.body_part_id = bp.id
        JOIN age a ON m.age_id = a.id
        JOIN size s ON m.size_id = s.id
        JOIN gender g ON m.gender_id = g.id
        WHERE m.is_active = TRUE
    """)

    # Retrieve chart_coordinate for this chart
    coordinates = execute_query("SELECT x, y, element_id FROM chart_coordinate WHERE chart_id = %s AND is_active = TRUE", (id,))
    # Build a dict {(row, col): element_id}
    # Use string keys for JSON serialization
    cell_symbols = {f"{coord['y']},{coord['x']}": coord['element_id'] for coord in coordinates}

    # Load row sections (three-level hierarchy: row sections → row subsections → column sections)
    row_sections_result = execute_query(
        """SELECT id, start_row, end_row, repeat_count, instructions, label, include_in_pdf
           FROM chart_row_section
           WHERE chart_id = %s AND is_active = TRUE
           ORDER BY start_row""",
        (id,)
    )

    row_sections = []
    for section_row in row_sections_result:
        section_id = section_row['id']

        # Load row subsections for this row section
        row_subsections_result = execute_query(
            """SELECT id, start_row, end_row, instructions, label
               FROM chart_row_subsection
               WHERE row_section_id = %s AND is_active = TRUE
               ORDER BY start_row""",
            (section_id,)
        )

        row_subsections = []
        for subsection_row in row_subsections_result:
            subsection_id = subsection_row['id']

            # Load column sections for this row subsection
            col_sections_result = execute_query(
                """SELECT start_col, end_col, repeat_count, instructions
                   FROM chart_column_section
                   WHERE row_subsection_id = %s AND is_active = TRUE
                   ORDER BY start_col""",
                (subsection_id,)
            )

            col_sections = [
                {
                    'startCol': col_row['start_col'] + 1,  # Convert to 1-based for frontend
                    'endCol': col_row['end_col'] + 1,
                    'repeatCount': col_row['repeat_count'],
                    'instructions': col_row['instructions'] or ''
                }
                for col_row in col_sections_result
            ]

            row_subsections.append({
                'id': subsection_id,
                'startRow': subsection_row['start_row'] + 1,  # Convert to 1-based for frontend
                'endRow': subsection_row['end_row'] + 1,
                'instructions': subsection_row['instructions'] or '',
                'label': subsection_row['label'] or '',
                'columnSections': col_sections
            })

        row_sections.append({
            'id': section_id,
            'startRow': section_row['start_row'] + 1,  # Convert to 1-based for frontend
            'endRow': section_row['end_row'] + 1,
            'repeatCount': section_row['repeat_count'],
            'instructions': section_row['instructions'] or '',
            'label': section_row['label'] or '',
            'includeInPdf': bool(section_row['include_in_pdf']),
            'rowSubsections': row_subsections
        })

    return render_template('charts/create_clean.html', chart=chart, edit_mode=True, elements=elements, cell_symbols=cell_symbols, row_sections=row_sections, pattern_id=pattern_id, pattern_name=pattern_name, pieces=pieces, ages=ages, sizes=sizes, genders=genders, pattern_gauge=pattern_gauge, measurements=measurements)

@app.route('/charts/<int:id>/delete', methods=['POST'])
def charts_delete(id):
    # Get pattern_id for redirect
    pattern_id = request.form.get('pattern_id') or request.args.get('pattern_id')

    # Delete chart coordinates first (foreign key constraint)
    execute_query('DELETE FROM chart_coordinate WHERE chart_id = %s', (id,), fetch=False)

    # Delete row sections (cascade will delete subsections and column sections)
    execute_query('DELETE FROM chart_row_section WHERE chart_id = %s', (id,), fetch=False)

    # Delete pattern_chart linkages
    execute_query('DELETE FROM pattern_chart WHERE chart_id = %s', (id,), fetch=False)

    # Delete the chart
    execute_query('DELETE FROM chart WHERE id = %s', (id,), fetch=False)

    flash('Chart deleted successfully!', 'success')

    if pattern_id:
        return redirect(url_for('charts_list', pattern_id=pattern_id))
    else:
        return redirect(url_for('charts_list'))


@app.route('/charts/<int:id>/pdf')
def charts_pdf(id):
    """Generate a PDF of the chart grid.

    Layout follows knitting-chart convention:
      - Only row sections with include_in_pdf=True are rendered.
      - Each row subsection is drawn as its own labeled block (stacked top-to-bottom).
      - Column repeat columns (from column sections) are hidden.
      - Row 1 at the BOTTOM of each block, highest row at the TOP.
      - Stitch 1 on the RIGHT, highest stitch number on the LEFT.
      - Row number labels alternate: odd on the RIGHT, even on the LEFT.
    """
    from io import BytesIO

    from flask import send_file
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas as rl_canvas

    # ── Color palettes matching the web UI ───────────────────────────────
    SECTION_BG = [
        (0.875, 0.941, 0.980),
        (1.000, 0.902, 0.941),
        (1.000, 0.953, 0.902),
        (0.902, 0.969, 0.902),
        (0.941, 0.902, 1.000),
        (1.000, 0.976, 0.902),
    ]
    SUBSECTION_COLORS = [
        (0.090, 0.635, 0.722),
        (0.910, 0.243, 0.549),
        (0.992, 0.494, 0.078),
        (0.157, 0.655, 0.271),
        (0.435, 0.259, 0.757),
        (1.000, 0.757, 0.027),
    ]
    COL_SECTION_COLOR = (0.863, 0.208, 0.271)  # #dc3545

    def _make_message_pdf(chart_name, message, sub_message=""):
        """Return a BytesIO PDF with a plain message (no grid)."""
        buf = BytesIO()
        pw, ph = A4
        c = rl_canvas.Canvas(buf, pagesize=A4)
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(pw / 2, ph / 2 + 30, f"Chart: {chart_name}")
        c.setFont("Helvetica", 11)
        c.drawCentredString(pw / 2, ph / 2, message)
        if sub_message:
            c.setFont("Helvetica-Oblique", 9)
            c.drawCentredString(pw / 2, ph / 2 - 20, sub_message)
        c.save()
        buf.seek(0)
        return buf

    # ── Fetch chart metadata ──────────────────────────────────────────────
    chart_result = execute_query(
        """SELECT c.*, p.name as piece_name, a.name as age_name,
                  s.abbreviation as size_name, g.name as gender_name
           FROM chart c
           LEFT JOIN piece p ON c.piece_id = p.id
           LEFT JOIN age a ON c.age_id = a.id
           LEFT JOIN size s ON c.size_id = s.id
           LEFT JOIN gender g ON c.gender_id = g.id
           WHERE c.id = %s""",
        (id,)
    )
    if not chart_result:
        flash('Chart not found.', 'danger')
        return redirect(url_for('charts_list'))

    chart = chart_result[0]
    num_rows = chart['num_rows'] or 0
    num_cols = chart['num_columns'] or 0

    # ── Fetch coordinates ────────────────────────────────────────────────
    coords = execute_query(
        """SELECT cc.x, cc.y, e.id as element_id, e.abbrieviation, e.ascii_symbol, e.symbol,
                  e.description
           FROM chart_coordinate cc
           JOIN element e ON cc.element_id = e.id
           WHERE cc.chart_id = %s AND cc.is_active = TRUE""",
        (id,)
    )
    # y = 0-based row index (y=0 → row 1), x = 0-based col index (x=0 → stitch 1)
    cell_data = {(int(c['y']), int(c['x'])): c for c in coords}

    # ── Fetch row sections → subsections → column sections ───────────────
    rs_rows = execute_query(
        """SELECT id, start_row, end_row, repeat_count, label, instructions, include_in_pdf
           FROM chart_row_section WHERE chart_id = %s AND is_active = TRUE
           ORDER BY start_row""",
        (id,)
    )
    row_sections = []
    for rs in rs_rows:
        sub_rows = execute_query(
            """SELECT id, start_row, end_row, label, instructions
               FROM chart_row_subsection WHERE row_section_id = %s AND is_active = TRUE
               ORDER BY start_row""",
            (rs['id'],)
        )
        subsections = []
        for sub in sub_rows:
            col_rows = execute_query(
                """SELECT start_col, end_col, repeat_count, instructions
                   FROM chart_column_section WHERE row_subsection_id = %s AND is_active = TRUE
                   ORDER BY start_col""",
                (sub['id'],)
            )
            subsections.append({
                'start_row': sub['start_row'],   # 0-based
                'end_row': sub['end_row'],
                'label': sub['label'] or '',
                'col_sections': [dict(c) for c in col_rows],
            })
        row_sections.append({
            'start_row': rs['start_row'],        # 0-based
            'end_row': rs['end_row'],
            'repeat_count': rs['repeat_count'],
            'label': rs['label'] or '',
            'instructions': rs['instructions'] or '',
            'include_in_pdf': bool(rs['include_in_pdf']),
            'subsections': subsections,
        })

    # ── Filter to include_in_pdf=True only ───────────────────────────────
    row_sections = [rs for rs in row_sections if rs.get('include_in_pdf', True)]

    safe_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in chart['name'])

    if not row_sections:
        buf = _make_message_pdf(
            chart['name'],
            "No row sections are marked for PDF export.",
            "Enable 'Include in PDF export' on at least one row section.",
        )
        return send_file(buf, mimetype='application/pdf', as_attachment=True,
                         download_name=f"chart_{id}_{safe_name}.pdf")

    # ── Suppress repeat rows (mirrors JS renderGrid logic) ────────────────
    # Only rows within include_in_pdf sections are candidates; the repeat
    # suppression then hides the collapsed copies after each section's end_row.
    included_rows: set = set()
    for rs in row_sections:
        for r in range(rs['start_row'], rs['end_row'] + 1):
            included_rows.add(r)

    suppressed_rows: set = set()
    for rs in row_sections:
        rows_in_section = rs['end_row'] - rs['start_row'] + 1
        collapsed_count = rows_in_section * rs['repeat_count']
        for i in range(1, collapsed_count + 1):
            suppressed_rows.add(rs['end_row'] + i)

    # ── Build drawing blocks ──────────────────────────────────────────────
    # One block per subsection; or one block per section when no subsections.
    # show_section_header=True on the LAST subsection of each section so that,
    # after reversed() drawing, the "Section X — Repeat N Times" banner appears
    # at the TOP of the section group in the PDF (once per section).
    # show_section_name=True only when there are multiple row sections.
    _num_sections = len(row_sections)
    blocks = []
    for sec_idx, rs in enumerate(row_sections):
        sec_color = SECTION_BG[sec_idx % len(SECTION_BG)]
        sec_label = rs['label'] or f"Section {sec_idx + 1}"
        sec_repeat = rs['repeat_count'] or 1
        repeat_text = f"Repeat {sec_repeat} Times" if sec_repeat > 1 else ""
        _TEAL = (0.09, 0.635, 0.722)
        if rs['subsections']:
            n_subs = len(rs['subsections'])
            for sub_idx, sub in enumerate(rs['subsections']):
                blocks.append({
                    'label': sec_label,
                    'repeat_text': repeat_text,
                    'show_section_header': sub_idx == n_subs - 1,  # last sub → top of group
                    'show_section_name': _num_sections > 1,
                    'sub_label': sub['label'] or f"Sub {sub_idx + 1}",
                    'instructions': rs.get('instructions') or '',  # noqa: WPS529
                    'start_row': sub['start_row'],
                    'end_row':   sub['end_row'],
                    'col_sections': sub['col_sections'],
                    'bg_color': (1.0, 1.0, 1.0),  # white for subsection grids
                    'border_color': _TEAL,
                    'repeat_count': sec_repeat,
                    'sec_idx': sec_idx,
                })
        else:
            blocks.append({
                'label': sec_label,
                'repeat_text': repeat_text,
                'show_section_header': True,
                'show_section_name': _num_sections > 1,
                'sub_label': '',
                'instructions': rs.get('instructions') or '',  # noqa: WPS529
                'start_row': rs['start_row'],
                'end_row':   rs['end_row'],
                'col_sections': [],
                'bg_color': sec_color,
                'border_color': tuple(x * 0.65 for x in sec_color),
                'repeat_count': sec_repeat,
                'sec_idx': sec_idx,
            })

    # ── Compute suppressed columns (global, from all col_sections) ────────
    suppressed_cols: set = set()
    for block in blocks:
        for cs in block['col_sections']:
            cols_in_cs = cs['end_col'] - cs['start_col'] + 1
            collapsed_cols = cols_in_cs * cs['repeat_count']
            for i in range(1, collapsed_cols + 1):
                suppressed_cols.add(cs['end_col'] + i)

    visible_cols = [c for c in range(num_cols) if c not in suppressed_cols]
    num_visible_cols = len(visible_cols)
    col_to_slot: dict = {c: i for i, c in enumerate(visible_cols)}

    # ── Compute visible rows per block ────────────────────────────────────
    for block in blocks:
        block['visible_rows'] = [
            r for r in range(block['start_row'], block['end_row'] + 1)
            if r in included_rows and r not in suppressed_rows
        ]
    blocks = [b for b in blocks if b['visible_rows']]

    if not blocks:
        buf = _make_message_pdf(
            chart['name'],
            "No visible rows after suppression.",
            "Check that row sections marked for PDF have at least one visible row.",
        )
        return send_file(buf, mimetype='application/pdf', as_attachment=True,
                         download_name=f"chart_{id}_{safe_name}.pdf")

    # ── Per-section landscape pages ────────────────────────────────────────
    import math as _math
    from itertools import groupby as _groupby

    # Fixed layout constants (CELL is computed per-section below)
    HEADER_H       = 30   # chart-name banner height
    BLOCK_LABEL_H  = 50   # section/sub label band above each block
    COL_LABEL_H    = 14   # stitch-number labels below each block
    BLOCK_GAP      = 4    # vertical gap between consecutive blocks
    LABEL_W        = 30   # left margin (even-row numbers)
    LABEL_W_R      = 30   # right margin (odd-row numbers)
    PADDING        = 10   # top padding below header
    LEGEND_CELL    = 18   # legend symbol-box size
    LEGEND_COLS    = 1    # single column layout
    LEGEND_X_GAP   = 10   # gap between legend entries
    LEGEND_ROW_H   = LEGEND_CELL + 3
    origin_x       = LABEL_W

    page_w, page_h = A4

    # Group blocks by section (sec_idx) → one portrait A4 page per section
    section_groups = [list(g) for _, g in _groupby(blocks, key=lambda b: b['sec_idx'])]

    buffer = BytesIO()
    pdf = rl_canvas.Canvas(buffer, pagesize=A4)

    # ── Draw one landscape page per section ───────────────────────────────
    for sec_blocks in section_groups:
        sec_total_rows = sum(len(b['visible_rows']) for b in sec_blocks)
        n_blocks = len(sec_blocks)

        # Collect unique elements used in this section's visible rows (for the inline legend)
        section_visible_rows: set = set()
        for b in sec_blocks:
            section_visible_rows.update(b['visible_rows'])
        seen_ids_sec: set = set()
        section_legend_elements = []
        for (row, _col), elem in sorted(cell_data.items()):
            if row in section_visible_rows:
                eid = elem.get('element_id')
                if eid not in seen_ids_sec:
                    seen_ids_sec.add(eid)
                    section_legend_elements.append(elem)

        # Estimate legend height so we can reserve vertical space before computing CELL
        # +1 for the always-present blank "knit RS / purl WS" entry
        n_leg_rows = _math.ceil((len(section_legend_elements) + 1) / LEGEND_COLS)
        LEGEND_H   = (n_leg_rows * LEGEND_ROW_H + 22) if n_leg_rows > 0 else 0
        legend_gap = 24 if LEGEND_H > 0 else 0

        # Compute CELL: largest square that fits all blocks + legend on one landscape A4 page
        available_h = (page_h - HEADER_H - PADDING
                       - n_blocks * (BLOCK_LABEL_H + COL_LABEL_H)
                       - max(0, n_blocks - 1) * BLOCK_GAP
                       - LEGEND_H - legend_gap)
        available_w = page_w - LABEL_W - LABEL_W_R
        CELL = min(
            (available_w / num_visible_cols) if num_visible_cols > 0 else 24,
            (available_h / sec_total_rows)   if sec_total_rows   > 0 else 24,
            24,
        )

        grid_w     = CELL * num_visible_cols
        label_font = max(6, min(10, int(CELL * 0.65)))
        col_font   = max(6, min(10, int(CELL * 0.65)))

        # ── Page header ────────────────────────────────────────────────────
        pdf.setFont("Helvetica-Bold", 12)
        pdf.setFillColor(colors.black)
        pdf.drawString(LABEL_W, page_h - 18, f"Chart: {chart['name']}")

        # ── Draw blocks (reversed: highest row numbers appear at top of page) ─
        current_top_y = page_h - HEADER_H

        for block in reversed(sec_blocks):
            bv_rows        = block['visible_rows']
            n_brows        = len(bv_rows)
            block_h        = n_brows * CELL
            block_origin_y = current_top_y - BLOCK_LABEL_H - block_h

            section_y = current_top_y - 11
            instr_y   = current_top_y - 26
            sub_y     = block_origin_y + block_h + 10
            pdf.setFillColor(colors.black)

            if block['show_section_header']:
                if block['show_section_name']:
                    pdf.setFont("Helvetica-Bold", 11)
                    pdf.setFillColor(colors.black)
                    pdf.drawString(origin_x, section_y, block['label'])
                    name_w = pdf.stringWidth(block['label'], "Helvetica-Bold", 11)
                    if block['repeat_text']:
                        pdf.setFont("Helvetica", 10)
                        pdf.setFillColorRGB(0.3, 0.3, 0.3)
                        pdf.drawString(origin_x + name_w + 6, section_y, block['repeat_text'])
                elif block['repeat_text']:
                    pdf.setFont("Helvetica-Bold", 11)
                    pdf.setFillColor(colors.black)
                    pdf.drawString(origin_x, section_y, block['repeat_text'])

                if block['instructions']:
                    pdf.setFont("Helvetica-Oblique", 10)
                    pdf.setFillColorRGB(0.25, 0.25, 0.25)
                    pdf.drawString(origin_x, instr_y, block['instructions'][:130])

            if block['sub_label']:
                pdf.setFont("Helvetica-Bold", 11)
                pdf.setFillColorRGB(0.09, 0.635, 0.722)
                pdf.drawString(origin_x, sub_y, block['sub_label'])

            # Background fill
            pdf.setFillColorRGB(*block['bg_color'])
            pdf.rect(origin_x, block_origin_y, grid_w, block_h, stroke=0, fill=1)

            # Cell grid + row labels + symbols
            pdf.setLineWidth(0.4)
            for i, row in enumerate(bv_rows):
                yb = block_origin_y + i * CELL
                row_number = row + 1
                pdf.setFont("Helvetica", label_font)
                pdf.setFillColor(colors.black)
                if row_number % 2 == 1:
                    pdf.drawString(origin_x + grid_w + 2, yb + CELL * 0.3, str(row_number))
                else:
                    pdf.drawRightString(origin_x - 2, yb + CELL * 0.3, str(row_number))

                for col in visible_cols:
                    slot = col_to_slot[col]
                    xL = origin_x + (num_visible_cols - 1 - slot) * CELL
                    pdf.setStrokeColor(colors.Color(0.7, 0.7, 0.7))
                    pdf.rect(xL, yb, CELL, CELL, stroke=1, fill=0)

                    element = cell_data.get((row, col))
                    if element:
                        sym_bytes = element.get('symbol')
                        drawn = False
                        if sym_bytes:
                            try:
                                from PIL import Image as PILImage
                                img_buf = BytesIO(bytes(sym_bytes))
                                pil_img = PILImage.open(img_buf)
                                out_buf = BytesIO()
                                pil_img.save(out_buf, format='PNG')
                                out_buf.seek(0)
                                img_reader = ImageReader(out_buf)
                                pad = max(1, CELL * 0.05)
                                pdf.drawImage(img_reader, xL + pad, yb + pad,
                                              CELL - 2 * pad, CELL - 2 * pad,
                                              preserveAspectRatio=True, mask='auto')
                                drawn = True
                            except Exception:
                                drawn = False
                        if not drawn:
                            abbr = (element.get('abbrieviation') or element.get('ascii_symbol') or '?')
                            font_size = max(4, min(8, int(CELL * 0.45)))
                            pdf.setFont("Helvetica-Bold", font_size)
                            pdf.setFillColor(colors.black)
                            pdf.drawCentredString(xL + CELL / 2, yb + CELL * 0.25, str(abbr)[:3])

            # Column section borders + ×N label
            cs_border_w = max(1.0, CELL * 0.09)
            for cs in block['col_sections']:
                vis_in_cs = [c for c in visible_cols if cs['start_col'] <= c <= cs['end_col']]
                if not vis_in_cs:
                    continue
                right_slot = col_to_slot[min(vis_in_cs)]
                left_slot  = col_to_slot[max(vis_in_cs)]
                xL = origin_x + (num_visible_cols - 1 - left_slot) * CELL
                xR = origin_x + (num_visible_cols - right_slot) * CELL
                box_w = xR - xL
                pdf.setStrokeColorRGB(*COL_SECTION_COLOR)
                pdf.setLineWidth(cs_border_w)
                pdf.setDash()
                pdf.line(xL, block_origin_y + block_h, xR, block_origin_y + block_h)
                pdf.line(xL, block_origin_y, xR, block_origin_y)
                pdf.line(xL, block_origin_y, xL, block_origin_y + block_h)
                pdf.line(xR, block_origin_y, xR, block_origin_y + block_h)
                if cs.get('repeat_count') and cs['repeat_count'] > 1:
                    repeat_label = f"\xd7{cs['repeat_count']}"
                    pdf.setFont("Helvetica-Bold", max(7, min(9, int(CELL * 0.6))))
                    pdf.setFillColorRGB(*COL_SECTION_COLOR)
                    pdf.drawCentredString(xL + box_w / 2, block_origin_y + block_h + 2, repeat_label)

            # Block border
            br, bg, bb = block['border_color']
            pdf.setStrokeColorRGB(br, bg, bb)
            pdf.setLineWidth(1.0)
            pdf.setDash()
            pdf.rect(origin_x, block_origin_y, grid_w, block_h, stroke=1, fill=0)

            # Column stitch-number labels below this block
            col_label_y = block_origin_y - COL_LABEL_H * 0.85
            pdf.setFont("Helvetica", col_font)
            pdf.setFillColor(colors.black)
            for p_col in range(num_visible_cols):
                slot = num_visible_cols - 1 - p_col
                actual_stitch = visible_cols[slot] + 1
                x_center = origin_x + p_col * CELL + CELL / 2
                pdf.drawCentredString(x_center, col_label_y, str(actual_stitch))

            current_top_y = block_origin_y - COL_LABEL_H - BLOCK_GAP

        # ── Legend at bottom of this section's page ────────────────────────
        # Always prepend the blank-square entry at position 0
        blank_entry = {
            'symbol': None,
            'abbrieviation': '',
            'ascii_symbol': '',
            'description': 'knit on right side / purl on wrong side',
            'white_box': True,
        }
        legend_entries = [blank_entry] + section_legend_elements
        if legend_entries:
            DESC_X       = LABEL_W + LEGEND_CELL + 8   # description starts right after box
            legend_top_y = current_top_y - 18
            pdf.setFont("Helvetica-Bold", 9)
            pdf.setFillColor(colors.black)
            pdf.drawString(LABEL_W, legend_top_y, "Legend")
            pdf.setLineWidth(0.4)
            pdf.setStrokeColorRGB(0.7, 0.7, 0.7)
            pdf.line(LABEL_W, legend_top_y - 3, page_w - LABEL_W_R, legend_top_y - 3)
            entry_top_y = legend_top_y - 6

            for li, elem in enumerate(legend_entries):
                lx = LABEL_W
                ly = entry_top_y - li * LEGEND_ROW_H
                text_y = ly - LEGEND_CELL + LEGEND_CELL * 0.3

                # Symbol box (white for blank entry, light gray for others)
                if elem.get('white_box'):
                    pdf.setFillColorRGB(1.0, 1.0, 1.0)
                else:
                    pdf.setFillColorRGB(0.95, 0.95, 0.95)
                pdf.setStrokeColorRGB(0.7, 0.7, 0.7)
                pdf.setLineWidth(0.4)
                pdf.rect(lx, ly - LEGEND_CELL, LEGEND_CELL, LEGEND_CELL, stroke=1, fill=1)

                sym_bytes = elem.get('symbol')
                sym_drawn = False
                if sym_bytes:
                    try:
                        from PIL import Image as PILImage
                        img_buf = BytesIO(bytes(sym_bytes))
                        pil_img = PILImage.open(img_buf)
                        out_buf = BytesIO()
                        pil_img.save(out_buf, format='PNG')
                        out_buf.seek(0)
                        img_reader = ImageReader(out_buf)
                        pad = max(1, LEGEND_CELL * 0.05)
                        pdf.drawImage(img_reader, lx + pad, ly - LEGEND_CELL + pad,
                                      LEGEND_CELL - 2 * pad, LEGEND_CELL - 2 * pad,
                                      preserveAspectRatio=True, mask='auto')
                        sym_drawn = True
                    except Exception:
                        pass

                # If no symbol image, show abbreviation inside the box, shrunk to fit
                if not sym_drawn:
                    abbr = (elem.get('abbrieviation') or elem.get('ascii_symbol') or '')
                    max_text_w = LEGEND_CELL - 2
                    fs = max(6, min(9, int(LEGEND_CELL * 0.45)))
                    while fs > 4 and pdf.stringWidth(str(abbr), "Helvetica-Bold", fs) > max_text_w:
                        fs -= 0.5
                    pdf.setFont("Helvetica-Bold", fs)
                    pdf.setFillColor(colors.black)
                    pdf.drawCentredString(lx + LEGEND_CELL / 2,
                                         ly - LEGEND_CELL + LEGEND_CELL * 0.25,
                                         str(abbr))

                # Description immediately to the right of the box
                desc = elem.get('description') or (elem.get('abbrieviation') or '')
                pdf.setFont("Helvetica", 8)
                pdf.setFillColor(colors.black)
                pdf.drawString(DESC_X, text_y, str(desc)[:80])

        pdf.showPage()

    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"chart_{id}_{safe_name}.pdf"
    )


# Pattern Category Routes
@app.route('/pattern_categories/<int:id>/edit', methods=['GET', 'POST'], endpoint='pattern_categories_edit')
def pattern_categories_edit(id):
    category = execute_query("SELECT * FROM pattern_category WHERE id = %s", (id,))
    category = category[0] if category else None
    if not category:
        flash('Pattern category not found.', 'danger')
        return redirect(url_for('pattern_categories_list'))
    if request.method == 'POST':
        query = 'UPDATE pattern_category SET category = %s, sub_category = %s WHERE id = %s'
        execute_query(query, (
            request.form['category'],
            request.form.get('sub_category', ''),
            id
        ), fetch=False)
        flash('Pattern category updated successfully!', 'success')
        return redirect(url_for('pattern_categories_list'))
    return render_template('pattern_categories/edit.html', category=category)


@app.route('/pattern_categories/<int:id>/delete', methods=['POST'], endpoint='pattern_categories_delete')
def pattern_categories_delete(id):
    execute_query("DELETE FROM pattern_category WHERE id = %s", (id,), fetch=False)
    flash('Pattern category deleted successfully!', 'success')
    return redirect(url_for('pattern_categories_list'))

# Pattern Routes
@app.route('/test-patterns')
def test_patterns():
    """Debug route to test pattern database connectivity"""
    try:
        # Test basic pattern count
        count_result = execute_query("SELECT COUNT(*) as count FROM pattern")
        total_count = count_result[0]['count'] if count_result else 0

        # Test pattern sample
        patterns = execute_query("SELECT id, name, is_active FROM pattern LIMIT 5")

        # Test active pattern count
        active_count_result = execute_query("SELECT COUNT(*) as count FROM pattern WHERE is_active = TRUE")
        active_count = active_count_result[0]['count'] if active_count_result else 0

        # Activate the Alice Cowl pattern to test the fix
        execute_query("UPDATE pattern SET is_active = TRUE WHERE name = 'Alice Cowl'")

        # Test pattern sample after update
        patterns_updated = execute_query("SELECT id, name, is_active FROM pattern LIMIT 5")
        active_count_updated = execute_query("SELECT COUNT(*) as count FROM pattern WHERE is_active = TRUE")

        return f"""
        <h1>Pattern Database Test</h1>
        <p>Total patterns: {total_count}</p>
        <p>Before update - Active patterns: {active_count}</p>
        <p>Sample patterns before: {patterns}</p>
        <p>After activating Alice Cowl - Active patterns: {active_count_updated[0]['count'] if active_count_updated else 0}</p>
        <p>Sample patterns after: {patterns_updated}</p>
        <p><a href="/patterns">Go to Pattern List</a></p>
        """
    except Exception as e:
        import traceback
        return f"""
        <h1>Pattern Database Error</h1>
        <p>Error: {str(e)}</p>
        <pre>{traceback.format_exc()}</pre>
        """

@app.route('/patterns')
def patterns_list():
    try:
        # Get all patterns to check if any exist
        all_patterns = execute_query("SELECT COUNT(*) as count FROM pattern")
        total_count = all_patterns[0]['count'] if all_patterns else 0

        # Get active patterns with necessary joins
        patterns = execute_query("""
            SELECT p.id, p.name, p.description, p.category_id, p.level_of_difficulty_id,
                   p.yarn_weight_id, p.is_active, p.created_at, p.created_by,
                   p.schematic IS NOT NULL as has_schematic,
                   COALESCE(pc.category, 'N/A') as category,
                   COALESCE(pc.sub_category, 'N/A') as sub_category,
                   COALESCE(lod.name, 'N/A') AS difficulty_name,
                   COALESCE(yw.weight_name, 'N/A') AS yarn_weight_name
            FROM pattern p
            LEFT JOIN pattern_category pc ON p.category_id = pc.id
            LEFT JOIN level_of_difficulty lod ON p.level_of_difficulty_id = lod.id
            LEFT JOIN yarn_weight yw ON p.yarn_weight_id = yw.weight_id
            WHERE p.is_active = TRUE
            ORDER BY p.id
        """)

        return render_template('patterns/list.html',
                             patterns=patterns or [],
                             total_patterns=total_count,
                             active_count=len(patterns or []))
    except Exception as e:
        print(f"Error in patterns_list: {e}")
        import traceback
        print(traceback.format_exc())
        return render_template('patterns/list.html', patterns=[], total_patterns=0, active_count=0)

@app.route('/patterns/create', methods=['GET', 'POST'])
def patterns_create():
    if request.method == 'POST':

        schematic_data = None
        picture1_data = None
        picture2_data = None
        picture3_data = None
        if 'schematic' in request.files:
            file = request.files['schematic']
            if file and file.filename:
                schematic_data = file.read()
        if 'picture1' in request.files:
            file = request.files['picture1']
            if file and file.filename:
                picture1_data = file.read()
        if 'picture2' in request.files:
            file = request.files['picture2']
            if file and file.filename:
                picture2_data = file.read()
        if 'picture3' in request.files:
            file = request.files['picture3']
            if file and file.filename:
                picture3_data = file.read()
        gauge_measurement_data = None
        if 'gauge_measurement' in request.files:
            file = request.files['gauge_measurement']
            if file and file.filename:
                gauge_measurement_data = file.read()

        is_active = True if request.form.get('is_active') == 'on' else False
        query = """
            INSERT INTO pattern (id, name, description, category_id, level_of_difficulty_id, yarn_weight_id, gauge_stitches_p4inch, gauge_rows_p4inch, schematic, picture1, picture2, picture3, additional_details, gauge_measurement, needle_type, is_active, created_by)
            VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM pattern), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        execute_query(query, (
            request.form['name'],
            request.form.get('description', ''),
            request.form['category_id'],
            request.form['difficulty_level'],
            int(request.form['yarn_weight_id']) if request.form.get('yarn_weight_id') else None,
            float(request.form['gauge_stitches_p4inch']) if request.form.get('gauge_stitches_p4inch') else None,
            float(request.form['gauge_rows_p4inch']) if request.form.get('gauge_rows_p4inch') else None,
            schematic_data,
            picture1_data,
            picture2_data,
            picture3_data,
            request.form.get('additional_details', ''),
            gauge_measurement_data,
            request.form.get('needle_type', ''),
            is_active,
            current_user.username
        ), fetch=False)
        # Save selected features to pattern_element
        pattern_id = execute_query("SELECT MAX(id) as id FROM pattern")[0]['id']
        feature_ids = request.form.getlist('features')
        for feature_id in feature_ids:
            execute_query(
                "INSERT INTO pattern_element (id, pattern_id, element_id, created_by) VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM pattern_element), %s, %s, %s)",
                (pattern_id, feature_id, current_user.username),
                fetch=False
            )
        flash('Pattern created successfully!', 'success')
        return redirect(url_for('patterns_list'))

    categories = execute_query("SELECT * FROM pattern_category WHERE is_active = TRUE ORDER BY category")
    features = execute_query("SELECT id, description FROM element WHERE type = 'feature' AND is_active = TRUE ORDER BY description")
    levels = execute_query("SELECT id, name FROM level_of_difficulty WHERE is_active = TRUE ORDER BY seq, id")
    yarn_weights = execute_query("SELECT * FROM yarn_weight WHERE is_active = TRUE ORDER BY weight_id")
    return render_template('patterns/create.html', categories=categories, features=features, levels=levels, yarn_weights=yarn_weights)

@app.route('/patterns/<int:id>/edit', methods=['GET', 'POST'])
def patterns_edit(id):
    if request.method == 'POST':
        schematic_data = None
        picture1_data = None
        picture2_data = None
        picture3_data = None
        gauge_measurement_data = None

        # Handle file uploads
        if 'schematic' in request.files:
            file = request.files['schematic']
            if file and file.filename:
                schematic_data = file.read()
        if 'picture1' in request.files:
            file = request.files['picture1']
            if file and file.filename:
                picture1_data = file.read()
        if 'picture2' in request.files:
            file = request.files['picture2']
            if file and file.filename:
                picture2_data = file.read()
        if 'picture3' in request.files:
            file = request.files['picture3']
            if file and file.filename:
                picture3_data = file.read()
        if 'gauge_measurement' in request.files:
            file = request.files['gauge_measurement']
            if file and file.filename:
                gauge_measurement_data = file.read()

        # Get current pattern to preserve is_active if not specified in form
        current_pattern = execute_query("SELECT is_active FROM pattern WHERE id = %s", (id,))

        if request.form.get('is_active') is not None:
            # If form includes is_active field, use that
            is_active = True if request.form.get('is_active') == 'on' else False
        else:
            # If form doesn't include is_active field, preserve current value
            is_active = current_pattern[0]['is_active'] if current_pattern else True

        # Build update query - only update files if new ones were uploaded
        update_fields = []
        update_values = []

        # Always update text fields
        update_fields.extend(['name = %s', 'description = %s', 'category_id = %s', 'level_of_difficulty_id = %s', 'yarn_weight_id = %s',
                             'gauge_stitches_p4inch = %s', 'gauge_rows_p4inch = %s', 'additional_details = %s', 'needle_type = %s', 'is_active = %s',
                             'created_by = %s', 'created_at = %s'])
        update_values.extend([
            request.form['name'],
            request.form.get('description', ''),
            request.form['category_id'],
            request.form['difficulty_level'],
            int(request.form['yarn_weight_id']) if request.form.get('yarn_weight_id') else None,
            float(request.form['gauge_stitches_p4inch']) if request.form.get('gauge_stitches_p4inch') else None,
            float(request.form['gauge_rows_p4inch']) if request.form.get('gauge_rows_p4inch') else None,
            request.form.get('additional_details', ''),
            request.form.get('needle_type', ''),
            is_active,
            current_user.username,
            _now()
        ])

        # Add file updates if new files were uploaded
        if schematic_data is not None:
            update_fields.append('schematic = %s')
            update_values.append(schematic_data)
        if picture1_data is not None:
            update_fields.append('picture1 = %s')
            update_values.append(picture1_data)
        if picture2_data is not None:
            update_fields.append('picture2 = %s')
            update_values.append(picture2_data)
        if picture3_data is not None:
            update_fields.append('picture3 = %s')
            update_values.append(picture3_data)
        if gauge_measurement_data is not None:
            update_fields.append('gauge_measurement = %s')
            update_values.append(gauge_measurement_data)

        update_values.append(id)  # For WHERE clause

        # nosec B608 — update_fields contains only hardcoded column name strings, never user input
        query = f"UPDATE pattern SET {', '.join(update_fields)} WHERE id = %s"  # nosec B608
        execute_query(query, update_values, fetch=False)

        # Update pattern features
        # First, delete existing features
        execute_query("DELETE FROM pattern_element WHERE pattern_id = %s", (id,), fetch=False)

        # Then add selected features
        feature_ids = request.form.getlist('features')
        for feature_id in feature_ids:
            execute_query(
                "INSERT INTO pattern_element (id, pattern_id, element_id, created_by) VALUES ((SELECT COALESCE(MAX(id), 0) + 1 FROM pattern_element), %s, %s, %s)",
                (id, feature_id, current_user.username),
                fetch=False
            )

        flash('Pattern updated successfully!', 'success')
        return redirect(url_for('patterns_list'))

    # GET request - show edit form
    pattern = execute_query("SELECT * FROM pattern WHERE id = %s", (id,))
    if not pattern:
        flash('Pattern not found!', 'error')
        return redirect(url_for('patterns_list'))

    pattern = pattern[0]
    categories = execute_query("SELECT * FROM pattern_category WHERE is_active = TRUE ORDER BY category")
    features = execute_query("SELECT id, description FROM element WHERE type = 'feature' AND is_active = TRUE ORDER BY description")
    levels = execute_query("SELECT id, name FROM level_of_difficulty WHERE is_active = TRUE ORDER BY seq, id")
    yarn_weights = execute_query("SELECT * FROM yarn_weight WHERE is_active = TRUE ORDER BY weight_id")

    # Get current pattern features
    selected_features = execute_query("SELECT element_id FROM pattern_element WHERE pattern_id = %s", (id,))
    selected_feature_ids = [f['element_id'] for f in selected_features] if selected_features else []

    return render_template('patterns/edit.html', pattern=pattern, categories=categories,
                         features=features, levels=levels, yarn_weights=yarn_weights, selected_features=selected_feature_ids)


if __name__ == '__main__':
    import argparse as _ap
    _parser = _ap.ArgumentParser(add_help=False)
    _parser.add_argument('--port', '-p', type=int, default=5000)
    _args, _ = _parser.parse_known_args()
    _env = os.getenv('ENVIRONMENT', 'dev')
    # Attempt to connect to the database at container startup
    from database import get_db_connection
    _log.info(
        "DB config at startup",
        extra={
            "DB_HOST":    Config.DB_HOST,
            "DB_PORT":    Config.DB_PORT,
            "DB_NAME":    Config.DB_NAME,
            "DB_USER":    Config.DB_USER,
            "DB_SSLMODE": os.getenv('DB_SSLMODE', 'not set'),
        }
    )
    try:
        _log.debug("Attempting database connection at startup...")
        conn = get_db_connection()
        conn.close()
        _log.info("Database connection test succeeded at startup.")
    except Exception as db_exc:
        _log.warning(
            f"Database connection test failed at startup (app will still start): {db_exc}",
            exc_info=True,
        )
    # Only enable debug for 'dev' environment
    app.run(debug=(_env == 'dev'), host='0.0.0.0', port=_args.port)  # nosec B104 — 0.0.0.0 required for Docker container binding

