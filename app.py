
# ── Environment must be bootstrapped before Config is imported ──────────────
import set_env
_active_env = set_env.setup()  # loads .env section + Azure Key Vault secrets into os.environ
# ────────────────────────────────────────────────────────────────────────────

import pcp_logger as _pcp_logger
_log = _pcp_logger.setup(_active_env)   # configure logging for this environment

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from database import execute_query
from datetime import datetime, timedelta
import base64
import io
import pyDMNrules
import os
import secrets
import smtplib
import qrcode
import pyotp
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename
import pandas as pd

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

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
        f"Unhandled exception: {exc}",
        extra={
            "path":      request.path,
            "method":    request.method,
            "ip":        request.remote_addr,
            "traceback": _tb.format_exc(),
        },
        exc_info=True,
    )
    # Re-raise so Flask shows its default 500 page in dev or a clean page in prod
    raise exc


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def login():
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
            try:
                send_otp_email(user.email, otp)
                _log.info(
                    "MFA initiated (email OTP)",
                    extra={"username": username, "user_id": user.id, "ip": request.remote_addr},
                )
                flash(f'A 6-digit code has been sent to {user.email[:4]}***{user.email[user.email.index("@"):]}', 'info')
            except Exception as e:
                _log.error(
                    f"Failed to send email OTP: {e}",
                    extra={"username": username, "ip": request.remote_addr},
                )
                flash(f'Could not send email OTP: {e}', 'error')
                session.clear()
                return render_template('auth/login.html', next=next_url)

        return redirect(url_for('mfa_verify'))

    return render_template('auth/login.html', next=request.args.get('next', ''))


@app.route('/mfa/verify', methods=['GET', 'POST'], endpoint='mfa_verify')
def mfa_verify():
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
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        is_admin = request.form.get('is_admin') == 'on'
        if not username or not email or not password:
            flash('Username, email, and password are required.', 'error')
            return render_template('users/create.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('users/create.html')
        if execute_query("SELECT id FROM users WHERE username=%s OR email=%s", (username, email)):
            flash('A user with that username or email already exists.', 'error')
            return render_template('users/create.html')
        execute_query(
            "INSERT INTO users (username, email, password_hash, is_active, is_admin, created_by) "
            "VALUES (%s, %s, %s, TRUE, %s, %s)",
            (username, email, generate_password_hash(password), is_admin, current_user.id)
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
        email       = request.form.get('email', '').strip()
        is_admin    = request.form.get('is_admin') == 'on'
        is_active   = request.form.get('is_active') == 'on'
        new_password = request.form.get('new_password', '').strip()
        if new_password:
            if len(new_password) < 8:
                flash('New password must be at least 8 characters.', 'error')
                return render_template('users/edit.html', user=user_row)
            execute_query(
                "UPDATE users SET email=%s, is_admin=%s, is_active=%s, password_hash=%s WHERE id=%s",
                (email, is_admin, is_active, generate_password_hash(new_password), id)
            )
        else:
            execute_query(
                "UPDATE users SET email=%s, is_admin=%s, is_active=%s WHERE id=%s",
                (email, is_admin, is_active, id)
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
    return float(eval(formula, {"__builtins__": {}}, safe_locals))

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
    from flask import send_file
    import io
    pattern = execute_query("SELECT name, schematic FROM pattern WHERE id = %s", (id,))
    if pattern and pattern[0]['schematic']:
        return send_file(
            io.BytesIO(pattern[0]['schematic']),
            mimetype='image/jpeg',
            as_attachment=False,
            download_name=f"{pattern[0]['name']}_schematic.jpg"
        )
    return "No schematic available", 404

@app.route('/patterns/<int:id>/picture/<int:pic>')
def pattern_picture(id, pic):
    from flask import send_file
    import io
    # Validate pic parameter (1, 2, or 3)
    if pic not in [1, 2, 3]:
        return "Invalid picture number", 404
    
    picture_column = f"picture{pic}"
    pattern = execute_query(f"SELECT name, {picture_column} FROM pattern WHERE id = %s", (id,))
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
        symbol_data = None
        if 'symbol' in request.files and request.files['symbol'].filename:
            symbol_file = request.files['symbol']
            symbol_data = symbol_file.read()
        query = '''
            UPDATE yarn_weight SET weight_name=%s, lower_stitches_p4inch=%s, upper_stitches_p4inch=%s,
                lower_needle_size_mm=%s, upper_needle_size_mm=%s, lower_needle_size_us=%s, upper_needle_size_us=%s,
                wraps_per_inch_lower=%s, wraps_per_inch_upper=%s,
                inexpensive_yarn_type=%s, mid_range_yarn_type=%s, premium_yarn_type=%s,
                is_active=%s, created_by=%s, created_at=%s{symbol_clause}
            WHERE weight_id=%s
        '''
        symbol_clause = ', symbol=%s' if symbol_data is not None else ''
        params = [
            request.form['weight_name'],
            int(request.form['lower_stitches_p4inch']),
            int(request.form['upper_stitches_p4inch']),
            float(request.form['lower_needle_size_mm']),
            float(request.form['upper_needle_size_mm']),
            int(request.form['lower_needle_size_us']),
            int(request.form['upper_needle_size_us']),
            int(request.form['wraps_per_inch_lower']),
            int(request.form['wraps_per_inch_upper']),
            request.form.get('inexpensive_yarn_type', ''),
            request.form.get('mid_range_yarn_type', ''),
            request.form.get('premium_yarn_type', ''),
            request.form.get('is_active', 'true').lower() == 'true',
            current_user.username,
            _now(),
        ]
        if symbol_data is not None:
            params.append(symbol_data)
        params.append(id)
        execute_query(query.format(symbol_clause=symbol_clause), tuple(params), fetch=False)
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
    import pandas as pd
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
    from flask import send_file, Response
    from PIL import Image
    import io
    
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
        calc_rows = dim['num_rows']
        calc_cols = dim['num_stitches']
        print(
            f"[DMN] charts_create using DMN dimensions rows={calc_rows}, cols={calc_cols}, "
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
            values_str = ','.join([
                f"((SELECT COALESCE(MAX(id), 0) + {i+1} FROM chart_coordinate), %s, %s, %s, %s, %s, %s, %s)"
                for i in range(len(coordinates))
            ])
            insert_query = f"""
                INSERT INTO chart_coordinate (id, chart_id, x, y, element_id, is_active, created_at, created_by)
                VALUES {values_str}
            """
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
                INSERT INTO chart_row_section (chart_id, start_row, end_row, repeat_count, instructions, label, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
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
                    INSERT INTO chart_row_subsection (row_section_id, start_row, end_row, instructions, created_by)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """
                row_subsection_id = execute_query(
                    row_subsection_query,
                    (
                        row_section_id,
                        int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_start_row']),
                        int(request.form[f'section_{section_idx}_subsec_{subsec_idx}_end_row']),
                        request.form.get(f'section_{section_idx}_subsec_{subsec_idx}_instructions', '') or None,
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
            values_str = ','.join([
                f"((SELECT COALESCE(MAX(id), 0) + {i+1} FROM chart_coordinate), %s, %s, %s, %s, %s, %s, %s)"
                for i in range(len(coordinates))
            ])
            insert_query = f"""
                INSERT INTO chart_coordinate (id, chart_id, x, y, element_id, is_active, created_at, created_by)
                VALUES {values_str}
            """
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
                INSERT INTO chart_row_section (chart_id, start_row, end_row, repeat_count, instructions, label, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
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
        """SELECT id, start_row, end_row, repeat_count, instructions, label 
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

@app.template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return ''


# Pattern Category Routes
@app.route('/pattern_categories')


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
        print(f"DEBUG: Current pattern is_active: {current_pattern}")
        print(f"DEBUG: Form is_active value: {request.form.get('is_active')}")
        
        if request.form.get('is_active') is not None:
            # If form includes is_active field, use that
            is_active = True if request.form.get('is_active') == 'on' else False
            print(f"DEBUG: Using form value: {is_active}")
        else:
            # If form doesn't include is_active field, preserve current value
            is_active = current_pattern[0]['is_active'] if current_pattern else True
            print(f"DEBUG: Preserving current value: {is_active}")
        
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
        
        query = f"UPDATE pattern SET {', '.join(update_fields)} WHERE id = %s"
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
    app.run(debug=(_env != 'prod'), host='0.0.0.0', port=_args.port)

