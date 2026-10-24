import os
import json
import sqlite3
import hmac
from functools import wraps
from flask import send_from_directory
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


RECOVERY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'recovery_config.json')

def load_recovery_hash():
    if os.path.exists(RECOVERY_FILE):
        with open(RECOVERY_FILE, 'r') as f:
            data = json.load(f)
        return data.get('recovery_hash', '')
    initial_key = os.environ.get('ADMIN_RECOVERY_KEY', '')
    if initial_key:
        value = generate_password_hash(initial_key)
        save_recovery_hash(value)
        return value
    return ''

def save_recovery_hash(value):
    with open(RECOVERY_FILE, 'w') as f:
        json.dump({'recovery_hash': value}, f)
    try:
        os.chmod(RECOVERY_FILE, 0o600)
    except OSError:
        pass

def verify_recovery_key(value):
    saved_hash = load_recovery_hash()
    return bool(saved_hash and check_password_hash(saved_hash, value))


app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

if not app.secret_key:
    raise RuntimeError("Hay dat FLASK_SECRET_KEY truoc khi chay app.py")

DB_PATH = os.path.join(os.path.dirname(__file__), 'profile.db')

DEFAULT_PROFILE = {
    'name': 'Ngô Thị Ánh Ngọc',
    'birthday': '',
    'school': '',
    'major': '',
    'intro': 'Xin chào! Đây là trang hồ sơ cá nhân của tôi.',
    'email': '',
    'address': '',
    'hobbies': '',
    'avatar': '',
    'facebook': '',
    'instagram': '',
    'github': '',
    'skills': 'HTML, CSS, JavaScript, C++, Python, SQL',
    'projects': 'Website cá nhân - Xây dựng website giới thiệu bản thân',
    'routine': 'Sáng: Học tập\nChiều: Làm bài tập\nTối: Ôn bài'
}
FIELDS = list(DEFAULT_PROFILE.keys())


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = connect_db()
    conn.execute(
        'CREATE TABLE IF NOT EXISTS profile '
        '(id INTEGER PRIMARY KEY, data TEXT NOT NULL)'
    )
    conn.execute(
        'CREATE TABLE IF NOT EXISTS admin_password '
        '(id INTEGER PRIMARY KEY, password_hash TEXT NOT NULL)'
    )

    if not conn.execute('SELECT id FROM profile WHERE id=1').fetchone():
        conn.execute(
            'INSERT INTO profile (id, data) VALUES (1, ?)',
            (json.dumps(DEFAULT_PROFILE, ensure_ascii=False),)
        )

    # Chỉ tạo mật khẩu ban đầu nếu chưa có mật khẩu lưu trong database.
    row = conn.execute(
        'SELECT id FROM admin_password WHERE id=1'
    ).fetchone()

    if not row:
        username = os.environ.get('ADMIN_USERNAME', '')
        password = os.environ.get('ADMIN_PASSWORD', '')
        if username and password:
            conn.execute(
                'INSERT INTO admin_password (id, password_hash) VALUES (1, ?)',
                (generate_password_hash(password),)
            )

    conn.commit()
    conn.close()


def get_profile():
    conn = connect_db()
    row = conn.execute('SELECT data FROM profile WHERE id=1').fetchone()
    conn.close()

    if row:
        data = json.loads(row['data'])
        for field in FIELDS:
            data.setdefault(field, '')
        return data

    return DEFAULT_PROFILE.copy()


def save_profile(data):
    conn = connect_db()
    conn.execute(
        'INSERT OR REPLACE INTO profile (id, data) VALUES (1, ?)',
        (json.dumps(data, ensure_ascii=False),)
    )
    conn.commit()
    conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


@app.route('/css/<path:filename>')
def old_css(filename):
    return send_from_directory(os.path.join(app.root_path, 'css'), filename)

@app.route('/js/<path:filename>')
def old_js(filename):
    return send_from_directory(os.path.join(app.root_path, 'js'), filename)


@app.route('/')
def index():
    return render_template('profile.html', profile=get_profile())


@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = os.environ.get('ADMIN_USERNAME', '')
        entered_username = request.form.get('username', '')
        entered_password = request.form.get('password', '')

        conn = connect_db()
        row = conn.execute(
            'SELECT password_hash FROM admin_password WHERE id=1'
        ).fetchone()
        conn.close()

        if not username:
            flash('Chưa cấu hình tên đăng nhập quản trị.')
        elif not row:
            flash('Chưa có mật khẩu quản trị. Hãy kiểm tra cấu hình máy chủ.')
        elif (hmac.compare_digest(entered_username, username)
              and check_password_hash(row['password_hash'], entered_password)):
            session['logged_in'] = True
            return redirect(url_for('admin'))
        else:
            flash('Tên đăng nhập hoặc mật khẩu không đúng.')

    return render_template('login.html')




@app.route('/admin/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '')
        recovery_key = request.form.get('recovery_key', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        expected_username = os.environ.get('ADMIN_USERNAME', 'anhngoc')
        expected_key = load_recovery_hash()

        if (not expected_key
                or not hmac.compare_digest(username, expected_username)
                or not verify_recovery_key(recovery_key)):
            flash('Tên tài khoản hoặc mã khôi phục không đúng.')
        elif len(new_password) < 8:
            flash('Mật khẩu mới phải có ít nhất 8 ký tự.')
        elif new_password != confirm_password:
            flash('Mật khẩu xác nhận không khớp.')
        else:
            conn = connect_db()
            conn.execute(
                'INSERT OR REPLACE INTO admin_password (id, password_hash) VALUES (1, ?)',
                (generate_password_hash(new_password),)
            )
            conn.commit()
            conn.close()
            flash('Đặt lại mật khẩu thành công. Hãy đăng nhập.')
            return redirect(url_for('login'))

    return render_template('forgot_password.html')




@app.route('/admin/change-recovery-key', methods=['GET', 'POST'])
@login_required
def change_recovery_key():
    if request.method == 'POST':
        current_key = request.form.get('current_key', '')
        new_key = request.form.get('new_key', '')
        confirm_key = request.form.get('confirm_key', '')

        if not verify_recovery_key(current_key):
            flash('Mã khôi phục hiện tại không đúng.')
        elif len(new_key) < 8:
            flash('Mã khôi phục mới phải có ít nhất 8 ký tự.')
        elif new_key != confirm_key:
            flash('Mã khôi phục xác nhận không khớp.')
        else:
            save_recovery_hash(generate_password_hash(new_key))
            flash('Đổi mã khôi phục thành công.')
            return redirect(url_for('admin'))

    return render_template('change_recovery_key.html')


@app.route('/admin/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    profile = get_profile()

    if request.method == 'POST':
        for field in FIELDS:
            if field != 'avatar':
                profile[field] = request.form.get(field, '').strip()

        file = request.files.get('avatar_file')
        if file and file.filename:
            filename = secure_filename(file.filename)
            extension = os.path.splitext(filename)[1].lower()

            if extension not in ('.png', '.jpg', '.jpeg', '.gif', '.webp'):
                flash('Ảnh phải là PNG, JPG, JPEG, GIF hoặc WEBP.')
                return render_template('admin.html', profile=profile)

            filename = 'avatar' + extension
            file.save(os.path.join(app.root_path, 'static', 'uploads', filename))
            profile['avatar'] = 'uploads/' + filename

        save_profile(profile)
        flash('Đã lưu thông tin hồ sơ.')
        return redirect(url_for('admin'))

    return render_template('admin.html', profile=profile)


@app.route('/admin/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        conn = connect_db()
        row = conn.execute(
            'SELECT password_hash FROM admin_password WHERE id=1'
        ).fetchone()

        if not row or not check_password_hash(
                row['password_hash'], current_password):
            flash('Mật khẩu hiện tại không đúng.')
        elif len(new_password) < 8:
            flash('Mật khẩu mới phải có ít nhất 8 ký tự.')
        elif new_password != confirm_password:
            flash('Mật khẩu xác nhận không khớp.')
        elif new_password == current_password:
            flash('Mật khẩu mới phải khác mật khẩu hiện tại.')
        else:
            conn.execute(
                'UPDATE admin_password SET password_hash=? WHERE id=1',
                (generate_password_hash(new_password),)
            )
            conn.commit()
            conn.close()
            session.clear()
            flash('Đổi mật khẩu thành công. Hãy đăng nhập lại.')
            return redirect(url_for('login'))

        conn.close()

    return render_template('change_password.html')


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
