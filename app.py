"""
주요 기능:
 - 회원가입 / 로그인 / 로그아웃
 - 상품 등록 / 목록 / 상세보기
 - 프로필 페이지에서 사용자 소개(bio) 수정
 - 신고 기능 (유저ID, 상품ID 등)
 - 실시간 채팅 (Flask-SocketIO)
 - SQLite DB 사용
 - 비밀번호 해싱, 세션 관리, (간단) CSRF 대비 예시
 - 보안을 위해 하드코딩된 SECRET_KEY 대신 환경변수를 사용 권장
"""

import os
import uuid
import sqlite3
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, abort
from flask_socketio import SocketIO, send, emit
from werkzeug.security import generate_password_hash, check_password_hash

# CSRF 토큰 간단 예시 (실제로는 Flask-WTF 권장)
# 여기서는 단순히 session에 랜덤 토큰을 저장해두고 폼 hidden으로 전달받아 검증하는 식
# 사용하려면 템플릿에서 <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}"> 해주어야 함.
def generate_csrf_token():
    return uuid.uuid4().hex

def check_csrf_token(request_token):
    stored = session.get('csrf_token')
    return stored and stored == request_token

############################
# Flask & SocketIO 초기화
############################

app = Flask(__name__, static_folder='static', template_folder='templates')

# SECRET_KEY는 환경변수에서 가져오고, 없으면 임시로 "dev_secret"
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", "dev_secret")

# 예시로 세션 만료시간 30분 설정
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# 디버그 모드는 개발 시에만 True, 운영 시에는 False로
DEBUG_MODE = True

socketio = SocketIO(app, cors_allowed_origins="*")  # 필요하면 CORS 설정

############################
# DB 연결
############################

DATABASE = os.path.join(os.path.dirname(__file__), 'market.db')

def get_db():
    if 'db_conn' not in g:
        g.db_conn = sqlite3.connect(DATABASE, isolation_level=None)
        g.db_conn.row_factory = sqlite3.Row
    return g.db_conn

@app.teardown_appcontext
def close_connection(exception):
    db_conn = g.pop('db_conn', None)
    if db_conn is not None:
        db_conn.close()

def init_db():
    """DB 테이블 초기화 (없으면 생성)"""
    db = get_db()
    # users 테이블: id, username, password(해시), bio
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        bio TEXT
    )
    """)
    # products 테이블: id, title, description, price, seller_id(FK)
    db.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        price TEXT,
        seller_id TEXT NOT NULL
    )
    """)
    # reports 테이블: id, reporter_id, target_id, reason
    db.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        reporter_id TEXT NOT NULL,
        target_id TEXT NOT NULL,
        reason TEXT
    )
    """)

############################
# 헬퍼 함수
############################

def get_current_user():
    """세션에 user_id가 있으면 해당 사용자 레코드 반환, 없으면 None"""
    user_id = session.get('user_id')
    if not user_id:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return user

def login_required(f):
    """로그인해야 접근 가능하도록 하는 데코레이터"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("이 기능은 로그인 후 이용 가능합니다.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

############################
# 라우트
############################

@app.route('/')
def index():
    """홈 페이지 (로그인되어 있으면 대시보드로, 아니면 환영 페이지)"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.before_request
def before_request():
    """매 요청마다 DB 초기화 & CSRF 토큰이 없으면 생성"""
    init_db()
    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf_token()

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        # CSRF 토큰 검증
        form_csrf = request.form.get('csrf_token', '')
        if not check_csrf_token(form_csrf):
            flash("CSRF 토큰이 유효하지 않습니다.")
            return redirect(url_for('register'))

        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력하세요.")
            return redirect(url_for('register'))

        db = get_db()
        existing = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            flash("이미 존재하는 사용자명입니다.")
            return redirect(url_for('register'))

        # 비밀번호 해시
        hashed_pw = generate_password_hash(password)
        user_id = str(uuid.uuid4())
        db.execute("INSERT INTO users (id, username, password) VALUES (?,?,?)",
                   (user_id, username, hashed_pw))
        flash("회원가입이 완료되었습니다. 로그인 해주세요.")
        return redirect(url_for('login'))
    else:
        return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        form_csrf = request.form.get('csrf_token', '')
        if not check_csrf_token(form_csrf):
            flash("CSRF 토큰이 유효하지 않습니다.")
            return redirect(url_for('login'))

        username = request.form.get('username','')
        password = request.form.get('password','')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user:
            flash("아이디 또는 비밀번호가 잘못되었습니다.")
            return redirect(url_for('login'))

        # check_password_hash로 검증
        if check_password_hash(user['password'], password):
            # 로그인 성공: 세션 재생성(간단하게 이전 세션 clear 후 새로 할당)
            session.clear()
            session['user_id'] = user['id']
            session.permanent = True  # PERMANENT_SESSION_LIFETIME 적용
            flash("로그인 성공")
            return redirect(url_for('dashboard'))
        else:
            flash("아이디 또는 비밀번호가 잘못되었습니다.")
            return redirect(url_for('login'))
    else:
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("로그아웃되었습니다.")
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """로그인한 사용자의 메인 페이지: 상품 목록 & 채팅 포함"""
    user = get_current_user()
    db = get_db()
    products = db.execute("SELECT * FROM products").fetchall()
    return render_template('dashboard.html', user=user, products=products)

@app.route('/product/new', methods=['GET','POST'])
@login_required
def new_product():
    user = get_current_user()
    if request.method == 'POST':
        form_csrf = request.form.get('csrf_token', '')
        if not check_csrf_token(form_csrf):
            flash("CSRF 토큰이 유효하지 않습니다.")
            return redirect(url_for('new_product'))

        title = request.form.get('title','').strip()
        description = request.form.get('description','').strip()
        price = request.form.get('price','').strip()
        if not title:
            flash("상품명은 필수입니다.")
            return redirect(url_for('new_product'))

        product_id = str(uuid.uuid4())
        db = get_db()
        db.execute("INSERT INTO products (id, title, description, price, seller_id) VALUES (?,?,?,?,?)",
                   (product_id, title, description, price, user['id']))
        flash("상품이 등록되었습니다.")
        return redirect(url_for('dashboard'))
    else:
        return render_template('new_product.html', user=user)

@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        flash("해당 상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))

    seller = db.execute("SELECT * FROM users WHERE id=?", (product['seller_id'],)).fetchone()
    return render_template('view_product.html', product=product, seller=seller)

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    user = get_current_user()
    if request.method == 'POST':
        form_csrf = request.form.get('csrf_token', '')
        if not check_csrf_token(form_csrf):
            flash("CSRF 토큰이 유효하지 않습니다.")
            return redirect(url_for('profile'))

        bio = request.form.get('bio','')
        db = get_db()
        db.execute("UPDATE users SET bio=? WHERE id=?", (bio, user['id']))
        flash("프로필이 업데이트되었습니다.")
        return redirect(url_for('profile'))
    else:
        return render_template('profile.html', user=user)

@app.route('/report', methods=['GET','POST'])
@login_required
def report():
    user = get_current_user()
    if request.method == 'POST':
        form_csrf = request.form.get('csrf_token', '')
        if not check_csrf_token(form_csrf):
            flash("CSRF 토큰이 유효하지 않습니다.")
            return redirect(url_for('report'))

        target_id = request.form.get('target_id','').strip()
        reason = request.form.get('reason','').strip()
        if not target_id or not reason:
            flash("신고 대상과 사유를 모두 입력해주세요.")
            return redirect(url_for('report'))

        report_id = str(uuid.uuid4())
        db = get_db()
        db.execute("INSERT INTO reports (id, reporter_id, target_id, reason) VALUES (?,?,?,?)",
                   (report_id, user['id'], target_id, reason))
        flash("신고가 접수되었습니다.")
        return redirect(url_for('dashboard'))
    else:
        return render_template('report.html', user=user)

############################
# SocketIO 이벤트
############################
@socketio.on('connect')
def handle_connect():
    print("사용자 소켓 연결됨")

@socketio.on('disconnect')
def handle_disconnect():
    print("사용자 소켓 연결 해제됨")

@socketio.on('send_message')
def handle_send_message(data):
    """
    클라이언트가 보낸 채팅 메시지를 모든 사용자에게 브로드캐스트
    data: { 'username': ..., 'message': ... }
    """
    # 보안을 위해 username을 여기서 session에서 가져와 대입하는게 이상적
    # 여기서는 편의상 클라이언트가 준 username을 그대로 씀 (데모 목적)
    broadcast_data = {
        'username': data.get('username', '???'),
        'message': data.get('message', ''),
        'msg_id': str(uuid.uuid4())
    }
    send(broadcast_data, broadcast=True)

############################
# 메인 실행
############################

if __name__ == '__main__':
    # 실제 운영 시에는 debug=False로 전환하고, eventlet/gevent와 같은 프로덕션 서버를 사용
    print("===== Starting Flask-SocketIO Server =====")
    socketio.run(app, host='0.0.0.0', port=5000, debug=DEBUG_MODE)
