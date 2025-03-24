import os
import sqlite3
import uuid
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------- 설정 ---------------- #
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 이미지 업로드 설정
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------- DB ---------------- #
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                category TEXT,
                is_reported INTEGER DEFAULT 0,
                image_filename TEXT
            );

            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            );

            CREATE TABLE IF NOT EXISTS message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount REAL NOT NULL,
                product_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cursor.execute("SELECT * FROM user WHERE username = 'admin'")
        if not cursor.fetchone():
            hashed_pw = generate_password_hash('admin')
            cursor.execute("""
                INSERT INTO user (id, username, password, is_admin)
                VALUES (?, ?, ?, 1)
            """, (str(uuid.uuid4()), 'admin', hashed_pw))
        db.commit()

# ---------------- 라우트 ---------------- #
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, password))
        db.commit()
        flash('회원가입 성공! 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            if not user['is_active']:
                flash('비활성화된 계정입니다.')
                return redirect(url_for('login'))

            session['user_id'] = user['id']
            session['is_admin'] = bool(user['is_admin'])
            flash('로그인 성공!')

            if user['is_admin']:
                return redirect(url_for('admin'))

            return redirect(url_for('dashboard'))

        flash('로그인 실패!')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃 되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    return render_template('dashboard.html', products=products, user=user)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form.get('bio')
        password = request.form.get('password')
        if bio:
            cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        if password:
            hashed_pw = generate_password_hash(password)
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (hashed_pw, session['user_id']))
        db.commit()
        flash('프로필 업데이트 완료')
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    return render_template('profile.html', user=user)

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        category = request.form.get('category', '기타')
        file = request.files.get('image')
        image_filename = None

        if file and allowed_file(file.filename):
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        product_id = str(uuid.uuid4())
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO product (id, title, description, price, seller_id, category, image_filename)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (product_id, title, description, price, session['user_id'], category, image_filename))
        db.commit()
        flash('상품 등록 완료!')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')

@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품이 존재하지 않습니다.')
        return redirect(url_for('dashboard'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

@app.route('/product/<product_id>/delete', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 삭제 전에 판매자인지 검증
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품이 존재하지 않습니다.')
        return redirect(url_for('dashboard'))

    if product['seller_id'] != session['user_id']:
        flash('삭제 권한이 없습니다.')
        return redirect(url_for('view_product', product_id=product_id))

    # 이미지 파일도 삭제
    if product['image_filename']:
        img_path = os.path.join(app.config['UPLOAD_FOLDER'], product['image_filename'])
        if os.path.exists(img_path):
            os.remove(img_path)

    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('dashboard'))

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE title LIKE ?", (f'%{keyword}%',))
    results = cursor.fetchall()
    return render_template('search.html', products=results, keyword=keyword)

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        target_id = request.form['target_id']
        reason = request.form['reason']
        report_type = request.form['type']
        report_id = str(uuid.uuid4())
        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO report (id, reporter_id, target_id, reason, type) VALUES (?, ?, ?, ?, ?)",
                       (report_id, session['user_id'], target_id, reason, report_type))
        db.commit()
        flash('신고 접수 완료')
        return redirect(url_for('dashboard'))
    return render_template('report.html')

@app.route('/inbox')
def inbox():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # 상대방 ID를 기준으로 유저 닉네임까지 JOIN
    cursor.execute("""
        SELECT u.id, u.username
        FROM user u
        WHERE u.id IN (
            SELECT DISTINCT receiver_id FROM message WHERE sender_id = ?
            UNION
            SELECT DISTINCT sender_id FROM message WHERE receiver_id = ?
        ) AND u.id != ?
    """, (user_id, user_id, user_id))

    partners = cursor.fetchall()
    return render_template('inbox.html', partners=partners)


@app.route('/chat/<receiver_id>')
def chat(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 로그인한 사용자 정보 가져오기 → chat.html에서 user.username 쓰기 위해 필요!
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    # 상대방 닉네임 가져오기
    cursor.execute("SELECT username FROM user WHERE id = ?", (receiver_id,))
    receiver = cursor.fetchone()
    receiver_username = receiver['username'] if receiver else '알 수 없음'

    # 메시지 조회
    cursor.execute("""
        SELECT * FROM message
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], receiver_id, receiver_id, session['user_id']))
    messages = cursor.fetchall()

    return render_template('chat.html',
                           messages=messages,
                           receiver_id=receiver_id,
                           receiver_username=receiver_username,
                           user=user)  


@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        flash('관리자 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) AS user_count FROM user")
    user_count = cursor.fetchone()['user_count']
    cursor.execute("SELECT COUNT(*) AS product_count FROM product")
    product_count = cursor.fetchone()['product_count']
    
    return render_template('admin/dashboard.html', user_count=user_count, product_count=product_count)

@app.route('/admin/products')
def admin_products():
    if not session.get('is_admin'):
        flash('접근 불가')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product")
    products = cursor.fetchall()

    return render_template('admin/products.html', products=products)

@app.route('/admin/delete_product/<product_id>', methods=['POST'])
def admin_delete_product(product_id):
    if not session.get('is_admin'):
        flash('접근 불가')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('admin_products'))

@app.route('/admin/reports')
def admin_reports():
    if not session.get('is_admin'):
        flash('접근 불가')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM report WHERE status = 'pending'")
    reports = cursor.fetchall()

    return render_template('admin/reports.html', reports=reports)

@app.route('/admin/handle_user_report', methods=['POST'])
def handle_user_report():
    if not session.get('is_admin'):
        flash('접근 불가')
        return redirect(url_for('dashboard'))

    user_id = request.form['user_id']
    report_id = request.form['report_id']

    db = get_db()
    cursor = db.cursor()

    # 1. 유저 휴면 처리
    cursor.execute("UPDATE user SET is_active = 0 WHERE id = ?", (user_id,))

    # 2. 유저의 상품 전부 삭제
    cursor.execute("DELETE FROM product WHERE seller_id = ?", (user_id,))

    # 3. 신고 상태 처리
    cursor.execute("UPDATE report SET status = 'approved' WHERE id = ?", (report_id,))
    
    db.commit()
    flash('유저를 휴면 처리하고 상품을 삭제했습니다.')
    return redirect(url_for('admin_reports'))


@socketio.on('private_message')
def handle_private_message(data):
    room = f"{data['sender_id']}_{data['receiver_id']}"
    join_room(room)

    db = get_db()
    cursor = db.cursor()
    msg_id = str(uuid.uuid4())

    cursor.execute("INSERT INTO message (id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)",
                   (msg_id, data['sender_id'], data['receiver_id'], data['message']))
    db.commit()

    emit('private_message', data, room=room)

@socketio.on('broadcast_message')
def handle_broadcast_message(data):
    
    data['timestamp'] = datetime.now().strftime('%H:%M:%S')
    emit('broadcast_message', data, broadcast=True)

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)


