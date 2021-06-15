import sqlite3
from contextlib import closing
from flask import Flask, render_template, request, session, url_for, redirect, g, flash, abort
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from datetime import datetime
import time
from hashlib import md5  # gravatar 이용하기 위해

# 데이터베이스 환경설정
DATABASE = 'twit.db'
SECRET_KEY = 'development key'
PER_PAGE = 10

app = Flask(__name__)
app.config.from_object(__name__)


def connect_db():
    # con = sqlite3.connect(app.config['DATABASE'])
    return sqlite3.connect(app.config['DATABASE'])


def query_db(query, args=(), one=False):
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value) for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


# 데이터베이스 초기화
def init_db():
    with closing(connect_db()) as db:  # with closing() 블럭이 끝나면 인자로 받은 객체를 닫거난 제거한다.
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def get_user_id(username):
    sql = 'select user_id from user where user_name = ?'
    rv = g.db.execute(sql, [username]).fetchone()
    return rv[0] if rv else None


def format_datetime(timestamp):
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')


# gavatar.com에서 제공하는 이미지 서비스를 받기 위한 함수 설정
def gravatar_url(email, size=50):
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
           (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.db = connect_db()  # 글로벌 변수 g에 데이터베이스 연결 정보인 g.db 객첵 생성
    g.user = None        # 글로벌 변수 g에 g.user 객체 생성하고 초기화
    if 'user_id' in session:   # session 객체에 user_id 라는 속성이 있으면 g.user 에 값을 할당
        g.user = query_db('select * from user where user_id = ?', [session['user_id']], one=True)


@app.teardown_request
def teardown_request(exception):
    if hasattr(g, 'db'): # g 클래스에 db 라는 항목이 있으면 db close 한다
        g.db.close()
    return exception


@app.route('/public')
def public_twit():
    sql = '''SELECT message.*, user.* FROM message, user
    WHERE message.author_id = user.user_id ORDER BY message.pub_date DESC LIMIT ?'''
    messages = query_db(sql, [PER_PAGE])
    return render_template('twit_list.html', messages=messages)


@app.route('/')
def twit_list():
    if not g.user:
        # print(g.user)
        return redirect(url_for('public_twit'))
    # 기존 : follower 추가 전
    # sql = '''SELECT message.*, user.* FROM message, user
    # WHERE message.author_id = user.user_id AND user.user_id = ?
    # ORDER BY message.pub_date DESC LIMIT ?'''
    # messages = query_db(sql, [session['user_id'], PER_PAGE])

    sql = '''SELECT message.*, user.* FROM message, user
        WHERE message.author_id = user.user_id 
        AND (user.user_id = ? or user.user_id in (SELECT whom_id FROM follower WHERE who_id = ?))    
        ORDER BY message.pub_date DESC LIMIT ?'''
    messages = query_db(sql, [session['user_id'], session['user_id'],PER_PAGE])

    return render_template('twit_list.html', messages=messages)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    # 최초에 들어갈 때는 GET 방식 이므로 register.html 을 렌더링한다
    if request.method == 'POST':
        # 유효성 검사
        if not request.form['username']:
            error = "사용자 이름을 입력하세요"
        elif not request.form['email'] or '@' not in request.form['email']:
            error = "잘못된 이메일 형식이거나 이메일을 잘못 입력하셨습니다"
        elif not request.form['password']:
            error = "비밀번호를 입력하세요"
        elif request.form['password'] != request.form['password2']:
            error = "비밀번호가 일치하지 않습니다"
        elif get_user_id(request.form['username']) is not None:  # 등록된 사용자가 아닌지 검사
            error = "이미 등록된 사용자입니다"
        else:
            # 데이터베이스에 등록하기
            sql = 'insert into user (user_name, email, pw_hash) values (?, ?, ?)'
            g.db.execute(sql, [request.form['username'], request.form['email'],
                               generate_password_hash(request.form['password'])])
            g.db.commit()
            flash('사용자 처리가 완료되었습니다. 로그인할 수 있습니다.')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/<username>/follow')
def follow_user(username):
    if not g.user:
        abort(401)

    whom_id = get_user_id(username)

    if whom_id is None:
        abort(404)

    sql = 'INSERT INTO follower(who_id, whom_id) VALUES(?, ?)'
    g.db.execute(query_db(sql, [session['user_id'], whom_id]))
    g.db.commit()
    flash('지금 "%s"를 팔로으 했습니다.' % username)
    return redirect(url_for('user_twit', username=username))


@app.route('/<username>/unfollow')
def unfollow(username):
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    sql = 'DELETE FORM follow WHERE who_id = ? and whom_id = ?'
    g.db.execute(sql, [session['user_id'], whom_id])
    g.db.commit()
    flash('"%s"를 언팔로우 처리가 되었습니다.' % username)
    return redirect(url_for('user_twit'), username=username)


@app.route('/<username>')
def user_twit(username):
    sql = 'SELECT * FROM user WHERE username = ?'
    profile_user = query_db(sql, [username], one=True)

    if profile_user is None:
        abort(404)

    followed = False

    if g.user:
        sql = 'SELECT 1 FROM follower WHERE who_id = ? and whom_id = ?'
        # sql = 'SELECT 1 FROM follower WHERE follower.who_id = ? and follower.whom_id = ?'
        followed = query_db(sql, [session['uer_id'], profile_user['user_id']], one=True) is not None
        # 값이 none이 아니면 followed 는 Ture값을 갖음

    sql = '''SELECT message.*, user.* FROM message, user 
            WHERE message.author_id = user.user_id AND user.user_id = ?
            ORDER BY pub_date DESC limit ?'''
    messages = query_db(sql, [profile_user['user_id'], PER_PAGE])

    return render_template('twit_list.html', messsages=messages)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('twit_list'))
    error = None
    if request.method == 'POST':
        # 유효성 검사
        sql = 'select * from user where user_name = ?'
        user = query_db(sql, [request.form['username']], one=True)
        if user is None:
            error = "사용자 이름이 잘못 되었습니다."
        # check_password_hash() 함수는 해시화된 암호와 사용자가 입력한 평문형태의 암호를 비교하는 함수
        # 두개 값이 일치하면 Ture
        elif not check_password_hash(user['pw_hash'], request.form['password']):
            error = "비밀번호가 일치하지 않습니다. 다시 확인하세요"
        else:
            flash("로그인에 성공했습니다.")
            session['user_id'] = user['user_id']
            return redirect(url_for('twit_list'))

    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    flash("로그 아웃 되었습니다.")
    session.pop('user_id', None)
    return redirect(url_for('twit_list'))


@app.route('/add_message', methods=['POST'])
def add_message():
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        sql = 'INSERT INTO message(author_id, text, pub_date) VALUES(?, ?, ?)'
        g.db.execute(sql, [session['user_id'], request.form['text'], int(time.time())])
        g.db.commit()
        flash("메시지가 저장되었습니다.")
    return redirect(url_for('twit_list'))


# 진자 템플릿에 핕터 설정
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url


if __name__ == '__main__':
    init_db()
    app.run()
