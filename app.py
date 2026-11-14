"""Global AI Mission Community — self-hosted pilot MVP.
Run: python app.py. Requires fastapi, uvicorn, jinja2, python-multipart, itsdangerous.
This is a pilot implementation, not a security-audited production release.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from contextlib import contextmanager
from urllib.parse import quote

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get('GAMC_DATA_DIR', ROOT / 'data')).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / 'gamc.sqlite3'
SECRET_PATH = DATA_DIR / '.session_secret'
if os.environ.get('GAMC_SECRET_KEY'):
    SECRET_KEY = os.environ['GAMC_SECRET_KEY']
elif SECRET_PATH.exists():
    SECRET_KEY = SECRET_PATH.read_text().strip()
else:
    SECRET_KEY = secrets.token_urlsafe(48)
    SECRET_PATH.write_text(SECRET_KEY)
    try: SECRET_PATH.chmod(0o600)
    except OSError: pass

app = FastAPI(title='Global AI Mission Community', docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site='lax', https_only=os.getenv('GAMC_HTTPS_ONLY','0') == '1', max_age=60*60*24*14)
app.mount('/static', StaticFiles(directory=ROOT / 'static'), name='static')
templates = Jinja2Templates(directory=str(ROOT / 'templates'))

@app.middleware('http')
async def baseline_security_headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    )
    return response

LANG = {
    'ko': {
        'home':'홈','community':'커뮤니티','resources':'자료실','events':'행사','projects':'프로젝트','about':'소개',
        'login':'로그인','join':'회원가입','logout':'로그아웃','my':'내 공간','admin':'운영 관리','search':'검색','ask':'질문하기',
        'welcome':'환영합니다','language':'언어','all':'전체','general':'자유대화','help':'질문·도움','collaborate':'협력 제안',
        'open':'답변 대기','solved':'해결됨','reply':'답변','save':'저장','cancel':'취소','view':'자세히 보기',
        'learn':'배우고','connect':'연결되고','serve':'함께 섬깁니다','browse':'자료 둘러보기',
        'newpost':'새 글 작성','no_results':'아직 등록된 내용이 없습니다.','memberonly':'회원 전용 공간입니다.',
        'signin_to_continue':'참여하시려면 로그인하거나 가입해 주세요.','guidelines':'커뮤니티 규칙','privacy':'개인정보 안내','safety':'현장 안전',
        'profile':'내 프로필','notifications':'알림','preferences':'환경설정','account':'계정 관리','report':'신고하기',
        'helpcenter':'도움말','created':'등록일','read':'읽기','apply':'참여 신청','rsvp':'참석 신청',
        'search_placeholder':'질문·자료·행사·프로젝트 검색','send':'제출','back':'돌아가기', 'empty_questions':'첫 질문을 남겨 동료들의 배움을 시작해 보세요.'
    },
    'en': {
        'home':'Home','community':'Community','resources':'Resources','events':'Events','projects':'Projects','about':'About',
        'login':'Sign in','join':'Join','logout':'Sign out','my':'My Space','admin':'Administration','search':'Search','ask':'Ask a question',
        'welcome':'Welcome','language':'Language','all':'All','general':'General','help':'Ask & Help','collaborate':'Collaborate',
        'open':'Awaiting answer','solved':'Solved','reply':'Reply','save':'Save','cancel':'Cancel','view':'Details',
        'learn':'Learn AI','connect':'Connect across borders','serve':'Serve together','browse':'Explore resources',
        'newpost':'New discussion','no_results':'Nothing here yet.','memberonly':'Members-only space.',
        'signin_to_continue':'Sign in or join to participate.','guidelines':'Community Guidelines','privacy':'Privacy notice','safety':'Field safety',
        'profile':'My profile','notifications':'Notifications','preferences':'Preferences','account':'Account','report':'Report',
        'helpcenter':'Help center','created':'Created','read':'Read','apply':'Apply to contribute','rsvp':'RSVP',
        'search_placeholder':'Search questions, resources, events and projects','send':'Submit','back':'Back', 'empty_questions':'Be the first to ask a question.'
    }
}
TOPICS = ['AI Basics','Translation','Bible Study','Content Creation','Education','Digital Outreach','Ethics & Safety','Tools & Workflow']
SPACES = ['general','help','collaborate']

def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 15000')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def getone(query, values=()):
    with db() as conn:
        return conn.execute(query, values).fetchone()


def getall(query, values=()):
    with db() as conn:
        return conn.execute(query, values).fetchall()


def execute(query, values=()):
    with db() as conn:
        cur = conn.execute(query, values)
        conn.commit()
        return cur.lastrowid


def init_db():
    with db() as conn:
        conn.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
          display_name TEXT NOT NULL, locale TEXT NOT NULL DEFAULT 'ko', interests TEXT NOT NULL DEFAULT '',
          profile_visible INTEGER NOT NULL DEFAULT 0, intro TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'member',
          is_active INTEGER NOT NULL DEFAULT 1, onboarded INTEGER NOT NULL DEFAULT 0, notify_replies INTEGER NOT NULL DEFAULT 1,
          accepted_terms_at TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS posts (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
          space TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, tag TEXT NOT NULL, language TEXT NOT NULL,
          solved_reply_id INTEGER, status TEXT NOT NULL DEFAULT 'visible', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS replies (
          id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL REFERENCES posts(id), user_id INTEGER NOT NULL REFERENCES users(id),
          body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'visible', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS resources (
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, summary TEXT NOT NULL, content TEXT NOT NULL,
          url TEXT NOT NULL DEFAULT '', language TEXT NOT NULL DEFAULT 'ko', topic TEXT NOT NULL, license TEXT NOT NULL,
          source TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'published', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, summary TEXT NOT NULL, content TEXT NOT NULL,
          start_at TEXT NOT NULL, end_at TEXT NOT NULL DEFAULT '', timezone TEXT NOT NULL DEFAULT 'Asia/Seoul',
          location TEXT NOT NULL DEFAULT 'Online', url TEXT NOT NULL DEFAULT '', capacity INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL DEFAULT 'published', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS rsvps (
          id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL REFERENCES events(id),
          user_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, UNIQUE(event_id,user_id));
        CREATE TABLE IF NOT EXISTS projects (
          id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, summary TEXT NOT NULL, content TEXT NOT NULL,
          skills TEXT NOT NULL DEFAULT '', language TEXT NOT NULL DEFAULT 'ko', status TEXT NOT NULL DEFAULT 'open',
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS project_apps (
          id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER NOT NULL REFERENCES projects(id),
          user_id INTEGER NOT NULL REFERENCES users(id), why TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          created_at TEXT NOT NULL, UNIQUE(project_id,user_id));
        CREATE TABLE IF NOT EXISTS notifications (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
          kind TEXT NOT NULL, message TEXT NOT NULL, url TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reports (
          id INTEGER PRIMARY KEY AUTOINCREMENT, reporter_id INTEGER NOT NULL REFERENCES users(id),
          target_type TEXT NOT NULL, target_id INTEGER NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          resolution TEXT NOT NULL DEFAULT '', handled_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audits (
          id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER REFERENCES users(id),
          action TEXT NOT NULL, subject TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS posts_status_created ON posts(status,created_at);
        CREATE INDEX IF NOT EXISTS replies_post_id ON replies(post_id,status);
        CREATE INDEX IF NOT EXISTS notifications_user_id ON notifications(user_id,is_read);
        CREATE INDEX IF NOT EXISTS reports_status ON reports(status);
        ''')
        if conn.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 0:
            initial = [
              ('GAMC 시작 가이드 · 첫 7일', '가입부터 첫 질문·답변까지 참여 방법을 안내합니다.',
               '1. 프로필에는 가명을 사용할 수 있습니다.\n2. 관심 주제를 선택해 주세요.\n3. 질문·도움 공간에서 궁금한 점을 공유해 보세요.\n4. 동료의 질문에 짧은 도움을 나눠 보세요.\n5. 안전을 위해 실명·정확한 위치·민감한 현장 정보를 게시하지 마세요.',
               '', 'ko','AI Basics','GAMC 운영자료 · 자유 열람','GAMC 초기 운영 가이드'),
              ('현장을 보호하는 게시글 작성법', '민감한 선교·난민·아동 관련 정보를 안전하게 다루는 실무 안내입니다.',
               '질문에 필요한 상황만 설명하세요. 이름·주소·구체적인 이동 경로·허락받지 않은 사진과 대화 기록을 올리지 마세요.\n노출 우려가 생기면 즉시 게시글을 편집하고 운영팀에 신고하세요.\nAI 도구로 정보를 처리할 때에는 외부 전송 여부를 먼저 확인하세요.\n이 안내는 일반적 권고이며 실제 현장 보안 검토를 대체하지 않습니다.',
               '', 'ko','Ethics & Safety','GAMC 운영자료 · 자유 열람','GAMC 안전 설계 원칙'),
              ('How to get started with GAMC', 'A short guide to your first week in the community.',
               '1. Use a display name instead of sharing your identity.\n2. Choose your areas of interest.\n3. Ask a question or help someone else.\n4. Never share confidential field information, precise locations, or personal data without consent.',
               '', 'en','AI Basics','GAMC original guide · free to read','GAMC community onboarding')
            ]
            conn.executemany('''INSERT INTO resources (title,summary,content,url,language,topic,license,source,status,created_at)
                                VALUES (?,?,?,?,?,?,?,?,'published',?)''', [(*r,now()) for r in initial])
        conn.commit()

init_db()


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,390000)
    return 'pbkdf2_sha256$390000$'+base64.b64encode(salt).decode()+'$'+base64.b64encode(digest).decode()


def verify_password(password, encoded):
    try:
        name, rounds, salt, expected = encoded.split('$')
        if name != 'pbkdf2_sha256': return False
        real = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),base64.b64decode(salt),int(rounds))
        return hmac.compare_digest(real,base64.b64decode(expected))
    except Exception: return False


def get_user(request):
    uid = request.session.get('uid')
    if not isinstance(uid,int): return None
    return getone('SELECT * FROM users WHERE id=? AND is_active=1',(uid,))


def csrf(request):
    if 'csrf' not in request.session: request.session['csrf'] = secrets.token_urlsafe(32)
    return request.session['csrf']


def verify_csrf(request, form):
    if not hmac.compare_digest(str(form.get('csrf','')),csrf(request)):
        raise HTTPException(status_code=403, detail='Invalid form security token.')


def flash(request,message,category='info'):
    request.session['flash'] = (str(message)[:240],category)


def go(url='/'):
    return RedirectResponse(url, status_code=303)


def safe_next(url):
    return url if isinstance(url,str) and url.startswith('/') and not url.startswith('//') and not '\\' in url else '/me'


def render(request, template='page.html', status_code=200, **context):
    user = get_user(request)
    locale = request.session.get('locale') or (user['locale'] if user else 'ko')
    if locale not in LANG: locale='ko'
    t=lambda k: LANG[locale].get(k,LANG['ko'].get(k,k))
    unread = getone('SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0',(user['id'],))['c'] if user else 0
    notice = request.session.pop('flash',None)
    state = {'request':request,'user':user,'locale':locale,'t':t,'csrf':csrf(request),'unread':unread,'notice':notice,
             'topics':TOPICS,'spaces':SPACES,'current_path':request.url.path,'brand':'Global AI Mission Community',
             'year':datetime.now().year}
    state.update(context)
    return templates.TemplateResponse(request=request,name=template,context=state,status_code=status_code)


def auth_required(request):
    if not get_user(request): return go('/sign-in?next='+quote(request.url.path,safe='/'))
    return None


def require_admin(request):
    u=get_user(request)
    if not u or u['role'] not in ('admin','moderator'): raise HTTPException(status_code=403,detail='Not authorized')
    return u


def require_owner_admin(request,owner):
    u=get_user(request)
    return u and (u['id']==owner or u['role']=='admin')


def audit(actor, action, subject, note=''):
    execute('INSERT INTO audits (actor_id,action,subject,note,created_at) VALUES (?,?,?,?,?)',(actor,action,subject,note,now()))


def notify(user_id,kind,message,url):
    settings=getone('SELECT notify_replies FROM users WHERE id=? AND is_active=1',(user_id,))
    if not settings or (kind=='reply' and not settings['notify_replies']):return
    execute('INSERT INTO notifications(user_id,kind,message,url,created_at) VALUES (?,?,?,?,?)',(user_id,kind,message,url,now()))


def clamp(value, n=100): return str(value or '').strip()[:n]

def public_https_link(url):
    val=clamp(url,1500)
    return val if re.match(r'^https?://[^\s]+$',val,re.I) else ''


def validate_post(title,body):
    if not (5<=len(title)<=140): return '제목은 5~140자로 작성해 주세요.'
    if not (10<=len(body)<=6000): return '본문은 10~6000자로 작성해 주세요.'
    return None


@app.get('/',response_class=HTMLResponse)
def home(request:Request):
    posts=getall("SELECT p.*,u.display_name, (SELECT COUNT(*) FROM replies r WHERE r.post_id=p.id AND r.status='visible') reply_count FROM posts p JOIN users u ON p.user_id=u.id WHERE p.status='visible' ORDER BY p.created_at DESC LIMIT 4") if get_user(request) else []
    resources=getall("SELECT * FROM resources WHERE status='published' ORDER BY created_at DESC LIMIT 3")
    events=getall("SELECT * FROM events WHERE status='published' AND start_at >= ? ORDER BY start_at LIMIT 2",(now()[:10],))
    return render(request,page='home',posts=posts,resources=resources,events=events,heading='Global AI Mission Community')

@app.get('/about',response_class=HTMLResponse)
def about(request:Request): return render(request,page='about',heading='About GAMC')

@app.get('/join',response_class=HTMLResponse)
def join(request:Request):return render(request,page='join',heading='함께하기 / Join GAMC')

@app.post('/join')
async def join_post(request:Request):
    f=await request.form(); verify_csrf(request,f)
    email=clamp(f.get('email'),240).lower(); name=clamp(f.get('display_name'),42);password=str(f.get('password',''))
    locale=clamp(f.get('locale'),3);locale=locale if locale in LANG else 'ko'
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email) or not 2<=len(name)<=42 or len(password)<10 or len(password)>128 or f.get('agree')!='yes':
        flash(request,'이메일·표시 이름·10자 이상 비밀번호·규칙 동의를 확인해 주세요.','error');return go('/join')
    if getone('SELECT id FROM users WHERE email=?',(email,)):
        flash(request,'이미 가입된 이메일입니다. 로그인해 주세요.','error');return go('/sign-in')
    uid=execute('''INSERT INTO users(email,password_hash,display_name,locale,accepted_terms_at,created_at) VALUES(?,?,?,?,?,?)''',(email,hash_password(password),name,locale,now(),now()))
    request.session.clear();request.session['uid']=uid;request.session['locale']=locale;csrf(request)
    audit(uid,'register','user:'+str(uid))
    flash(request,'가입이 완료되었습니다. 공동체에 오신 것을 환영합니다!','success')
    return go('/welcome')

@app.get('/sign-in',response_class=HTMLResponse)
def sign_in(request:Request):return render(request,page='sign-in',heading='로그인',next=safe_next(request.query_params.get('next','/me')))

@app.post('/sign-in')
async def sign_in_post(request:Request):
    f=await request.form();verify_csrf(request,f)
    user=getone('SELECT * FROM users WHERE email=? AND is_active=1',(clamp(f.get('email'),240).lower(),))
    if not user or not verify_password(str(f.get('password','')),user['password_hash']):
        flash(request,'이메일 또는 비밀번호가 일치하지 않습니다.','error');return go('/sign-in')
    request.session.clear();request.session['uid']=user['id'];request.session['locale']=user['locale'];csrf(request)
    flash(request,'반갑습니다, '+user['display_name']+'님!','success')
    return go(safe_next(f.get('next','/me')))

@app.post('/sign-out')
async def sign_out(request:Request):
    f=await request.form();verify_csrf(request,f);request.session.clear();return go('/')

@app.post('/language')
async def language_post(request:Request):
    f=await request.form();verify_csrf(request,f)
    v=clamp(f.get('locale'),3)
    if v in LANG: request.session['locale']=v
    return go(safe_next(f.get('return_to','/')))

@app.get('/welcome',response_class=HTMLResponse)
def welcome(request:Request):
    a=auth_required(request)
    if a:return a
    return render(request,page='welcome',heading='GAMC 시작하기')

@app.post('/welcome')
async def welcome_post(request:Request):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request)
    interests=','.join([x for x in f.getlist('interests') if x in TOPICS][:5])
    execute('UPDATE users SET interests=?,onboarded=1 WHERE id=?',(interests,u['id']))
    flash(request,'시작 준비를 마쳤습니다. 첫 질문을 찾아보세요.','success')
    return go('/community/help')


def list_posts(request,space=None):
    a=auth_required(request)
    if a:return a
    u=get_user(request)
    query="""SELECT p.*,u.display_name, (SELECT COUNT(*) FROM replies r WHERE r.post_id=p.id AND r.status='visible') reply_count
            FROM posts p JOIN users u ON u.id=p.user_id WHERE p.status='visible'"""
    vals=[]
    if space:
        query+=' AND p.space=?';vals.append(space)
    status=request.query_params.get('status','all')
    if status=='solved':query+=' AND p.solved_reply_id IS NOT NULL'
    elif status=='open':query+=' AND p.solved_reply_id IS NULL'
    tag=request.query_params.get('tag','')
    if tag in TOPICS:query+=' AND p.tag=?';vals.append(tag)
    query+=' ORDER BY p.created_at DESC LIMIT 100'
    return render(request,page='community',heading='Community',posts=getall(query,vals),space=space or 'all',status=status,selected_tag=tag)

@app.get('/community',response_class=HTMLResponse)
def community(request:Request):return list_posts(request)

@app.get('/community/{space}',response_class=HTMLResponse)
def community_space(request:Request,space:str):
    if space == 'new': return new_post(request)
    if space not in SPACES:raise HTTPException(status_code=404)
    return list_posts(request,space)

@app.get('/community/new',response_class=HTMLResponse)
def new_post(request:Request):
    a=auth_required(request)
    if a:return a
    return render(request,page='compose',heading='새 글 작성',post=None)

@app.post('/community/new')
async def new_post_post(request:Request):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request)
    space=clamp(f.get('space'),20);space=space if space in SPACES else 'help'
    title=clamp(f.get('title'),140);body=clamp(f.get('body'),6001)
    error=validate_post(title,body)
    if error:flash(request,error,'error');return go('/community/new')
    tag=clamp(f.get('tag'),60);tag=tag if tag in TOPICS else TOPICS[0]
    language=clamp(f.get('language'),3);language=language if language in ('ko','en','ru','ar') else 'ko'
    ident=execute('INSERT INTO posts(user_id,space,title,body,tag,language,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',(u['id'],space,title,body,tag,language,now(),now()))
    audit(u['id'],'create_post','post:'+str(ident));flash(request,'게시글을 등록했습니다. 답변이 달리면 사이트에서 알려드립니다.','success')
    return go('/community/t/'+str(ident))


def fetch_post(post_id):
    return getone('''SELECT p.*,u.display_name,u.is_active FROM posts p JOIN users u ON p.user_id=u.id WHERE p.id=?''',(post_id,))

@app.get('/community/t/{post_id}',response_class=HTMLResponse)
def post_detail(request:Request,post_id:int):
    a=auth_required(request)
    if a:return a
    p=fetch_post(post_id)
    if not p or (p['status']!='visible' and not require_owner_admin(request,p['user_id'])):raise HTTPException(status_code=404)
    replies=getall('''SELECT r.*,u.display_name FROM replies r JOIN users u ON r.user_id=u.id WHERE r.post_id=? AND r.status='visible' ORDER BY r.created_at''',(post_id,))
    return render(request,page='topic',heading=p['title'],post=p,replies=replies,can_edit=bool(require_owner_admin(request,p['user_id'])))

@app.post('/community/t/{post_id}/reply')
async def reply_post(request:Request,post_id:int):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request);p=fetch_post(post_id)
    if not p or p['status']!='visible':raise HTTPException(status_code=404)
    body=clamp(f.get('body'),4001)
    if len(body)<5 or len(body)>4000:flash(request,'답변은 5~4000자로 작성해 주세요.','error');return go('/community/t/'+str(post_id))
    rid=execute('INSERT INTO replies(post_id,user_id,body,created_at) VALUES(?,?,?,?)',(post_id,u['id'],body,now()))
    if p['user_id']!=u['id']:notify(p['user_id'],'reply','나의 질문에 새 답변이 달렸습니다: '+p['title'],'/community/t/'+str(post_id))
    audit(u['id'],'create_reply','reply:'+str(rid))
    flash(request,'답변을 남겼습니다. 감사합니다!','success');return go('/community/t/'+str(post_id)+'#replies')

@app.post('/community/t/{post_id}/solve')
async def solve_post(request:Request,post_id:int):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request);p=fetch_post(post_id)
    if not p or p['status']!='visible':raise HTTPException(status_code=404)
    if not require_owner_admin(request,p['user_id']):raise HTTPException(status_code=403)
    rid=clamp(f.get('reply_id'),20)
    reply=getone("SELECT * FROM replies WHERE id=? AND post_id=? AND status='visible'",(rid,post_id)) if rid.isdigit() else None
    if not reply:raise HTTPException(status_code=400,detail='Invalid answer')
    chosen=None if p['solved_reply_id']==reply['id'] else reply['id']
    execute('UPDATE posts SET solved_reply_id=?,updated_at=? WHERE id=?',(chosen,now(),post_id))
    if chosen and reply['user_id']!=u['id']:notify(reply['user_id'],'solved','작성자가 나의 답변을 해결 답변으로 선택했습니다.','/community/t/'+str(post_id))
    audit(u['id'],'mark_solved','post:'+str(post_id),str(chosen))
    flash(request,'해결 상태를 변경했습니다.','success');return go('/community/t/'+str(post_id))

@app.get('/community/t/{post_id}/edit',response_class=HTMLResponse)
def edit_post(request:Request,post_id:int):
    a=auth_required(request)
    if a:return a
    p=fetch_post(post_id)
    if not p or not require_owner_admin(request,p['user_id']):raise HTTPException(status_code=403)
    return render(request,page='compose',heading='글 수정',post=p)

@app.post('/community/t/{post_id}/edit')
async def edit_post_post(request:Request,post_id:int):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request);p=fetch_post(post_id)
    if not p or not require_owner_admin(request,p['user_id']):raise HTTPException(status_code=403)
    title=clamp(f.get('title'),140);body=clamp(f.get('body'),6001)
    err=validate_post(title,body)
    if err:flash(request,err,'error');return go('/community/t/'+str(post_id)+'/edit')
    tag=clamp(f.get('tag'),60);tag=tag if tag in TOPICS else TOPICS[0]
    execute('UPDATE posts SET title=?,body=?,tag=?,updated_at=? WHERE id=?',(title,body,tag,now(),post_id))
    audit(u['id'],'edit_post','post:'+str(post_id));flash(request,'수정했습니다.','success');return go('/community/t/'+str(post_id))

@app.post('/community/t/{post_id}/delete')
async def delete_post(request:Request,post_id:int):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request);p=fetch_post(post_id)
    if not p or not require_owner_admin(request,p['user_id']):raise HTTPException(status_code=403)
    execute("UPDATE posts SET status='deleted',updated_at=? WHERE id=?",(now(),post_id))
    audit(u['id'],'delete_post','post:'+str(post_id));flash(request,'글을 삭제 처리했습니다.','success');return go('/community')

@app.get('/search',response_class=HTMLResponse)
def search(request:Request):
    q=clamp(request.query_params.get('q',''),120)
    pat='%'+q.replace('%','\\%').replace('_','\\_')+'%'
    posts=[]
    if get_user(request) and q:
        posts=getall("""SELECT p.id,p.title,p.tag,p.space,p.created_at,p.solved_reply_id,u.display_name FROM posts p JOIN users u ON p.user_id=u.id
            WHERE p.status='visible' AND (p.title LIKE ? ESCAPE '\\' OR p.body LIKE ? ESCAPE '\\' OR p.tag LIKE ? ESCAPE '\\') ORDER BY p.created_at DESC LIMIT 30""",(pat,pat,pat))
    resources=getall("SELECT * FROM resources WHERE status='published' AND (title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\' OR topic LIKE ? ESCAPE '\\') LIMIT 20",(pat,pat,pat)) if q else []
    events=getall("SELECT * FROM events WHERE status='published' AND (title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\') LIMIT 12",(pat,pat)) if q else []
    projects=getall("SELECT * FROM projects WHERE status IN ('open','closed') AND (title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\') LIMIT 12",(pat,pat)) if q else []
    return render(request,page='search',heading='검색',q=q,posts=posts,resources=resources,events=events,projects=projects)

@app.get('/resources',response_class=HTMLResponse)
def resources(request:Request):
    lang=request.query_params.get('lang','all');tag=request.query_params.get('tag','all')
    query="SELECT * FROM resources WHERE status='published'";params=[]
    if lang in ('ko','en','ru','ar'):query+=' AND language=?';params.append(lang)
    if tag in TOPICS:query+=' AND topic=?';params.append(tag)
    query+=' ORDER BY created_at DESC LIMIT 100'
    return render(request,page='resources',heading='Resources',resources=getall(query,params),lang=lang,tag=tag)

@app.get('/resources/{rid}',response_class=HTMLResponse)
def resource_detail(request:Request,rid:int):
    r=getone("SELECT * FROM resources WHERE id=? AND status='published'",(rid,))
    if not r:raise HTTPException(status_code=404)
    return render(request,page='resource',heading=r['title'],resource=r)

@app.get('/events',response_class=HTMLResponse)
def events(request:Request):
    ev=getall("SELECT e.*, (SELECT COUNT(*) FROM rsvps WHERE event_id=e.id) rsvp_count FROM events e WHERE e.status='published' ORDER BY start_at LIMIT 100")
    return render(request,page='events',heading='Events',events=ev)

@app.get('/events/{eid}',response_class=HTMLResponse)
def event_detail(request:Request,eid:int):
    e=getone("SELECT e.*, (SELECT COUNT(*) FROM rsvps WHERE event_id=e.id) rsvp_count FROM events e WHERE e.id=? AND e.status='published'",(eid,))
    if not e:raise HTTPException(status_code=404)
    u=get_user(request)
    joined=bool(getone('SELECT id FROM rsvps WHERE event_id=? AND user_id=?',(eid,u['id']))) if u else False
    try:
        utc_start=datetime.fromisoformat(e['start_at']).replace(tzinfo=ZoneInfo(e['timezone'])).astimezone(timezone.utc).isoformat()
    except (ValueError, ZoneInfoNotFoundError):
        utc_start=''
    return render(request,page='event',heading=e['title'],event=e,joined=joined,utc_start=utc_start)

@app.post('/events/{eid}/rsvp')
async def event_rsvp(request:Request,eid:int):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request)
    ev=getone("SELECT * FROM events WHERE id=? AND status='published'",(eid,))
    if not ev:raise HTTPException(status_code=404)
    if getone('SELECT id FROM rsvps WHERE event_id=? AND user_id=?',(eid,u['id'])):
        execute('DELETE FROM rsvps WHERE event_id=? AND user_id=?',(eid,u['id']))
        flash(request,'행사 참석 신청을 취소했습니다.','success')
    else:
        count=getone('SELECT COUNT(*) n FROM rsvps WHERE event_id=?',(eid,))['n']
        if ev['capacity'] and count>=ev['capacity']:
            flash(request,'행사 신청 인원이 가득 찼습니다.','error');return go('/events/'+str(eid))
        execute('INSERT OR IGNORE INTO rsvps(event_id,user_id,created_at) VALUES (?,?,?)',(eid,u['id'],now()))
        notify(u['id'],'event','행사 참석 신청이 접수되었습니다: '+ev['title'],'/events/'+str(eid))
        flash(request,'행사 참석 신청이 접수되었습니다.','success')
    return go('/events/'+str(eid))

@app.get('/projects',response_class=HTMLResponse)
def projects(request:Request):
    pro=getall("SELECT * FROM projects WHERE status IN ('open','closed') ORDER BY created_at DESC LIMIT 100")
    return render(request,page='projects',heading='Projects',projects=pro)

@app.get('/projects/{pid}',response_class=HTMLResponse)
def project_detail(request:Request,pid:int):
    p=getone("SELECT * FROM projects WHERE id=? AND status IN ('open','closed')",(pid,))
    if not p:raise HTTPException(status_code=404)
    u=get_user(request);application=getone('SELECT * FROM project_apps WHERE project_id=? AND user_id=?',(pid,u['id'])) if u else None
    return render(request,page='project',heading=p['title'],project=p,application=application)

@app.post('/projects/{pid}/apply')
async def project_apply(request:Request,pid:int):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request);p=getone("SELECT * FROM projects WHERE id=? AND status='open'",(pid,))
    if not p:raise HTTPException(status_code=404)
    why=clamp(f.get('why'),900)
    if len(why)<10:flash(request,'참여 의사를 10자 이상 작성해 주세요.','error');return go('/projects/'+str(pid))
    if not getone('SELECT id FROM project_apps WHERE project_id=? AND user_id=?',(pid,u['id'])):
        execute('INSERT INTO project_apps(project_id,user_id,why,created_at) VALUES(?,?,?,?)',(pid,u['id'],why,now()))
        audit(u['id'],'apply_project','project:'+str(pid))
        for admin in getall("SELECT id FROM users WHERE role='admin' AND is_active=1"):
            notify(admin['id'],'project','새 프로젝트 참여 요청: '+p['title'],'/admin/projects')
    flash(request,'참여 의사가 운영팀에 접수되었습니다. 승인 전에는 연락처가 공유되지 않습니다.','success')
    return go('/projects/'+str(pid))

@app.get('/me',response_class=HTMLResponse)
def my_space(request:Request):
    a=auth_required(request)
    if a:return a
    u=get_user(request)
    mine=getall("SELECT p.*, (SELECT COUNT(*) FROM replies r WHERE r.post_id=p.id AND r.status='visible') reply_count FROM posts p WHERE user_id=? AND status='visible' ORDER BY created_at DESC LIMIT 8",(u['id'],))
    replies=getall("SELECT r.id,r.post_id,p.title,r.created_at FROM replies r JOIN posts p ON r.post_id=p.id WHERE r.user_id=? AND r.status='visible' ORDER BY r.created_at DESC LIMIT 8",(u['id'],))
    app=getall("SELECT a.*,p.title FROM project_apps a JOIN projects p ON a.project_id=p.id WHERE a.user_id=? ORDER BY a.created_at DESC",(u['id'],))
    return render(request,page='me',heading='내 공간',mine=mine,replies=replies,applications=app)

@app.get('/me/profile',response_class=HTMLResponse)
def my_profile(request:Request):
    a=auth_required(request)
    if a:return a
    return render(request,page='profile',heading='프로필 수정')

@app.post('/me/profile')
async def profile_post(request:Request):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request)
    name=clamp(f.get('display_name'),42);intro=clamp(f.get('intro'),420)
    if len(name)<2:flash(request,'표시 이름은 2자 이상이어야 합니다.','error');return go('/me/profile')
    language=clamp(f.get('locale'),3);language=language if language in LANG else u['locale']
    interests=','.join([i for i in f.getlist('interests') if i in TOPICS][:5])
    execute('UPDATE users SET display_name=?,intro=?,locale=?,interests=?,profile_visible=? WHERE id=?',(name,intro,language,interests,1 if f.get('profile_visible')=='1' else 0,u['id']))
    request.session['locale']=language
    flash(request,'프로필이 저장되었습니다.','success');return go('/me/profile')

@app.get('/me/notifications',response_class=HTMLResponse)
def notifications(request:Request):
    a=auth_required(request)
    if a:return a
    u=get_user(request);n=getall('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100',(u['id'],))
    return render(request,page='notifications',heading='알림',notifications=n)

@app.post('/me/notifications/read')
async def read_notifications(request:Request):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f)
    execute('UPDATE notifications SET is_read=1 WHERE user_id=?',(get_user(request)['id'],))
    flash(request,'알림을 모두 확인했습니다.','success');return go('/me/notifications')

@app.get('/me/preferences',response_class=HTMLResponse)
def preferences(request:Request):
    a=auth_required(request)
    if a:return a
    return render(request,page='preferences',heading='알림 환경설정')

@app.post('/me/preferences')
async def preferences_post(request:Request):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f)
    execute('UPDATE users SET notify_replies=? WHERE id=?',(1 if f.get('notify_replies')=='1' else 0,get_user(request)['id']))
    flash(request,'환경설정이 저장되었습니다.','success');return go('/me/preferences')

@app.get('/me/account',response_class=HTMLResponse)
def account(request:Request):
    a=auth_required(request)
    if a:return a
    return render(request,page='account',heading='계정 관리')

@app.post('/me/account/password')
async def password_change(request:Request):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request)
    if not verify_password(str(f.get('old_password','')),u['password_hash']):flash(request,'현재 비밀번호가 일치하지 않습니다.','error')
    elif not 10<=len(str(f.get('new_password','')))<=128:flash(request,'새 비밀번호는 10자 이상으로 작성해 주세요.','error')
    else:
        execute('UPDATE users SET password_hash=? WHERE id=?',(hash_password(str(f.get('new_password'))),u['id']))
        audit(u['id'],'change_password','user:'+str(u['id']))
        flash(request,'비밀번호를 변경했습니다.','success')
    return go('/me/account')

@app.post('/me/account/delete')
async def delete_account(request:Request):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request)
    if f.get('confirm')!='DELETE' or not verify_password(str(f.get('password','')),u['password_hash']):
        flash(request,'DELETE 문구와 현재 비밀번호를 확인해 주세요.','error');return go('/me/account')
    with db() as conn:
        conn.execute("UPDATE posts SET status='deleted',body='[removed]' WHERE user_id=?",(u['id'],))
        conn.execute("UPDATE replies SET status='deleted',body='[removed]' WHERE user_id=?",(u['id'],))
        conn.execute('DELETE FROM notifications WHERE user_id=?',(u['id'],))
        conn.execute('DELETE FROM rsvps WHERE user_id=?',(u['id'],))
        conn.execute('DELETE FROM project_apps WHERE user_id=?',(u['id'],))
        conn.execute("UPDATE users SET email=?, password_hash='',display_name='탈퇴 회원',intro='',interests='',profile_visible=0,is_active=0 WHERE id=?",('deleted_'+str(u['id'])+'_'+secrets.token_hex(5)+'@invalid.local',u['id']))
        conn.execute('INSERT INTO audits(actor_id,action,subject,created_at) VALUES(?,?,?,?)',(u['id'],'delete_account','user:'+str(u['id']),now()))
        conn.commit()
    request.session.clear();return go('/')

@app.get('/guidelines',response_class=HTMLResponse)
def guidelines(request:Request):return render(request,page='policy',heading='커뮤니티 규칙',policy='guidelines')

@app.get('/privacy',response_class=HTMLResponse)
def privacy(request:Request):return render(request,page='policy',heading='개인정보 안내',policy='privacy')

@app.get('/safety',response_class=HTMLResponse)
def safety(request:Request):return render(request,page='policy',heading='현장 안전',policy='safety')

@app.get('/help',response_class=HTMLResponse)
def help_center(request:Request):return render(request,page='policy',heading='도움말',policy='help')

@app.get('/report/{kind}/{target_id}',response_class=HTMLResponse)
def report_view(request:Request,kind:str,target_id:int):
    a=auth_required(request)
    if a:return a
    if kind not in ('post','reply'):raise HTTPException(status_code=404)
    exists=getone('SELECT id FROM posts WHERE id=?',(target_id,)) if kind=='post' else getone('SELECT id FROM replies WHERE id=?',(target_id,))
    if not exists:raise HTTPException(status_code=404)
    return render(request,page='report',heading='콘텐츠 신고',target_kind=kind,target_id=target_id)

@app.post('/report/{kind}/{target_id}')
async def report_post(request:Request,kind:str,target_id:int):
    a=auth_required(request)
    if a:return a
    f=await request.form();verify_csrf(request,f);u=get_user(request)
    if kind not in ('post','reply'):raise HTTPException(status_code=404)
    exists=getone('SELECT id FROM posts WHERE id=?',(target_id,)) if kind=='post' else getone('SELECT id FROM replies WHERE id=?',(target_id,))
    if not exists:raise HTTPException(status_code=404)
    reason=clamp(f.get('reason'),1100)
    if len(reason)<10:flash(request,'신고 사유를 10자 이상 작성해 주세요.','error');return go('/report/'+kind+'/'+str(target_id))
    ident=execute('INSERT INTO reports(reporter_id,target_type,target_id,reason,created_at) VALUES(?,?,?,?,?)',(u['id'],kind,target_id,reason,now()))
    audit(u['id'],'report','report:'+str(ident))
    flash(request,'신고가 접수되었습니다. 운영팀이 검토합니다.','success');return go('/me')

@app.get('/admin',response_class=HTMLResponse)
def admin_home(request:Request):
    require_admin(request)
    count=lambda q: getone(q)['n']
    metrics={'members':count('SELECT COUNT(*) n FROM users WHERE is_active=1'),
             'pending':count("SELECT COUNT(*) n FROM reports WHERE status='pending'"),
             'unanswered':count("SELECT COUNT(*) n FROM posts p WHERE p.status='visible' AND NOT EXISTS (SELECT 1 FROM replies r WHERE r.post_id=p.id AND r.status='visible')"),
             'solved':count("SELECT COUNT(*) n FROM posts WHERE status='visible' AND solved_reply_id IS NOT NULL")}
    return render(request,page='admin',heading='운영 관리',section='overview',metrics=metrics)

@app.get('/admin/reports',response_class=HTMLResponse)
def admin_reports(request:Request):
    require_admin(request)
    reports=getall('''SELECT r.*,u.display_name AS reporter,m.display_name AS handler FROM reports r JOIN users u ON u.id=r.reporter_id LEFT JOIN users m ON m.id=r.handled_by ORDER BY r.created_at DESC LIMIT 100''')
    return render(request,page='admin',heading='신고 관리',section='reports',reports=reports)

@app.post('/admin/reports/{rid}')
async def report_action(request:Request,rid:int):
    u=require_admin(request)
    f=await request.form();verify_csrf(request,f);r=getone('SELECT * FROM reports WHERE id=?',(rid,))
    if not r:raise HTTPException(status_code=404)
    action=clamp(f.get('action'),20);resolution=clamp(f.get('resolution'),300)
    if action in ('resolve','dismiss'):
        execute('UPDATE reports SET status=?,resolution=?,handled_by=? WHERE id=?',('resolved' if action=='resolve' else 'dismissed',resolution,u['id'],rid))
        audit(u['id'],'review_report','report:'+str(rid),action)
    elif action=='hide' and r['target_type'] in ('post','reply'):
        table='posts' if r['target_type']=='post' else 'replies'
        execute(f"UPDATE {table} SET status='hidden' WHERE id=? AND status='visible'",(r['target_id'],))
        execute("UPDATE reports SET status='resolved',resolution=?,handled_by=? WHERE id=?",(resolution or 'Content hidden',u['id'],rid))
        audit(u['id'],'hide_content',r['target_type']+':'+str(r['target_id']))
    flash(request,'신고 처리 결과가 저장되었습니다.','success');return go('/admin/reports')

@app.get('/admin/content',response_class=HTMLResponse)
def admin_content(request:Request):
    require_admin(request)
    resources=getall('SELECT * FROM resources ORDER BY created_at DESC LIMIT 100')
    events=getall('SELECT * FROM events ORDER BY created_at DESC LIMIT 100')
    projects=getall('SELECT * FROM projects ORDER BY created_at DESC LIMIT 100')
    posts=getall('''SELECT p.*,u.display_name FROM posts p JOIN users u ON p.user_id=u.id ORDER BY p.created_at DESC LIMIT 50''')
    return render(request,page='admin',heading='콘텐츠 관리',section='content',resources=resources,events=events,projects=projects,posts=posts)

@app.post('/admin/content/create')
async def admin_create(request:Request):
    u=require_admin(request)
    if u['role']!='admin':raise HTTPException(status_code=403)
    f=await request.form();verify_csrf(request,f)
    kind=clamp(f.get('kind'),20);title=clamp(f.get('title'),140);summary=clamp(f.get('summary'),350);content=clamp(f.get('content'),8000)
    if len(title)<4 or len(summary)<5:flash(request,'제목과 요약을 확인해 주세요.','error');return go('/admin/content')
    if kind=='resource':
        language=clamp(f.get('language'),3);language=language if language in ('ko','en','ru','ar') else 'ko'
        topic=clamp(f.get('topic'),60);topic=topic if topic in TOPICS else 'AI Basics'
        rid=execute('INSERT INTO resources(title,summary,content,url,language,topic,license,source,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
          (title,summary,content,public_https_link(f.get('url')),language,topic,clamp(f.get('license'),120) or '저작권 확인 필요',clamp(f.get('source'),140) or '운영팀 등록',now()))
    elif kind=='event':
        start=clamp(f.get('start_at'),32)
        if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d',start):flash(request,'행사 시작 날짜와 시간을 입력해 주세요.','error');return go('/admin/content')
        capacity=clamp(f.get('capacity'),6);capacity=int(capacity) if capacity.isdigit() else 0
        zone=clamp(f.get('timezone'),50) or 'Asia/Seoul'
        try: ZoneInfo(zone)
        except ZoneInfoNotFoundError:
            flash(request,'유효한 IANA 시간대를 입력해 주세요. 예: Asia/Seoul','error');return go('/admin/content')
        rid=execute('INSERT INTO events(title,summary,content,start_at,timezone,location,url,capacity,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
          (title,summary,content,start,zone,clamp(f.get('location'),100) or 'Online',public_https_link(f.get('url')),capacity,now()))
    elif kind=='project':
        rid=execute('INSERT INTO projects(title,summary,content,skills,language,created_at) VALUES(?,?,?,?,?,?)',
          (title,summary,content,clamp(f.get('skills'),160),clamp(f.get('language'),3) or 'ko',now()))
    else:raise HTTPException(status_code=400)
    audit(u['id'],'create_'+kind,kind+':'+str(rid));flash(request,'콘텐츠를 공개했습니다.','success');return go('/admin/content')

@app.post('/admin/content/{kind}/{rid}/toggle')
async def admin_toggle(request:Request,kind:str,rid:int):
    u=require_admin(request)
    if u['role']!='admin':raise HTTPException(status_code=403)
    f=await request.form();verify_csrf(request,f)
    tab={'resource':'resources','event':'events','project':'projects','post':'posts'}.get(kind)
    if not tab:raise HTTPException(status_code=404)
    row=getone(f'SELECT * FROM {tab} WHERE id=?',(rid,))
    if not row:raise HTTPException(status_code=404)
    if kind=='project':status='closed' if row['status']=='open' else 'open'
    elif kind=='post':status='hidden' if row['status']=='visible' else 'visible'
    else:status='hidden' if row['status']=='published' else 'published'
    execute(f'UPDATE {tab} SET status=? WHERE id=?',(status,rid))
    audit(u['id'],'toggle_content',kind+':'+str(rid),status);flash(request,'상태를 변경했습니다.','success')
    return go('/admin/content')

@app.get('/admin/projects',response_class=HTMLResponse)
def admin_applications(request:Request):
    require_admin(request)
    apps=getall('''SELECT a.*,p.title AS project_title,u.display_name,u.email FROM project_apps a JOIN projects p ON p.id=a.project_id JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 200''')
    return render(request,page='admin',heading='프로젝트 참여 요청',section='applications',applications=apps)

@app.post('/admin/projects/{aid}')
async def admin_application_action(request:Request,aid:int):
    u=require_admin(request)
    f=await request.form();verify_csrf(request,f)
    action=clamp(f.get('action'),20)
    if action not in ('approved','declined'):raise HTTPException(status_code=400)
    ap=getone('SELECT * FROM project_apps WHERE id=?',(aid,))
    if not ap:raise HTTPException(status_code=404)
    execute('UPDATE project_apps SET status=? WHERE id=?',(action,aid))
    notify(ap['user_id'],'project','프로젝트 참여 요청 상태가 변경되었습니다: '+('승인' if action=='approved' else '미선정'),'/me')
    audit(u['id'],'review_project_application','application:'+str(aid),action)
    flash(request,'신청 처리 결과가 저장되었습니다.','success');return go('/admin/projects')

@app.get('/admin/members',response_class=HTMLResponse)
def admin_members(request:Request):
    u=require_admin(request)
    if u['role']!='admin':raise HTTPException(status_code=403)
    members=getall('SELECT * FROM users ORDER BY created_at DESC LIMIT 150')
    return render(request,page='admin',heading='회원 관리',section='members',members=members)

@app.post('/admin/members/{uid}/role')
async def admin_role(request:Request,uid:int):
    u=require_admin(request)
    if u['role']!='admin':raise HTTPException(status_code=403)
    f=await request.form();verify_csrf(request,f)
    role=clamp(f.get('role'),20)
    if role not in ('member','moderator','admin') or uid==u['id']:raise HTTPException(status_code=400)
    execute('UPDATE users SET role=? WHERE id=? AND is_active=1',(role,uid));audit(u['id'],'change_role','user:'+str(uid),role)
    flash(request,'회원 역할을 변경했습니다.','success');return go('/admin/members')

@app.get('/admin/audit',response_class=HTMLResponse)
def admin_audit(request:Request):
    u=require_admin(request)
    if u['role']!='admin':raise HTTPException(status_code=403)
    logs=getall('''SELECT a.*,u.display_name FROM audits a LEFT JOIN users u ON a.actor_id=u.id ORDER BY a.id DESC LIMIT 200''')
    return render(request,page='admin',heading='감사 기록',section='audit',logs=logs)

@app.get('/admin/insights',response_class=HTMLResponse)
def admin_insights(request:Request):
    require_admin(request)
    activity=getall('''SELECT substr(created_at,1,10) day, COUNT(*) n FROM posts WHERE status='visible' AND created_at >= date('now','-30 day') GROUP BY day ORDER BY day''')
    helpful=getone('''SELECT COUNT(DISTINCT user_id) n FROM (SELECT user_id FROM replies WHERE status='visible' AND created_at >= date('now','-30 day') UNION ALL SELECT user_id FROM posts WHERE status='visible' AND solved_reply_id IS NOT NULL AND created_at >= date('now','-30 day'))''')['n']
    return render(request,page='admin',heading='커뮤니티 건강 지표',section='insights',activity=activity,helpful=helpful)

@app.exception_handler(HTTPException)
async def http_error(request,exc):
    if exc.status_code in (403,404):
        return render(request,page='error',heading='접근할 수 없습니다',status_code=exc.status_code,error_code=exc.status_code)
    return PlainTextResponse(str(exc.detail),status_code=exc.status_code)

if __name__=='__main__':
    import uvicorn
    uvicorn.run(app,host=os.getenv('GAMC_HOST','127.0.0.1'),port=int(os.getenv('GAMC_PORT','8000')))
