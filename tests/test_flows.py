"""Integration smoke tests for the user-critical pilot flows."""
import os
import re
import tempfile
from pathlib import Path

# Import after setting isolated database; no real user's data is touched.
os.environ['GAMC_DATA_DIR'] = tempfile.mkdtemp(prefix='gamc_test_')
from fastapi.testclient import TestClient
from app import app, execute, getone, hash_password, now


def token(page):
    found=re.search(r'name="csrf" value="([^"]+)"',page.text)
    assert found, page.text[:800]
    return found.group(1)


def register(client,email,name):
    t=token(client.get('/join'))
    r=client.post('/join',data={'csrf':t,'display_name':name,'email':email,'password':'safePassword2094!','locale':'ko','agree':'yes'},follow_redirects=False)
    assert r.status_code==303
    assert r.headers['location']=='/welcome'
    return getone('SELECT * FROM users WHERE email=?',(email,))


def admin_account():
    mail='operator@local.invalid'
    if getone('SELECT id FROM users WHERE email=?',(mail,)):
        return
    execute("INSERT INTO users(email,password_hash,display_name,role,onboarded,accepted_terms_at,created_at) VALUES(?,?,?,'admin',1,?,?)",
            (mail,hash_password('adminSecurePassword12!'),'Community Admin',now(),now()))


def sign_in(client,email,password):
    r=client.get('/sign-in')
    data={'csrf':token(r),'email':email,'password':password,'next':'/me'}
    r=client.post('/sign-in',data=data,follow_redirects=False)
    assert r.status_code==303


def test_full_community_flow():
    owner=TestClient(app)
    other=TestClient(app)
    guest=TestClient(app)
    assert guest.get('/community',follow_redirects=False).status_code==303
    assert guest.get('/community/t/123',follow_redirects=False).status_code==303
    user=register(owner,'first@example.org','첫 질문자')
    other_user=register(other,'helper@example.org','도움 주는 회원')

    # Onboarding and profile privacy are persistent
    welcome=owner.get('/welcome')
    r=owner.post('/welcome',data={'csrf':token(welcome),'interests':['Translation','AI Basics']},follow_redirects=False)
    assert r.headers['location']=='/community/help'
    assert getone('SELECT onboarded FROM users WHERE id=?',(user['id'],))['onboarded']==1
    # Add forum question
    compose=owner.get('/community/new')
    r=owner.post('/community/new',data={'csrf':token(compose),'title':'AI 자막 안전 가이드가 필요합니다','body':'가명을 사용하는 온라인 강의에서 안전하게 AI 자막을 설정하는 방법이 궁금합니다.','space':'help','tag':'Translation','language':'ko'},follow_redirects=False)
    assert r.status_code==303
    post_url=r.headers['location']; assert post_url.startswith('/community/t/')
    postid=int(post_url.split('/')[-1]); assert getone('SELECT * FROM posts WHERE id=?',(postid,))['tag']=='Translation'
    assert guest.get('/search?q=자막').text.find('AI 자막 안전 가이드가 필요합니다')==-1
    assert 'AI 자막 안전 가이드가 필요합니다' in other.get('/search?q=자막').text
    assert 'AI 자막 안전 가이드가 필요합니다' in other.get(post_url).text
    # Another member answers and owner sees notification
    r=other.post(post_url+'/reply',data={'csrf':token(other.get(post_url)),'body':'먼저 자막 입력 언어를 확인하고 개인정보를 포함하지 않은 예시로 테스트해 보세요.'},follow_redirects=False)
    assert r.status_code==303
    rid=getone('SELECT id FROM replies WHERE post_id=?',(postid,))['id']
    assert '나의 질문에 새 답변이 달렸습니다' in owner.get('/me/notifications').text
    # Non-author cannot mark solved
    assert other.post(post_url+'/solve',data={'csrf':token(other.get(post_url)),'reply_id':str(rid)}).status_code==403
    # Author marks solution
    r=owner.post(post_url+'/solve',data={'csrf':token(owner.get(post_url)),'reply_id':str(rid)},follow_redirects=False)
    assert r.status_code==303
    assert getone('SELECT solved_reply_id FROM posts WHERE id=?',(postid,))['solved_reply_id']==rid
    assert '해결 답변' in owner.get(post_url).text
    # Persist across new login (separate session with same database)
    session_again=TestClient(app)
    sign_in(session_again,'first@example.org','safePassword2094!')
    assert 'AI 자막 안전 가이드가 필요합니다' in session_again.get(post_url).text

    # Report from a third party is received privately by moderation queue
    rr=other.get('/report/post/'+str(postid))
    r=other.post('/report/post/'+str(postid),data={'csrf':token(rr),'reason':'민감한 정보가 있는지 확인이 필요합니다.'},follow_redirects=False)
    assert r.status_code==303
    assert '민감한 정보가 있는지' not in owner.get(post_url).text
    assert getone('SELECT COUNT(*) n FROM reports')['n']>=1


def test_admin_resources_events_projects_and_permissions():
    admin_account()
    admin=TestClient(app);member=TestClient(app);visitor=TestClient(app)
    sign_in(admin,'operator@local.invalid','adminSecurePassword12!')
    member_row=register(member,'newperson@example.org','새로운 참여자')
    assert member.get('/admin').status_code==403
    assert visitor.get('/admin/content').status_code==403
    # Admin creates event, with timezone and real registration
    r=admin.post('/admin/content/create',data={
        'csrf':token(admin.get('/admin/content')),'kind':'event','title':'테스트 전용 모임 2027',
        'summary':'통합 테스트 중에 만드는 시연용 모임','content':'행사내용 테스트',
        'start_at':'2027-02-05T20:00','timezone':'Asia/Seoul','capacity':'5','location':'Online'
    },follow_redirects=False)
    assert r.status_code==303
    eid=getone("SELECT id FROM events WHERE title='테스트 전용 모임 2027'")['id']
    assert '테스트 전용 모임' in visitor.get('/events').text
    event_page=member.get(f'/events/{eid}')
    assert '나의 현지 시간' not in event_page.text  # browser inserts this on load
    assert 'data-utc=' in event_page.text
    r=member.post(f'/events/{eid}/rsvp',data={'csrf':token(event_page)},follow_redirects=False)
    assert r.status_code==303
    assert getone('SELECT COUNT(*) n FROM rsvps WHERE event_id=?',(eid,))['n']==1
    r=member.post(f'/events/{eid}/rsvp',data={'csrf':token(member.get(f'/events/{eid}'))},follow_redirects=False)
    assert r.status_code==303
    assert getone('SELECT COUNT(*) n FROM rsvps WHERE event_id=?',(eid,))['n']==0
    # Admin creates project, member applies, admin approves
    r=admin.post('/admin/content/create',data={'csrf':token(admin.get('/admin/content')),
        'kind':'project','title':'번역 콘텐츠 현장 테스트','summary':'선교 현장을 돕는 번역 협력','content':'협력 설명','skills':'Translation'},follow_redirects=False)
    assert r.status_code==303
    pid=getone("SELECT id FROM projects WHERE title='번역 콘텐츠 현장 테스트'")['id']
    r=member.post(f'/projects/{pid}/apply',data={'csrf':token(member.get(f'/projects/{pid}')),'why':'자막 번역과 검수 작업에 기여하고 싶습니다.'},follow_redirects=False)
    assert r.status_code==303
    aid=getone('SELECT id FROM project_apps WHERE project_id=?',(pid,))['id']
    assert '자막 번역과 검수' not in visitor.get(f'/projects/{pid}').text
    assert '자막 번역과 검수' in admin.get('/admin/projects').text
    r=admin.post(f'/admin/projects/{aid}',data={'csrf':token(admin.get('/admin/projects')),'action':'approved'},follow_redirects=False)
    assert r.status_code==303
    assert getone('SELECT status FROM project_apps WHERE id=?',(aid,))['status']=='approved'
    assert 'approved' in member.get('/me').text
    # Admin can create resource, nonadmin cannot
    admin.post('/admin/content/create',data={'csrf':token(admin.get('/admin/content')),'kind':'resource','title':'교육 자료 테스트 제목','summary':'교육 자료를 소개합니다.','content':'원문 교육 자료 내용','topic':'Education','license':'Original','source':'GAMC'},follow_redirects=False)
    assert '교육 자료 테스트 제목' in visitor.get('/resources').text
    assert member.post('/admin/content/create',data={'csrf':token(member.get('/me')),'kind':'resource','title':'악성 게시','summary':'아무 자료'},follow_redirects=False).status_code==403
    # Negative CSRF
    assert member.post('/me/profile',data={'csrf':'not-valid','display_name':'hacked'},follow_redirects=False).status_code==403
    assert getone('SELECT display_name FROM users WHERE id=?',(member_row['id'],))['display_name']=='새로운 참여자'


def test_no_executable_user_html_and_account_deletion():
    c=TestClient(app)
    user=register(c,'deleted@example.org','개인정보 확인자')
    post=c.get('/community/new')
    r=c.post('/community/new',data={'csrf':token(post),'title':'HTML 안전성 점검 제목','body':'이 입력은 &lt;script&gt;가 아니라 <script>alert(1)</script> 텍스트입니다.','space':'general','tag':'AI Basics'},follow_redirects=False)
    assert r.status_code==303
    page=c.get(r.headers['location'])
    assert '<script>alert(1)</script>' not in page.text
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in page.text
    account=c.get('/me/account')
    r=c.post('/me/account/delete',data={'csrf':token(account),'confirm':'DELETE','password':'safePassword2094!'},follow_redirects=False)
    assert r.status_code==303
    assert getone('SELECT is_active FROM users WHERE id=?',(user['id'],))['is_active']==0
    assert c.get('/me',follow_redirects=False).status_code==303
