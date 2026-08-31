import os,secrets
from datetime import datetime,timedelta
from urllib.parse import urlencode
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI,Request,Depends,Form,HTTPException,Header
from fastapi.responses import HTMLResponse,RedirectResponse,JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session
from authlib.integrations.starlette_client import OAuth
import httpx,jwt

from .db import Base,engine,SessionLocal,get_db
from .models import User,Ticket,TicketMessage,IPBan,VPNAllowlist,AuditLog
from .security import hash_password,verify_password,client_ip,csrf_for,is_ip_banned,vpn_allowed,network_risky

APP_NAME='Vyxel'
SECRET_KEY=os.getenv('SECRET_KEY','dev-change-me')
BASE_URL=os.getenv('BASE_URL','http://127.0.0.1:8000').rstrip('/')
APP_ENV='production' if os.getenv('VERCEL') else os.getenv('APP_ENV','development')

GOOGLE_CLIENT_ID=''
GOOGLE_CLIENT_SECRET=''
APPLE_CLIENT_ID=''

app=FastAPI(title=APP_NAME)
app.add_middleware(SessionMiddleware,secret_key=SECRET_KEY,session_cookie='pentesthub_session',same_site='lax',https_only=APP_ENV=='production',max_age=604800)
templates=Jinja2Templates(directory='app/templates')
app.mount('/static',StaticFiles(directory='app/static'),name='static')

STARTUP_ERROR=None
OWNER_PANEL_TOKENS={}

def initialize_database():
    global STARTUP_ERROR
    try:
        Base.metadata.create_all(bind=engine)
        STARTUP_ERROR=None
        return True
    except Exception as e:
        STARTUP_ERROR=f"{type(e).__name__}: {e}"
        print("PentestHub database startup error:", STARTUP_ERROR)
        return False

oauth=OAuth()
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(name='google',client_id=GOOGLE_CLIENT_ID,client_secret=GOOGLE_CLIENT_SECRET,server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',client_kwargs={'scope':'openid email profile'})

def audit(db,req,actor,action,target_type=None,target_id=None,detail=None):
    db.add(AuditLog(actor_user_id=actor,action=action,target_type=target_type,target_id=str(target_id) if target_id is not None else None,detail=detail,ip=client_ip(req) if req else None));db.commit()

def bootstrap_owner():
    global STARTUP_ERROR

    email=os.getenv('OWNER_EMAIL','').lower().strip()
    password=os.getenv('OWNER_PASSWORD','')

    if not email or not password:
        return

    if len(password)<12:
        print("PentestHub warning: OWNER_PASSWORD must be at least 12 characters. Owner was not created.")
        return

    db=SessionLocal()
    try:
        if not db.query(User).filter(User.email==email).first():
            db.add(User(
                email=email,
                display_name='Owner',
                password_hash=hash_password(password),
                role='owner'
            ))
            db.commit()
    except Exception as e:
        db.rollback()
        STARTUP_ERROR=f"{type(e).__name__}: {e}"
        print("PentestHub owner bootstrap error:", STARTUP_ERROR)
    finally:
        db.close()

if initialize_database():
    bootstrap_owner()

@app.middleware('http')
async def secure(req,call_next):
    if req.url.path=='/health':
        return await call_next(req)

    if STARTUP_ERROR:
        return JSONResponse({
            'detail':'PentestHub database setup failed.',
            'startup_error':STARTUP_ERROR,
            'help':'Check DATABASE_URL in Vercel Environment Variables.'
        },status_code=503)

    db=SessionLocal()
    try:
        ip=client_ip(req);banned,reason=is_ip_banned(db,ip)
        if banned and not req.url.path.startswith('/owner-api/'):
            return JSONResponse({'detail':reason},status_code=403)
        if network_risky(req) and not vpn_allowed(db,ip) and not req.url.path.startswith('/owner-api/'):
            return JSONResponse({'detail':'Network blocked by anti-VPN/proxy policy'},status_code=403)
    finally:db.close()
    r=await call_next(req)
    r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY';r.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    r.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    r.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'self' https://accounts.google.com https://appleid.apple.com"
    if APP_ENV=='production':r.headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    return r

def sid(req):
    s=req.session.get('sid')
    if not s:s=secrets.token_urlsafe(32);req.session['sid']=s
    return s

def csrf(req):return csrf_for(sid(req))
def check_csrf(req,v):
    if not v or not secrets.compare_digest(v,csrf(req)):raise HTTPException(403,'Invalid CSRF token')

def current_user(req,db):
    uid=req.session.get('uid');u=db.get(User,uid) if uid else None
    if u and u.is_restricted:raise HTTPException(403,u.restricted_reason or 'Account restricted')
    if u and u.temp_banned_until and u.temp_banned_until>datetime.utcnow():raise HTTPException(403,'Account temporarily banned')
    return u

def require_user(req:Request,db:Session=Depends(get_db)):
    u=current_user(req,db)
    if not u:raise HTTPException(401,'Login required')
    return u

def visible(u,t):return u.role=='owner' or (u.role=='pentester' and t.assigned_pentester_id==u.id) or t.owner_user_id==u.id

@app.get('/',response_class=HTMLResponse)
def home(req:Request,db:Session=Depends(get_db)):
    u=current_user(req,db)
    if u:
        return RedirectResponse('/dashboard',303)
    return templates.TemplateResponse(
        'login.html',
        {
            'request':req,
            'csrf':csrf(req),
            'app_name':APP_NAME,
            'google_enabled':False,
            'apple_enabled':False
        }
    )
@app.get('/register',response_class=HTMLResponse)
def register_page(req:Request):return templates.TemplateResponse('register.html',{'request':req,'csrf':csrf(req),'app_name':APP_NAME})
@app.post('/register')
def register(req:Request,email:str=Form(...),display_name:str=Form(...),password:str=Form(...),csrf_token:str=Form(...),db:Session=Depends(get_db)):
    check_csrf(req,csrf_token);email=email.strip().lower()
    if db.query(User).filter(User.email==email).first():raise HTTPException(409,'Email already registered')
    u=User(email=email,display_name=display_name.strip()[:80],password_hash=hash_password(password),last_ip=client_ip(req));db.add(u);db.commit();db.refresh(u);req.session['uid']=u.id;audit(db,req,u.id,'account.register','user',u.id);return RedirectResponse('/dashboard',303)
@app.get('/login',response_class=HTMLResponse)
def login_page(req:Request):
    return templates.TemplateResponse(
        'login.html',
        {
            'request':req,
            'csrf':csrf(req),
            'app_name':APP_NAME,
            'google_enabled':False,
            'apple_enabled':False
        }
    )
@app.post('/login')
def login(req:Request,email:str=Form(...),password:str=Form(...),csrf_token:str=Form(...),db:Session=Depends(get_db)):
    check_csrf(req,csrf_token);u=db.query(User).filter(User.email==email.strip().lower()).first()
    if not u or not verify_password(password,u.password_hash):raise HTTPException(401,'Invalid email or password')
    u.last_ip=client_ip(req);db.commit();req.session['uid']=u.id;audit(db,req,u.id,'account.login','user',u.id);return RedirectResponse('/dashboard',303)
@app.post('/logout')
def logout(req:Request,csrf_token:str=Form(...)):
    check_csrf(req,csrf_token);req.session.clear();return RedirectResponse('/',303)

@app.get('/auth/google')
async def auth_google(req:Request):
    if not GOOGLE_CLIENT_ID:raise HTTPException(503,'Google login is not configured')
    return await oauth.google.authorize_redirect(req,BASE_URL+'/auth/google/callback')
@app.get('/auth/google/callback')
async def google_cb(req:Request,db:Session=Depends(get_db)):
    token=await oauth.google.authorize_access_token(req);info=token.get('userinfo') or await oauth.google.parse_id_token(req,token);email=(info.get('email') or '').lower()
    if not email:raise HTTPException(400,'Google did not provide an email')
    u=db.query(User).filter(User.email==email).first()
    if not u:u=User(email=email,display_name=(info.get('name') or email.split('@')[0])[:80],auth_provider='google',provider_subject=info.get('sub'));db.add(u);db.commit();db.refresh(u)
    req.session['uid']=u.id;return RedirectResponse('/dashboard',303)

@app.get('/auth/apple')
def auth_apple(req:Request):
    if not APPLE_CLIENT_ID:raise HTTPException(503,'Apple login is not configured')
    state=secrets.token_urlsafe(24);req.session['apple_state']=state
    return RedirectResponse('https://appleid.apple.com/auth/authorize?'+urlencode({'client_id':APPLE_CLIENT_ID,'redirect_uri':BASE_URL+'/auth/apple/callback','response_type':'code','response_mode':'form_post','scope':'name email','state':state}))
@app.post('/auth/apple/callback')
async def apple_cb(req:Request,code:str=Form(...),state:str=Form(...),db:Session=Depends(get_db)):
    if state!=req.session.get('apple_state'):raise HTTPException(403,'Invalid Apple state')
    raise HTTPException(503,'Apple token exchange hook is scaffolded; configure Apple team/key credentials before enabling this button')

@app.get('/dashboard',response_class=HTMLResponse)
def dashboard(req:Request,u:User=Depends(require_user),db:Session=Depends(get_db)):
    q=db.query(Ticket).filter(Ticket.status!='deleted')
    if u.role=='client':q=q.filter(Ticket.owner_user_id==u.id)
    elif u.role=='pentester':q=q.filter(Ticket.assigned_pentester_id==u.id)
    tickets=q.order_by(Ticket.updated_at.desc()).all()
    return templates.TemplateResponse('dashboard.html',{'request':req,'user':u,'tickets':tickets,'csrf':csrf(req),'app_name':APP_NAME})
@app.post('/tickets')
def create_ticket(req:Request,title:str=Form(...),target:str=Form(...),scope:str=Form(...),authorization_confirmed:str|None=Form(None),csrf_token:str=Form(...),u:User=Depends(require_user),db:Session=Depends(get_db)):
    check_csrf(req,csrf_token)
    if u.role!='client':raise HTTPException(403,'Only clients create tickets')
    if authorization_confirmed!='yes':raise HTTPException(400,'Authorization confirmation required')
    t=Ticket(owner_user_id=u.id,title=title[:160],target=target[:255],scope=scope[:10000],authorization_confirmed=True);db.add(t);db.commit();db.refresh(t);audit(db,req,u.id,'ticket.create','ticket',t.id,t.target);return RedirectResponse(f'/tickets/{t.id}',303)
@app.get('/tickets/{tid}',response_class=HTMLResponse)
def ticket_page(tid:int,req:Request,u:User=Depends(require_user),db:Session=Depends(get_db)):
    t=db.get(Ticket,tid)
    if not t or not visible(u,t):raise HTTPException(404,'Ticket not found')
    msgs=db.query(TicketMessage).filter(TicketMessage.ticket_id==tid).order_by(TicketMessage.id).all();ids={m.sender_user_id for m in msgs};users={x.id:x for x in db.query(User).filter(User.id.in_(ids or {u.id})).all()};pentesters=db.query(User).filter(User.role.in_(['pentester','owner'])).all()
    return templates.TemplateResponse('ticket.html',{'request':req,'user':u,'ticket':t,'messages':msgs,'users':users,'pentesters':pentesters,'csrf':csrf(req),'app_name':APP_NAME})
@app.post('/tickets/{tid}/messages')
def message(tid:int,req:Request,content:str=Form(...),csrf_token:str=Form(...),u:User=Depends(require_user),db:Session=Depends(get_db)):
    check_csrf(req,csrf_token);t=db.get(Ticket,tid)
    if not t or not visible(u,t):raise HTTPException(404,'Ticket not found')
    if t.status in ('archived','deleted'):raise HTTPException(409,'Ticket is read-only')
    db.add(TicketMessage(ticket_id=tid,sender_user_id=u.id,content=content.strip()[:8000]));t.updated_at=datetime.utcnow();db.commit();return RedirectResponse(f'/tickets/{tid}',303)
@app.post('/tickets/{tid}/action')
def action(tid:int,req:Request,action:str=Form(...),value:str|None=Form(None),csrf_token:str=Form(...),u:User=Depends(require_user),db:Session=Depends(get_db)):
    check_csrf(req,csrf_token)
    if u.role not in ('pentester','owner'):raise HTTPException(403,'Staff only')
    t=db.get(Ticket,tid)
    if not t or not visible(u,t):raise HTTPException(404,'Ticket not found')
    if action=='assign':
        if u.role!='owner':raise HTTPException(403,'Owner only')
        t.assigned_pentester_id=int(value) if value else None
    elif action in ('archive','delete','report','close','in_progress'):
        t.status={'close':'closed'}.get(action,action);t.report_reason=(value or '')[:255] if action=='report' else t.report_reason
    else:raise HTTPException(400,'Unknown action')
    t.updated_at=datetime.utcnow();db.commit();audit(db,req,u.id,'ticket.'+action,'ticket',tid,value);return RedirectResponse(f'/tickets/{tid}',303)

def owner_auth(authorization:str|None=Header(None),db:Session=Depends(get_db)):
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(401,'Owner Panel login required')
    token=authorization[7:]
    session=OWNER_PANEL_TOKENS.get(token)
    if not session:
        raise HTTPException(401,'Owner Panel session expired')
    if session['expires']<=datetime.utcnow():
        OWNER_PANEL_TOKENS.pop(token,None)
        raise HTTPException(401,'Owner Panel session expired')
    u=db.get(User,session['uid'])
    if not u or u.role!='owner':
        OWNER_PANEL_TOKENS.pop(token,None)
        raise HTTPException(403,'Owner access required')
    return True

@app.post('/owner-api/login')
def owner_panel_login(payload:dict,db:Session=Depends(get_db)):
    email=str(payload.get('email','')).strip().lower()
    password=str(payload.get('password',''))
    u=db.query(User).filter(User.email==email).first()
    if not u or u.role!='owner' or not verify_password(password,u.password_hash):
        raise HTTPException(401,'Invalid owner login')
    token=secrets.token_urlsafe(48)
    OWNER_PANEL_TOKENS[token]={'uid':u.id,'expires':datetime.utcnow()+timedelta(hours=12)}
    return {'token':token,'expires_in_hours':12}


@app.get('/owner-api/users')
def ou(_:bool=Depends(owner_auth),db:Session=Depends(get_db)):
    return [{'id':u.id,'display_name':u.display_name,'email':u.email,'role':u.role,'restricted':u.is_restricted,'temp_banned_until':u.temp_banned_until.isoformat() if u.temp_banned_until else None,'last_ip':u.last_ip or '','created_at':u.created_at.isoformat()} for u in db.query(User).order_by(User.created_at.desc()).all()]
@app.post('/owner-api/users/{uid}/restrict')
def orst(uid:int,payload:dict,_:bool=Depends(owner_auth),db:Session=Depends(get_db)):
    u=db.get(User,uid)
    if not u:raise HTTPException(404,'User not found')
    u.is_restricted=bool(payload.get('restricted',True));u.restricted_reason=str(payload.get('reason','Restricted by owner'))[:255] if u.is_restricted else None;db.commit();return {'ok':True}
@app.post('/owner-api/users/{uid}/temp-ban')
def otb(uid:int,payload:dict,_:bool=Depends(owner_auth),db:Session=Depends(get_db)):
    u=db.get(User,uid)
    if not u:raise HTTPException(404,'User not found')
    mins=max(0,min(int(payload.get('minutes',60)),525600));u.temp_banned_until=datetime.utcnow()+timedelta(minutes=mins) if mins else None;db.commit();return {'ok':True}
@app.post('/owner-api/ip-ban')
def oib(payload:dict,_:bool=Depends(owner_auth),db:Session=Depends(get_db)):
    ip=str(payload.get('ip','')).strip();row=db.query(IPBan).filter(IPBan.ip==ip).first() or IPBan(ip=ip);db.add(row);row.reason=str(payload.get('reason','Owner ban'))[:255];mins=payload.get('minutes');row.expires_at=datetime.utcnow()+timedelta(minutes=int(mins)) if mins else None;db.commit();return {'ok':True}
@app.delete('/owner-api/ip-ban/{ip}')
def oiu(ip:str,_:bool=Depends(owner_auth),db:Session=Depends(get_db)):
    row=db.query(IPBan).filter(IPBan.ip==ip).first();db.delete(row) if row else None;db.commit();return {'ok':True}
@app.post('/owner-api/vpn-allowlist')
def ova(payload:dict,_:bool=Depends(owner_auth),db:Session=Depends(get_db)):
    ip=str(payload.get('ip','')).strip();row=db.query(VPNAllowlist).filter(VPNAllowlist.ip==ip).first() or VPNAllowlist(ip=ip);db.add(row);row.note=str(payload.get('note',''))[:255];db.commit();return {'ok':True}
@app.delete('/owner-api/vpn-allowlist/{ip}')
def ovd(ip:str,_:bool=Depends(owner_auth),db:Session=Depends(get_db)):
    row=db.query(VPNAllowlist).filter(VPNAllowlist.ip==ip).first();db.delete(row) if row else None;db.commit();return {'ok':True}
@app.get('/owner-api/tickets')
def ots(_:bool=Depends(owner_auth),db:Session=Depends(get_db)):
    return [{'id':t.id,'title':t.title,'target':t.target,'status':t.status,'owner_user_id':t.owner_user_id,'assigned_pentester_id':t.assigned_pentester_id,'updated_at':t.updated_at.isoformat()} for t in db.query(Ticket).order_by(Ticket.updated_at.desc()).all()]
@app.get('/health')
def health():
    return {
        'ok': STARTUP_ERROR is None,
        'app': APP_NAME,
        'database_configured': bool(os.getenv('DATABASE_URL')),
        'owner_email_configured': bool(os.getenv('OWNER_EMAIL')),
        'owner_password_configured': bool(os.getenv('OWNER_PASSWORD')),
        'startup_error': STARTUP_ERROR
    }
