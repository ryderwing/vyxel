import os,secrets,json
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

GOOGLE_CLIENT_ID=os.getenv('GOOGLE_CLIENT_ID','').strip()
GOOGLE_CLIENT_SECRET=os.getenv('GOOGLE_CLIENT_SECRET','').strip()

GITHUB_CLIENT_ID=os.getenv('GITHUB_CLIENT_ID','').strip()
GITHUB_CLIENT_SECRET=os.getenv('GITHUB_CLIENT_SECRET','').strip()

MICROSOFT_CLIENT_ID=os.getenv('MICROSOFT_CLIENT_ID','').strip()
MICROSOFT_CLIENT_SECRET=os.getenv('MICROSOFT_CLIENT_SECRET','').strip()

APPLE_CLIENT_ID=os.getenv('APPLE_CLIENT_ID','').strip()
APPLE_TEAM_ID=os.getenv('APPLE_TEAM_ID','').strip()
APPLE_KEY_ID=os.getenv('APPLE_KEY_ID','').strip()
APPLE_PRIVATE_KEY=os.getenv('APPLE_PRIVATE_KEY','').replace('\\n','\n').strip()

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

def public_base_url(req: Request):
    configured=os.getenv('BASE_URL','').strip().rstrip('/')
    if configured:
        return configured
    return str(req.base_url).rstrip('/')

if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope':'openid email profile'}
    )

if GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET:
    oauth.register(
        name='github',
        client_id=GITHUB_CLIENT_ID,
        client_secret=GITHUB_CLIENT_SECRET,
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={'scope':'read:user user:email'}
    )

if MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET:
    oauth.register(
        name='microsoft',
        client_id=MICROSOFT_CLIENT_ID,
        client_secret=MICROSOFT_CLIENT_SECRET,
        server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
        client_kwargs={'scope':'openid email profile User.Read'}
    )

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
    r.headers['Content-Security-Policy']="default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'self' https://accounts.google.com https://appleid.apple.com https://github.com https://login.microsoftonline.com"
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

@app.get('/api', response_class=HTMLResponse)
def home(req: Request, db: Session = Depends(get_db)):
    user=current_user(req,db)
    if user:
        return RedirectResponse('/api/dashboard',303)
    return templates.TemplateResponse(
        'login.html',
        {
            'request':req,
            'csrf':csrf(req),
            'app_name':'Vyxel',
            'google_enabled':bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
            'apple_enabled':bool(APPLE_CLIENT_ID and APPLE_TEAM_ID and APPLE_KEY_ID and APPLE_PRIVATE_KEY),
            'github_enabled':bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET),
            'microsoft_enabled':bool(MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET)
        }
    )

@app.get('/api/register',response_class=HTMLResponse)
def register_page(req:Request):
    return templates.TemplateResponse(
        'register.html',
        {
            'request':req,
            'csrf':csrf(req),
            'app_name':'Vyxel',
            'google_enabled':bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
            'apple_enabled':bool(APPLE_CLIENT_ID and APPLE_TEAM_ID and APPLE_KEY_ID and APPLE_PRIVATE_KEY),
            'github_enabled':bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET),
            'microsoft_enabled':bool(MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET)
        }
    )
@app.post('/api/register')
def register(req:Request,email:str=Form(...),display_name:str=Form(...),password:str=Form(...),csrf_token:str=Form(...),db:Session=Depends(get_db)):
    check_csrf(req,csrf_token);email=email.strip().lower()
    if db.query(User).filter(User.email==email).first():raise HTTPException(409,'Email already registered')
    u=User(email=email,display_name=display_name.strip()[:80],password_hash=hash_password(password),last_ip=client_ip(req));db.add(u);db.commit();db.refresh(u);req.session['uid']=u.id;audit(db,req,u.id,'account.register','user',u.id);return RedirectResponse('/api/dashboard',303)
@app.get('/api/login',response_class=HTMLResponse)
def login_page(req:Request):
    return templates.TemplateResponse(
        'login.html',
        {
            'request':req,
            'csrf':csrf(req),
            'app_name':'Vyxel',
            'google_enabled':bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET),
            'apple_enabled':bool(APPLE_CLIENT_ID and APPLE_TEAM_ID and APPLE_KEY_ID and APPLE_PRIVATE_KEY),
            'github_enabled':bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET),
            'microsoft_enabled':bool(MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET)
        }
    )

@app.post('/api/login')
def login(req:Request,email:str=Form(...),password:str=Form(...),csrf_token:str=Form(...),db:Session=Depends(get_db)):
    check_csrf(req,csrf_token);u=db.query(User).filter(User.email==email.strip().lower()).first()
    if not u or not verify_password(password,u.password_hash):raise HTTPException(401,'Invalid email or password')
    u.last_ip=client_ip(req);db.commit();req.session['uid']=u.id;audit(db,req,u.id,'account.login','user',u.id);return RedirectResponse('/api/dashboard',303)
@app.post('/api/logout')
def logout(req:Request,csrf_token:str=Form(...)):
    check_csrf(req,csrf_token);req.session.clear();return RedirectResponse('/api',303)

def oauth_upsert_user(db: Session, email: str, display_name: str, provider: str, subject: str | None):
    email=(email or '').strip().lower()
    if not email:
        raise HTTPException(400,'Sign-in provider did not return an email address')

    u=db.query(User).filter(User.email==email).first()
    if not u:
        u=User(
            email=email,
            display_name=(display_name or email.split('@')[0])[:80],
            auth_provider=provider,
            provider_subject=subject
        )
        db.add(u)
        db.commit()
        db.refresh(u)
    return u

def apple_client_secret():
    if not (APPLE_CLIENT_ID and APPLE_TEAM_ID and APPLE_KEY_ID and APPLE_PRIVATE_KEY):
        raise HTTPException(503,'Apple sign-in is not configured yet')

    now=int(datetime.utcnow().timestamp())
    return jwt.encode(
        {
            'iss':APPLE_TEAM_ID,
            'iat':now,
            'exp':now+300,
            'aud':'https://appleid.apple.com',
            'sub':APPLE_CLIENT_ID
        },
        APPLE_PRIVATE_KEY,
        algorithm='ES256',
        headers={'kid':APPLE_KEY_ID}
    )

async def verify_apple_id_token(id_token: str):
    async with httpx.AsyncClient(timeout=15) as client:
        jwks=(await client.get('https://appleid.apple.com/auth/keys')).json()

    header=jwt.get_unverified_header(id_token)
    kid=header.get('kid')
    key_data=next((k for k in jwks.get('keys',[]) if k.get('kid')==kid),None)
    if not key_data:
        raise HTTPException(401,'Apple signing key not found')

    public_key=jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
    try:
        return jwt.decode(
            id_token,
            public_key,
            algorithms=['RS256'],
            audience=APPLE_CLIENT_ID,
            issuer='https://appleid.apple.com'
        )
    except Exception:
        raise HTTPException(401,'Invalid Apple identity token')

@app.get('/api/auth/google')
async def auth_google(req:Request):
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(503,'Google sign-in is not configured yet')
    return await oauth.google.authorize_redirect(
        req,
        public_base_url(req)+'/api/auth/google/callback'
    )

@app.get('/api/auth/google/callback')
async def google_cb(req:Request,db:Session=Depends(get_db)):
    token=await oauth.google.authorize_access_token(req)
    info=token.get('userinfo')
    if not info:
        info=await oauth.google.parse_id_token(req,token)
    u=oauth_upsert_user(
        db,
        info.get('email'),
        info.get('name') or '',
        'google',
        info.get('sub')
    )
    req.session['uid']=u.id
    return RedirectResponse('/api/dashboard',303)

@app.get('/api/auth/github')
async def auth_github(req:Request):
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(503,'GitHub sign-in is not configured yet')
    return await oauth.github.authorize_redirect(
        req,
        public_base_url(req)+'/api/auth/github/callback'
    )

@app.get('/api/auth/github/callback')
async def github_cb(req:Request,db:Session=Depends(get_db)):
    token=await oauth.github.authorize_access_token(req)
    profile=(await oauth.github.get('user',token=token)).json()

    email=profile.get('email')
    if not email:
        emails=(await oauth.github.get('user/emails',token=token)).json()
        primary=next((x for x in emails if x.get('primary') and x.get('verified')),None)
        if not primary:
            primary=next((x for x in emails if x.get('verified')),None)
        email=primary.get('email') if primary else None

    u=oauth_upsert_user(
        db,
        email,
        profile.get('name') or profile.get('login') or '',
        'github',
        str(profile.get('id') or '')
    )
    req.session['uid']=u.id
    return RedirectResponse('/api/dashboard',303)

@app.get('/api/auth/microsoft')
async def auth_microsoft(req:Request):
    if not MICROSOFT_CLIENT_ID or not MICROSOFT_CLIENT_SECRET:
        raise HTTPException(503,'Microsoft sign-in is not configured yet')
    return await oauth.microsoft.authorize_redirect(
        req,
        public_base_url(req)+'/api/auth/microsoft/callback'
    )

@app.get('/api/auth/microsoft/callback')
async def microsoft_cb(req:Request,db:Session=Depends(get_db)):
    token=await oauth.microsoft.authorize_access_token(req)
    info=token.get('userinfo')
    if not info:
        info=await oauth.microsoft.parse_id_token(req,token)
    email=info.get('email') or info.get('preferred_username')
    u=oauth_upsert_user(
        db,
        email,
        info.get('name') or '',
        'microsoft',
        info.get('sub')
    )
    req.session['uid']=u.id
    return RedirectResponse('/api/dashboard',303)

@app.get('/api/auth/apple')
def auth_apple(req:Request):
    if not (APPLE_CLIENT_ID and APPLE_TEAM_ID and APPLE_KEY_ID and APPLE_PRIVATE_KEY):
        raise HTTPException(503,'Apple sign-in is not configured yet')

    state=secrets.token_urlsafe(32)
    nonce=secrets.token_urlsafe(32)
    req.session['apple_state']=state
    req.session['apple_nonce']=nonce

    params={
        'client_id':APPLE_CLIENT_ID,
        'redirect_uri':public_base_url(req)+'/api/auth/apple/callback',
        'response_type':'code id_token',
        'response_mode':'form_post',
        'scope':'name email',
        'state':state,
        'nonce':nonce
    }
    return RedirectResponse('https://appleid.apple.com/auth/authorize?'+urlencode(params))

@app.post('/api/auth/apple/callback')
async def apple_cb(
    req:Request,
    code:str=Form(...),
    state:str=Form(...),
    id_token:str|None=Form(None),
    user:str|None=Form(None),
    db:Session=Depends(get_db)
):
    expected=req.session.pop('apple_state',None)
    if not expected or not secrets.compare_digest(state,expected):
        raise HTTPException(403,'Invalid Apple sign-in state')

    async with httpx.AsyncClient(timeout=15) as client:
        response=await client.post(
            'https://appleid.apple.com/auth/token',
            data={
                'client_id':APPLE_CLIENT_ID,
                'client_secret':apple_client_secret(),
                'code':code,
                'grant_type':'authorization_code',
                'redirect_uri':public_base_url(req)+'/api/auth/apple/callback'
            }
        )

    if response.status_code>=400:
        raise HTTPException(401,'Apple sign-in failed')

    token_data=response.json()
    final_id_token=token_data.get('id_token') or id_token
    if not final_id_token:
        raise HTTPException(401,'Apple did not return an identity token')

    claims=await verify_apple_id_token(final_id_token)

    expected_nonce=req.session.pop('apple_nonce',None)
    token_nonce=claims.get('nonce')
    if expected_nonce and token_nonce and not secrets.compare_digest(str(token_nonce),str(expected_nonce)):
        raise HTTPException(401,'Invalid Apple sign-in nonce')

    email=(claims.get('email') or '').strip().lower()
    name=''

    if user:
        try:
            user_data=json.loads(user)
            n=user_data.get('name') or {}
            name=(' '.join(x for x in [n.get('firstName'),n.get('lastName')] if x)).strip()
        except Exception:
            pass

    u=oauth_upsert_user(
        db,
        email,
        name or email.split('@')[0],
        'apple',
        claims.get('sub')
    )
    req.session['uid']=u.id
    return RedirectResponse('/api/dashboard',303)

@app.get('/api/dashboard',response_class=HTMLResponse)
def dashboard(req:Request,u:User=Depends(require_user),db:Session=Depends(get_db)):
    q=db.query(Ticket).filter(Ticket.status!='deleted')

    if u.role=='client':
                                                           
        q=q.filter(Ticket.owner_user_id==u.id)

    elif u.role=='pentester':
                                                       
        q=q.filter(Ticket.assigned_pentester_id==u.id)

    tickets=q.order_by(Ticket.updated_at.desc()).all()

    members=[]
    if u.role=='owner':
        members=db.query(User).order_by(User.created_at.desc()).all()

    return templates.TemplateResponse(
        'dashboard.html',
        {
            'request':req,
            'user':u,
            'tickets':tickets,
            'members':members,
            'config_owner_email':os.getenv('OWNER_EMAIL','').strip().lower(),
            'csrf':csrf(req),
            'app_name':APP_NAME
        }
    )
@app.post('/api/tickets')
def create_ticket(req:Request,title:str=Form(...),target:str=Form(...),scope:str=Form(...),authorization_confirmed:str|None=Form(None),csrf_token:str=Form(...),u:User=Depends(require_user),db:Session=Depends(get_db)):
    check_csrf(req,csrf_token)
    if u.role!='client':raise HTTPException(403,'Only clients create tickets')
    if authorization_confirmed!='yes':raise HTTPException(400,'Authorization confirmation required')
    t=Ticket(owner_user_id=u.id,title=title[:160],target=target[:255],scope=scope[:10000],authorization_confirmed=True);db.add(t);db.commit();db.refresh(t);audit(db,req,u.id,'ticket.create','ticket',t.id,t.target);return RedirectResponse(f'/api/tickets/{t.id}',303)
@app.get('/api/tickets/{tid}',response_class=HTMLResponse)
def ticket_page(tid:int,req:Request,u:User=Depends(require_user),db:Session=Depends(get_db)):
    t=db.get(Ticket,tid)
    if not t or not visible(u,t):raise HTTPException(404,'Ticket not found')
    msgs=db.query(TicketMessage).filter(TicketMessage.ticket_id==tid).order_by(TicketMessage.id).all();ids={m.sender_user_id for m in msgs};users={x.id:x for x in db.query(User).filter(User.id.in_(ids or {u.id})).all()};pentesters=db.query(User).filter(User.role.in_(['pentester','owner'])).all()
    return templates.TemplateResponse('ticket.html',{'request':req,'user':u,'ticket':t,'messages':msgs,'users':users,'pentesters':pentesters,'csrf':csrf(req),'app_name':APP_NAME})
@app.post('/api/tickets/{tid}/messages')
def message(tid:int,req:Request,content:str=Form(...),csrf_token:str=Form(...),u:User=Depends(require_user),db:Session=Depends(get_db)):
    check_csrf(req,csrf_token);t=db.get(Ticket,tid)
    if not t or not visible(u,t):raise HTTPException(404,'Ticket not found')
    if t.status in ('archived','deleted'):raise HTTPException(409,'Ticket is read-only')
    db.add(TicketMessage(ticket_id=tid,sender_user_id=u.id,content=content.strip()[:8000]));t.updated_at=datetime.utcnow();db.commit();return RedirectResponse(f'/api/tickets/{tid}',303)
@app.post('/api/tickets/{tid}/action')
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
    t.updated_at=datetime.utcnow();db.commit();audit(db,req,u.id,'ticket.'+action,'ticket',tid,value);return RedirectResponse(f'/api/tickets/{tid}',303)

def primary_owner_email():
    return os.getenv('OWNER_EMAIL','').strip().lower()

def is_primary_owner(u):
    return bool(u and u.email and u.email.strip().lower()==primary_owner_email())

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
    return u

def protect_primary(actor,target):
    if is_primary_owner(target) and actor.id!=target.id:
        raise HTTPException(403,'The main owner account is protected')
    if target.role=='owner' and not is_primary_owner(actor) and actor.id!=target.id:
        raise HTTPException(403,'Only the main owner can manage another owner')

@app.post('/owner-api/login')
def owner_panel_login(payload:dict,db:Session=Depends(get_db)):
    email=str(payload.get('email','')).strip().lower()
    password=str(payload.get('password',''))
    u=db.query(User).filter(User.email==email).first()
    if not u or u.role!='owner' or not verify_password(password,u.password_hash):
        raise HTTPException(401,'Invalid owner login')
    token=secrets.token_urlsafe(48)
    OWNER_PANEL_TOKENS[token]={'uid':u.id,'expires':datetime.utcnow()+timedelta(hours=12)}
    return {
        'token':token,
        'expires_in_hours':12,
        'user_id':u.id,
        'email':u.email,
        'is_primary_owner':is_primary_owner(u)
    }

@app.post('/owner-api/logout')
def owner_panel_logout(authorization:str|None=Header(None)):
    if authorization and authorization.startswith('Bearer '):
        OWNER_PANEL_TOKENS.pop(authorization[7:],None)
    return {'ok':True}

@app.get('/owner-api/users')
def owner_users(actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    return [{
        'id':u.id,
        'display_name':u.display_name,
        'email':u.email,
        'role':u.role,
        'restricted':u.is_restricted,
        'temp_banned_until':u.temp_banned_until.isoformat() if u.temp_banned_until else None,
        'last_ip':u.last_ip or '',
        'created_at':u.created_at.isoformat(),
        'primary_owner':is_primary_owner(u)
    } for u in db.query(User).order_by(User.created_at.desc()).all()]

@app.post('/owner-api/users/{uid}/role')
def owner_set_role(uid:int,payload:dict,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    target=db.get(User,uid)
    if not target:
        raise HTTPException(404,'User not found')
    if is_primary_owner(target):
        raise HTTPException(403,'The main owner role cannot be changed')
    new_role=str(payload.get('role','client')).strip().lower()
    if new_role not in ('client','pentester','owner'):
        raise HTTPException(400,'Invalid role')
    if new_role=='owner' or target.role=='owner':
        if not is_primary_owner(actor):
            raise HTTPException(403,'Only the main owner can grant or remove Owner access')
    target.role=new_role
    db.commit()
    return {'ok':True,'user_id':target.id,'role':target.role}

@app.post('/owner-api/users/{uid}/restrict')
def owner_restrict(uid:int,payload:dict,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    target=db.get(User,uid)
    if not target:
        raise HTTPException(404,'User not found')
    protect_primary(actor,target)
    if is_primary_owner(target):
        raise HTTPException(403,'The main owner cannot be restricted')
    target.is_restricted=bool(payload.get('restricted',True))
    target.restricted_reason=str(payload.get('reason','Restricted by owner'))[:255] if target.is_restricted else None
    db.commit()
    return {'ok':True}

@app.post('/owner-api/users/{uid}/temp-ban')
def owner_temp_ban(uid:int,payload:dict,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    target=db.get(User,uid)
    if not target:
        raise HTTPException(404,'User not found')
    protect_primary(actor,target)
    if is_primary_owner(target):
        raise HTTPException(403,'The main owner cannot be temp banned')
    mins=max(0,min(int(payload.get('minutes',60)),525600))
    target.temp_banned_until=datetime.utcnow()+timedelta(minutes=mins) if mins else None
    db.commit()
    return {'ok':True}

@app.post('/owner-api/users/{uid}/ip-ban')
def owner_user_ip_ban(uid:int,payload:dict,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    target=db.get(User,uid)
    if not target:
        raise HTTPException(404,'User not found')
    protect_primary(actor,target)
    if is_primary_owner(target):
        raise HTTPException(403,'The main owner cannot be IP banned')
    ip=(target.last_ip or '').strip()
    if not ip:
        raise HTTPException(400,'User has no recorded IP')
    row=db.query(IPBan).filter(IPBan.ip==ip).first() or IPBan(ip=ip)
    db.add(row)
    row.reason=str(payload.get('reason','User IP banned by owner'))[:255]
    mins=payload.get('minutes')
    row.expires_at=datetime.utcnow()+timedelta(minutes=int(mins)) if mins else None
    db.commit()
    return {'ok':True,'ip':ip}

@app.post('/owner-api/users/{uid}/vpn-bypass')
def owner_user_vpn_bypass(uid:int,payload:dict,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    target=db.get(User,uid)
    if not target:
        raise HTTPException(404,'User not found')
    ip=(target.last_ip or '').strip()
    if not ip:
        raise HTTPException(400,'User has no recorded IP')
    enabled=bool(payload.get('enabled',True))
    row=db.query(VPNAllowlist).filter(VPNAllowlist.ip==ip).first()
    if enabled:
        if not row:
            row=VPNAllowlist(ip=ip)
            db.add(row)
        row.note=str(payload.get('note','Allowed from user options'))[:255]
    elif row:
        db.delete(row)
    db.commit()
    return {'ok':True,'enabled':enabled,'ip':ip}

@app.delete('/owner-api/users/{uid}')
def owner_delete_user(uid:int,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    target=db.get(User,uid)
    if not target:
        raise HTTPException(404,'User not found')
    if is_primary_owner(target):
        raise HTTPException(403,'The main owner account cannot be deleted')
    protect_primary(actor,target)
    db.query(TicketMessage).filter(TicketMessage.sender_user_id==uid).delete(synchronize_session=False)
    owned=db.query(Ticket).filter(Ticket.owner_user_id==uid).all()
    for ticket in owned:
        db.query(TicketMessage).filter(TicketMessage.ticket_id==ticket.id).delete(synchronize_session=False)
        db.delete(ticket)
    for ticket in db.query(Ticket).filter(Ticket.assigned_pentester_id==uid).all():
        ticket.assigned_pentester_id=None
    for log in db.query(AuditLog).filter(AuditLog.actor_user_id==uid).all():
        log.actor_user_id=None
    db.delete(target)
    db.commit()
    return {'ok':True}

@app.post('/owner-api/ip-ban')
def owner_ip_ban(payload:dict,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    ip=str(payload.get('ip','')).strip()
    primary=db.query(User).filter(User.email==primary_owner_email()).first()
    if primary and primary.last_ip==ip and not is_primary_owner(actor):
        raise HTTPException(403,'The main owner IP is protected')
    row=db.query(IPBan).filter(IPBan.ip==ip).first() or IPBan(ip=ip)
    db.add(row)
    row.reason=str(payload.get('reason','Owner ban'))[:255]
    mins=payload.get('minutes')
    row.expires_at=datetime.utcnow()+timedelta(minutes=int(mins)) if mins else None
    db.commit()
    return {'ok':True}

@app.delete('/owner-api/ip-ban/{ip}')
def owner_ip_unban(ip:str,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    row=db.query(IPBan).filter(IPBan.ip==ip).first()
    if row:
        db.delete(row)
    db.commit()
    return {'ok':True}

@app.post('/owner-api/vpn-allowlist')
def owner_vpn_allow(payload:dict,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    ip=str(payload.get('ip','')).strip()
    row=db.query(VPNAllowlist).filter(VPNAllowlist.ip==ip).first() or VPNAllowlist(ip=ip)
    db.add(row)
    row.note=str(payload.get('note',''))[:255]
    db.commit()
    return {'ok':True}

@app.delete('/owner-api/vpn-allowlist/{ip}')
def owner_vpn_unallow(ip:str,actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    row=db.query(VPNAllowlist).filter(VPNAllowlist.ip==ip).first()
    if row:
        db.delete(row)
    db.commit()
    return {'ok':True}

@app.get('/owner-api/tickets')
def owner_tickets(actor:User=Depends(owner_auth),db:Session=Depends(get_db)):
    return [{
        'id':t.id,
        'title':t.title,
        'target':t.target,
        'status':t.status,
        'owner_user_id':t.owner_user_id,
        'assigned_pentester_id':t.assigned_pentester_id,
        'updated_at':t.updated_at.isoformat()
    } for t in db.query(Ticket).order_by(Ticket.updated_at.desc()).all()]


@app.post('/api/owner/users/{uid}/action')
def website_owner_user_action(
    uid:int,
    req:Request,
    action:str=Form(...),
    value:str|None=Form(None),
    csrf_token:str=Form(...),
    u:User=Depends(require_user),
    db:Session=Depends(get_db)
):
    check_csrf(req,csrf_token)

    if u.role!='owner':
        raise HTTPException(403,'Owner only')

    target=db.get(User,uid)
    if not target:
        raise HTTPException(404,'User not found')

    main_email=os.getenv('OWNER_EMAIL','').strip().lower()
    is_main_actor=(u.email or '').strip().lower()==main_email
    is_main_target=(target.email or '').strip().lower()==main_email

    if is_main_target and target.id!=u.id:
        raise HTTPException(403,'Main owner account is protected')

    if target.role=='owner' and not is_main_actor and target.id!=u.id:
        raise HTTPException(403,'Only the main owner can manage another owner')

    if action=='temp_ban':
        minutes=max(1,min(int(value or 60),525600))
        target.temp_banned_until=datetime.utcnow()+timedelta(minutes=minutes)

    elif action=='remove_temp_ban':
        target.temp_banned_until=None

    elif action=='restrict':
        target.is_restricted=True
        target.restricted_reason=(value or 'Restricted by owner')[:255]

    elif action=='unrestrict':
        target.is_restricted=False
        target.restricted_reason=None

    elif action=='ip_ban':
        ip=(target.last_ip or '').strip()
        if not ip:
            raise HTTPException(400,'User has no recorded IP')
        row=db.query(IPBan).filter(IPBan.ip==ip).first() or IPBan(ip=ip)
        db.add(row)
        row.reason='Banned from website owner panel'
        row.expires_at=None

    elif action=='vpn_bypass':
        ip=(target.last_ip or '').strip()
        if not ip:
            raise HTTPException(400,'User has no recorded IP')
        row=db.query(VPNAllowlist).filter(VPNAllowlist.ip==ip).first() or VPNAllowlist(ip=ip)
        db.add(row)
        row.note='Allowed from website owner panel'

    elif action=='remove_vpn_bypass':
        ip=(target.last_ip or '').strip()
        if not ip:
            raise HTTPException(400,'User has no recorded IP')
        row=db.query(VPNAllowlist).filter(VPNAllowlist.ip==ip).first()
        if row:
            db.delete(row)

    elif action=='make_pentester':
        if target.role=='owner':
            raise HTTPException(400,'Remove Owner access first')
        target.role='pentester'

    elif action=='remove_pentester':
        if target.role=='pentester':
            target.role='client'

    elif action=='make_owner':
        if not is_main_actor:
            raise HTTPException(403,'Only the main owner can grant Owner access')
        if is_main_target:
            raise HTTPException(400,'Already main owner')
        target.role='owner'
        target.is_restricted=False
        target.restricted_reason=None
        target.temp_banned_until=None

    elif action=='remove_owner':
        if not is_main_actor:
            raise HTTPException(403,'Only the main owner can remove Owner access')
        if is_main_target:
            raise HTTPException(403,'Main owner role cannot be removed')
        if target.role=='owner':
            target.role='client'

    elif action=='delete':
        if is_main_target:
            raise HTTPException(403,'Main owner account cannot be deleted')
        if target.role=='owner' and not is_main_actor:
            raise HTTPException(403,'Only the main owner can delete another owner')

        db.query(TicketMessage).filter(TicketMessage.sender_user_id==target.id).delete(synchronize_session=False)

        owned=db.query(Ticket).filter(Ticket.owner_user_id==target.id).all()
        for ticket in owned:
            db.query(TicketMessage).filter(TicketMessage.ticket_id==ticket.id).delete(synchronize_session=False)
            db.delete(ticket)

        for ticket in db.query(Ticket).filter(Ticket.assigned_pentester_id==target.id).all():
            ticket.assigned_pentester_id=None

        for log in db.query(AuditLog).filter(AuditLog.actor_user_id==target.id).all():
            log.actor_user_id=None

        db.delete(target)

    else:
        raise HTTPException(400,'Unknown action')

    db.commit()
    return RedirectResponse('/api/dashboard',303)

@app.get('/api/health')
def health():
    return {
        'ok': STARTUP_ERROR is None,
        'app': APP_NAME,
        'database_configured': bool(os.getenv('DATABASE_URL')),
        'owner_email_configured': bool(os.getenv('OWNER_EMAIL')),
        'owner_password_configured': bool(os.getenv('OWNER_PASSWORD')),
        'startup_error': STARTUP_ERROR
    }
