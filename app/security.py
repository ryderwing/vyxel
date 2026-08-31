import os,hmac,hashlib
from datetime import datetime
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Request
from .models import IPBan,VPNAllowlist

ph=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=2)
SECRET_KEY=os.getenv('SECRET_KEY','dev-change-me')
TRUST_PROXY_HEADERS=os.getenv('TRUST_PROXY_HEADERS','true').lower()=='true'

def hash_password(p):
    if len(p)<12: raise ValueError('Password must be at least 12 characters')
    return ph.hash(p)

def verify_password(p,h):
    try: return bool(h) and ph.verify(h,p)
    except VerifyMismatchError: return False
    except Exception: return False

def client_ip(req:Request):
    if TRUST_PROXY_HEADERS:
        if req.headers.get('cf-connecting-ip'): return req.headers['cf-connecting-ip'].strip()
        if req.headers.get('x-forwarded-for'): return req.headers['x-forwarded-for'].split(',')[0].strip()
    return req.client.host if req.client else 'unknown'

def csrf_for(sid):
    return hmac.new(SECRET_KEY.encode(),f'csrf:{sid}'.encode(),hashlib.sha256).hexdigest()

def is_ip_banned(db,ip):
    row=db.query(IPBan).filter(IPBan.ip==ip).first()
    if not row:return False,''
    if row.expires_at and row.expires_at<=datetime.utcnow():
        db.delete(row);db.commit();return False,''
    return True,row.reason or 'Access blocked'

def vpn_allowed(db,ip):
    return db.query(VPNAllowlist).filter(VPNAllowlist.ip==ip).first() is not None

def network_risky(req):
    # Conservative risk signals only. This is not proof of VPN usage.
    h={k.lower():v.lower() for k,v in req.headers.items()}
    if h.get('x-vpn')=='true' or h.get('x-proxy')=='true' or h.get('cf-ipcountry')=='t1':
        return True
    return False
