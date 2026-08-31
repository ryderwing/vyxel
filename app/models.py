from datetime import datetime
from sqlalchemy import Column,Integer,String,DateTime,Boolean,ForeignKey,Text
from .db import Base

def now(): return datetime.utcnow()

class User(Base):
    __tablename__='users'
    id=Column(Integer,primary_key=True)
    email=Column(String(320),unique=True,index=True,nullable=False)
    display_name=Column(String(80),nullable=False)
    password_hash=Column(String(255),nullable=True)
    auth_provider=Column(String(20),default='email',nullable=False)
    provider_subject=Column(String(255),nullable=True)
    role=Column(String(20),default='client',nullable=False)
    is_restricted=Column(Boolean,default=False,nullable=False)
    restricted_reason=Column(String(255),nullable=True)
    temp_banned_until=Column(DateTime,nullable=True)
    created_at=Column(DateTime,default=now,nullable=False)
    last_ip=Column(String(64),nullable=True)

class IPBan(Base):
    __tablename__='ip_bans'
    id=Column(Integer,primary_key=True)
    ip=Column(String(64),unique=True,index=True,nullable=False)
    reason=Column(String(255),nullable=True)
    expires_at=Column(DateTime,nullable=True)

class VPNAllowlist(Base):
    __tablename__='vpn_allowlist'
    id=Column(Integer,primary_key=True)
    ip=Column(String(64),unique=True,index=True,nullable=False)
    note=Column(String(255),nullable=True)

class Ticket(Base):
    __tablename__='tickets'
    id=Column(Integer,primary_key=True)
    owner_user_id=Column(Integer,ForeignKey('users.id',ondelete='CASCADE'),nullable=False,index=True)
    assigned_pentester_id=Column(Integer,ForeignKey('users.id',ondelete='SET NULL'),nullable=True,index=True)
    title=Column(String(160),nullable=False)
    target=Column(String(255),nullable=False)
    scope=Column(Text,nullable=False)
    authorization_confirmed=Column(Boolean,default=False,nullable=False)
    status=Column(String(20),default='open',nullable=False)
    report_reason=Column(String(255),nullable=True)
    created_at=Column(DateTime,default=now,nullable=False)
    updated_at=Column(DateTime,default=now,nullable=False)

class TicketMessage(Base):
    __tablename__='ticket_messages'
    id=Column(Integer,primary_key=True)
    ticket_id=Column(Integer,ForeignKey('tickets.id',ondelete='CASCADE'),nullable=False,index=True)
    sender_user_id=Column(Integer,ForeignKey('users.id',ondelete='CASCADE'),nullable=False)
    content=Column(Text,nullable=False)
    created_at=Column(DateTime,default=now,nullable=False)

class AuditLog(Base):
    __tablename__='audit_logs'
    id=Column(Integer,primary_key=True)
    actor_user_id=Column(Integer,ForeignKey('users.id',ondelete='SET NULL'),nullable=True)
    action=Column(String(80),nullable=False)
    target_type=Column(String(80),nullable=True)
    target_id=Column(String(80),nullable=True)
    detail=Column(Text,nullable=True)
    ip=Column(String(64),nullable=True)
    created_at=Column(DateTime,default=now,nullable=False,index=True)
