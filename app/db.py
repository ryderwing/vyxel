import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./pentesthub.db").strip()

# Neon normally gives URLs starting with postgresql://.
# Force SQLAlchemy to use psycopg v3, which is installed in requirements.txt.
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql://"):]

# Also normalize old psycopg2-style URLs if one was pasted manually.
if DATABASE_URL.startswith("postgresql+psycopg2://"):
    DATABASE_URL = "postgresql+psycopg://" + DATABASE_URL[len("postgresql+psycopg2://"):]

# Neon and most Postgres hosts give a normal postgresql:// URL.
# SQLAlchemy+psycopg needs the driver name, so normalize it automatically.
if DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL='postgresql+psycopg://'+DATABASE_URL[len('postgresql://'):]

kwargs={'pool_pre_ping':True}
if DATABASE_URL.startswith('sqlite'):
    kwargs['connect_args']={'check_same_thread':False}
if DATABASE_URL.startswith('postgresql'):
    kwargs.update({
        'pool_pre_ping': True,
        'pool_recycle': 300,
    })

engine=create_engine(DATABASE_URL,**kwargs)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False,expire_on_commit=False)
Base=declarative_base()

def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()
