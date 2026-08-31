import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL=os.getenv('DATABASE_URL','sqlite:///./pentesthub.db')
kwargs={'pool_pre_ping':True}
if DATABASE_URL.startswith('sqlite'):
    kwargs['connect_args']={'check_same_thread':False}
engine=create_engine(DATABASE_URL,**kwargs)
SessionLocal=sessionmaker(bind=engine,autoflush=False,autocommit=False,expire_on_commit=False)
Base=declarative_base()

def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()
