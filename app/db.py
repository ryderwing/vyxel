import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite:///./pentesthub.db"
).strip()

# Neon normally gives postgresql:// URLs.
# Force SQLAlchemy to use psycopg v3 instead of psycopg2.
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = (
        "postgresql+psycopg://"
        + DATABASE_URL[len("postgresql://"):]
    )

if DATABASE_URL.startswith("postgresql+psycopg2://"):
    DATABASE_URL = (
        "postgresql+psycopg://"
        + DATABASE_URL[len("postgresql+psycopg2://"):]
    )

kwargs = {
    "pool_pre_ping": True
}

if DATABASE_URL.startswith("sqlite"):
    kwargs["connect_args"] = {
        "check_same_thread": False
    }

engine = create_engine(
    DATABASE_URL,
    **kwargs
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False
)

Base = declarative_base()


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
