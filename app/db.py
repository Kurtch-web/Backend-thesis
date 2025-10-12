from __future__ import annotations

from typing import AsyncGenerator, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import (
    DATA_DIR,
    DATABASE_URL,
    DB_MAX_OVERFLOW,
    DB_POOL_SIZE,
    ssl_context,
)


class Base(DeclarativeBase):
    pass


def _coerce_database_url(raw: Optional[str]) -> Tuple[str, bool]:
    if raw:
        url = raw
        if url.startswith('postgres://'):
            url = url.replace('postgres://', 'postgresql+asyncpg://', 1)
        elif url.startswith('postgresql://'):
            url = url.replace('postgresql://', 'postgresql+asyncpg://', 1)
        return url, True
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{(DATA_DIR / 'app.db').as_posix()}", False


DB_URL, IS_EXTERNAL_DB = _coerce_database_url(DATABASE_URL)

if DB_URL.startswith('postgresql+asyncpg://'):
    parsed = urlparse(DB_URL)
    qs = dict(parse_qsl(parsed.query))
    # Disable prepared statement caches for pgbouncer transaction/statement pooling
    qs['statement_cache_size'] = '0'
    qs['prepared_statement_cache_size'] = '0'
    DB_URL = urlunparse(parsed._replace(query=urlencode(qs)))

connect_args: dict = {}
if DB_URL.startswith('postgresql+asyncpg://'):
    connect_args['statement_cache_size'] = 0
    connect_args['prepared_statement_cache_size'] = 0
    if IS_EXTERNAL_DB:
        connect_args['ssl'] = ssl_context

engine = create_async_engine(
    DB_URL,
    echo=False,
    connect_args=connect_args,
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_MAX_OVERFLOW,
    pool_pre_ping=True,
    pool_recycle=300,
)

AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def init_models() -> None:
    from . import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
