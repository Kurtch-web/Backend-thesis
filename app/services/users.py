import asyncio
import asyncio
import json
import os
from dataclasses import dataclass
from typing import Iterable, List

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..config import USERS_FILE
from ..models import UserAccount
from ..schemas import UserRole
from ..security import hash_password, verify_password


@dataclass
class UserRecord:
    username: str
    password_hash: str
    role: UserRole


class UserStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._init_lock = asyncio.Lock()
        self._initialized = False

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        async with self._init_lock:
            if self._initialized:
                return
            async with self._session_factory() as session:
                count = await session.scalar(select(func.count()).select_from(UserAccount))
                if not count:
                    await self._seed_defaults(session)
            self._initialized = True

    async def _seed_defaults(self, session: AsyncSession) -> None:
        legacy_records: List[UserAccount] = []
        if USERS_FILE.exists():
            with USERS_FILE.open('r', encoding='utf-8') as file:
                payload = json.load(file)
            for raw in payload:
                legacy_records.append(
                    UserAccount(
                        username=raw['username'],
                        password_hash=raw['password_hash'],
                        role=raw['role']
                    )
                )
        if legacy_records:
            session.add_all(legacy_records)
            await session.commit()
            return

        admin_username = os.getenv('ADMIN_DEFAULT_USERNAME', 'admin')
        admin_password = os.getenv('ADMIN_DEFAULT_PASSWORD', 'Admin@1234')
        member_username = os.getenv('USER_DEFAULT_USERNAME', 'member')
        member_password = os.getenv('USER_DEFAULT_PASSWORD', 'Member@1234')

        session.add_all(
            [
                UserAccount(username=admin_username, password_hash=hash_password(admin_password), role='admin'),
                UserAccount(username=member_username, password_hash=hash_password(member_password), role='user')
            ]
        )
        await session.commit()

    @staticmethod
    def _normalize_username(username: str) -> str:
        return username.strip().lower()

    async def verify_credentials(self, username: str, password: str, role: UserRole) -> UserRecord:
        await self._ensure_initialized()
        normalized = self._normalize_username(username)
        async with self._session_factory() as session:
            account = await session.scalar(
                select(UserAccount).where(func.lower(UserAccount.username) == normalized)
            )
            if account is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail='Account not found. Please sign up first.'
                )
            if account.role != role:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Role mismatch for account')
            if not verify_password(password, account.password_hash):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials')
            return UserRecord(username=account.username, password_hash=account.password_hash, role=account.role)

    async def create_member(self, username: str, password: str) -> UserRecord:
        await self._ensure_initialized()
        normalized = self._normalize_username(username)
        if not normalized:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Username cannot be empty')
        async with self._session_factory() as session:
            existing = await session.scalar(
                select(UserAccount).where(func.lower(UserAccount.username) == normalized)
            )
            if existing is not None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Username already exists')
            account = UserAccount(
                username=username.strip(),
                password_hash=hash_password(password),
                role='user'
            )
            session.add(account)
            await session.commit()
            await session.refresh(account)
            return UserRecord(username=account.username, password_hash=account.password_hash, role=account.role)

    async def user_exists(self, username: str) -> bool:
        await self._ensure_initialized()
        normalized = self._normalize_username(username)
        async with self._session_factory() as session:
            account = await session.scalar(
                select(UserAccount.id).where(func.lower(UserAccount.username) == normalized)
            )
            return account is not None

    async def all_users(self) -> Iterable[UserRecord]:
        await self._ensure_initialized()
        async with self._session_factory() as session:
            result = await session.execute(select(UserAccount))
            accounts = result.scalars().all()
        return [UserRecord(username=entry.username, password_hash=entry.password_hash, role=entry.role) for entry in accounts]

    async def count_users(self) -> int:
        await self._ensure_initialized()
        async with self._session_factory() as session:
            total = await session.scalar(select(func.count()).select_from(UserAccount))
        return int(total or 0)
