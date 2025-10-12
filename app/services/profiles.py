from __future__ import annotations

from datetime import timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import UserAccount, UserProfile
from ..schemas import UserProfileOut, UpdateProfilePayload
from ..utils import utc_now
from ..security import hash_password, verify_password


CODE_TTL_MINUTES = 15
REQUEST_COOLDOWN_SECONDS = 60


class ProfileStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def _get_account(self, username: str) -> Optional[UserAccount]:
        async with self._session_factory() as session:
            return await session.scalar(select(UserAccount).where(UserAccount.username == username))

    async def _get_or_create_profile(self, session: AsyncSession, user_id: int) -> UserProfile:
        profile = await session.scalar(select(UserProfile).where(UserProfile.user_id == user_id))
        if profile is None:
            profile = UserProfile(user_id=user_id)
            session.add(profile)
            await session.flush()
        return profile

    async def get_profile(self, username: str) -> UserProfileOut:
        async with self._session_factory() as session:
            account = await session.scalar(select(UserAccount).where(UserAccount.username == username))
            if account is None:
                raise ValueError('Account not found')
            profile = await self._get_or_create_profile(session, account.id)
            return self._to_out(account, profile)

    async def update_profile(self, username: str, payload: UpdateProfilePayload) -> UserProfileOut:
        async with self._session_factory() as session:
            account = await session.scalar(select(UserAccount).where(UserAccount.username == username))
            if account is None:
                raise ValueError('Account not found')
            profile = await self._get_or_create_profile(session, account.id)

            # Changing email/phone resets verification
            if payload.email is not None and payload.email != profile.email:
                profile.email = payload.email.lower().strip() or None
                profile.email_verified_at = None
                profile.verify_email_code_hash = None
                profile.verify_expires_at = None
                profile.verify_requested_at = None
            if payload.phoneE164 is not None and payload.phoneE164 != profile.phone_e164:
                profile.phone_e164 = payload.phoneE164.strip() or None
                profile.phone_verified_at = None
                profile.verify_phone_code_hash = None
                profile.verify_expires_at = None
                profile.verify_requested_at = None

            if payload.firstName is not None:
                profile.first_name = payload.firstName
            if payload.lastName is not None:
                profile.last_name = payload.lastName
            if payload.displayName is not None:
                profile.display_name = payload.displayName
            if payload.avatarUrl is not None:
                profile.avatar_url = payload.avatarUrl
            if payload.bio is not None:
                profile.bio = payload.bio
            if payload.timezone is not None:
                profile.timezone = payload.timezone
            if payload.locale is not None:
                profile.locale = payload.locale
            if payload.marketingOptIn is not None:
                profile.marketing_opt_in = bool(payload.marketingOptIn)
            if payload.notifyPrefs is not None:
                profile.notify_prefs = payload.notifyPrefs

            await session.commit()
            await session.refresh(profile)
            return self._to_out(account, profile)

    async def request_email_code(self, username: str, email: str) -> None:
        now = utc_now()
        async with self._session_factory() as session:
            account = await session.scalar(select(UserAccount).where(UserAccount.username == username))
            if account is None:
                raise ValueError('Account not found')
            profile = await self._get_or_create_profile(session, account.id)
            # rate limit
            if profile.verify_requested_at and (now - profile.verify_requested_at).total_seconds() < REQUEST_COOLDOWN_SECONDS:
                raise RuntimeError('Please wait before requesting another code')
            profile.email = email.lower().strip()
            code = self._generate_code()
            profile.verify_email_code_hash = hash_password(code)
            profile.verify_phone_code_hash = None
            profile.verify_expires_at = now + timedelta(minutes=CODE_TTL_MINUTES)
            profile.verify_requested_at = now
            await session.commit()

    async def verify_email(self, username: str, code: str) -> bool:
        now = utc_now()
        async with self._session_factory() as session:
            account = await session.scalar(select(UserAccount).where(UserAccount.username == username))
            if account is None:
                raise ValueError('Account not found')
            profile = await self._get_or_create_profile(session, account.id)
            if not profile.verify_email_code_hash or not profile.verify_expires_at or profile.verify_expires_at < now:
                return False
            if not verify_password(code, profile.verify_email_code_hash):
                return False
            profile.email_verified_at = now
            profile.verify_email_code_hash = None
            profile.verify_expires_at = None
            profile.verify_requested_at = None
            await session.commit()
            return True

    async def request_phone_code(self, username: str, phone_e164: str) -> None:
        now = utc_now()
        async with self._session_factory() as session:
            account = await session.scalar(select(UserAccount).where(UserAccount.username == username))
            if account is None:
                raise ValueError('Account not found')
            profile = await self._get_or_create_profile(session, account.id)
            if profile.verify_requested_at and (now - profile.verify_requested_at).total_seconds() < REQUEST_COOLDOWN_SECONDS:
                raise RuntimeError('Please wait before requesting another code')
            profile.phone_e164 = phone_e164.strip()
            code = self._generate_code()
            profile.verify_phone_code_hash = hash_password(code)
            profile.verify_email_code_hash = None
            profile.verify_expires_at = now + timedelta(minutes=CODE_TTL_MINUTES)
            profile.verify_requested_at = now
            await session.commit()

    async def verify_phone(self, username: str, code: str) -> bool:
        now = utc_now()
        async with self._session_factory() as session:
            account = await session.scalar(select(UserAccount).where(UserAccount.username == username))
            if account is None:
                raise ValueError('Account not found')
            profile = await self._get_or_create_profile(session, account.id)
            if not profile.verify_phone_code_hash or not profile.verify_expires_at or profile.verify_expires_at < now:
                return False
            if not verify_password(code, profile.verify_phone_code_hash):
                return False
            profile.phone_verified_at = now
            profile.verify_phone_code_hash = None
            profile.verify_expires_at = None
            profile.verify_requested_at = None
            await session.commit()
            return True

    @staticmethod
    def _to_out(account: UserAccount, profile: UserProfile) -> UserProfileOut:
        return UserProfileOut(
            username=account.username,
            role=account.role,  # type: ignore[assignment]
            email=profile.email,
            emailVerifiedAt=profile.email_verified_at,
            phoneE164=profile.phone_e164,
            phoneVerifiedAt=profile.phone_verified_at,
            firstName=profile.first_name,
            lastName=profile.last_name,
            displayName=profile.display_name,
            avatarUrl=profile.avatar_url,
            bio=profile.bio,
            timezone=profile.timezone,
            locale=profile.locale,
            marketingOptIn=bool(profile.marketing_opt_in),
            notifyPrefs=profile.notify_prefs or {},
            updatedAt=profile.updated_at,
        )

    @staticmethod
    def _generate_code() -> str:
        import random

        return f"{random.randint(0, 999999):06d}"
