from __future__ import annotations

import os
import smtplib
from datetime import timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import UserAccount, UserProfile
from ..schemas import UserProfileOut, UpdateProfilePayload
from ..utils import utc_now
from ..security import hash_password, verify_password


CODE_TTL_MINUTES = 60
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

            await self._send_verification_email(email, code)

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

    @staticmethod
    async def _send_verification_email(email: str, code: str) -> None:
        email_from = os.getenv('EMAIL_FROM')
        email_password = os.getenv('EMAIL_PASSWORD')

        if not email_from or not email_password:
            raise RuntimeError('Email configuration is missing')

        subject = 'Verify Your Email Address'
        html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .container {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%;
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 28px;
            margin-bottom: 8px;
            font-weight: 700;
        }}
        .header p {{
            font-size: 14px;
            opacity: 0.9;
        }}
        .content {{
            padding: 40px 30px;
        }}
        .greeting {{
            font-size: 16px;
            color: #333;
            margin-bottom: 24px;
            line-height: 1.6;
        }}
        .code-section {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 12px;
            padding: 30px;
            margin: 30px 0;
            text-align: center;
        }}
        .code-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #667eea;
            font-weight: 600;
            margin-bottom: 12px;
        }}
        .code {{
            font-size: 42px;
            font-weight: 700;
            color: #667eea;
            letter-spacing: 4px;
            font-family: 'Monaco', 'Courier New', monospace;
            word-break: break-all;
        }}
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 16px;
            border-radius: 6px;
            margin: 24px 0;
        }}
        .warning-title {{
            font-weight: 600;
            color: #856404;
            font-size: 14px;
            margin-bottom: 8px;
        }}
        .warning-text {{
            color: #856404;
            font-size: 13px;
            line-height: 1.6;
        }}
        .info {{
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 16px;
            border-radius: 6px;
            margin: 24px 0;
        }}
        .info-title {{
            font-weight: 600;
            color: #0d47a1;
            font-size: 14px;
            margin-bottom: 8px;
        }}
        .info-text {{
            color: #0d47a1;
            font-size: 13px;
            line-height: 1.6;
        }}
        .footer {{
            border-top: 1px solid #e0e0e0;
            padding-top: 24px;
            margin-top: 24px;
            text-align: center;
            color: #666;
            font-size: 12px;
            line-height: 1.8;
        }}
        .footer-brand {{
            font-weight: 600;
            color: #667eea;
            margin-top: 16px;
        }}
        .btn {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 32px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            margin: 20px 0;
            font-size: 14px;
            transition: transform 0.2s;
        }}
        .btn:hover {{
            transform: translateY(-2px);
        }}
        .divider {{
            height: 1px;
            background: #e0e0e0;
            margin: 24px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Email Verification</h1>
            <p>Secure your account now</p>
        </div>
        <div class="content">
            <p class="greeting">
                Hi there! 👋<br><br>
                Welcome to <strong>LET AI Control Hub</strong>. To keep your account safe and secure, please verify your email address.
            </p>

            <div class="code-section">
                <div class="code-label">Your Verification Code</div>
                <div class="code">{code}</div>
            </div>

            <p style="text-align: center; color: #666; font-size: 13px; margin: 16px 0;">
                This code will expire in <strong>1 hour</strong>
            </p>

            <div class="info">
                <div class="info-title">ℹ️ How to verify</div>
                <div class="info-text">
                    Enter this 6-digit code in the email verification section of your Settings page. You can also use it to verify your email on your next login.
                </div>
            </div>

            <div class="warning">
                <div class="warning-title">⚠️ Important Notice</div>
                <div class="warning-text">
                    If you do not verify your email within 24 hours, your account may be at risk of losing access. Please verify your email as soon as possible to keep your account secure.
                </div>
            </div>

            <p style="color: #666; font-size: 13px; line-height: 1.8;">
                Didn't request this code? No action is needed. If you believe your account is compromised, please contact our support team immediately.
            </p>

            <div class="divider"></div>

            <div class="footer">
                <p>Questions? We're here to help!</p>
                <p style="margin-top: 12px; color: #999;">
                    This is an automated message, please do not reply to this email.
                </p>
                <div class="footer-brand">
                    🚀 LET AI Control Hub Team<br>
                    <span style="font-size: 11px; color: #999;">Monitoring and Guiding Every Live Workspace</span>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = email_from
            msg['To'] = email
            msg['Subject'] = subject
            msg.attach(MIMEText(html_body, 'html'))

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(email_from, email_password)
                server.send_message(msg)
        except Exception as e:
            raise RuntimeError(f'Failed to send verification email: {str(e)}')

    async def request_password_reset(self, email: str) -> None:
        """Request a password reset code for an email address"""
        email = email.lower().strip()
        async with self._session_factory() as session:
            now = utc_now()
            profile = await session.scalar(select(UserProfile).where(UserProfile.email.ilike(email)))
            if not profile:
                raise ValueError('Email not found')

            # Check cooldown
            if profile.verify_requested_at and now - profile.verify_requested_at < timedelta(seconds=REQUEST_COOLDOWN_SECONDS):
                raise RuntimeError('Please wait before requesting another code')

            code = self._generate_code()
            profile.verify_email_code_hash = hash_password(code)
            profile.verify_expires_at = now + timedelta(minutes=CODE_TTL_MINUTES)
            profile.verify_requested_at = now
            await session.commit()

            await self._send_password_reset_email(email, code)

    async def verify_password_reset_code(self, email: str, code: str) -> bool:
        """Verify password reset code"""
        email = email.lower().strip()
        async with self._session_factory() as session:
            now = utc_now()
            profile = await session.scalar(select(UserProfile).where(UserProfile.email.ilike(email)))
            if not profile:
                return False

            if not profile.verify_email_code_hash or not profile.verify_expires_at or profile.verify_expires_at < now:
                return False

            if not verify_password(code, profile.verify_email_code_hash):
                return False

            return True

    @staticmethod
    async def _send_password_reset_email(email: str, code: str) -> None:
        email_from = os.getenv('EMAIL_FROM')
        email_password = os.getenv('EMAIL_PASSWORD')

        if not email_from or not email_password:
            raise RuntimeError('Email configuration is missing')

        subject = 'Reset Your Password'
        html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px 20px;
            border-radius: 12px;
        }}
        .card {{
            background: white;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 20px;
        }}
        .header h1 {{
            font-size: 28px;
            color: #667eea;
            margin-bottom: 10px;
        }}
        .header p {{
            color: #666;
            font-size: 14px;
        }}
        .content {{
            text-align: center;
            margin: 30px 0;
        }}
        .content p {{
            margin: 15px 0;
            color: #555;
            font-size: 16px;
        }}
        .code-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin: 30px 0;
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 6px;
            text-align: center;
            font-family: 'Monaco', 'Courier New', monospace;
        }}
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            color: #856404;
            font-size: 14px;
        }}
        .info-text {{
            color: #666;
            font-size: 13px;
            margin-top: 20px;
            line-height: 1.8;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            border-top: 1px solid #ddd;
            padding-top: 20px;
            color: #999;
            font-size: 12px;
        }}
        .button {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 12px 30px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            margin: 20px 0;
            transition: transform 0.2s;
        }}
        .button:hover {{
            transform: translateY(-2px);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <h1>🔐 Password Reset Request</h1>
                <p>Secure your account</p>
            </div>

            <div class="content">
                <p>You requested a password reset. Use the code below to reset your password:</p>

                <div class="code-box">{code}</div>

                <p>This code will expire in 60 minutes.</p>

                <div class="warning">
                    ⚠️ If you didn't request this, please ignore this email and your password will remain unchanged.
                </div>

                <div class="info-text">
                    <strong>Steps to reset your password:</strong><br>
                    1. Enter this code on the password reset page<br>
                    2. Create a new password<br>
                    3. Sign in with your new password
                </div>
            </div>

            <div class="footer">
                <p>This is an automated message, please do not reply to this email.</p>
                <p>© LET AI Control Hub. All rights reserved.</p>
            </div>
        </div>
    </div>
</body>
</html>
"""

        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = email_from
            msg['To'] = email
            msg['Subject'] = subject
            msg.attach(MIMEText(html_body, 'html'))

            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(email_from, email_password)
                server.send_message(msg)
        except Exception as e:
            raise RuntimeError(f'Failed to send password reset email: {str(e)}')
