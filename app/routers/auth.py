from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..config import SESSION_TTL_MINUTES
from ..dependencies import get_event_store, get_profile_store, get_session_manager, get_user_store, require_session
from ..schemas import LoginPayload, LoginResponse, PasswordResetConfirm, PasswordResetRequest, PasswordResetVerify, SignupPayload, SignupResponse
from ..services.events import EventStore
from ..services.profiles import ProfileStore
from ..services.sessions import Session, SessionManager
from ..services.users import UserStore

router = APIRouter()


@router.post('/auth/signup', response_model=SignupResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    payload: SignupPayload,
    user_store: UserStore = Depends(get_user_store),
    session_manager: SessionManager = Depends(get_session_manager),
    event_store: EventStore = Depends(get_event_store),
) -> SignupResponse:
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Username cannot be empty')
    record = await user_store.create_member(username, payload.password)
    session_manager.record_signup(record.username, record.role)
    await event_store.record_signup(record.username, record.role)
    return SignupResponse(username=record.username, message='Account created. You can now sign in.')


@router.post('/auth/login', response_model=LoginResponse)
async def login(
    payload: LoginPayload,
    response: Response,
    user_store: UserStore = Depends(get_user_store),
    session_manager: SessionManager = Depends(get_session_manager),
) -> LoginResponse:
    sanitized_username = payload.username.strip()
    if not sanitized_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Username cannot be empty')

    record = await user_store.verify_credentials(sanitized_username, payload.password, payload.role)
    session = session_manager.create(record.username, record.role)
    message = 'Welcome back, admin!' if record.role == 'admin' else 'You are now online.'
    max_age = SESSION_TTL_MINUTES * 60
    response.set_cookie('session_token', session.token, httponly=True, samesite='lax', max_age=max_age)
    response.set_cookie('session_role', session.role, httponly=False, samesite='lax', max_age=max_age)
    return LoginResponse(token=session.token, role=session.role, username=session.username, message=message)


@router.post('/auth/logout', status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    session: Session = Depends(require_session),
    session_manager: SessionManager = Depends(get_session_manager),
) -> Response:
    session_manager.invalidate(session.token)
    response.delete_cookie('session_token')
    response.delete_cookie('session_role')
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post('/auth/request-password-reset', status_code=status.HTTP_204_NO_CONTENT)
async def request_password_reset(
    payload: PasswordResetRequest,
    user_store: UserStore = Depends(get_user_store),
    profile_store: ProfileStore = Depends(get_profile_store),
) -> Response:
    """Request a password reset code for an email address"""
    # Find user by email
    async with user_store._session_factory() as session:
        from sqlalchemy import select
        from ..models import UserProfile, UserAccount
        profile = await session.scalar(select(UserProfile).where(UserProfile.email.ilike(payload.email.strip())))
        if not profile:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Email not found')
        user = await session.scalar(select(UserAccount).where(UserAccount.id == profile.user_id))
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')

    # Request password reset code using profile store
    await profile_store.request_password_reset(payload.email)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post('/auth/verify-password-reset', response_model=dict)
async def verify_password_reset(
    payload: PasswordResetVerify,
    profile_store: ProfileStore = Depends(get_profile_store),
) -> dict:
    """Verify password reset code"""
    is_valid = await profile_store.verify_password_reset_code(payload.email, payload.code)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid or expired code')
    return {'valid': True, 'message': 'Code verified successfully'}


@router.post('/auth/reset-password', response_model=dict)
async def reset_password(
    payload: PasswordResetConfirm,
    user_store: UserStore = Depends(get_user_store),
    profile_store: ProfileStore = Depends(get_profile_store),
) -> dict:
    """Reset password with verified code"""
    # Verify code first
    is_valid = await profile_store.verify_password_reset_code(payload.email, payload.code)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid or expired code')

    # Find user by email and update password
    async with user_store._session_factory() as session:
        from sqlalchemy import select, update
        from ..models import UserProfile, UserAccount
        from ..security import hash_password

        profile = await session.scalar(select(UserProfile).where(UserProfile.email.ilike(payload.email.strip())))
        if not profile:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Email not found')

        user = await session.scalar(select(UserAccount).where(UserAccount.id == profile.user_id))
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')

        # Update password
        user.password_hash = hash_password(payload.new_password)

        # Clear reset codes
        profile.verify_email_code_hash = None
        profile.verify_expires_at = None
        profile.verify_requested_at = None

        await session.commit()

    return {'message': 'Password reset successfully'}
