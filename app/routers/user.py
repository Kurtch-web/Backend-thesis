from fastapi import APIRouter, Depends, HTTPException, status

from ..dependencies import get_profile_store, require_session
from ..schemas import (
    RequestEmailCodePayload,
    RequestSmsCodePayload,
    UpdateProfilePayload,
    UserProfileOut,
    VerifyEmailPayload,
    VerifyPhonePayload,
)
from ..services.profiles import ProfileStore
from ..services.sessions import Session

router = APIRouter()


@router.get('/user/profile', response_model=UserProfileOut)
async def get_profile(session: Session = Depends(require_session), store: ProfileStore = Depends(get_profile_store)) -> UserProfileOut:
    return await store.get_profile(session.username)


@router.put('/user/profile', response_model=UserProfileOut)
async def update_profile(
    payload: UpdateProfilePayload,
    session: Session = Depends(require_session),
    store: ProfileStore = Depends(get_profile_store),
) -> UserProfileOut:
    try:
        return await store.update_profile(session.username, payload)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Account not found')


@router.post('/user/request-email-code', status_code=status.HTTP_204_NO_CONTENT)
async def request_email_code(
    payload: RequestEmailCodePayload,
    session: Session = Depends(require_session),
    store: ProfileStore = Depends(get_profile_store),
) -> None:
    try:
        await store.request_email_code(session.username, payload.email)
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))


@router.post('/user/verify-email', status_code=status.HTTP_204_NO_CONTENT)
async def verify_email(
    payload: VerifyEmailPayload,
    session: Session = Depends(require_session),
    store: ProfileStore = Depends(get_profile_store),
) -> None:
    ok = await store.verify_email(session.username, payload.code)
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid or expired code')


@router.post('/user/request-sms-code', status_code=status.HTTP_204_NO_CONTENT)
async def request_sms_code(
    payload: RequestSmsCodePayload,
    session: Session = Depends(require_session),
    store: ProfileStore = Depends(get_profile_store),
) -> None:
    try:
        await store.request_phone_code(session.username, payload.phoneE164)
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))


@router.post('/user/verify-phone', status_code=status.HTTP_204_NO_CONTENT)
async def verify_phone(
    payload: VerifyPhonePayload,
    session: Session = Depends(require_session),
    store: ProfileStore = Depends(get_profile_store),
) -> None:
    ok = await store.verify_phone(session.username, payload.code)
    if not ok:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Invalid or expired code')
