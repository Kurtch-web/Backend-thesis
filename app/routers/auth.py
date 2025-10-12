from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..config import SESSION_TTL_MINUTES
from ..dependencies import get_event_store, get_session_manager, get_user_store, require_session
from ..schemas import LoginPayload, LoginResponse, SignupPayload, SignupResponse
from ..services.events import EventStore
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
