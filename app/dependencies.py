from typing import Optional

from fastapi import Depends, Header, HTTPException, status

from .db import AsyncSessionLocal
from .services.events import EventStore
from .services.profiles import ProfileStore
from .services.sessions import Session, SessionManager
from .services.users import UserStore

_user_store = UserStore(AsyncSessionLocal)
_profile_store = ProfileStore(AsyncSessionLocal)
_event_store = EventStore(AsyncSessionLocal)
_session_manager = SessionManager()


def get_user_store() -> UserStore:
    return _user_store


def get_profile_store() -> ProfileStore:
    return _profile_store


def get_event_store() -> EventStore:
    return _event_store


def get_session_manager() -> SessionManager:
    return _session_manager


def extract_token(authorization: Optional[str] = Header(None)) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Authorization header is missing')
    scheme, _, param = authorization.partition(' ')
    if scheme.lower() != 'bearer' or not param:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid authorization header')
    return param


def require_session(token: str = Depends(extract_token), manager: SessionManager = Depends(get_session_manager)) -> Session:
    return manager.require(token)


def require_admin_session(session: Session = Depends(require_session)) -> Session:
    if session.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Admin access required')
    return session
