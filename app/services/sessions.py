import secrets
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import HTTPException, status

from ..config import SESSION_TTL_MINUTES
from ..schemas import OnlineUser, PresenceEvent, UserRole
from ..utils import utc_now


@dataclass
class Session:
    token: str
    username: str
    role: UserRole
    issued_at: datetime
    last_seen: datetime


class SessionManager:
    def __init__(self) -> None:
        self._sessions: Dict[str, Session] = {}
        self._events: List[PresenceEvent] = []

    def _purge_expired(self) -> None:
        if not self._sessions:
            return
        now = utc_now()
        ttl = timedelta(minutes=SESSION_TTL_MINUTES)
        expired_tokens = [
            token
            for token, session in self._sessions.items()
            if now - session.last_seen > ttl
        ]
        for token in expired_tokens:
            self._sessions.pop(token, None)

    def create(self, username: str, role: UserRole) -> Session:
        self._purge_expired()
        token = secrets.token_urlsafe(32)
        now = utc_now()
        session = Session(token=token, username=username, role=role, issued_at=now, last_seen=now)
        self._sessions[token] = session
        self._append_event(username=username, role=role, event_type='login')
        return session

    def invalidate(self, token: str) -> Optional[Session]:
        self._purge_expired()
        session = self._sessions.pop(token, None)
        if session is not None:
            self._append_event(username=session.username, role=session.role, event_type='logout')
        return session

    def require(self, token: str) -> Session:
        self._purge_expired()
        session = self._sessions.get(token)
        if session is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid session token')
        session.last_seen = utc_now()
        return session

    def list_active_users(self) -> List[OnlineUser]:
        self._purge_expired()
        aggregated: Dict[str, Session] = {}
        for session in self._sessions.values():
            existing = aggregated.get(session.username)
            if existing is None or session.last_seen > existing.last_seen:
                aggregated[session.username] = session
        return [
            OnlineUser(username=entry.username, role=entry.role, lastSeen=entry.last_seen)
            for entry in sorted(aggregated.values(), key=lambda item: item.last_seen, reverse=True)
        ]

    def recent_events(self, limit: int = 100) -> List[PresenceEvent]:
        return list(self._events)[-limit:]

    def record_signup(self, username: str, role: UserRole = 'user') -> None:
        self._append_event(username=username, role=role, event_type='signup')

    def _append_event(self, username: str, role: UserRole, event_type: str) -> None:
        event = PresenceEvent(id=str(uuid.uuid4()), username=username, role=role, type=event_type, timestamp=utc_now())
        self._events.append(event)
        if len(self._events) > 500:
            self._events = self._events[-500:]
