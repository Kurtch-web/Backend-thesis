from datetime import datetime, timezone
from typing import Dict, List

from fastapi import APIRouter, Depends

from ..dependencies import get_event_store, get_session_manager, get_user_store, require_admin_session, require_session
from ..schemas import OnlineUser, PresenceEvent, PresenceOverview, UserInfo
from ..services.events import EventStore
from ..services.presence import build_presence_overview
from ..services.sessions import Session, SessionManager
from ..services.users import UserStore

router = APIRouter()


@router.get('/admin/online-users', response_model=Dict[str, List[OnlineUser]])
async def list_online_users(
    _: Session = Depends(require_admin_session),
    session_manager: SessionManager = Depends(get_session_manager),
) -> Dict[str, List[OnlineUser]]:
    users = session_manager.list_active_users()
    return {'users': users}


@router.get('/admin/presence-events', response_model=Dict[str, List[PresenceEvent]])
async def presence_events(
    _: Session = Depends(require_admin_session),
    session_manager: SessionManager = Depends(get_session_manager),
    event_store: EventStore = Depends(get_event_store),
) -> Dict[str, List[PresenceEvent]]:
    # Persisted events already include signups; avoid duplicating them with in-memory copies
    mem = session_manager.recent_events(limit=100)
    in_memory = [e for e in mem if e.type != 'signup']
    stored = await event_store.recent(limit=100)
    combined = (stored + in_memory)[:100]
    return {'events': combined}


@router.get('/presence/overview', response_model=PresenceOverview)
async def presence_overview(
    _: Session = Depends(require_session),
    session_manager: SessionManager = Depends(get_session_manager),
    user_store: UserStore = Depends(get_user_store),
) -> PresenceOverview:
    return await build_presence_overview(user_store, session_manager.list_active_users())


@router.get('/admin/stats', response_model=Dict[str, int])
async def stats(
    _: Session = Depends(require_admin_session),
    session_manager: SessionManager = Depends(get_session_manager),
    user_store: UserStore = Depends(get_user_store),
) -> Dict[str, int]:
    users = session_manager.list_active_users()
    active_admins = sum(1 for u in users if u.role == 'admin')
    active_members = sum(1 for u in users if u.role == 'user')
    total_users = await user_store.count_users()
    return {
        'totalUsers': total_users,
        'activeAdmins': active_admins,
        'activeMembers': active_members,
    }


@router.get('/admin/users', response_model=Dict[str, List[UserInfo]])
async def list_all_users(
    _: Session = Depends(require_admin_session),
    session_manager: SessionManager = Depends(get_session_manager),
    user_store: UserStore = Depends(get_user_store),
) -> Dict[str, List[UserInfo]]:
    overview = await build_presence_overview(user_store, session_manager.list_active_users())
    combined = overview.admins + overview.users
    combined.sort(
        key=lambda item: (
            1 if item.online else 0,
            item.lastSeen or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    return {'users': combined}
