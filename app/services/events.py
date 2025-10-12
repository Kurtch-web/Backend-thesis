from __future__ import annotations

from typing import List, Optional

from sqlalchemy import Select, desc, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..models import EventLog
from ..schemas import PresenceEvent, UserRole


class EventStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def record(self, *, event_type: str, username: str, role: UserRole) -> PresenceEvent:
        async with self._session_factory() as session:
            row = EventLog(event_type=event_type, username=username, role=role)
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return PresenceEvent(
                id=row.id,
                username=row.username,
                role=row.role,  # type: ignore[assignment]
                type=event_type,  # type: ignore[assignment]
                timestamp=row.created_at,
            )

    async def record_signup(self, username: str, role: UserRole = 'user') -> PresenceEvent:
        return await self.record(event_type='signup', username=username, role=role)

    async def recent(self, limit: int = 100, types: Optional[List[str]] = None) -> List[PresenceEvent]:
        async with self._session_factory() as session:
            stmt: Select[EventLog] = select(EventLog).order_by(desc(EventLog.created_at)).limit(limit)
            if types:
                stmt = stmt.where(EventLog.event_type.in_(types))
            result = await session.execute(stmt)
            rows = result.scalars().all()
        return [
            PresenceEvent(
                id=row.id,
                username=row.username,
                role=row.role,  # type: ignore[assignment]
                type=row.event_type,  # type: ignore[assignment]
                timestamp=row.created_at,
            )
            for row in rows
        ]
