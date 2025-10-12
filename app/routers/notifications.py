from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..dependencies import require_session
from ..models import Notification, UserAccount
from ..schemas import NotificationList, NotificationOut
from ..services.sessions import Session

router = APIRouter()


async def _get_user(session: Session, db: AsyncSession) -> UserAccount:
    user = await db.scalar(select(UserAccount).where(UserAccount.username == session.username))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Account not found')
    return user


@router.get('/notifications', response_model=NotificationList)
async def list_notifications(
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> NotificationList:
    user = await _get_user(session, db)
    result = await db.execute(
        select(Notification).where(Notification.user_id == user.id).order_by(Notification.created_at.desc()).limit(50)
    )
    items = [
        NotificationOut(
            id=n.id,
            type=n.type,
            data=n.data or {},
            createdAt=n.created_at,
            readAt=n.read_at,
        )
        for n in result.scalars().all()
    ]
    return NotificationList(notifications=items)


@router.post('/notifications/{notification_id}/read', status_code=status.HTTP_204_NO_CONTENT, response_class=Response)
async def mark_notification_read(
    notification_id: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await _get_user(session, db)
    notif = await db.scalar(
        select(Notification).where(Notification.id == notification_id, Notification.user_id == user.id)
    )
    if not notif:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Notification not found')
    from datetime import datetime
    notif.read_at = datetime.utcnow()
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
