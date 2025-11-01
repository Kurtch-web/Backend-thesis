from datetime import datetime, timezone
from typing import List, Dict

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..db import get_db
from ..dependencies import require_session
from ..models import Conversation, MessageRead, MessageRow, Participant
from ..schemas import ConversationOut, MessageOut, ParticipantRef, SendMessagePayload, OpenConversationPayload
from ..services.sessions import Session

router = APIRouter()


async def _ensure_conversation(db: AsyncSession, participants: List[ParticipantRef]) -> Conversation:
    names = sorted({p.username for p in participants})
    key = '|'.join(names)
    existing = await db.execute(select(Conversation).options(selectinload(Conversation.participants)).where(Conversation.key == key))
    convo = existing.scalar_one_or_none()
    if convo:
        return convo
    convo = Conversation(key=key)
    db.add(convo)
    await db.flush()
    for participant in participants:
        db.add(Participant(conversation_id=convo.id, username=participant.username, role=participant.role))
    await db.commit()
    await db.refresh(convo, ['participants'])
    return convo


async def _user_is_participant(db: AsyncSession, conversation_id: str, username: str) -> bool:
    res = await db.execute(select(Participant).where(Participant.conversation_id == conversation_id, Participant.username == username))
    return res.scalar_one_or_none() is not None


def _conversation_to_out(row: tuple[Conversation, MessageRow | None, int]) -> ConversationOut:
    convo, last_msg, unread = row
    participants = [ParticipantRef(username=p.username, role=p.role) for p in convo.participants]
    return ConversationOut(
        id=convo.id,
        participants=participants,
        lastMessageAt=(last_msg.created_at if last_msg else None),
        lastMessagePreview=(last_msg.body if last_msg else None),
        unreadCount=unread,
    )


@router.post('/chat/conversations/open')
async def open_conversation(
    payload: OpenConversationPayload,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, ConversationOut]:
    participants = payload.participants
    if not any(p.username == session.username for p in participants):
        participants = participants + [ParticipantRef(username=session.username, role=session.role)]
    convo = await _ensure_conversation(db, participants)
    await db.refresh(convo, ['participants'])
    return {'conversation': _conversation_to_out((convo, None, 0))}


@router.get('/chat/conversations')
async def list_conversations(
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, List[ConversationOut]]:
    query = await db.execute(
        select(Conversation)
        .options(selectinload(Conversation.participants))
        .join(Participant)
        .where(Participant.username == session.username)
    )
    conversations = query.scalars().unique().all()
    output: List[ConversationOut] = []
    for conversation in conversations:
        last_query = await db.execute(
            select(MessageRow)
            .where(MessageRow.conversation_id == conversation.id)
            .order_by(MessageRow.created_at.desc())
            .limit(1)
        )
        last_message = last_query.scalar_one_or_none()
        unread_query = await db.execute(
            select(func.count(MessageRow.id)).where(
                MessageRow.conversation_id == conversation.id,
                MessageRow.sender_username != session.username,
                ~MessageRow.id.in_(
                    select(MessageRead.message_id).where(MessageRead.username == session.username)
                ),
            )
        )
        unread = int(unread_query.scalar() or 0)
        output.append(_conversation_to_out((conversation, last_message, unread)))
    output.sort(
        key=lambda item: item.lastMessageAt or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return {'conversations': output}


@router.get('/chat/conversations/{conversation_id}/messages')
async def list_messages(
    conversation_id: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, List[MessageOut]]:
    if not await _user_is_participant(db, conversation_id, session.username):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not a participant')
    query = await db.execute(
        select(MessageRow)
        .where(MessageRow.conversation_id == conversation_id)
        .order_by(MessageRow.created_at.asc())
        .limit(500)
    )
    rows = query.scalars().all()
    message_ids = [row.id for row in rows]
    read_index: Dict[str, List[str]] = {}
    if message_ids:
        reads = await db.execute(
            select(MessageRead.message_id, MessageRead.username).where(MessageRead.message_id.in_(message_ids))
        )
        for message_id, username in reads.tuples().all():
            read_index.setdefault(message_id, []).append(username)
    messages = [
        MessageOut(
            id=row.id,
            conversationId=row.conversation_id,
            sender=ParticipantRef(username=row.sender_username, role=row.sender_role),
            body=row.body,
            createdAt=row.created_at,
            readBy=read_index.get(row.id, []),
        )
        for row in rows
    ]
    return {'messages': messages}


@router.post('/chat/conversations/{conversation_id}/messages')
async def send_message(
    conversation_id: str,
    payload: SendMessagePayload,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, MessageOut]:
    if not await _user_is_participant(db, conversation_id, session.username):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not a participant')
    row = MessageRow(
        conversation_id=conversation_id,
        sender_username=session.username,
        sender_role=session.role,
        body=payload.body,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    message = MessageOut(
        id=row.id,
        conversationId=row.conversation_id,
        sender=ParticipantRef(username=row.sender_username, role=row.sender_role),
        body=row.body,
        createdAt=row.created_at,
    )
    return {'message': message}


@router.post('/chat/conversations/{conversation_id}/read', status_code=status.HTTP_204_NO_CONTENT)
async def mark_read(
    conversation_id: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Response:
    if not await _user_is_participant(db, conversation_id, session.username):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not a participant')
    query = await db.execute(
        select(MessageRow.id)
        .where(
            MessageRow.conversation_id == conversation_id,
            MessageRow.sender_username != session.username,
            ~MessageRow.id.in_(
                select(MessageRead.message_id).where(MessageRead.username == session.username)
            ),
        )
    )
    ids = [message_id for (message_id,) in query.tuples().all()]
    for message_id in ids:
        db.add(MessageRead(message_id=message_id, username=session.username))
    if ids:
        await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
