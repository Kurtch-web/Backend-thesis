from __future__ import annotations

from typing import Dict, List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..db import get_db
from ..dependencies import require_session, get_event_store
from ..models import (
    CommunityAttachment,
    CommunityComment,
    CommunityLike,
    CommunityPost,
    CommunityPostMeta,
    CommunityTag,
    Notification,
    UserAccount,
    UserProfile,
)
from ..schemas import (
    CommunityAttachmentOut,
    CommunityCommentOut,
    CommunityPostOut,
    CommunityFeedResponse,
    CreateCommentPayload,
    UpdatePostPayload,
    ArchivePostPayload,
    ReportPostPayload,
)
from ..services.sessions import Session
from ..services.events import EventStore
from ..services.storage import get_supabase_storage, build_attachment_path

router = APIRouter()


async def _get_user(session: Session, db: AsyncSession) -> UserAccount:
    user = await db.scalar(select(UserAccount).where(UserAccount.username == session.username))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Account not found')
    return user


def _attachment_out(att: CommunityAttachment) -> CommunityAttachmentOut:
    storage = get_supabase_storage()
    if storage is not None:
        path = build_attachment_path(att.post_id, att.id, att.filename)
        url = storage.public_url(path)
    else:
        url = f"/api/community/attachments/{att.id}"
    return CommunityAttachmentOut(
        id=att.id,
        filename=att.filename,
        contentType=att.content_type,
        url=url,
    )


def _comment_out(c: CommunityComment, author_username: str) -> CommunityCommentOut:
    return CommunityCommentOut(
        id=c.id,
        authorUsername=author_username,
        body=c.body,
        createdAt=c.created_at,
    )


def _post_out(
    post: CommunityPost,
    author_username: str,
    like_count: int,
    liked_by_me: bool,
    comment_count: int,
    attachments: Optional[List[CommunityAttachment]] = None,
    comments: Optional[List[tuple[CommunityComment, str]]] = None,
    tags: Optional[List[str]] = None,
    is_archived: bool = False,
    updated_at: Optional[datetime] = None,
    can_edit: bool = False,
    can_archive: bool = False,
    can_delete: bool = False,
    can_report: bool = False,
) -> CommunityPostOut:
    return CommunityPostOut(
        id=post.id,
        authorUsername=author_username,
        body=post.body,
        createdAt=post.created_at,
        updatedAt=updated_at,
        likeCount=like_count,
        likedByMe=liked_by_me,
        commentCount=comment_count,
        attachments=[_attachment_out(a) for a in (attachments or [])],
        comments=[_comment_out(c, uname) for c, uname in (comments or [])],
        tags=tags or [],
        isArchived=is_archived,
        canEdit=can_edit,
        canArchive=can_archive,
        canDelete=can_delete,
        canReport=can_report,
    )


@router.post('/community/posts', response_model=Dict[str, CommunityPostOut], status_code=status.HTTP_201_CREATED)
async def create_post(
    body: str = Form(...),
    files: List[UploadFile] = File(default=[]),
    tags: Optional[List[str]] = Form(default=None),
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
    event_store: EventStore = Depends(get_event_store),
) -> Dict[str, CommunityPostOut]:
    user = await _get_user(session, db)
    post = CommunityPost(author_id=user.id, body=body)
    db.add(post)
    await db.flush()

    saved_attachments: List[CommunityAttachment] = []
    for up in files:
        content = await up.read()
        if not content:
            continue
        att = CommunityAttachment(post_id=post.id, filename=up.filename or 'file', content_type=up.content_type or 'application/octet-stream', data=content)
        db.add(att)
        # flush so that defaults like primary key are populated
        await db.flush()
        saved_attachments.append(att)
        # Attempt to upload to Supabase Storage if configured
        try:
            storage = get_supabase_storage()
            if storage is not None:
                path = build_attachment_path(post.id, att.id, att.filename)
                storage.upload(path=path, content=content, content_type=att.content_type, upsert=True)
        except Exception:
            # Do not fail post creation if external upload fails
            pass

    # Handle tags (collect display names eagerly to avoid async lazy-load later)
    normalized_tags: List[str] = []
    tag_display_names: List[str] = []
    if tags:
        normalized_tags = [t.strip().lower().lstrip('#') for t in tags if t and t.strip()]
    else:
        # fallback: extract hashtags from body
        import re
        candidates = set(m.group(2).lower() for m in re.finditer(r'(^|\s)#([\w\d_]+)', body))
        normalized_tags = [t for t in candidates if t]
    if normalized_tags:
        normalized_tags = list({t for t in normalized_tags if t})
        for tag_name in normalized_tags:
            existing = await db.scalar(select(CommunityTag).where(CommunityTag.name == tag_name))
            if not existing:
                display = tag_name
                existing = CommunityTag(name=tag_name, display_name=display)
                db.add(existing)
                await db.flush()
            post.tags.append(existing)
            tag_display_names.append(existing.display_name)

    await db.commit()
    await db.refresh(post)

    try:
        await event_store.record(event_type='community_post', username=user.username, role=session.role)
    except Exception:
        pass

    like_count = 0
    liked_by_me = False
    comment_count = 0

    return {'post': _post_out(post, user.username, like_count, liked_by_me, comment_count, attachments=saved_attachments, tags=tag_display_names, is_archived=False, updated_at=None, can_edit=True, can_archive=True, can_delete=True, can_report=False)}


@router.get('/community/posts', response_model=CommunityFeedResponse)
async def list_posts(
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
    limit: int = 20,
    before: Optional[datetime] = None,
    q: Optional[str] = None,
    sort: Optional[str] = 'latest',
) -> CommunityFeedResponse:
    if limit > 100:
        limit = 100

    sort = (sort or 'latest').lower()
    if sort not in {'latest', 'oldest', 'most_liked', 'random'}:
        sort = 'latest'

    # Base query with eager loads
    query = select(CommunityPost).options(
        selectinload(CommunityPost.attachments),
        selectinload(CommunityPost.tags),
        selectinload(CommunityPost.meta)
    )

    # Optional text search (simple)
    if q:
        query = query.where(CommunityPost.body.ilike(f'%{q}%'))

    # Sorting and pagination
    if sort == 'latest':
        if before is not None:
            query = query.where(CommunityPost.created_at < before)
        query = query.order_by(CommunityPost.created_at.desc()).limit(limit + 1)
    elif sort == 'oldest':
        query = query.order_by(CommunityPost.created_at.asc()).limit(limit + 1)
    elif sort == 'most_liked':
        from sqlalchemy import func as _func
        like_counts = select(CommunityLike.post_id, _func.count(CommunityLike.id).label('lc')).group_by(CommunityLike.post_id).subquery()
        query = query.outerjoin(like_counts, CommunityPost.id == like_counts.c.post_id).order_by(like_counts.c.lc.desc().nullslast(), CommunityPost.created_at.desc()).limit(limit + 1)
    else:  # random
        from sqlalchemy import func as _func
        query = query.order_by(_func.random()).limit(limit + 1)

    result = await db.execute(query)
    rows = result.scalars().unique().all()

    has_more = len(rows) > limit
    posts = rows[:limit]

    author_ids = {p.author_id for p in posts}
    authors = {}
    if author_ids:
        res = await db.execute(select(UserAccount.id, UserAccount.username).where(UserAccount.id.in_(author_ids)))
        authors = {id_: username for id_, username in res.tuples().all()}

    like_counts = {}
    my_likes = set()
    comment_counts = {}

    if posts:
        pid_list = [p.id for p in posts]
        res = await db.execute(select(CommunityLike.post_id, func.count(CommunityLike.id)).where(CommunityLike.post_id.in_(pid_list)).group_by(CommunityLike.post_id))
        like_counts = {pid: int(count) for pid, count in res.tuples().all()}

        res = await db.execute(select(CommunityLike.post_id).join(UserAccount, UserAccount.id == CommunityLike.user_id).where(CommunityLike.post_id.in_(pid_list), UserAccount.username == session.username))
        my_likes = {pid for (pid,) in res.tuples().all()}

        res = await db.execute(select(CommunityComment.post_id, func.count(CommunityComment.id)).where(CommunityComment.post_id.in_(pid_list)).group_by(CommunityComment.post_id))
        comment_counts = {pid: int(count) for pid, count in res.tuples().all()}

    items: List[CommunityPostOut] = []
    for p in posts:
        is_archived = bool(p.meta.archived) if p.meta else False
        updated_at = p.meta.updated_at if p.meta else None
        me_is_author = authors.get(p.author_id, 'unknown') == session.username
        can_edit = me_is_author or session.role == 'admin'
        can_archive = can_edit
        can_delete = can_edit
        can_report = not me_is_author
        items.append(
            _post_out(
                p,
                authors.get(p.author_id, 'unknown'),
                like_counts.get(p.id, 0),
                p.id in my_likes,
                comment_counts.get(p.id, 0),
                attachments=p.attachments,
                tags=[t.display_name for t in (p.tags or [])],
                is_archived=is_archived,
                updated_at=updated_at,
                can_edit=can_edit,
                can_archive=can_archive,
                can_delete=can_delete,
                can_report=can_report,
            )
        )

    # Only provide cursor when using 'latest' sort; others return a single page (no cursor)
    next_cursor = items[-1].createdAt if (sort == 'latest' and has_more and items) else None
    return CommunityFeedResponse(posts=items, nextCursor=next_cursor)


@router.get('/community/my-posts', response_model=Dict[str, List[CommunityPostOut]])
async def list_my_posts(
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, List[CommunityPostOut]]:
    user = await _get_user(session, db)
    result = await db.execute(
        select(CommunityPost)
        .options(selectinload(CommunityPost.attachments), selectinload(CommunityPost.tags), selectinload(CommunityPost.meta))
        .where(CommunityPost.author_id == user.id)
        .order_by(CommunityPost.created_at.desc())
        .limit(100)
    )
    posts = result.scalars().unique().all()

    pid_list = [p.id for p in posts]

    like_counts = {}
    my_likes = set(pid_list)
    comment_counts = {}

    if pid_list:
        res = await db.execute(select(CommunityLike.post_id, func.count(CommunityLike.id)).where(CommunityLike.post_id.in_(pid_list)).group_by(CommunityLike.post_id))
        like_counts = {pid: int(count) for pid, count in res.tuples().all()}
        res = await db.execute(select(CommunityComment.post_id, func.count(CommunityComment.id)).where(CommunityComment.post_id.in_(pid_list)).group_by(CommunityComment.post_id))
        comment_counts = {pid: int(count) for pid, count in res.tuples().all()}

    items: List[CommunityPostOut] = []
    for p in posts:
        is_archived = bool(p.meta.archived) if p.meta else False
        updated_at = p.meta.updated_at if p.meta else None
        items.append(
            _post_out(
                p,
                user.username,
                like_counts.get(p.id, 0),
                p.id in my_likes,
                comment_counts.get(p.id, 0),
                attachments=p.attachments,
                tags=[t.display_name for t in (p.tags or [])],
                is_archived=is_archived,
                updated_at=updated_at,
                can_edit=True,
                can_archive=True,
                can_delete=True,
                can_report=False,
            )
        )

    return {'posts': items}


@router.get('/community/attachments/{attachment_id}')
async def get_attachment(
    attachment_id: str,
    _: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Response:
    att = await db.scalar(select(CommunityAttachment).where(CommunityAttachment.id == attachment_id))
    if not att:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Attachment not found')
    return StreamingResponse(iter([att.data]), media_type=att.content_type, headers={
        'Content-Disposition': f'inline; filename="{att.filename}"'
    })


@router.post('/community/posts/{post_id}/like', status_code=status.HTTP_204_NO_CONTENT)
async def like_post(
    post_id: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await _get_user(session, db)
    exists = await db.scalar(select(CommunityLike.id).where(CommunityLike.post_id == post_id, CommunityLike.user_id == user.id))
    if not exists:
        db.add(CommunityLike(post_id=post_id, user_id=user.id))
        await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete('/community/posts/{post_id}/like', status_code=status.HTTP_204_NO_CONTENT)
async def unlike_post(
    post_id: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await _get_user(session, db)
    row = await db.scalar(select(CommunityLike).where(CommunityLike.post_id == post_id, CommunityLike.user_id == user.id))
    if row:
        await db.delete(row)
        await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get('/community/posts/{post_id}/likes', response_model=Dict[str, List[str]])
async def list_likes(
    post_id: str,
    _: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, List[str]]:
    result = await db.execute(
        select(UserAccount.username)
        .join(CommunityLike, CommunityLike.user_id == UserAccount.id)
        .where(CommunityLike.post_id == post_id)
        .order_by(CommunityLike.created_at.asc())
        .limit(500)
    )
    usernames = [uname for (uname,) in result.tuples().all()]
    return {'likes': usernames}

@router.post('/community/posts/{post_id}/comments', response_model=Dict[str, CommunityCommentOut], status_code=status.HTTP_201_CREATED)
async def add_comment(
    post_id: str,
    payload: CreateCommentPayload,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, CommunityCommentOut]:
    user = await _get_user(session, db)
    exists = await db.scalar(select(CommunityPost.id).where(CommunityPost.id == post_id))
    if not exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Post not found')
    comment = CommunityComment(post_id=post_id, user_id=user.id, body=payload.body)
    db.add(comment)
    await db.commit()
    await db.refresh(comment)
    return {'comment': _comment_out(comment, user.username)}


@router.get('/community/posts/{post_id}/comments', response_model=Dict[str, List[CommunityCommentOut]])
async def list_comments(
    post_id: str,
    _: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, List[CommunityCommentOut]]:
    result = await db.execute(
        select(CommunityComment, UserAccount.username)
        .join(UserAccount, UserAccount.id == CommunityComment.user_id)
        .where(CommunityComment.post_id == post_id)
        .order_by(CommunityComment.created_at.asc())
        .limit(200)
    )
    items = [_comment_out(c, username) for c, username in result.all()]
    return {'comments': items}


@router.put('/community/posts/{post_id}', response_model=Dict[str, CommunityPostOut])
async def update_post(
    post_id: str,
    payload: UpdatePostPayload,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, CommunityPostOut]:
    user = await _get_user(session, db)
    post = await db.scalar(select(CommunityPost).options(selectinload(CommunityPost.tags), selectinload(CommunityPost.meta)).where(CommunityPost.id == post_id))
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Post not found')
    if post.author_id != user.id and session.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not allowed')
    post.body = payload.body
    # upsert meta to bump updated_at
    if not post.meta:
        post.meta = CommunityPostMeta(post_id=post.id, archived=False)
    # update tags if provided
    if payload.tags is not None:
        normalized = list({t.strip().lower().lstrip('#') for t in payload.tags if t and t.strip()})
        # clear existing
        post.tags.clear()
        for tag_name in normalized:
            existing = await db.scalar(select(CommunityTag).where(CommunityTag.name == tag_name))
            if not existing:
                existing = CommunityTag(name=tag_name, display_name=tag_name)
                db.add(existing)
                await db.flush()
            post.tags.append(existing)
    await db.commit()
    await db.refresh(post)
    author_username = (await db.scalar(select(UserAccount.username).where(UserAccount.id == post.author_id))) or 'unknown'
    like_count = int((await db.scalar(select(func.count(CommunityLike.id)).where(CommunityLike.post_id == post.id))) or 0)
    comment_count = int((await db.scalar(select(func.count(CommunityComment.id)).where(CommunityComment.post_id == post.id))) or 0)
    # notify admins and author
    admin_ids = [uid for (uid,) in (await db.execute(select(UserAccount.id).where(UserAccount.role == 'admin'))).tuples().all()]
    recipients = set(admin_ids + [post.author_id])
    for uid in recipients:
        db.add(Notification(user_id=uid, type='community_post_edited', data={'postId': post.id, 'author': author_username}))
    await db.commit()
    return {'post': _post_out(post, author_username, like_count, False, comment_count, attachments=[], tags=[t.display_name for t in (post.tags or [])], is_archived=bool(post.meta.archived) if post.meta else False, updated_at=post.meta.updated_at if post.meta else None, can_edit=True, can_archive=True, can_delete=True, can_report=False)}


@router.post('/community/posts/{post_id}/archive', response_model=Dict[str, CommunityPostOut])
async def archive_post(
    post_id: str,
    payload: ArchivePostPayload,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, CommunityPostOut]:
    user = await _get_user(session, db)
    post = await db.scalar(select(CommunityPost).options(selectinload(CommunityPost.tags), selectinload(CommunityPost.meta), selectinload(CommunityPost.attachments)).where(CommunityPost.id == post_id))
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Post not found')
    if post.author_id != user.id and session.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not allowed')
    if not post.meta:
        post.meta = CommunityPostMeta(post_id=post.id, archived=payload.archive)
    else:
        post.meta.archived = payload.archive
    await db.commit()
    await db.refresh(post)
    author_username = (await db.scalar(select(UserAccount.username).where(UserAccount.id == post.author_id))) or 'unknown'
    like_count = int((await db.scalar(select(func.count(CommunityLike.id)).where(CommunityLike.post_id == post.id))) or 0)
    comment_count = int((await db.scalar(select(func.count(CommunityComment.id)).where(CommunityComment.post_id == post.id))) or 0)
    return {'post': _post_out(post, author_username, like_count, False, comment_count, attachments=post.attachments, tags=[t.display_name for t in (post.tags or [])], is_archived=bool(post.meta.archived) if post.meta else False, updated_at=post.meta.updated_at if post.meta else None, can_edit=True, can_archive=True, can_delete=True, can_report=False)}


@router.post('/community/posts/{post_id}/attachments', response_model=Dict[str, CommunityPostOut])
async def add_attachments(
    post_id: str,
    files: List[UploadFile] = File(default=[]),
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, CommunityPostOut]:
    user = await _get_user(session, db)
    post = await db.scalar(select(CommunityPost).options(selectinload(CommunityPost.attachments), selectinload(CommunityPost.tags), selectinload(CommunityPost.meta)).where(CommunityPost.id == post_id))
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Post not found')
    if post.author_id != user.id and session.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not allowed')

    storage = get_supabase_storage()

    for up in files:
        content = await up.read()
        if not content:
            continue
        att = CommunityAttachment(post_id=post.id, filename=up.filename or 'file', content_type=up.content_type or 'application/octet-stream', data=content)
        db.add(att)
        await db.flush()
        try:
            if storage is not None:
                path = build_attachment_path(post.id, att.id, att.filename)
                storage.upload(path=path, content=content, content_type=att.content_type, upsert=True)
        except Exception:
            pass

    await db.commit()
    await db.refresh(post)

    author_username = (await db.scalar(select(UserAccount.username).where(UserAccount.id == post.author_id))) or 'unknown'
    like_count = int((await db.scalar(select(func.count(CommunityLike.id)).where(CommunityLike.post_id == post.id))) or 0)
    comment_count = int((await db.scalar(select(func.count(CommunityComment.id)).where(CommunityComment.post_id == post.id))) or 0)
    return {'post': _post_out(post, author_username, like_count, False, comment_count, attachments=post.attachments, tags=[t.display_name for t in (post.tags or [])], is_archived=bool(post.meta.archived) if post.meta else False, updated_at=post.meta.updated_at if post.meta else None, can_edit=True, can_archive=True, can_delete=True, can_report=False)}


@router.delete('/community/posts/{post_id}/attachments/{attachment_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_attachment(
    post_id: str,
    attachment_id: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await _get_user(session, db)
    att = await db.scalar(select(CommunityAttachment).where(CommunityAttachment.id == attachment_id, CommunityAttachment.post_id == post_id))
    if not att:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    # verify ownership via post
    post = await db.scalar(select(CommunityPost).where(CommunityPost.id == post_id))
    if not post:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    if post.author_id != user.id and session.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not allowed')

    try:
        storage = get_supabase_storage()
        if storage is not None:
            path = build_attachment_path(post_id, att.id, att.filename)
            storage.delete(path)
    except Exception:
        pass

    await db.delete(att)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete('/community/posts/{post_id}', status_code=status.HTTP_204_NO_CONTENT)
async def delete_post(
    post_id: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await _get_user(session, db)
    post = await db.scalar(select(CommunityPost).where(CommunityPost.id == post_id))
    if not post:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    if post.author_id != user.id and session.role != 'admin':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Not allowed')

    # collect attachments to delete from external storage if configured
    atts = (await db.execute(select(CommunityAttachment).where(CommunityAttachment.post_id == post_id))).scalars().all()
    try:
        storage = get_supabase_storage()
        if storage is not None:
            for a in atts:
                path = build_attachment_path(post_id, a.id, a.filename)
                try:
                    storage.delete(path)
                except Exception:
                    pass
    except Exception:
        pass

    author_username = (await db.scalar(select(UserAccount.username).where(UserAccount.id == post.author_id))) or 'unknown'
    await db.delete(post)
    await db.commit()
    # notify admins and author
    admin_ids = [uid for (uid,) in (await db.execute(select(UserAccount.id).where(UserAccount.role == 'admin'))).tuples().all()]
    recipients = set(admin_ids + [user.id])
    for uid in recipients:
        db.add(Notification(user_id=uid, type='community_post_deleted', data={'postId': post_id, 'author': author_username}))
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post('/community/posts/{post_id}/report', status_code=status.HTTP_204_NO_CONTENT)
async def report_post(
    post_id: str,
    payload: ReportPostPayload,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Response:
    user = await _get_user(session, db)
    post = await db.scalar(select(CommunityPost).where(CommunityPost.id == post_id))
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Post not found')
    if post.author_id == user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Cannot report your own post')
    from ..models import CommunityPostReport
    report = CommunityPostReport(post_id=post_id, reporter_id=user.id, category=payload.category, reason=payload.reason or '')
    db.add(report)
    await db.commit()
    # notify admins and author
    author_username = (await db.scalar(select(UserAccount.username).where(UserAccount.id == post.author_id))) or 'unknown'
    admin_ids = [uid for (uid,) in (await db.execute(select(UserAccount.id).where(UserAccount.role == 'admin'))).tuples().all()]
    recipients = set(admin_ids + [post.author_id])
    for uid in recipients:
        db.add(Notification(user_id=uid, type='community_post_reported', data={'postId': post_id, 'author': author_username, 'category': payload.category}))
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get('/community/search/users', response_model=Dict[str, List[Dict]])
async def search_users(
    q: Optional[str] = None,
    limit: int = 20,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, List[Dict]]:
    if not q:
        return {'users': []}

    if limit > 100:
        limit = 100

    query = select(UserAccount).where(UserAccount.username.ilike(f'%{q}%')).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()

    return {'users': [{'username': u.username, 'role': u.role} for u in users]}


@router.get('/community/users/{username}', response_model=Dict[str, object])
async def get_user_profile(
    username: str,
    session: Session = Depends(require_session),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, object]:
    user = await db.scalar(select(UserAccount).where(UserAccount.username == username))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='User not found')

    profile = await db.scalar(select(UserProfile).where(UserProfile.user_id == user.id))

    profile_data = {
        'username': user.username,
        'role': user.role,
        'email': profile.email if profile else None,
        'emailVerifiedAt': profile.email_verified_at if profile else None,
        'phoneE164': profile.phone_e164 if profile else None,
        'phoneVerifiedAt': profile.phone_verified_at if profile else None,
        'firstName': profile.first_name if profile else None,
        'lastName': profile.last_name if profile else None,
        'displayName': profile.display_name if profile else None,
        'avatarUrl': profile.avatar_url if profile else None,
        'bio': profile.bio if profile else None,
        'timezone': profile.timezone if profile else None,
    }

    result = await db.execute(
        select(CommunityPost)
        .options(selectinload(CommunityPost.attachments), selectinload(CommunityPost.tags), selectinload(CommunityPost.meta))
        .where(CommunityPost.author_id == user.id)
        .order_by(CommunityPost.created_at.desc())
        .limit(100)
    )
    posts = result.scalars().unique().all()

    pid_list = [p.id for p in posts]

    like_counts = {}
    my_likes = set()
    comment_counts = {}

    current_user = await _get_user(session, db)

    if pid_list:
        res = await db.execute(select(CommunityLike.post_id, func.count(CommunityLike.id)).where(CommunityLike.post_id.in_(pid_list)).group_by(CommunityLike.post_id))
        like_counts = {pid: int(count) for pid, count in res.tuples().all()}

        res = await db.execute(select(CommunityLike.post_id).join(UserAccount, UserAccount.id == CommunityLike.user_id).where(CommunityLike.post_id.in_(pid_list), UserAccount.id == current_user.id))
        my_likes = {pid for (pid,) in res.tuples().all()}

        res = await db.execute(select(CommunityComment.post_id, func.count(CommunityComment.id)).where(CommunityComment.post_id.in_(pid_list)).group_by(CommunityComment.post_id))
        comment_counts = {pid: int(count) for pid, count in res.tuples().all()}

    posts_out = []
    for p in posts:
        is_archived = bool(p.meta.archived) if p.meta else False
        updated_at = p.meta.updated_at if p.meta else None
        me_is_author = current_user.id == p.author_id
        can_edit = me_is_author or session.role == 'admin'
        can_archive = can_edit
        can_delete = can_edit
        can_report = not me_is_author
        posts_out.append(
            _post_out(
                p,
                user.username,
                like_counts.get(p.id, 0),
                p.id in my_likes,
                comment_counts.get(p.id, 0),
                attachments=p.attachments,
                tags=[t.display_name for t in (p.tags or [])],
                is_archived=is_archived,
                updated_at=updated_at,
                can_edit=can_edit,
                can_archive=can_archive,
                can_delete=can_delete,
                can_report=can_report,
            )
        )

    return {'profile': profile_data, 'posts': posts_out}
