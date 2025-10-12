from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class UserAccount(Base):
    __tablename__ = 'user_accounts'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Conversation(Base):
    __tablename__ = 'conversations'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key: Mapped[str] = mapped_column(String, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    participants: Mapped[List['Participant']] = relationship(back_populates='conversation', cascade='all, delete-orphan')
    messages: Mapped[List['MessageRow']] = relationship(back_populates='conversation', cascade='all, delete-orphan')


class Participant(Base):
    __tablename__ = 'participants'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    conversation_id: Mapped[str] = mapped_column(ForeignKey('conversations.id', ondelete='CASCADE'), index=True)
    username: Mapped[str] = mapped_column(String, index=True)
    role: Mapped[str] = mapped_column(String)
    conversation: Mapped[Conversation] = relationship(back_populates='participants')

    __table_args__ = (
        UniqueConstraint('conversation_id', 'username', name='uq_participant'),
    )


class MessageRow(Base):
    __tablename__ = 'messages'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    conversation_id: Mapped[str] = mapped_column(ForeignKey('conversations.id', ondelete='CASCADE'), index=True)
    sender_username: Mapped[str] = mapped_column(String)
    sender_role: Mapped[str] = mapped_column(String)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    conversation: Mapped[Conversation] = relationship(back_populates='messages')


class MessageRead(Base):
    __tablename__ = 'message_reads'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    message_id: Mapped[str] = mapped_column(ForeignKey('messages.id', ondelete='CASCADE'), index=True)
    username: Mapped[str] = mapped_column(String, index=True)
    read_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint('message_id', 'username', name='uq_message_read'),
    )


class UserProfile(Base):
    __tablename__ = 'user_profiles'

    user_id: Mapped[int] = mapped_column(ForeignKey('user_accounts.id', ondelete='CASCADE'), primary_key=True)

    email: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True, index=True)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    phone_e164: Mapped[Optional[str]] = mapped_column(String(32), unique=True, nullable=True, index=True)
    phone_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    verify_email_code_hash: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    verify_phone_code_hash: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    verify_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verify_requested_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    first_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    last_name: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    display_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    bio: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timezone: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    locale: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    marketing_opt_in: Mapped[bool] = mapped_column(Boolean, default=False, server_default='0')
    notify_prefs: Mapped[dict] = mapped_column(JSON, default=dict, server_default='{}')

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user: Mapped[UserAccount] = relationship('UserAccount')


class EventLog(Base):
    __tablename__ = 'event_logs'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type: Mapped[str] = mapped_column(String(16), index=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class CommunityPost(Base):
    __tablename__ = 'community_posts'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    author_id: Mapped[int] = mapped_column(ForeignKey('user_accounts.id', ondelete='CASCADE'), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    author: Mapped[UserAccount] = relationship('UserAccount')
    attachments: Mapped[List['CommunityAttachment']] = relationship(back_populates='post', cascade='all, delete-orphan')
    likes: Mapped[List['CommunityLike']] = relationship(back_populates='post', cascade='all, delete-orphan')
    comments: Mapped[List['CommunityComment']] = relationship(back_populates='post', cascade='all, delete-orphan')
    meta: Mapped[Optional['CommunityPostMeta']] = relationship('CommunityPostMeta', back_populates='post', cascade='all, delete-orphan', uselist=False)
    reports: Mapped[List['CommunityPostReport']] = relationship('CommunityPostReport', back_populates='post', cascade='all, delete-orphan')
    tags: Mapped[List['CommunityTag']] = relationship('CommunityTag', secondary='community_post_tags', back_populates='posts')


class CommunityAttachment(Base):
    __tablename__ = 'community_attachments'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    post_id: Mapped[str] = mapped_column(ForeignKey('community_posts.id', ondelete='CASCADE'), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(128))
    data: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    post: Mapped[CommunityPost] = relationship(back_populates='attachments')


class CommunityLike(Base):
    __tablename__ = 'community_likes'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    post_id: Mapped[str] = mapped_column(ForeignKey('community_posts.id', ondelete='CASCADE'), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user_accounts.id', ondelete='CASCADE'), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    post: Mapped[CommunityPost] = relationship(back_populates='likes')

    __table_args__ = (
        UniqueConstraint('post_id', 'user_id', name='uq_like_once'),
    )


class CommunityComment(Base):
    __tablename__ = 'community_comments'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    post_id: Mapped[str] = mapped_column(ForeignKey('community_posts.id', ondelete='CASCADE'), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('user_accounts.id', ondelete='CASCADE'), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    post: Mapped[CommunityPost] = relationship(back_populates='comments')


class CommunityPostMeta(Base):
    __tablename__ = 'community_post_meta'

    post_id: Mapped[str] = mapped_column(ForeignKey('community_posts.id', ondelete='CASCADE'), primary_key=True)
    archived: Mapped[bool] = mapped_column(Boolean, default=False, server_default='0', nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    post: Mapped[CommunityPost] = relationship('CommunityPost', back_populates='meta')


class CommunityPostReport(Base):
    __tablename__ = 'community_post_reports'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    post_id: Mapped[str] = mapped_column(ForeignKey('community_posts.id', ondelete='CASCADE'), index=True)
    reporter_id: Mapped[int] = mapped_column(ForeignKey('user_accounts.id', ondelete='CASCADE'), index=True)
    category: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    post: Mapped[CommunityPost] = relationship('CommunityPost', back_populates='reports')
    reporter: Mapped[UserAccount] = relationship('UserAccount')


class CommunityTag(Base):
    __tablename__ = 'community_tags'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    posts: Mapped[List[CommunityPost]] = relationship('CommunityPost', secondary='community_post_tags', back_populates='tags')


class CommunityPostTag(Base):
    __tablename__ = 'community_post_tags'

    post_id: Mapped[str] = mapped_column(ForeignKey('community_posts.id', ondelete='CASCADE'), primary_key=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey('community_tags.id', ondelete='CASCADE'), primary_key=True)
    __table_args__ = (
        UniqueConstraint('post_id', 'tag_id', name='uq_post_tag'),
    )


class Notification(Base):
    __tablename__ = 'notifications'

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[int] = mapped_column(ForeignKey('user_accounts.id', ondelete='CASCADE'), index=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict, server_default='{}')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
