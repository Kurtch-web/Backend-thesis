from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

UserRole = Literal['user', 'admin']


class LoginPayload(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)
    role: UserRole


class LoginResponse(BaseModel):
    token: str
    role: UserRole
    username: str
    message: str


class OnlineUser(BaseModel):
    username: str
    role: UserRole
    lastSeen: datetime


class UserInfo(BaseModel):
    username: str
    role: UserRole
    online: bool
    lastSeen: Optional[datetime] = None


class PresenceOverview(BaseModel):
    admins: List[UserInfo]
    users: List[UserInfo]


class PresenceEvent(BaseModel):
    id: str
    username: str
    role: UserRole
    type: Literal['login', 'logout', 'signup', 'community_post']
    timestamp: datetime


class SignupPayload(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=6, max_length=128)


class SignupResponse(BaseModel):
    username: str
    message: str


class ParticipantRef(BaseModel):
    username: str
    role: UserRole


class ConversationOut(BaseModel):
    id: str
    participants: List[ParticipantRef]
    lastMessageAt: Optional[datetime]
    lastMessagePreview: Optional[str]
    unreadCount: int


class MessageOut(BaseModel):
    id: str
    conversationId: str
    sender: ParticipantRef
    body: str
    createdAt: datetime
    readBy: List[str] = Field(default_factory=list)


class SendMessagePayload(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


# Profile API
class UserProfileOut(BaseModel):
    username: str
    role: UserRole
    email: Optional[str] = None
    emailVerifiedAt: Optional[datetime] = None
    phoneE164: Optional[str] = None
    phoneVerifiedAt: Optional[datetime] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    displayName: Optional[str] = None
    avatarUrl: Optional[str] = None
    bio: Optional[str] = None
    timezone: Optional[str] = None
    locale: Optional[str] = None
    marketingOptIn: bool = False
    notifyPrefs: Dict[str, object] = Field(default_factory=dict)
    updatedAt: Optional[datetime] = None


class UpdateProfilePayload(BaseModel):
    email: Optional[str] = None
    phoneE164: Optional[str] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    displayName: Optional[str] = None
    avatarUrl: Optional[str] = None
    bio: Optional[str] = None
    timezone: Optional[str] = None
    locale: Optional[str] = None
    marketingOptIn: Optional[bool] = None
    notifyPrefs: Optional[Dict[str, object]] = None


class RequestEmailCodePayload(BaseModel):
    email: str


class VerifyEmailPayload(BaseModel):
    code: str = Field(min_length=4, max_length=10)


class RequestSmsCodePayload(BaseModel):
    phoneE164: str


class VerifyPhonePayload(BaseModel):
    code: str = Field(min_length=4, max_length=10)


# Community API
class CommunityAttachmentOut(BaseModel):
    id: str
    filename: str
    contentType: str
    url: str


class CommunityCommentOut(BaseModel):
    id: str
    authorUsername: str
    body: str
    createdAt: datetime


class CommunityPostOut(BaseModel):
    id: str
    authorUsername: str
    body: str
    createdAt: datetime
    updatedAt: Optional[datetime] = None
    likeCount: int
    likedByMe: bool
    commentCount: int
    attachments: List[CommunityAttachmentOut] = Field(default_factory=list)
    comments: List[CommunityCommentOut] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    isArchived: bool = False
    canEdit: bool = False
    canArchive: bool = False
    canDelete: bool = False
    canReport: bool = False


class CommunityFeedResponse(BaseModel):
    posts: List[CommunityPostOut]
    nextCursor: Optional[datetime] = None


class CreateCommentPayload(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class UpdatePostPayload(BaseModel):
    body: str = Field(min_length=1, max_length=10000)
    tags: Optional[List[str]] = None


class ArchivePostPayload(BaseModel):
    archive: bool


CommunityReportCategory = Literal['spam', 'harassment', 'misinformation', 'off_topic', 'other']


class ReportPostPayload(BaseModel):
    category: CommunityReportCategory
    reason: Optional[str] = Field(default=None, max_length=2000)


class NotificationOut(BaseModel):
    id: str
    type: str
    data: Dict[str, object]
    createdAt: datetime
    readAt: Optional[datetime] = None


class NotificationList(BaseModel):
    notifications: List[NotificationOut]
