from datetime import datetime, timezone
from datetime import datetime, timezone
from typing import List

from ..schemas import OnlineUser, PresenceOverview, UserInfo
from .users import UserStore


async def build_presence_overview(user_store: UserStore, active_users: List[OnlineUser]) -> PresenceOverview:
    online_index = {entry.username.lower(): entry for entry in active_users}
    admin_bucket: List[UserInfo] = []
    member_bucket: List[UserInfo] = []

    for record in await user_store.all_users():
        key = record.username.lower()
        online_entry = online_index.get(key)
        info = UserInfo(
            username=record.username,
            role=record.role,
            online=online_entry is not None,
            lastSeen=online_entry.lastSeen if online_entry else None
        )
        if record.role == 'admin':
            admin_bucket.append(info)
        else:
            member_bucket.append(info)

    def sort_bucket(bucket: List[UserInfo]) -> None:
        bucket.sort(
            key=lambda item: (
                1 if item.online else 0,
                item.lastSeen or datetime.min.replace(tzinfo=timezone.utc)
            ),
            reverse=True
        )

    sort_bucket(admin_bucket)
    sort_bucket(member_bucket)
    return PresenceOverview(admins=admin_bucket, users=member_bucket)
