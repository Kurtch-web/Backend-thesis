import os
import os
import re
import urllib.parse
import urllib.request
from typing import Optional

# This module provides minimal Supabase Storage interactions via HTTP without extra deps.
# It expects the following env vars (already loaded by config.load_dotenv()):
# - SUPABASE_URL
# - SUPABASE_BUCKET
# - SUPABASE_SERVICE_ROLE_KEY


_filename_sanitize_re = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize_filename(name: str) -> str:
    base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    base = base.strip() or "file"
    # collapse disallowed chars to '-'
    base = _filename_sanitize_re.sub("-", base)
    # prevent hidden files issues
    if base.startswith('.'):
        base = base.lstrip('.') or 'file'
    # limit length
    return base[:200]


class SupabaseStorage:
    def __init__(self, url: str, bucket: str, service_role_key: str) -> None:
        self.url = url.rstrip('/')
        self.bucket = bucket
        self.key = service_role_key

    def object_url(self, path: str, public: bool = False) -> str:
        encoded_path = urllib.parse.quote(path)
        if public:
            return f"{self.url}/storage/v1/object/public/{self.bucket}/{encoded_path}"
        return f"{self.url}/storage/v1/object/{self.bucket}/{encoded_path}"

    def upload(self, path: str, content: bytes, content_type: str, upsert: bool = True) -> None:
        req = urllib.request.Request(
            self.object_url(path),
            data=content,
            method='POST',
            headers={
                'Authorization': f'Bearer {self.key}',
                'Content-Type': content_type or 'application/octet-stream',
                'x-upsert': 'true' if upsert else 'false',
            },
        )
        # Supabase responds with JSON but we don't need it here
        with urllib.request.urlopen(req) as resp:  # noqa: S310 - trusted URL from env
            # Read to ensure request completes
            _ = resp.read()

    def public_url(self, path: str) -> str:
        return self.object_url(path, public=True)

    def delete(self, path: str) -> None:
        req = urllib.request.Request(
            self.object_url(path),
            method='DELETE',
            headers={
                'Authorization': f'Bearer {self.key}',
            },
        )
        with urllib.request.urlopen(req) as resp:  # noqa: S310 - trusted URL from env
            _ = resp.read()


def get_supabase_storage() -> Optional[SupabaseStorage]:
    url = os.getenv('SUPABASE_URL')
    bucket = os.getenv('SUPABASE_BUCKET')
    key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
    if not url or not bucket or not key:
        return None
    return SupabaseStorage(url=url, bucket=bucket, service_role_key=key)


def build_attachment_path(post_id: str, attachment_id: str, original_filename: str) -> str:
    safe_name = _sanitize_filename(original_filename or 'file')
    return f"community/{post_id}/{attachment_id}/{safe_name}"
