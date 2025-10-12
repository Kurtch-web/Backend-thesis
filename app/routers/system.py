from typing import Dict

from fastapi import APIRouter

from ..utils import utc_now

router = APIRouter()


@router.get('/health', tags=['system'])
async def health_check() -> Dict[str, str]:
    return {'status': 'ok', 'timestamp': utc_now().isoformat()}
