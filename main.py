import os

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import FRONTEND_ORIGIN
from app.db import init_models
from app.routers import auth, chat, presence, system, user, community, notifications, flashcards

app = FastAPI(title='Presence Tracking Service', version='0.2.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.on_event('startup')
async def on_startup() -> None:
    await init_models()


app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(presence.router)
app.include_router(system.router)
app.include_router(user.router)
app.include_router(community.router)
app.include_router(notifications.router)
app.include_router(flashcards.router)


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(
        'main:app',
        host=os.getenv('HOST', '0.0.0.0'),
        port=int(os.getenv('PORT', '8000')),
        reload=os.getenv('RELOAD', 'false').lower() == 'true',
    )
