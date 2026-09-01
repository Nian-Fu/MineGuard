import asyncio
import json
from time import monotonic, time
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import StreamingResponse

from app.core.config import get_settings
from app.dependencies import get_streaming_user
from app.models import User
from app.services.realtime import (
    REALTIME_TOPICS,
    latest_realtime_signal_id,
    load_realtime_signals,
    realtime_session_active,
    signal_visible_to_scope,
)
from app.services.permissions import area_scope

router = APIRouter(prefix="/realtime", tags=["realtime"])


@router.get("/stream")
async def realtime_stream(
    request: Request,
    last_event_id: Annotated[
        str | None, Header(alias="Last-Event-ID", max_length=20)
    ] = None,
    user: User = Depends(get_streaming_user),
) -> StreamingResponse:
    try:
        requested_cursor = max(int(last_event_id), 0) if last_event_id is not None else None
    except ValueError:
        requested_cursor = None
    access_token_expires_at = float(request.state.access_token_expires_at)
    if access_token_expires_at - time() <= 5:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token is about to expire",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_id = user.id
    auth_version = user.auth_version
    scope = area_scope(user)

    async def generate():
        latest_cursor = await asyncio.to_thread(latest_realtime_signal_id)
        cursor = (
            min(requested_cursor, latest_cursor)
            if requested_cursor is not None
            else latest_cursor
        )
        started = monotonic()
        settings = get_settings()
        max_lifetime = min(
            settings.realtime_stream_max_seconds,
            max(access_token_expires_at - time() - 5, 0),
        )
        yield f"id: {cursor}\nevent: ready\ndata: {{}}\nretry: 3000\n\n"
        last_keepalive = monotonic()
        next_authorization_check = monotonic()
        while (
            monotonic() - started < max_lifetime
            and not await request.is_disconnected()
        ):
            if monotonic() >= next_authorization_check:
                if not await asyncio.to_thread(
                    realtime_session_active, user_id, auth_version
                ):
                    return
                next_authorization_check = monotonic() + 5
            signals = await asyncio.to_thread(load_realtime_signals, cursor)
            if signals:
                for signal in signals:
                    cursor = int(signal["id"])
                    if not signal_visible_to_scope(signal, scope):
                        continue
                    data = json.dumps(signal, ensure_ascii=False, separators=(",", ":"))
                    event_type = (
                        signal["topic"] if signal["topic"] in REALTIME_TOPICS else "system"
                    )
                    yield f"id: {cursor}\nevent: {event_type}\ndata: {data}\n\n"
                continue
            if monotonic() - last_keepalive >= 15:
                yield ": keepalive\n\n"
                last_keepalive = monotonic()
            await asyncio.sleep(settings.realtime_stream_poll_seconds)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
