import re
from typing import Annotated
from urllib.parse import unquote, urlsplit

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_media_token
from app.models import Camera, User
from app.services.permissions import can_access_area

router = APIRouter(prefix="/media", tags=["media-authorization"])
MEDIA_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")


@router.get("/authorize", status_code=status.HTTP_204_NO_CONTENT)
def authorize_media(
    original_uri: Annotated[str, Header(alias="X-Original-URI", max_length=500)],
    media_token: Annotated[str | None, Cookie(alias="mineguard_media")] = None,
    db: Session = Depends(get_db),
):
    if not media_token:
        raise HTTPException(status_code=401, detail="Media session missing")
    claims = decode_media_token(media_token)
    if claims.get("type") != "media":
        raise HTTPException(status_code=401, detail="Invalid media session")
    user = db.scalar(select(User).where(User.username == claims["sub"]))
    if not user or not user.active or user.auth_version != claims["ver"]:
        raise HTTPException(status_code=401, detail="Media session was revoked")

    raw_path = urlsplit(original_uri).path
    try:
        path = unquote(raw_path, errors="strict")
    except UnicodeError as exc:
        raise HTTPException(status_code=403, detail="Media path is not allowed") from exc
    parts = path.split("/")
    if (
        not original_uri.startswith("/")
        or original_uri.startswith("//")
        or path != raw_path
        or len(parts) != 4
        or parts[1] != "media"
        or not MEDIA_COMPONENT.fullmatch(parts[2])
        or not MEDIA_COMPONENT.fullmatch(parts[3])
        or "\\" in path
    ):
        raise HTTPException(status_code=403, detail="Media path is not allowed")
    playlist_path = f"/media/{parts[2]}/index.m3u8"
    camera = db.scalar(select(Camera).where(Camera.playback_path == playlist_path))
    if not camera or not can_access_area(user, camera.area):
        raise HTTPException(status_code=403, detail="Media access denied")
