import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from app.dependencies import get_current_user
from app.models import User
from app.schemas import VideoCaseManifest

router = APIRouter(prefix="/video-cases", tags=["video cases"])
MANIFEST_PATH = Path(__file__).resolve().parents[1] / "video_cases" / "manifest.json"


@router.get("", response_model=VideoCaseManifest)
def list_video_cases(_: User = Depends(get_current_user)) -> VideoCaseManifest:
    try:
        payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        return VideoCaseManifest.model_validate(payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="离线视频案例基准尚未生成") from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="离线视频案例基准文件无效") from exc
