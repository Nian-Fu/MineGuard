from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models import Camera
from app.services.camera_urls import camera_url_cipher_from_settings


def rotate_camera_urls(db: Session) -> int:
    settings = get_settings()
    if camera_url_cipher_from_settings(settings) is None:
        raise RuntimeError("camera URL encryption key is not configured")
    try:
        cameras = db.scalars(
            select(Camera).order_by(Camera.id).with_for_update()
        ).all()
        validated = [(camera, camera.stream_url) for camera in cameras]
        rotated = 0
        for camera, plaintext in validated:
            if (
                camera.stream_url_ciphertext is None
                or camera.stream_url_key_version != settings.camera_url_key_version
            ):
                camera.stream_url = plaintext
                rotated += 1
        db.commit()
        return rotated
    except Exception:
        db.rollback()
        raise


def main() -> None:
    with SessionLocal() as db:
        rotated = rotate_camera_urls(db)
    print(f"camera URL rotation complete: {rotated} row(s) re-encrypted")


if __name__ == "__main__":
    main()
