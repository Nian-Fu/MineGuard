import math

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models import FaceTemplate
from app.services.face import TemplateCipher, face_template_associated_data


def rotate_face_templates(db: Session) -> int:
    settings = get_settings()
    if not settings.face_template_key:
        raise RuntimeError("face template encryption key is not configured")
    keyring = {
        version: TemplateCipher(key.get_secret_value())
        for version, key in settings.face_template_previous_keys.items()
    }
    current_cipher = TemplateCipher(
        settings.face_template_key.get_secret_value()
    )
    keyring[settings.face_template_key_version] = current_cipher
    try:
        templates = db.scalars(
            select(FaceTemplate).order_by(FaceTemplate.id).with_for_update()
        ).all()
        validated: list[tuple[FaceTemplate, list[float], bytes]] = []
        for template in templates:
            cipher = keyring.get(template.key_version)
            if cipher is None:
                raise RuntimeError(
                    f"face template key version {template.key_version!r} is unavailable"
                )
            associated_data = face_template_associated_data(
                template.person_id,
                template.model_version,
                template.model_sha256,
            )
            embedding = cipher.decrypt(
                template.encrypted_embedding,
                template.nonce,
                associated_data,
            )
            if not 64 <= len(embedding) <= 2048 or not all(
                math.isfinite(value) for value in embedding
            ):
                raise RuntimeError("face template embedding payload is invalid")
            validated.append((template, embedding, associated_data))

        rotated = 0
        for template, embedding, associated_data in validated:
            if template.key_version == settings.face_template_key_version:
                continue
            encrypted, nonce = current_cipher.encrypt(embedding, associated_data)
            template.encrypted_embedding = encrypted
            template.nonce = nonce
            template.key_version = settings.face_template_key_version
            rotated += 1
        db.commit()
        return rotated
    except Exception:
        db.rollback()
        raise


def main() -> None:
    with SessionLocal() as db:
        rotated = rotate_face_templates(db)
    print(f"face template rotation complete: {rotated} row(s) re-encrypted")


if __name__ == "__main__":
    main()
