from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.security import hash_password
from app.models import AlertRule, AlgorithmConfig, Camera, CameraStatus, Event, Person, User
from app.services.permissions import replace_person_area_grants


def seed_database(db: Session) -> None:
    settings = get_settings()
    include_demo_data = settings.environment in {"development", "test"}
    if settings.bootstrap_admin_enabled and not db.scalar(
        select(User).where(
            func.lower(User.username) == settings.bootstrap_admin_username.lower()
        )
    ):
        db.add(
            User(
                username=settings.bootstrap_admin_username,
                full_name="系统管理员",
                password_hash=hash_password(
                    settings.bootstrap_admin_password.get_secret_value()
                ),
                role="admin",
            )
        )
    if include_demo_data and not db.scalar(select(Camera).limit(1)):
        cameras = [
            Camera(code="CAM-001", name="主井口东侧", area="主井口", stream_url="rtsp://source/cam001", playback_path="/media/cam-001/index.m3u8", status=CameraStatus.ONLINE, enabled_algorithms=["face", "intrusion", "helmet"], fps=25, latency_ms=82, last_seen_at=datetime.now(UTC)),
            Camera(code="CAM-002", name="运输巷道 3 号", area="运输巷道", stream_url="rtsp://source/cam002", playback_path="/media/cam-002/index.m3u8", status=CameraStatus.ONLINE, enabled_algorithms=["intrusion", "crowding"], fps=24, latency_ms=96, last_seen_at=datetime.now(UTC)),
            Camera(code="CAM-003", name="炸药库入口", area="高危禁区", stream_url="rtsp://source/cam003", playback_path="/media/cam-003/index.m3u8", status=CameraStatus.DEGRADED, enabled_algorithms=["face", "intrusion"], fps=12, latency_ms=280, last_seen_at=datetime.now(UTC) - timedelta(minutes=2)),
            Camera(code="CAM-004", name="洗煤车间北区", area="洗煤车间", stream_url="rtsp://source/cam004", playback_path="/media/cam-004/index.m3u8", status=CameraStatus.OFFLINE, enabled_algorithms=["helmet", "crowding"], fps=0, latency_ms=0),
        ]
        db.add_all(cameras)
        db.flush()
        person = Person(employee_no="M20260018", name="张伟", department="采掘一队", authorized_areas=["主井口", "运输巷道"], face_enrolled=False)
        db.add(person)
        db.flush()
        replace_person_area_grants(db, person.id, person.authorized_areas)
        db.add_all([
            Event(event_type="intrusion", severity="critical", camera_id=cameras[2].id, title="高危禁区检测到未授权进入", description="目标越过炸药库入口电子围栏", confidence=0.94, occurred_at=datetime.now(UTC) - timedelta(minutes=8), metadata_json={"track_id": 1842}),
            Event(event_type="no_helmet", severity="high", camera_id=cameras[0].id, person_id=person.id, title="检测到未佩戴安全帽", description="主井口入井通道", confidence=0.91, occurred_at=datetime.now(UTC) - timedelta(minutes=23)),
            Event(event_type="crowding", severity="medium", camera_id=cameras[1].id, title="巷道人员聚集", description="持续超过 30 秒", confidence=0.87, occurred_at=datetime.now(UTC) - timedelta(hours=1)),
        ])
    if include_demo_data and not db.scalar(select(AlgorithmConfig).limit(1)):
        db.add_all([
            AlgorithmConfig(name="人员与安全帽检测", algorithm_type="object_detection", model_version="mine-detector-demo-1.2.0", threshold=0.65, config={"classes": ["person", "head", "helmet"], "input_size": 960}),
            AlgorithmConfig(name="人脸检测与识别", algorithm_type="face_recognition", model_version="face-provider-demo-1.0.0", threshold=0.72, config={"liveness_required": True, "top_k": 3}),
            AlgorithmConfig(name="区域入侵与跟踪", algorithm_type="tracking", model_version="bytetrack-1.0", threshold=0.6, config={"dwell_seconds": 2, "track_buffer": 30}),
            AlgorithmConfig(name="推理资源调度", algorithm_type="rl_scheduler", model_version="safe-ppo-shadow-0.1", enabled=False, threshold=0.8, deployment_status="shadow", config={"safety_layer": True, "max_critical_stride": 2}),
        ])
    if include_demo_data and not db.scalar(select(AlertRule).limit(1)):
        db.add_all([
            AlertRule(name="高危禁区入侵", event_types=["intrusion", "unknown_face"], minimum_severity="high", areas=["高危禁区"], channels=["console", "broadcast"], cooldown_seconds=30),
            AlertRule(name="全区域人员安全事件", event_types=["no_helmet", "crowding"], minimum_severity="high", areas=[], channels=["console", "sms"], cooldown_seconds=120),
            AlertRule(name="设备离线", event_types=["camera_offline"], minimum_severity="high", areas=[], channels=["console", "sms"], cooldown_seconds=120),
        ])
    db.commit()
