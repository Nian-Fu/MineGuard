"""Explicit, idempotent business demo data for Beijing Elink Intelligent Control.

This module is intentionally not called by application startup.  The records describe
demonstration scenarios based on publicly presented business lines; they are not claims
about real customers, projects, employees, incidents, or biometric identities.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models import (
    AlertRule,
    AlgorithmConfig,
    AuditLog,
    Camera,
    CameraStatus,
    DeliveryStatus,
    EdgeNode,
    EdgeNodeStatus,
    Event,
    ModelArtifact,
    NotificationDelivery,
    Person,
    Role,
    User,
)
from app.services.permissions import replace_person_area_grants

DEMO_PREFIX = "YLZK-DEMO"
COMPANY_NAME = "北京易联智控科技有限公司"
LEGAL_REPRESENTATIVE = "侯笃君"
DEMO_NOTICE = "业务演示数据，非真实客户项目、人员或生产事件"

AREAS = [
    "北京研发测试中心",
    "山西生产测试基地",
    "智能掘进工作面",
    "辅助运输无人驾驶线路",
    "矿用无线遥控作业区",
    "特种机器人巡检区",
    "设备检修硐室",
]

CAMERA_SPECS = [
    ("北京研发测试中心", "算法联调实验区", ["helmet", "intrusion", "crowding"]),
    ("北京研发测试中心", "无线遥控试验台", ["intrusion", "face"]),
    ("北京研发测试中心", "无人驾驶仿真区", ["intrusion", "crowding"]),
    ("北京研发测试中心", "样机展示与培训区", ["helmet", "face"]),
    ("山西生产测试基地", "设备总装工位", ["helmet", "crowding"]),
    ("山西生产测试基地", "控制柜测试工位", ["intrusion", "helmet"]),
    ("山西生产测试基地", "整机老化测试区", ["intrusion", "thermal"]),
    ("山西生产测试基地", "出厂检验通道", ["face", "helmet"]),
    ("智能掘进工作面", "掘进机机身左侧", ["intrusion", "helmet"]),
    ("智能掘进工作面", "掘进机机身右侧", ["intrusion", "helmet"]),
    ("智能掘进工作面", "迎头人员警戒区", ["intrusion", "crowding"]),
    ("智能掘进工作面", "远程操控硐室", ["face", "crowding"]),
    ("辅助运输无人驾驶线路", "车辆始发站", ["intrusion", "vehicle"]),
    ("辅助运输无人驾驶线路", "巷道会车点", ["intrusion", "vehicle"]),
    ("辅助运输无人驾驶线路", "弯道盲区", ["intrusion", "vehicle"]),
    ("辅助运输无人驾驶线路", "井下装卸站", ["helmet", "crowding", "vehicle"]),
    ("矿用无线遥控作业区", "遥控装载作业面", ["intrusion", "helmet"]),
    ("矿用无线遥控作业区", "遥控操作员站位", ["face", "intrusion"]),
    ("矿用无线遥控作业区", "设备安全边界", ["intrusion", "thermal"]),
    ("特种机器人巡检区", "轨道巡检起点", ["intrusion", "thermal"]),
    ("特种机器人巡检区", "KBA12R 热成像监测点", ["thermal", "intrusion"]),
    ("特种机器人巡检区", "机器人充电维护点", ["intrusion", "thermal"]),
    ("设备检修硐室", "电气检修工位", ["helmet", "intrusion"]),
    ("设备检修硐室", "备件与工具区", ["face", "intrusion"]),
]

DEPARTMENT_AREAS = [
    ("智能控制研发部", ["北京研发测试中心", "山西生产测试基地"]),
    ("矿山智能掘进事业部", ["智能掘进工作面", "矿用无线遥控作业区"]),
    ("无人驾驶事业部", ["辅助运输无人驾驶线路", "北京研发测试中心"]),
    ("特种机器人事业部", ["特种机器人巡检区", "设备检修硐室"]),
    ("项目实施部", ["智能掘进工作面", "辅助运输无人驾驶线路"]),
    ("售后运维部", ["山西生产测试基地", "设备检修硐室"]),
    ("设备制造与质检部", ["山西生产测试基地", "矿用无线遥控作业区"]),
    ("矿山驻场演示班组", ["智能掘进工作面", "辅助运输无人驾驶线路"]),
]

EVENT_DETAILS = {
    "intrusion": ("电子围栏检测到人员进入", "目标进入设备作业安全边界"),
    "no_helmet": ("检测到未规范佩戴安全帽", "人员防护用品状态需要现场复核"),
    "crowding": ("作业区域人员聚集", "区域人数持续超过演示阈值"),
    "camera_offline": ("视频设备链路中断", "边缘节点检测到视频流暂时不可用"),
    "unknown_face": ("检测到未登记人员", "受控区域出现未登记的演示目标"),
    "face_match": ("授权演示人员身份核验通过", "演示身份与区域授权规则匹配"),
}


def _sha(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _set_values(record, values: dict) -> None:
    for key, value in values.items():
        setattr(record, key, value)


def _upsert(db: Session, model, lookup, values: dict):
    record = db.scalar(select(model).where(lookup))
    if record is None:
        record = model(**values)
        db.add(record)
    else:
        _set_values(record, values)
    return record


def _seed_reviewer(db: Session) -> User:
    username = "ylzk-demo-reviewer"
    reviewer = db.scalar(select(User).where(User.username == username))
    if reviewer is None:
        reviewer = User(
            username=username,
            full_name="业务演示模型复核员（停用）",
            password_hash=hash_password(f"{DEMO_PREFIX}:{_sha(username)}"),
            role=Role.ADMIN.value,
            active=False,
        )
        db.add(reviewer)
        db.flush()
    else:
        reviewer.full_name = "业务演示模型复核员（停用）"
        reviewer.role = Role.ADMIN.value
        reviewer.active = False
    return reviewer


def _seed_cameras(db: Session, now: datetime) -> list[Camera]:
    statuses = [
        CameraStatus.ONLINE.value,
        CameraStatus.ONLINE.value,
        CameraStatus.ONLINE.value,
        CameraStatus.DEGRADED.value,
        CameraStatus.ONLINE.value,
        CameraStatus.ONLINE.value,
        CameraStatus.MAINTENANCE.value,
        CameraStatus.OFFLINE.value,
    ]
    cameras = []
    for index, (area, location, algorithms) in enumerate(CAMERA_SPECS, start=1):
        code = f"{DEMO_PREFIX}-CAM-{index:03d}"
        status = statuses[(index - 1) % len(statuses)]
        active_stream = status in {CameraStatus.ONLINE.value, CameraStatus.DEGRADED.value}
        values = {
            "code": code,
            "name": f"{location}（演示）",
            "area": area,
            "playback_path": f"/media/ylzk-demo-cam-{index:03d}/index.m3u8",
            "status": status,
            "enabled_algorithms": algorithms,
            "fps": 25.0 if status == CameraStatus.ONLINE.value else (15.0 if active_stream else 0.0),
            "latency_ms": 68 + (index * 7 % 95) if active_stream else 0,
            "last_seen_at": now - timedelta(seconds=index * 5) if active_stream else None,
        }
        camera = db.scalar(select(Camera).where(Camera.code == code))
        if camera is None:
            camera = Camera(**values)
            camera.stream_url = f"rtsp://demo-source.invalid/ylzk/cam-{index:03d}"
            db.add(camera)
        else:
            _set_values(camera, values)
        cameras.append(camera)
    db.flush()
    return cameras


def _seed_persons(db: Session) -> list[Person]:
    persons = []
    for index in range(1, 49):
        department, areas = DEPARTMENT_AREAS[(index - 1) % len(DEPARTMENT_AREAS)]
        employee_no = f"{DEMO_PREFIX}-P-{index:03d}"
        values = {
            "employee_no": employee_no,
            "name": f"演示人员 {index:02d}",
            "department": department,
            "person_type": "contractor" if index % 9 == 0 else "employee",
            "authorized_areas": areas,
            "face_enrolled": False,
            "active": index % 17 != 0,
        }
        person = _upsert(db, Person, Person.employee_no == employee_no, values)
        db.flush()
        replace_person_area_grants(db, person.id, areas)
        persons.append(person)
    db.flush()
    return persons


def _seed_model_artifacts(
    db: Session, creator: User, reviewer: User, now: datetime
) -> list[ModelArtifact]:
    specs = [
        ("人员与安全帽检测模型（演示）", "object_detection", "ylzk-demo-ppe-2.3.0", 0.942),
        ("车辆与巷道障碍物检测模型（演示）", "vehicle_detection", "ylzk-demo-vehicle-1.8.0", 0.916),
        ("区域入侵与目标跟踪模型（演示）", "tracking", "ylzk-demo-track-2.1.0", 0.931),
        ("热成像温升异常模型（演示）", "thermal_anomaly", "ylzk-demo-thermal-1.4.0", 0.905),
        ("受控区域身份核验模型（演示）", "face_recognition", "ylzk-demo-face-1.2.0", 0.889),
    ]
    artifacts = []
    for index, (name, algorithm_type, version, score) in enumerate(specs, start=1):
        digest = _sha(f"{DEMO_PREFIX}:{algorithm_type}:{version}")
        values = {
            "name": name,
            "algorithm_type": algorithm_type,
            "model_version": version,
            "sha256": digest,
            "runtime": "ONNX Runtime（演示）",
            "license_id": f"{DEMO_PREFIX}-INTERNAL-{index:02d}",
            "source_repository": "internal-demo://beijing-elink/business-scenarios",
            "source_commit": _sha(f"commit:{version}")[:40],
            "metrics": {
                "validation_score": score,
                "validation_dataset": "业务演示验证集",
                "demo_data": True,
                "notice": DEMO_NOTICE,
            },
            "created_by": creator.id,
            "approved": True,
            "approved_by": reviewer.id,
            "approved_at": now - timedelta(days=45 - index),
        }
        artifact = _upsert(
            db,
            ModelArtifact,
            (ModelArtifact.algorithm_type == algorithm_type)
            & (ModelArtifact.model_version == version)
            & (ModelArtifact.sha256 == digest),
            values,
        )
        artifacts.append(artifact)
    db.flush()
    return artifacts


def _seed_algorithms(db: Session) -> None:
    specs = [
        ("人员与安全帽检测（易联业务演示）", "object_detection", "ylzk-demo-ppe-2.3.0", 0.72, {"classes": ["person", "helmet", "head"], "input_size": 960}),
        ("无人驾驶车辆环境感知（易联业务演示）", "vehicle_detection", "ylzk-demo-vehicle-1.8.0", 0.68, {"classes": ["vehicle", "person", "obstacle"], "blind_zone_alert": True}),
        ("掘进工作面电子围栏（易联业务演示）", "tracking", "ylzk-demo-track-2.1.0", 0.70, {"dwell_seconds": 2, "track_buffer": 45}),
        ("KBA12R 热成像温升监测（易联业务演示）", "thermal_anomaly", "ylzk-demo-thermal-1.4.0", 0.76, {"temperature_delta_c": 12, "continuous_seconds": 5}),
        ("受控区域身份核验（易联业务演示）", "face_recognition", "ylzk-demo-face-1.2.0", 0.78, {"liveness_required": True, "template_policy": "demo-no-biometric-template"}),
        ("边缘推理资源调度（易联业务演示）", "rl_scheduler", "safe-ppo-shadow-0.2", 0.80, {"safety_layer": True, "max_critical_stride": 2}),
    ]
    for index, (name, algorithm_type, version, threshold, config) in enumerate(specs):
        _upsert(
            db,
            AlgorithmConfig,
            AlgorithmConfig.name == name,
            {
                "name": name,
                "algorithm_type": algorithm_type,
                "model_version": version,
                "enabled": index != 5,
                "threshold": threshold,
                "config": {**config, "demo_data": True, "notice": DEMO_NOTICE},
                "deployment_status": "shadow" if index == 5 else "ready",
            },
        )


def _seed_edge_nodes(
    db: Session, cameras: list[Camera], artifacts: list[ModelArtifact], now: datetime
) -> list[EdgeNode]:
    node_specs = [
        ("BJ-RD", "北京研发测试边缘节点（演示）", [0, 1, 2, 3]),
        ("SX-TEST", "山西生产测试边缘节点（演示）", [4, 5, 6, 7]),
        ("ROADHEAD", "智能掘进业务边缘节点（演示）", [8, 9, 10, 11]),
        ("DRIVERLESS", "辅助运输无人驾驶边缘节点（演示）", [12, 13, 14, 15]),
        ("REMOTE", "矿用无线遥控边缘节点（演示）", [16, 17, 18]),
        ("ROBOT", "特种机器人与检修边缘节点（演示）", [19, 20, 21, 22, 23]),
    ]
    model_reports = [
        {
            "algorithm_type": item.algorithm_type,
            "model_version": item.model_version,
            "sha256": item.sha256,
            "ready": True,
        }
        for item in artifacts
    ]
    nodes = []
    for index, (suffix, name, camera_indexes) in enumerate(node_specs):
        code = f"{DEMO_PREFIX}-EDGE-{suffix}"
        assigned = [cameras[item] for item in camera_indexes]
        area_counts = {area: 1 + (index + offset) % 5 for offset, area in enumerate(sorted({camera.area for camera in assigned}))}
        status = EdgeNodeStatus.DEGRADED.value if index == 4 else EdgeNodeStatus.ONLINE.value
        values = {
            "code": code,
            "name": name,
            "api_key_hash": _sha(f"{DEMO_PREFIX}:edge-credential:{suffix}"),
            "status": status,
            "active": True,
            "camera_ids": [camera.id for camera in assigned],
            "software_version": "mineguard-edge-demo-2.6.1",
            "telemetry": {
                "gpu_healthy": True,
                "gpu_utilization": 38 + index * 7,
                "gpu_memory_utilization": 42 + index * 5,
                "queue_depth": index * 3,
                "dead_letter_depth": 0,
                "outbox_capacity": 100000,
                "stream_reconnects_last_5m": 1 if index == 4 else 0,
                "central_reconnects_last_5m": 0,
                "area_counts": area_counts,
                "models": model_reports,
                "unapproved_models": [],
                "model_policy_enforced": True,
                "reported_cameras": len(assigned),
                "business_context": {
                    "legal_entity": COMPANY_NAME,
                    "legal_representative": LEGAL_REPRESENTATIVE,
                    "business_scope": [
                        "矿用无线遥控系统",
                        "矿山智能掘进系统",
                        "辅助运输无人驾驶系统",
                        "特种行业机器人系统",
                    ],
                    "related_operation": "山西生产测试基地/关联业务板块（演示）",
                    "notice": DEMO_NOTICE,
                },
            },
            "last_seen_at": now - timedelta(seconds=10 + index * 6),
        }
        node = _upsert(db, EdgeNode, EdgeNode.code == code, values)
        nodes.append(node)
    db.flush()
    return nodes


def _seed_events(
    db: Session,
    cameras: list[Camera],
    persons: list[Person],
    nodes: list[EdgeNode],
    actor: User,
    now: datetime,
) -> list[Event]:
    event_types = [
        "intrusion",
        "no_helmet",
        "intrusion",
        "crowding",
        "camera_offline",
        "unknown_face",
        "intrusion",
        "face_match",
    ]
    severities = ["high", "medium", "critical", "medium", "high", "high", "low", "low"]
    statuses = ["open", "acknowledged", "resolved", "resolved", "false_positive"]
    node_by_camera_id = {
        camera_id: node for node in nodes for camera_id in node.camera_ids
    }
    events = []
    for index in range(1, 241):
        camera = cameras[(index * 7 - 1) % len(cameras)]
        event_type = event_types[(index - 1) % len(event_types)]
        severity = severities[(index - 1) % len(severities)]
        event_status = statuses[(index - 1) % len(statuses)]
        title, description = EVENT_DETAILS[event_type]
        occurred_at = now - timedelta(minutes=(index * 173) % (30 * 24 * 60))
        person = persons[(index * 5) % len(persons)] if event_type == "face_match" else None
        key = f"{DEMO_PREFIX}-EVENT-{index:04d}"
        values = {
            "idempotency_key": key,
            "event_type": event_type,
            "severity": severity,
            "status": event_status,
            "camera_id": camera.id,
            "person_id": person.id if person else None,
            "title": f"{title}（业务演示）",
            "description": f"{camera.area} / {camera.name}：{description}。{DEMO_NOTICE}。",
            "confidence": round(0.78 + (index % 19) / 100, 2),
            "snapshot_url": None,
            "occurred_at": occurred_at,
            "acknowledged_by": actor.id if event_status in {"acknowledged", "resolved", "false_positive"} else None,
            "resolved_at": occurred_at + timedelta(minutes=6 + index % 24) if event_status in {"resolved", "false_positive"} else None,
            "metadata_json": {
                "demo_data": True,
                "demo_seed_key": key,
                "company": COMPANY_NAME,
                "legal_representative": LEGAL_REPRESENTATIVE,
                "business_line": camera.area,
                "edge_node_code": node_by_camera_id[camera.id].code,
                "notice": DEMO_NOTICE,
                "track_id": f"DEMO-{index:06d}",
            },
            "legal_hold": False,
        }
        event = _upsert(db, Event, Event.idempotency_key == key, values)
        events.append(event)
    db.flush()
    return events


def _seed_rules(db: Session) -> list[AlertRule]:
    specs = [
        ("掘进工作面人员闯入（业务演示）", ["intrusion"], "high", ["智能掘进工作面"], ["console", "broadcast"], 30),
        ("无人驾驶线路占用（业务演示）", ["intrusion", "crowding"], "high", ["辅助运输无人驾驶线路"], ["console", "broadcast"], 45),
        ("热成像温升异常（业务演示）", ["intrusion"], "high", ["特种机器人巡检区", "矿用无线遥控作业区"], ["console"], 60),
        ("检修区域未授权进入（业务演示）", ["unknown_face", "intrusion"], "high", ["设备检修硐室"], ["console", "sms"], 90),
        ("作业人员防护用品（业务演示）", ["no_helmet"], "medium", [], ["console", "broadcast"], 120),
        ("生产区域人员聚集（业务演示）", ["crowding"], "medium", [], ["console"], 120),
        ("视频设备离线（业务演示）", ["camera_offline"], "high", [], ["console", "sms"], 180),
    ]
    rules = []
    for name, event_types, severity, areas, channels, cooldown in specs:
        rule = _upsert(
            db,
            AlertRule,
            AlertRule.name == name,
            {
                "name": name,
                "event_types": event_types,
                "minimum_severity": severity,
                "areas": areas,
                "channels": channels,
                "channel_targets": {
                    "console": "安全运营中心（演示）",
                    "broadcast": "井下广播分区（演示）",
                    "sms": "已脱敏值班组（演示）",
                },
                "cooldown_seconds": cooldown,
                "enabled": True,
            },
        )
        rules.append(rule)
    db.flush()
    return rules


def _seed_deliveries(
    db: Session, events: list[Event], rules: list[AlertRule], now: datetime
) -> None:
    for index in range(1, 73):
        event = events[(index * 3) % len(events)]
        rule = rules[(index - 1) % len(rules)]
        key = f"{DEMO_PREFIX}-DELIVERY-{index:04d}"
        status = DeliveryStatus.FAILED.value if index % 17 == 0 else DeliveryStatus.SENT.value
        values = {
            "event_id": event.id,
            "rule_id": rule.id,
            "channel": "console",
            "target": "安全运营中心（业务演示）",
            "status": status,
            "idempotency_key": key,
            "payload": {
                "demo_data": True,
                "event_title": event.title,
                "area": event.camera.area,
                "notice": DEMO_NOTICE,
            },
            "attempts": 2 if status == DeliveryStatus.FAILED.value else 1,
            "next_attempt_at": now + timedelta(days=30) if status == DeliveryStatus.FAILED.value else now,
            "last_error": "演示：通知通道暂时不可达" if status == DeliveryStatus.FAILED.value else None,
            "sent_at": now - timedelta(minutes=index * 2) if status == DeliveryStatus.SENT.value else None,
            "created_at": now - timedelta(minutes=index * 2 + 1),
        }
        _upsert(
            db,
            NotificationDelivery,
            NotificationDelivery.idempotency_key == key,
            values,
        )


def _seed_audit_logs(db: Session, actor: User, now: datetime) -> None:
    actions = [
        ("business_demo.camera_health_review", "camera"),
        ("business_demo.event_review", "event"),
        ("business_demo.edge_maintenance", "edge_node"),
        ("business_demo.algorithm_release_review", "model_artifact"),
    ]
    for index in range(1, 65):
        action, resource_type = actions[(index - 1) % len(actions)]
        resource_id = f"{DEMO_PREFIX}-AUDIT-{index:04d}"
        values = {
            "user_id": actor.id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "detail": {
                "demo_data": True,
                "company": COMPANY_NAME,
                "legal_representative": LEGAL_REPRESENTATIVE,
                "result": "completed" if index % 11 else "follow_up_required",
                "notice": DEMO_NOTICE,
            },
            "legal_hold": False,
            "ip_address": "127.0.0.1",
            "created_at": now - timedelta(hours=index * 5),
        }
        _upsert(
            db,
            AuditLog,
            (AuditLog.action == action)
            & (AuditLog.resource_type == resource_type)
            & (AuditLog.resource_id == resource_id),
            values,
        )


def seed_company_demo_data(db: Session, *, now: datetime | None = None) -> dict[str, int]:
    """Create or refresh the explicit company business demonstration dataset."""

    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    actor = db.scalar(
        select(User).where(User.role == Role.ADMIN.value, User.active.is_(True)).order_by(User.id)
    )
    if actor is None:
        raise RuntimeError("an active administrator is required before importing demo data")

    reviewer = _seed_reviewer(db)
    cameras = _seed_cameras(db, now)
    persons = _seed_persons(db)
    artifacts = _seed_model_artifacts(db, actor, reviewer, now)
    _seed_algorithms(db)
    nodes = _seed_edge_nodes(db, cameras, artifacts, now)
    events = _seed_events(db, cameras, persons, nodes, actor, now)
    rules = _seed_rules(db)
    _seed_deliveries(db, events, rules, now)
    _seed_audit_logs(db, actor, now)
    db.commit()

    return {
        "cameras": len(cameras),
        "persons": len(persons),
        "events": len(events),
        "edge_nodes": len(nodes),
        "model_artifacts": len(artifacts),
        "algorithms": 6,
        "alert_rules": len(rules),
        "notification_deliveries": 72,
        "audit_logs": 64,
    }


def main() -> None:
    from app.core.database import SessionLocal

    with SessionLocal() as db:
        counts = seed_company_demo_data(db)
    print("company demo data imported: " + ", ".join(f"{key}={value}" for key, value in counts.items()))


if __name__ == "__main__":
    main()
