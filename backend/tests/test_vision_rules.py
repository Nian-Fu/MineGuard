import pytest

from app.vision.rules import (
    BoundingBox,
    CrossingDirection,
    HelmetRule,
    IntrusionRule,
    LineCounter,
    Point,
    Track,
    count_in_area,
    point_in_polygon,
    validate_polygon,
)


ZONE = [Point(0, 0), Point(10, 0), Point(10, 10), Point(0, 10)]


def track(track_id: int, x: float, foot_y: float) -> Track:
    return Track(track_id, BoundingBox(x - 0.5, foot_y - 2, x + 0.5, foot_y), 0.9)


def test_polygon_uses_person_foot_point():
    assert point_in_polygon(track(1, 5, 5).box.foot, ZONE)
    assert not point_in_polygon(track(1, 11, 5).box.foot, ZONE)


def test_polygon_rejects_degenerate_and_self_intersecting_geometry():
    with pytest.raises(ValueError, match="area"):
        validate_polygon([Point(0, 0), Point(1, 1), Point(2, 2)])
    with pytest.raises(ValueError, match="intersect|area"):
        validate_polygon(
            [Point(0, 0), Point(2, 2), Point(0, 2), Point(2, 0)]
        )


@pytest.mark.parametrize("value", [True, float("nan"), float("inf")])
def test_temporal_rules_reject_non_finite_or_coerced_dwell(value):
    with pytest.raises(ValueError, match="finite"):
        IntrusionRule(ZONE, dwell_seconds=value)
    with pytest.raises(ValueError, match="finite"):
        HelmetRule(dwell_seconds=value)


def test_intrusion_requires_dwell_and_emits_once():
    rule = IntrusionRule(ZONE, dwell_seconds=2)
    assert rule.evaluate([track(7, 5, 5)], timestamp=10) == []
    assert rule.evaluate([track(7, 5, 5)], timestamp=11.9) == []
    events = rule.evaluate([track(7, 5, 5)], timestamp=12)
    assert events[0].track_id == 7
    assert rule.evaluate([track(7, 5, 5)], timestamp=20) == []
    rule.evaluate([track(7, 12, 5)], timestamp=21)
    assert rule.evaluate([track(7, 5, 5)], timestamp=24) == []


def test_line_counter_counts_direction_without_frame_duplication():
    counter = LineCounter(Point(0, 5), Point(10, 5))
    counter.evaluate([track(3, 4, 4)])
    crossing = counter.evaluate([track(3, 4, 6)])
    assert crossing[0].direction == CrossingDirection.FORWARD
    assert counter.evaluate([track(3, 4, 7)]) == []
    assert counter.forward_count == 1


def test_line_counter_releases_disappeared_track_history():
    counter = LineCounter(Point(0, 5), Point(10, 5))
    counter.evaluate([track(3, 4, 4)])
    assert counter.evaluate([track(3, 4, 6)])
    counter.evaluate([])
    counter.evaluate([track(3, 4, 4)])
    assert counter.evaluate([track(3, 4, 6)])
    assert counter.forward_count == 2


def test_line_counter_rejects_non_finite_geometry():
    try:
        LineCounter(Point(0, 0), Point(float("nan"), 1))
    except ValueError as exc:
        assert "finite" in str(exc)
    else:
        raise AssertionError("non-finite line must be rejected")


def test_crowding_counts_unique_tracks_in_area():
    state = count_in_area(
        [
            track(1, 2, 2),
            track(1, 2.1, 2.1),
            track(2, 4, 4),
            track(3, 12, 2),
        ],
        ZONE,
        threshold=2,
    )
    assert state.exceeded is True
    assert state.track_ids == (1, 2)
    with pytest.raises(ValueError, match="positive"):
        count_in_area([], ZONE, threshold=True)


def test_helmet_rule_requires_sustained_absence_and_resets_after_compliance():
    rule = HelmetRule(dwell_seconds=1)
    person = track(8, 5, 8)
    assert rule.evaluate([person], [], timestamp=10) == []
    violations = rule.evaluate([person], [], timestamp=11)
    assert violations[0].track_id == 8
    assert rule.evaluate([person], [], timestamp=12) == []

    helmet = BoundingBox(4.5, 6.1, 5.5, 6.8)
    assert rule.evaluate([person], [helmet], timestamp=13) == []
    assert rule.evaluate([person], [], timestamp=14) == []
    assert rule.evaluate([person], [], timestamp=15)[0].track_id == 8


def test_helmet_outside_upper_body_does_not_match_person():
    rule = HelmetRule(dwell_seconds=0)
    person = track(9, 5, 8)
    outside = BoundingBox(10, 1, 11, 2)
    assert rule.evaluate([person], [outside], timestamp=20)[0].track_id == 9


def test_detected_head_prevents_handheld_helmet_from_matching():
    rule = HelmetRule(dwell_seconds=0)
    person = track(10, 5, 8)
    head = BoundingBox(4.6, 6.0, 5.4, 6.5)
    handheld = BoundingBox(4.6, 6.8, 5.4, 7.2)
    assert rule.evaluate([person], [handheld], timestamp=30, heads=[head])[0].track_id == 10
    worn = BoundingBox(4.6, 5.9, 5.4, 6.3)
    assert rule.evaluate([person], [worn], timestamp=31, heads=[head]) == []


def test_one_helmet_cannot_make_two_overlapping_people_compliant():
    rule = HelmetRule(dwell_seconds=0)
    people = [track(20, 5.0, 8), track(21, 5.2, 8)]
    helmet = BoundingBox(4.8, 6.0, 5.2, 6.5)

    violations = rule.evaluate(people, [helmet], timestamp=40)

    assert len(violations) == 1
    assert violations[0].track_id in {20, 21}
