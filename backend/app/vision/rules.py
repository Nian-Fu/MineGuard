from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from numbers import Real


@dataclass(frozen=True)
class Point:
    x: float
    y: float


@dataclass(frozen=True)
class BoundingBox:
    left: float
    top: float
    right: float
    bottom: float

    @property
    def foot(self) -> Point:
        return Point((self.left + self.right) / 2, self.bottom)


@dataclass(frozen=True)
class Track:
    track_id: int
    box: BoundingBox
    confidence: float


def _orientation(first: Point, second: Point, third: Point) -> float:
    return (second.x - first.x) * (third.y - first.y) - (
        second.y - first.y
    ) * (third.x - first.x)


def _point_on_segment(point: Point, start: Point, end: Point) -> bool:
    epsilon = 1e-12
    return (
        min(start.x, end.x) - epsilon <= point.x <= max(start.x, end.x) + epsilon
        and min(start.y, end.y) - epsilon
        <= point.y
        <= max(start.y, end.y) + epsilon
    )


def _segments_intersect(
    first_start: Point,
    first_end: Point,
    second_start: Point,
    second_end: Point,
) -> bool:
    epsilon = 1e-12
    orientations = (
        _orientation(first_start, first_end, second_start),
        _orientation(first_start, first_end, second_end),
        _orientation(second_start, second_end, first_start),
        _orientation(second_start, second_end, first_end),
    )
    first_a, first_b, second_a, second_b = orientations
    if first_a * first_b < 0 and second_a * second_b < 0:
        return True
    return any(
        abs(orientation) <= epsilon and _point_on_segment(point, start, end)
        for orientation, point, start, end in (
            (first_a, second_start, first_start, first_end),
            (first_b, second_end, first_start, first_end),
            (second_a, first_start, second_start, second_end),
            (second_b, first_end, second_start, second_end),
        )
    )


def validate_polygon(polygon: list[Point]) -> None:
    if len(polygon) < 3:
        raise ValueError("polygon requires at least three points")
    if any(not isfinite(value) for point in polygon for value in (point.x, point.y)):
        raise ValueError("polygon coordinates must be finite")
    if len({(point.x, point.y) for point in polygon}) != len(polygon):
        raise ValueError("polygon cannot contain duplicate points")
    doubled_area = abs(
        sum(
            point.x * polygon[(index + 1) % len(polygon)].y
            - polygon[(index + 1) % len(polygon)].x * point.y
            for index, point in enumerate(polygon)
        )
    )
    if doubled_area <= 1e-9:
        raise ValueError("polygon area must be non-zero")
    edge_count = len(polygon)
    for first_index in range(edge_count):
        first_end_index = (first_index + 1) % edge_count
        for second_index in range(first_index + 1, edge_count):
            second_end_index = (second_index + 1) % edge_count
            if (
                first_index == second_index
                or first_end_index == second_index
                or second_end_index == first_index
            ):
                continue
            if _segments_intersect(
                polygon[first_index],
                polygon[first_end_index],
                polygon[second_index],
                polygon[second_end_index],
            ):
                raise ValueError("polygon edges cannot intersect")


def point_in_polygon(point: Point, polygon: list[Point]) -> bool:
    if len(polygon) < 3:
        raise ValueError("polygon requires at least three points")
    inside = False
    previous = polygon[-1]
    for current in polygon:
        if (current.y > point.y) != (previous.y > point.y):
            x_intersection = (previous.x - current.x) * (point.y - current.y) / (
                previous.y - current.y
            ) + current.x
            if point.x < x_intersection:
                inside = not inside
        previous = current
    return inside


@dataclass(frozen=True)
class Intrusion:
    track_id: int
    dwell_seconds: float
    confidence: float


class IntrusionRule:
    def __init__(self, polygon: list[Point], dwell_seconds: float = 2.0) -> None:
        if (
            isinstance(dwell_seconds, bool)
            or not isinstance(dwell_seconds, Real)
            or not isfinite(dwell_seconds)
            or dwell_seconds < 0
        ):
            raise ValueError("dwell_seconds must be a finite non-negative value")
        validate_polygon(polygon)
        self.polygon = polygon
        self.dwell_seconds = dwell_seconds
        self._entered_at: dict[int, float] = {}
        self._alerted: set[int] = set()

    def evaluate(self, tracks: list[Track], timestamp: float) -> list[Intrusion]:
        present_ids = {track.track_id for track in tracks}
        for track_id in set(self._entered_at) - present_ids:
            self._entered_at.pop(track_id, None)
            self._alerted.discard(track_id)

        events = []
        for track in tracks:
            if not point_in_polygon(track.box.foot, self.polygon):
                self._entered_at.pop(track.track_id, None)
                self._alerted.discard(track.track_id)
                continue
            entered_at = self._entered_at.setdefault(track.track_id, timestamp)
            dwell = max(0.0, timestamp - entered_at)
            if dwell >= self.dwell_seconds and track.track_id not in self._alerted:
                events.append(Intrusion(track.track_id, dwell, track.confidence))
                self._alerted.add(track.track_id)
        return events


class CrossingDirection(StrEnum):
    FORWARD = "forward"
    REVERSE = "reverse"


@dataclass(frozen=True)
class Crossing:
    track_id: int
    direction: CrossingDirection


def side_of_line(point: Point, start: Point, end: Point) -> float:
    return (end.x - start.x) * (point.y - start.y) - (end.y - start.y) * (point.x - start.x)


class LineCounter:
    def __init__(self, start: Point, end: Point, dead_band: float = 0.001) -> None:
        if start == end:
            raise ValueError("counting line cannot have zero length")
        if not all(isfinite(value) for value in (start.x, start.y, end.x, end.y, dead_band)):
            raise ValueError("counting line values must be finite")
        self.start = start
        self.end = end
        self.dead_band = abs(dead_band)
        self._last_side: dict[int, int] = {}
        self._counted_direction: set[tuple[int, CrossingDirection]] = set()
        self.forward_count = 0
        self.reverse_count = 0

    def evaluate(self, tracks: list[Track]) -> list[Crossing]:
        present_ids = {track.track_id for track in tracks}
        for track_id in set(self._last_side) - present_ids:
            self._last_side.pop(track_id, None)
        self._counted_direction = {
            key for key in self._counted_direction if key[0] in present_ids
        }
        crossings = []
        for track in tracks:
            raw_side = side_of_line(track.box.foot, self.start, self.end)
            side = 1 if raw_side > self.dead_band else -1 if raw_side < -self.dead_band else 0
            previous = self._last_side.get(track.track_id)
            if side == 0:
                continue
            self._last_side[track.track_id] = side
            if previous is None or previous == side:
                continue
            direction = CrossingDirection.FORWARD if previous < side else CrossingDirection.REVERSE
            key = (track.track_id, direction)
            if key in self._counted_direction:
                continue
            self._counted_direction.add(key)
            if direction == CrossingDirection.FORWARD:
                self.forward_count += 1
            else:
                self.reverse_count += 1
            crossings.append(Crossing(track.track_id, direction))
        return crossings


@dataclass(frozen=True)
class CrowdingState:
    count: int
    exceeded: bool
    track_ids: tuple[int, ...]


def count_in_area(tracks: list[Track], polygon: list[Point], threshold: int) -> CrowdingState:
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise ValueError("threshold must be positive")
    track_ids = tuple(
        sorted(
            {
                track.track_id
                for track in tracks
                if point_in_polygon(track.box.foot, polygon)
            }
        )
    )
    return CrowdingState(len(track_ids), len(track_ids) >= threshold, track_ids)


@dataclass(frozen=True)
class HelmetViolation:
    track_id: int
    missing_seconds: float
    confidence: float


class HelmetRule:
    """Emits once when a tracked person has no helmet in the upper body region."""

    def __init__(self, dwell_seconds: float = 1.0, upper_body_ratio: float = 0.45) -> None:
        if (
            isinstance(dwell_seconds, bool)
            or not isinstance(dwell_seconds, Real)
            or not isfinite(dwell_seconds)
            or dwell_seconds < 0
        ):
            raise ValueError("dwell_seconds must be a finite non-negative value")
        if (
            isinstance(upper_body_ratio, bool)
            or not isinstance(upper_body_ratio, Real)
            or not isfinite(upper_body_ratio)
            or not 0 < upper_body_ratio <= 1
        ):
            raise ValueError("upper_body_ratio must be finite and in (0, 1]")
        self.dwell_seconds = dwell_seconds
        self.upper_body_ratio = upper_body_ratio
        self._missing_since: dict[int, float] = {}
        self._alerted: set[int] = set()

    def evaluate(
        self,
        people: list[Track],
        helmets: list[BoundingBox],
        timestamp: float,
        heads: list[BoundingBox] | None = None,
    ) -> list[HelmetViolation]:
        present_ids = {person.track_id for person in people}
        for track_id in set(self._missing_since) - present_ids:
            self._missing_since.pop(track_id, None)
            self._alerted.discard(track_id)

        assigned_heads: dict[int, int] = {}
        used_head_indexes: set[int] = set()
        head_candidates = sorted(
            (
                self._center_distance_squared(head, person.box),
                person.track_id,
                head_index,
            )
            for person in people
            for head_index, head in enumerate(heads or [])
            if self._head_matches_person(head, person.box)
        )
        for _, track_id, head_index in head_candidates:
            if track_id in assigned_heads or head_index in used_head_indexes:
                continue
            assigned_heads[track_id] = head_index
            used_head_indexes.add(head_index)

        compliant_ids: set[int] = set()
        used_helmet_indexes: set[int] = set()
        helmet_head_candidates = sorted(
            (
                self._center_distance_squared(helmet, (heads or [])[head_index]),
                track_id,
                helmet_index,
            )
            for track_id, head_index in assigned_heads.items()
            for helmet_index, helmet in enumerate(helmets)
            if self._helmet_matches_head(helmet, (heads or [])[head_index])
        )
        for _, track_id, helmet_index in helmet_head_candidates:
            if track_id in compliant_ids or helmet_index in used_helmet_indexes:
                continue
            compliant_ids.add(track_id)
            used_helmet_indexes.add(helmet_index)

        helmet_person_candidates = sorted(
            (
                self._center_distance_squared(helmet, person.box),
                person.track_id,
                helmet_index,
            )
            for person in people
            if person.track_id not in assigned_heads
            for helmet_index, helmet in enumerate(helmets)
            if helmet_index not in used_helmet_indexes
            and self._helmet_matches_person(helmet, person.box)
        )
        for _, track_id, helmet_index in helmet_person_candidates:
            if track_id in compliant_ids or helmet_index in used_helmet_indexes:
                continue
            compliant_ids.add(track_id)
            used_helmet_indexes.add(helmet_index)

        violations = []
        for person in people:
            if person.track_id in compliant_ids:
                self._missing_since.pop(person.track_id, None)
                self._alerted.discard(person.track_id)
                continue
            missing_since = self._missing_since.setdefault(person.track_id, timestamp)
            duration = max(0.0, timestamp - missing_since)
            if duration >= self.dwell_seconds and person.track_id not in self._alerted:
                violations.append(HelmetViolation(person.track_id, duration, person.confidence))
                self._alerted.add(person.track_id)
        return violations

    def _helmet_matches_person(self, helmet: BoundingBox, person: BoundingBox) -> bool:
        center = Point((helmet.left + helmet.right) / 2, (helmet.top + helmet.bottom) / 2)
        upper_bottom = person.top + (person.bottom - person.top) * self.upper_body_ratio
        return (
            person.left <= center.x <= person.right
            and person.top <= center.y <= upper_bottom
        )

    def _head_matches_person(self, head: BoundingBox, person: BoundingBox) -> bool:
        center = Point((head.left + head.right) / 2, (head.top + head.bottom) / 2)
        upper_bottom = person.top + (person.bottom - person.top) * self.upper_body_ratio
        return person.left <= center.x <= person.right and person.top <= center.y <= upper_bottom

    @staticmethod
    def _helmet_matches_head(helmet: BoundingBox, head: BoundingBox) -> bool:
        center = Point((helmet.left + helmet.right) / 2, (helmet.top + helmet.bottom) / 2)
        margin_x = (head.right - head.left) * 0.25
        margin_y = (head.bottom - head.top) * 0.25
        return (
            head.left - margin_x <= center.x <= head.right + margin_x
            and head.top - margin_y <= center.y <= head.bottom + margin_y
        )

    @staticmethod
    def _center_distance_squared(first: BoundingBox, second: BoundingBox) -> float:
        first_x = (first.left + first.right) / 2
        first_y = (first.top + first.bottom) / 2
        second_x = (second.left + second.right) / 2
        second_y = (second.top + second.bottom) / 2
        return (first_x - second_x) ** 2 + (first_y - second_y) ** 2
