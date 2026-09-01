import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from app.models import Camera
from app.services.http_payloads import json_response


MEDIA_GATEWAY_RESPONSE_MAXIMUM_BYTES = 2 * 1024 * 1024
MEDIA_PATH_NAME_PATTERN = re.compile(r"[a-z0-9_.-]{2,50}")


class MediaGatewayError(RuntimeError):
    pass


@dataclass(frozen=True)
class MediaReconcileResult:
    managed: int
    added: int
    updated: int
    removed: int


def media_path_name(playback_path: str) -> str:
    match = re.fullmatch(
        rf"/media/({MEDIA_PATH_NAME_PATTERN.pattern})/index\.m3u8",
        playback_path,
    )
    if not match:
        raise ValueError("camera playback_path does not map to a managed media path")
    return match.group(1)


class MediaGatewayReconciler:
    """Keeps MediaMTX pull paths aligned with camera records after restarts."""

    def __init__(
        self,
        base_url: str,
        timeout_seconds: float = 5.0,
        client: httpx.Client | None = None,
    ) -> None:
        self.client = client or httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds, connect=timeout_seconds),
        )

    def reconcile(
        self,
        cameras: Iterable[Camera],
        progress: Callable[[], None] | None = None,
    ) -> MediaReconcileResult:
        desired: dict[str, str] = {}
        unresolved_names: set[str] = set()
        camera_errors: list[Exception] = []
        for camera in cameras:
            name: str | None = None
            try:
                name = media_path_name(camera.playback_path)
                source = camera.stream_url
                if not isinstance(source, str) or not source:
                    raise ValueError("camera stream URL is invalid")
                if name in desired:
                    raise ValueError("camera media path is duplicated")
                desired[name] = source
            except Exception as exc:
                if name is not None:
                    unresolved_names.add(name)
                camera_errors.append(exc)
        try:
            existing = self._existing_paths(progress)
            added = 0
            updated = 0
            removed = 0
            for name, source in sorted(desired.items()):
                configuration = {
                    "source": source,
                    "sourceOnDemand": True,
                    "sourceOnDemandStartTimeout": "15s",
                    "sourceOnDemandCloseAfter": "60s",
                }
                encoded_name = quote(name, safe="")
                if name not in existing:
                    status_code = self._write_path_configuration(
                        "POST",
                        f"/v3/config/paths/add/{encoded_name}",
                        progress=progress,
                        json=configuration,
                    )
                    if status_code in {400, 409}:
                        self._write_path_configuration(
                            "PATCH",
                            f"/v3/config/paths/patch/{encoded_name}",
                            progress=progress,
                            json=configuration,
                        )
                    added += 1
                elif existing[name] != source:
                    self._write_path_configuration(
                        "PATCH",
                        f"/v3/config/paths/patch/{encoded_name}",
                        progress=progress,
                        json=configuration,
                    )
                    updated += 1
                else:
                    continue
            for name in sorted(
                set(existing) - set(desired) - unresolved_names - {"all_others"}
            ):
                if MEDIA_PATH_NAME_PATTERN.fullmatch(name) is None:
                    continue
                self._write_path_configuration(
                    "DELETE",
                    f"/v3/config/paths/delete/{quote(name, safe='')}",
                    progress=progress,
                )
                removed += 1
            result = MediaReconcileResult(
                managed=len(desired),
                added=added,
                updated=updated,
                removed=removed,
            )
            if camera_errors:
                raise MediaGatewayError(
                    f"media gateway skipped {len(camera_errors)} invalid camera record(s)"
                ) from camera_errors[0]
            return result
        except MediaGatewayError:
            raise
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            raise MediaGatewayError("media gateway reconciliation failed") from exc

    def _existing_paths(
        self, progress: Callable[[], None] | None = None
    ) -> dict[str, object]:
        existing: dict[str, object] = {}
        page = 0
        while True:
            payload = json_response(
                self.client,
                "GET",
                "/v3/config/paths/list",
                maximum_bytes=MEDIA_GATEWAY_RESPONSE_MAXIMUM_BYTES,
                params={"page": page, "itemsPerPage": 1000},
            )
            if progress is not None:
                progress()
            if not isinstance(payload, dict) or not isinstance(
                payload.get("items"), list
            ):
                raise ValueError("media gateway path list is invalid")
            existing.update(
                {
                    item["name"]: item.get("source")
                    for item in payload["items"]
                    if isinstance(item, dict)
                    and isinstance(item.get("name"), str)
                }
            )
            page_count = payload.get("pageCount", 1)
            if (
                isinstance(page_count, bool)
                or not isinstance(page_count, int)
                or not 0 <= page_count <= 10_000
            ):
                raise ValueError("media gateway page count is invalid")
            page += 1
            if page >= max(page_count, 1):
                return existing

    def _write_path_configuration(
        self,
        method: str,
        path: str,
        *,
        progress: Callable[[], None] | None = None,
        **options,
    ) -> int:
        with self.client.stream(method, path, **options) as response:
            if progress is not None:
                progress()
            if method == "POST" and response.status_code in {400, 409}:
                return response.status_code
            response.raise_for_status()
            return response.status_code

    def close(self) -> None:
        self.client.close()
