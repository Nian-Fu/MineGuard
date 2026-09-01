import json
from typing import Any

import httpx


def _validate_content_length(response: httpx.Response, maximum_bytes: int) -> None:
    raw_length = response.headers.get("content-length")
    if raw_length is None:
        return
    try:
        declared_length = int(raw_length)
    except ValueError as exc:
        raise ValueError("response Content-Length is invalid") from exc
    if declared_length < 0 or declared_length > maximum_bytes:
        raise ValueError("response body exceeds the configured limit")


async def async_json_response(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    maximum_bytes: int,
    **request_options: Any,
) -> Any:
    async with client.stream(method, url, **request_options) as response:
        response.raise_for_status()
        _validate_content_length(response, maximum_bytes)
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > maximum_bytes:
                raise ValueError("response body exceeds the configured limit")
        return json.loads(body)


def json_response(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    maximum_bytes: int,
    **request_options: Any,
) -> Any:
    with client.stream(method, url, **request_options) as response:
        response.raise_for_status()
        _validate_content_length(response, maximum_bytes)
        body = bytearray()
        for chunk in response.iter_bytes():
            body.extend(chunk)
            if len(body) > maximum_bytes:
                raise ValueError("response body exceeds the configured limit")
        return json.loads(body)
