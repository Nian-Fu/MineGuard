import asyncio

import httpx
import pytest

from app.services.http_payloads import async_json_response, json_response


def test_async_json_response_reads_a_bounded_payload():
    async def run():
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"ready": True}, request=request
            )
        )
        async with httpx.AsyncClient(transport=transport) as client:
            return await async_json_response(
                client,
                "GET",
                "https://service.test/status",
                maximum_bytes=1024,
            )

    assert asyncio.run(run()) == {"ready": True}


def test_async_json_response_rejects_actual_bytes_beyond_declared_length():
    async def run():
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-length": "1"},
                content=b'{"oversized":true}',
                request=request,
            )
        )
        async with httpx.AsyncClient(transport=transport) as client:
            return await async_json_response(
                client,
                "GET",
                "https://service.test/status",
                maximum_bytes=8,
            )

    with pytest.raises(ValueError, match="configured limit"):
        asyncio.run(run())


def test_sync_json_response_rejects_an_oversized_declared_length():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"content-length": "999999"},
            content=b"{}",
            request=request,
        )
    )
    with httpx.Client(transport=transport) as client:
        with pytest.raises(ValueError, match="configured limit"):
            json_response(
                client,
                "GET",
                "https://service.test/status",
                maximum_bytes=1024,
            )
