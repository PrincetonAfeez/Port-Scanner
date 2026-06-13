"""Banner grabbing for portsleuth CLI."""

from __future__ import annotations

import asyncio


async def grab_banner_async(host: str, port: int, timeout: float = 0.5, limit: int = 512) -> str | None:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, TimeoutError):
        return None
    try:
        return await read_banner_from_stream(reader, timeout=timeout, limit=limit)
    finally:
        writer.close()
        await writer.wait_closed()


async def read_banner_from_stream(
    reader: asyncio.StreamReader,
    *,
    timeout: float = 0.5,
    limit: int = 512,
) -> str | None:
    try:
        data = await asyncio.wait_for(reader.read(limit), timeout=timeout)
    except TimeoutError:
        data = b""
    if not data:
        return None
    text = data.decode("utf-8", errors="replace").strip()
    return text or None


def grab_banner_sync(host: str, port: int, timeout: float = 1.0, limit: int = 512) -> str | None:
    return asyncio.run(grab_banner_async(host, port, timeout=timeout, limit=limit))

