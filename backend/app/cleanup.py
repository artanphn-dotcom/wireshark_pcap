from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path


UPLOAD_RETENTION_SECONDS = 600


def ensure_upload_dir(upload_dir: Path) -> None:
    upload_dir.mkdir(parents=True, exist_ok=True)


async def delete_file_after_delay(file_path: Path, delay_seconds: int = UPLOAD_RETENTION_SECONDS) -> None:
    await asyncio.sleep(delay_seconds)
    try:
        file_path.unlink(missing_ok=True)
    except Exception:
        # Best-effort cleanup; endpoint flow should not crash on cleanup failure.
        return


def schedule_file_deletion(file_path: Path, delay_seconds: int = UPLOAD_RETENTION_SECONDS) -> None:
    asyncio.create_task(delete_file_after_delay(file_path, delay_seconds))


def purge_stale_uploads(upload_dir: Path, retention_seconds: int = UPLOAD_RETENTION_SECONDS) -> int:
    """Delete uploads older than retention window. Returns count removed."""
    if not upload_dir.exists():
        return 0

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=retention_seconds)
    removed = 0

    for item in upload_dir.iterdir():
        if not item.is_file():
            continue
        try:
            modified_at = datetime.fromtimestamp(item.stat().st_mtime, tz=timezone.utc)
            if modified_at <= cutoff:
                item.unlink(missing_ok=True)
                removed += 1
        except Exception:
            continue

    return removed
