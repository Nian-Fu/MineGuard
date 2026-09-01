from fastapi import HTTPException


def enforce_if_match(resource, if_match: str | None) -> None:
    """Reject a stale UI write after the resource row has been locked."""
    if if_match is None:
        return
    expected = f'"{resource.concurrency_token}"'
    if if_match.strip() != expected:
        raise HTTPException(
            status_code=409,
            detail="资源已被其他操作更新，请刷新后重新提交",
        )
