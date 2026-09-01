from app.worker import WorkerWatchdog


def test_worker_watchdog_deadline_moves_with_progress(monkeypatch):
    current = 100.0
    monkeypatch.setattr("app.worker.time.monotonic", lambda: current)
    watchdog = WorkerWatchdog(timeout_seconds=60)

    assert not watchdog.is_stale(now=160)
    assert watchdog.is_stale(now=160.001)

    current = 150
    watchdog.progress()
    assert not watchdog.is_stale(now=210)
    assert watchdog.is_stale(now=210.001)
