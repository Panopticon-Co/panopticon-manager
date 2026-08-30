from datetime import datetime, timedelta, timezone

from manager.routers.ingest import is_clock_skewed


def test_recent_timestamp_is_not_skewed() -> None:
    now = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
    ts = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert is_clock_skewed(ts, now) is False


def test_just_under_24h_is_not_skewed() -> None:
    now = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
    ts = (now - timedelta(hours=23, minutes=59)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert is_clock_skewed(ts, now) is False


def test_over_24h_in_the_past_is_skewed() -> None:
    now = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
    ts = (now - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert is_clock_skewed(ts, now) is True


def test_over_24h_in_the_future_is_skewed() -> None:
    now = datetime(2026, 8, 30, 12, 0, 0, tzinfo=timezone.utc)
    ts = (now + timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    assert is_clock_skewed(ts, now) is True
