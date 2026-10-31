"""Read-only analyst views of who is sending telemetry and what it says:
GET /api/v1/agents and GET /api/v1/events. Nothing here writes, and nothing is
synthesized -- every field is read from ``enrolled_agents``, ``events``,
``endpoint_records`` or ``alerts``. A field the stored telemetry does not carry
is null, never guessed.

``/api/v1/events`` tails both telemetry tables by SQLite rowid (insertion
order): pass the previous response's ``cursor`` back as ``after_event`` /
``after_record`` to receive only rows ingested since. Without a cursor it
returns the newest ``limit`` rows of each table."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Header, Query

from manager import db
from manager.auth import require_analyst_token
from manager.timeutil import iso_now

router = APIRouter()

ONLINE_SECONDS = 120
STALE_SECONDS = 900
MAX_EVENTS = 200
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _age_seconds(ts: str | None, now: datetime) -> float | None:
    if not ts:
        return None
    try:
        moment = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (now - moment).total_seconds()


def _connection_status(last_seen: str | None, revoked: bool, now: datetime) -> str:
    if revoked:
        return "revoked"
    age = _age_seconds(last_seen, now)
    if age is None:
        return "never_seen"
    if age <= ONLINE_SECONDS:
        return "online"
    return "stale" if age <= STALE_SECONDS else "offline"


def _host_of(raw: str | None) -> dict:
    try:
        host = json.loads(raw or "{}").get("host")
    except (ValueError, AttributeError):
        return {}
    return host if isinstance(host, dict) else {}


def _activity(conn) -> dict[str, dict]:
    """Per agent_id: last ingest, counts and host details across both tables."""
    out: dict[str, dict] = {}
    for table, ts_col in (("events", "event_timestamp"), ("endpoint_records", "observed_at")):
        for row in conn.execute(
            f"SELECT agent_id, MIN(host_id) AS host_id, COUNT(*) AS c, MAX(ingested_at) AS last, "
            f"MAX({ts_col}) AS last_observed FROM {table} GROUP BY agent_id"
        ):
            entry = out.setdefault(
                row["agent_id"],
                {
                    "host_id": row["host_id"],
                    "event_count": 0,
                    "record_count": 0,
                    "last_seen": None,
                    "last_observed": None,
                },
            )
            entry["event_count" if table == "events" else "record_count"] += row["c"]
            for key, value in (("last_seen", row["last"]), ("last_observed", row["last_observed"])):
                if value and (entry[key] is None or value > entry[key]):
                    entry[key] = value
    for agent_id, entry in out.items():
        latest = conn.execute(
            "SELECT category, raw_json FROM events WHERE agent_id = ? ORDER BY rowid DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
        if latest is None:
            latest = conn.execute(
                "SELECT category, NULL AS raw_json FROM endpoint_records WHERE agent_id = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (agent_id,),
            ).fetchone()
        host = _host_of(latest["raw_json"]) if latest else {}
        os_info = host.get("os") if isinstance(host.get("os"), dict) else {}
        entry["last_category"] = latest["category"] if latest else None
        entry["hostname"] = host.get("hostname")
        entry["os"] = (
            " ".join(str(v) for v in (os_info.get("name"), os_info.get("build")) if v) or None
        )
    return out


@router.get("/api/v1/agents")
async def list_agents(authorization: str | None = Header(default=None)) -> dict:
    require_analyst_token(authorization)
    conn = db.connect()
    now = datetime.now(timezone.utc)
    activity = _activity(conn)
    channels = {r["agent_id"] for r in conn.execute("SELECT agent_id FROM agent_response_channels")}
    agents = []
    for row in conn.execute(
        "SELECT agent_id, host_id, enrolled_at, revoked_at FROM enrolled_agents "
        "ORDER BY enrolled_at DESC"
    ):
        seen = activity.pop(row["agent_id"], {})
        agents.append(
            {
                "agent_id": row["agent_id"],
                "host_id": row["host_id"],
                "enrolled_at": row["enrolled_at"],
                "revoked_at": row["revoked_at"],
                "response_channel": row["agent_id"] in channels,
                "hostname": seen.get("hostname"),
                "os": seen.get("os"),
                "last_seen": seen.get("last_seen"),
                "last_observed": seen.get("last_observed"),
                "event_count": seen.get("event_count", 0),
                "record_count": seen.get("record_count", 0),
                "last_category": seen.get("last_category"),
                "status": _connection_status(
                    seen.get("last_seen"), row["revoked_at"] is not None, now
                ),
            }
        )
    unenrolled = [
        {
            "agent_id": agent_id,
            **entry,
            "status": _connection_status(entry["last_seen"], False, now),
        }
        for agent_id, entry in sorted(activity.items())
    ]
    return {
        "generated_at": iso_now(),
        "thresholds_seconds": {"online": ONLINE_SECONDS, "stale": STALE_SECONDS},
        "agents": agents,
        "unenrolled_sources": unenrolled,
    }


def _get(obj, *path):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _section(raw: dict, key: str) -> dict | None:
    value = raw.get(key)
    return value if isinstance(value, dict) else None


def _summarize_event(row) -> dict:
    try:
        raw = json.loads(row["raw_json"])
    except ValueError:
        raw = {}
    proc = _section(raw, "process") or {}
    return {
        "kind": "event",
        "cursor": row["rowid"],
        "event_id": row["event_id"],
        "agent_id": row["agent_id"],
        "host_id": row["host_id"],
        "category": row["category"],
        "type": _get(raw, "event", "type"),
        "timestamp": row["event_timestamp"],
        "ingested_at": row["ingested_at"],
        "schema_version": row["schema_version"],
        "detect_state": row["detect_state"],
        "source": _get(raw, "source", "kind"),
        "user": _get(raw, "user", "name"),
        "process": {
            "pid": proc.get("pid"),
            "name": proc.get("name"),
            "executable": proc.get("executable"),
            "command_line": proc.get("command_line"),
            "parent_pid": _get(proc, "parent", "pid"),
            "parent_name": _get(proc, "parent", "name"),
        },
        **{key: _section(raw, key) for key in ("network", "file", "registry", "dns")},
        "raw": raw,
    }


def _summarize_record(row) -> dict:
    try:
        raw = json.loads(row["raw_json"])
    except ValueError:
        raw = {}
    data = _section(raw, "data") or {}
    proc = _section(data, "process") or {}
    return {
        "kind": "endpoint_record",
        "cursor": row["rowid"],
        "event_id": row["record_id"],
        "agent_id": row["agent_id"],
        "host_id": row["host_id"],
        "category": row["category"],
        "type": row["kind"],
        "timestamp": row["observed_at"],
        "ingested_at": row["ingested_at"],
        "schema_version": "endpoint-v2",
        "detect_state": row["detect_state"],
        "source": _get(raw, "provenance", "kind"),
        "user": None,
        "process": {
            "pid": proc.get("observed_pid", proc.get("pid")),
            "name": proc.get("name"),
            "executable": proc.get("executable") or proc.get("image"),
            "command_line": proc.get("command_line"),
            "parent_pid": _get(data, "parent", "observed_pid"),
            "parent_name": _get(data, "parent", "name"),
        },
        "network": None,
        "file": None,
        "registry": None,
        "dns": None,
        "raw": raw,
    }


_TABLES = (
    (
        "events",
        "event",
        "rowid, event_id, agent_id, host_id, category, event_timestamp, ingested_at, "
        "schema_version, detect_state, raw_json",
        _summarize_event,
    ),
    (
        "endpoint_records",
        "record",
        "rowid, record_id, agent_id, host_id, kind, category, observed_at, ingested_at, "
        "detect_state, raw_json",
        _summarize_record,
    ),
)


@router.get("/api/v1/events")
async def list_events(
    authorization: str | None = Header(default=None),
    host_id: str | None = Query(default=None, max_length=256),
    category: str | None = Query(default=None, max_length=64),
    after_event: int | None = Query(default=None, ge=0),
    after_record: int | None = Query(default=None, ge=0),
    limit: int = Query(default=100, ge=1, le=MAX_EVENTS),
) -> dict:
    require_analyst_token(authorization)
    conn = db.connect()
    afters = {"event": after_event, "record": after_record}
    items: list[dict] = []
    cursor: dict[str, int] = {}
    for table, key, columns, summarize in _TABLES:
        after = afters[key]
        clauses, params = [], []
        for column, value in (("host_id", host_id), ("category", category)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        if after is not None:
            clauses.append("rowid > ?")
            params.append(after)
        where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
        # Tailing reads forward from the cursor; a first load takes the newest rows.
        order = "ASC" if after is not None else "DESC"
        rows = conn.execute(
            f"SELECT {columns} FROM {table} {where}ORDER BY rowid {order} LIMIT ?", (*params, limit)
        ).fetchall()
        items.extend(summarize(r) for r in rows)
        if after is None:
            cursor[key] = conn.execute(f"SELECT MAX(rowid) AS m FROM {table}").fetchone()["m"] or 0
        else:
            cursor[key] = max((r["rowid"] for r in rows), default=after)

    ids = [i["event_id"] for i in items]
    linked: dict[str, list] = {}
    for start in range(0, len(ids), 500):
        chunk = ids[start : start + 500]
        for row in conn.execute(
            f"SELECT event_id, alert_id, rule_id, severity FROM alerts "
            f"WHERE event_id IN ({','.join('?' * len(chunk))})",
            chunk,
        ):
            linked.setdefault(row["event_id"], []).append(
                {
                    "alert_id": row["alert_id"],
                    "rule_id": row["rule_id"],
                    "severity": row["severity"],
                }
            )
    for item in items:
        item["alerts"] = linked.get(item["event_id"], [])
        ranked = [a["severity"] for a in item["alerts"] if a["severity"] in _SEVERITY_RANK]
        item["severity"] = max(ranked, key=_SEVERITY_RANK.get) if ranked else "info"
    items.sort(key=lambda i: (i["ingested_at"] or "", i["cursor"]), reverse=True)
    return {
        "generated_at": iso_now(),
        "cursor": {"after_event": cursor["event"], "after_record": cursor["record"]},
        "events": items,
    }
