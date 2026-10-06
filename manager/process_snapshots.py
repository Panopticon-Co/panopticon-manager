"""Scoped immutable process pages. Assembly proof is distinct from native coverage."""
from __future__ import annotations

import json
import re

from fastapi import HTTPException

_ID = re.compile(r"rec_[0-9a-f]{64}\Z")
_VERIFY_BYTES = 64 * 1024 * 1024


def index_record(conn, record: dict) -> None:
    """Derived lookup only; called in the immutable record acceptance transaction."""
    if record.get("kind") != "state":
        return
    roles = {
        "process_inventory_begin": "begin",
        "process_inventory_page": "page",
        "process_inventory": "manifest",
    }
    role = roles.get(record.get("category"))
    if role is None:
        return
    data = record["data"]
    if role == "begin":
        if data.get("format") != "paged_process_inventory_begin_v1":
            return
        capture_id = record["record_id"]
    else:
        if role == "manifest" and data.get("format") != "paged_process_inventory_v1":
            return
        capture_id = data.get("capture_id")
    if not isinstance(capture_id, str) or _ID.fullmatch(capture_id) is None:
        return
    provenance = record["provenance"]
    page_index = data.get("page_index") if role == "page" else None
    # Preserve valid index text; malformed values remain explicit in the read API.
    if not isinstance(page_index, str) or len(page_index) > 64:
        page_index = None
    conn.execute(
        "INSERT INTO endpoint_process_capture_records "
        "(agent_id,capture_id,record_id,role,endpoint_scope,collector_epoch,"
        "collector_generation,page_index) VALUES (?,?,?,?,?,?,?,?)",
        (record["endpoint"]["agent_id"], capture_id, record["record_id"], role,
         json.dumps(record["endpoint"], sort_keys=True, separators=(",", ":")),
         provenance.get("collector_epoch"), provenance.get("collector_generation"), page_index),
    )


def load_begin(conn, agent_id: str, capture_id: str) -> dict:
    if _ID.fullmatch(capture_id) is None:
        raise HTTPException(422, "invalid immutable capture identifier")
    row = conn.execute(
        "SELECT raw_json FROM endpoint_records WHERE agent_id=? AND record_id=?",
        (agent_id, capture_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "process capture begin not retained")
    begin = json.loads(row["raw_json"])
    if (begin["kind"] != "state" or begin["category"] != "process_inventory_begin"
            or begin["data"].get("format") != "paged_process_inventory_begin_v1"):
        raise HTTPException(422, "record is not a process capture begin")
    return begin


def capture_record(conn, agent_id: str, capture_id: str, record_id: str) -> dict:
    begin = load_begin(conn, agent_id, capture_id)
    row = conn.execute(
        "SELECT e.raw_json FROM endpoint_process_capture_records AS c "
        "JOIN endpoint_records AS e ON e.agent_id=c.agent_id AND e.record_id=c.record_id "
        "WHERE c.agent_id=? AND c.capture_id=? AND c.record_id=?",
        (agent_id, capture_id, record_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "record not retained under this capture")
    record = json.loads(row["raw_json"])
    return {
        "record": record,
        "scope_matches_begin": record["endpoint"] == begin["endpoint"]
        and all(record["provenance"].get(key) == begin["provenance"].get(key)
                for key in ("collector_epoch", "collector_generation")),
        "scope": "one immutable record claiming this capture; assembly/lifecycle unverified",
    }


def capture(conn, agent_id: str, capture_id: str, after: str | None, limit: int) -> dict:
    """Discover an unfinished capture without parsing every retained page body."""
    if after is not None and _ID.fullmatch(after) is None:
        raise HTTPException(422, "invalid immutable capture cursor identifier")
    begin = load_begin(conn, agent_id, capture_id)
    scope = json.dumps(begin["endpoint"], sort_keys=True, separators=(",", ":"))
    epoch = begin["provenance"].get("collector_epoch")
    generation = begin["provenance"].get("collector_generation")
    rows = conn.execute(
        "SELECT * FROM endpoint_process_capture_records WHERE agent_id=? AND capture_id=? "
        "AND record_id>? ORDER BY record_id LIMIT ?",
        (agent_id, capture_id, after or "", limit + 1),
    ).fetchall()
    references = []
    for item in rows[:limit]:
        references.append({
            "record_id": item["record_id"], "role": item["role"],
            "page_index": item["page_index"],
            "scope_matches_begin": item["endpoint_scope"] == scope
            and item["collector_epoch"] == epoch and item["collector_generation"] == generation,
            "page_index_valid": item["role"] != "page" or (
                item["page_index"] is not None
                and re.fullmatch(r"0|[1-9][0-9]{0,3}", item["page_index"]) is not None
                and int(item["page_index"]) < 4096
            ),
        })
    counts = conn.execute(
        "SELECT role,COUNT(*) AS count FROM endpoint_process_capture_records "
        "WHERE agent_id=? AND capture_id=? GROUP BY role",
        (agent_id, capture_id),
    ).fetchall()
    by_role = {item["role"]: item["count"] for item in counts}
    return {
        "begin": begin, "references": references,
        "retained_record_counts": by_role,
        "manifest_status": "observed_unverified" if by_role.get("manifest", 0) else "not_observed",
        "next_cursor": references[-1]["record_id"] if len(rows) > limit else None,
        "inventory_complete": False,
        "scope": "retained capture discovery; manifest/page assembly and lifecycle unverified",
        "continuity": (
            "unverified; absent manifest can mean in-progress, delayed delivery "
            "or interrupted capture"
        ),
        "consistency": (
            "separate immutable lookups; concurrent arrivals may require restarting pagination"
        ),
    }


def load_manifest(conn, agent_id: str, record_id: str) -> dict:
    row = conn.execute(
        "SELECT raw_json FROM endpoint_records WHERE agent_id=? AND record_id=?",
        (agent_id, record_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "process manifest not retained")
    record = json.loads(row["raw_json"])
    data = record["data"]
    ids = data.get("page_record_ids")
    if (
        record["kind"] != "state" or record["category"] != "process_inventory"
        or data.get("format") != "paged_process_inventory_v1"
        or not isinstance(ids, list) or len(ids) > 4096
        or any(not isinstance(value, str) or _ID.fullmatch(value) is None for value in ids)
        or len(set(ids)) != len(ids)
        or not isinstance(data.get("capture_id"), str)
        or _ID.fullmatch(data["capture_id"]) is None
    ):
        raise HTTPException(422, "record is not a valid paged process manifest")
    return record


def load_page(conn, agent_id: str, manifest: dict, index: int) -> dict | None:
    ids = manifest["data"]["page_record_ids"]
    if index < 0 or index >= len(ids):
        raise HTTPException(404, "process page index outside retained manifest")
    row = conn.execute(
        "SELECT raw_json FROM endpoint_records WHERE agent_id=? AND record_id=?",
        (agent_id, ids[index]),
    ).fetchone()
    if row is None:
        return None
    page = json.loads(row["raw_json"])
    data = page["data"]
    if (
        page["kind"] != "state" or page["category"] != "process_inventory_page"
        or page["endpoint"] != manifest["endpoint"]
        or any(page["provenance"].get(key) != manifest["provenance"].get(key)
               for key in ("collector_epoch", "collector_generation"))
        or data.get("capture_id") != manifest["data"]["capture_id"]
        or data.get("page_index") != str(index)
        or not isinstance(data.get("entries"), list) or len(data["entries"]) > 8192
    ):
        raise HTTPException(409, "retained process page disagrees with manifest scope/index")
    return page


def overview(conn, agent_id: str, record_id: str) -> dict:
    manifest = load_manifest(conn, agent_id, record_id)
    issues = []
    entries = 0
    verified_bytes = 0
    for index in range(len(manifest["data"]["page_record_ids"])):
        size = conn.execute(
            "SELECT length(CAST(raw_json AS BLOB)) AS bytes FROM endpoint_records "
            "WHERE agent_id=? AND record_id=?",
            (agent_id, manifest["data"]["page_record_ids"][index]),
        ).fetchone()
        if size is not None:
            verified_bytes += size["bytes"]
        if verified_bytes > _VERIFY_BYTES:
            issues.append({"reason": "aggregate_verification_byte_budget_exceeded"})
            break
        try:
            page = load_page(conn, agent_id, manifest, index)
        except HTTPException:
            issues.append({"page_index": index, "reason": "scope_or_index_mismatch"})
            continue
        if page is None:
            issues.append({"page_index": index, "reason": "not_retained"})
        else:
            entries += len(page["data"]["entries"])
    data = manifest["data"]
    if data.get("entries_delivered") != str(entries):
        issues.append({"reason": "manifest_entry_count_disagrees"})
    begin = conn.execute(
        "SELECT raw_json FROM endpoint_records WHERE agent_id=? AND record_id=?",
        (agent_id, data["capture_id"]),
    ).fetchone()
    if begin is None:
        issues.append({"reason": "capture_begin_not_retained"})
    else:
        record = json.loads(begin["raw_json"])
        if (
            record["kind"] != "state" or record["category"] != "process_inventory_begin"
            or record["endpoint"] != manifest["endpoint"]
            or any(record["provenance"].get(key) != manifest["provenance"].get(key)
                   for key in ("collector_epoch", "collector_generation"))
        ):
            issues.append({"reason": "capture_begin_scope_mismatch"})
    return {
        "manifest": manifest, "page_count": len(data["page_record_ids"]),
        "verified_entry_count": entries, "issues": issues,
        "assembly_complete": not issues,
        "enumeration_complete": not issues and data.get("enumeration_complete") is True
        and data.get("bound_exceeded") is False and data.get("consumer_refused") is False,
        "inventory_complete": False,
        "verification_byte_limit": _VERIFY_BYTES,
        "scope": (
            "retained page assembly and endpoint-reported enumeration; "
            "native coverage/lifecycle unverified"
        ),
        "consistency": (
            "immutable records read separately; concurrent page arrival "
            "can change missing-page status"
        ),
    }
