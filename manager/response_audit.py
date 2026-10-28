"""Append-only decision facts; callers own the state-change transaction."""

import json
from uuid import uuid4

from manager.timeutil import iso_now


def record_decision(conn, response_id, event, actor, detail=None):
    conn.execute(
        "INSERT INTO response_decision_audit "
        "(event_id,response_id,event,actor,detail,occurred_at) VALUES (?,?,?,?,?,?)",
        (
            str(uuid4()),
            response_id,
            event,
            actor,
            json.dumps(detail, sort_keys=True) if detail is not None else None,
            iso_now(),
        ),
    )
