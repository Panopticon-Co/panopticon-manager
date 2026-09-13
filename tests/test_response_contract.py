"""Two-way contract test: manager.routers.commands.authorize_and_enqueue's
ACTUAL stored wire payload (the commands.command_json row an agent's poll()
call receives verbatim -- see manager/routers/commands.py) must validate
against Panopticon-Co/panopticon-contracts' schema/command.schema.json for
every one of the seven closed actions.

Follows the same sibling-checkout convention as test_ingest_contract.py
(panopticon-agent's schema): panopticon-contracts is checked out as a
workspace sibling in CI (see .github/workflows/ci.yml), not vendored as a
package or submodule -- this is a documentation/fixture repository, not a
runtime dependency (see panopticon-contracts/README.md).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest

from manager import migrations
from manager.routers.commands import Command, authorize_and_enqueue

_WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
_CONTRACTS_ROOT = _WORKSPACE_ROOT / "panopticon-contracts"
_COMMAND_SCHEMA = json.loads((_CONTRACTS_ROOT / "schema" / "command.schema.json").read_text())
_VALID_COMMAND_FIXTURES = json.loads(
    (_CONTRACTS_ROOT / "fixtures" / "commands" / "valid.json").read_text()
)

# Fields Manager injects at dispatch time -- see docs/CONTRACT.md section 2.
_MANAGER_INJECTED_FIELDS = ("host_id", "schema_version", "created_at")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    migrations.migrate(conn)
    return conn


def _enroll_agent(conn: sqlite3.Connection, agent_id: str, host_id: str) -> None:
    conn.execute(
        "INSERT INTO enrolled_agents (agent_id, host_id, token_digest, enrolled_at, revoked_at) "
        "VALUES (?, ?, 'digest', ?, NULL)",
        (agent_id, host_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


@pytest.mark.parametrize(
    "action", [key for key in _VALID_COMMAND_FIXTURES if not key.startswith("$")]
)
def test_dispatched_wire_payload_matches_the_canonical_schema(action: str) -> None:
    fixture = _VALID_COMMAND_FIXTURES[action]["command"]
    agent_id, host_id = fixture["agent_id"], fixture["host_id"]
    conn = _conn()
    _enroll_agent(conn, agent_id, host_id)

    # The fixture's own expires_at is a fixed, deterministic timestamp (see
    # panopticon-contracts/fixtures/README.md) -- authorize_and_enqueue checks
    # it against real wall-clock time, so it is overridden here to a
    # dynamically future value, exactly as that README instructs any
    # consuming test to do rather than comparing a fixed fixture timestamp
    # against "now".
    command_fields = {
        key: value for key, value in fixture.items() if key not in _MANAGER_INJECTED_FIELDS
    }
    command_fields["expires_at"] = datetime.now(timezone.utc) + timedelta(minutes=10)
    command = Command(**command_fields)

    authorize_and_enqueue(conn, command, actor="test:contract")

    stored = conn.execute(
        "SELECT command_json FROM commands WHERE command_id = ?", (command.command_id,)
    ).fetchone()
    assert stored is not None
    wire_payload = json.loads(stored["command_json"])

    # authorize_and_enqueue also injects created_at (see docs/CONTRACT.md
    # section 2's reconciliation), which the schema requires but this test
    # cannot pin to the fixture's original fixed value -- confirm it exists
    # and is schema-valid rather than asserting an exact value.
    assert "created_at" in wire_payload
    jsonschema.validate(wire_payload, _COMMAND_SCHEMA)
    assert wire_payload["action"] == action
    assert wire_payload["host_id"] == host_id
    assert wire_payload["schema_version"] == "1"
