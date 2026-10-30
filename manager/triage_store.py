"""Migration and transactional persistence for bounded collection workflows."""

import json


def install(conn):
    conn.execute("""CREATE TABLE triage_policy_revisions (
        rule_id TEXT NOT NULL, version INTEGER NOT NULL CHECK(version>0),
        policy_json TEXT NOT NULL, actor TEXT NOT NULL, created_at TEXT NOT NULL,
        PRIMARY KEY(rule_id,version))""")
    conn.execute("""CREATE TABLE triage_policy_heads (
        rule_id TEXT PRIMARY KEY, version INTEGER NOT NULL,
        FOREIGN KEY(rule_id,version) REFERENCES triage_policy_revisions(rule_id,version))""")
    conn.execute("""CREATE TABLE triage_asset_classes (
        host_id TEXT PRIMARY KEY, asset_class TEXT NOT NULL
        CHECK(asset_class IN ('standard','critical','unknown')), version INTEGER NOT NULL,
        actor TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE triage_runs (
        alert_id TEXT PRIMARY KEY REFERENCES alerts(alert_id), rule_id TEXT NOT NULL,
        policy_version INTEGER NOT NULL, policy_json TEXT NOT NULL,
        agent_id TEXT NOT NULL, host_id TEXT NOT NULL, asset_class TEXT NOT NULL,
        asset_version INTEGER NOT NULL, created_at TEXT NOT NULL, deadline TEXT NOT NULL,
        cancelled_at TEXT, FOREIGN KEY(rule_id,policy_version)
        REFERENCES triage_policy_revisions(rule_id,version))""")
    conn.execute("""CREATE TABLE triage_items (
        alert_id TEXT NOT NULL REFERENCES triage_runs(alert_id), action TEXT NOT NULL
        CHECK(action IN ('COLLECT_PROCESS_INFO','COLLECT_NETWORK_CONNECTIONS','COLLECT_FILE')),
        decision TEXT NOT NULL CHECK(decision IN ('auto_dispatch','skip','require_approval')),
        reason TEXT NOT NULL, target_json TEXT NOT NULL, reserved_bytes INTEGER NOT NULL
        CHECK(reserved_bytes IN (0,1048576)),
        response_id TEXT UNIQUE REFERENCES response_actions(response_id),
        PRIMARY KEY(alert_id,action))""")
    conn.execute("CREATE INDEX triage_endpoint_window ON triage_runs(agent_id,created_at)")
    conn.execute("""CREATE TABLE triage_admin_requests (
        actor TEXT NOT NULL, request_id TEXT NOT NULL, payload_json TEXT NOT NULL,
        result_json TEXT NOT NULL, PRIMARY KEY(actor,request_id))""")
    for table in ("triage_policy_revisions", "triage_items", "triage_admin_requests"):
        for operation in ("UPDATE", "DELETE"):
            conn.execute(f"""CREATE TRIGGER immutable_{table}_{operation.lower()}
                BEFORE {operation} ON {table}
                BEGIN SELECT RAISE(ABORT,'triage history is immutable'); END""")
    # These facts enter the existing hardened chain, not a second audit writer.
    for source, key, link, events in (
        ("command_audit", "command_id", "'resp-' || i.response_id=NEW.command_id",
         "'created','dispatched','accepted','result_received','cancelled','expired'"),
        ("response_decision_audit", "response_id", "i.response_id=NEW.response_id",
         "'authorized','rejected','cancelled','expired'"),
    ):
        audited = ""
        if source == "command_audit":
            audited = """INSERT INTO response_security_audit
                SELECT lower(hex(randomblob(16))),i.response_id,r.host_id,
                    'auto_triage_audited','system/auto-triage',
                    json_object('alert_id',r.alert_id,'rule_id',r.rule_id,
                        'policy_version',r.policy_version,'command_id',NEW.command_id),
                    NEW.occurred_at
                FROM triage_items i JOIN triage_runs r ON r.alert_id=i.alert_id
                WHERE 'resp-' || i.response_id=NEW.command_id AND NEW.event='result_received';"""
        conn.execute(f"""CREATE TRIGGER triage_mirror_{source} AFTER INSERT ON {source}
            WHEN NEW.event IN ({events}) BEGIN
            INSERT INTO response_security_audit
            SELECT lower(hex(randomblob(16))),i.response_id,r.host_id,
                'auto_triage_' || NEW.event,'system/auto-triage',
                json_object('alert_id',r.alert_id,'rule_id',r.rule_id,
                    'policy_version',r.policy_version,'action',i.action,
                    'source_actor',NEW.actor,'source_id',NEW.{key}),NEW.occurred_at
            FROM triage_items i JOIN triage_runs r ON r.alert_id=i.alert_id WHERE {link};
            {audited} END""")


def policy_for(conn, rule_id):
    row = conn.execute(
        "SELECT p.policy_json FROM triage_policy_heads h JOIN triage_policy_revisions p "
        "ON p.rule_id=h.rule_id AND p.version=h.version WHERE h.rule_id=?", (rule_id,),
    ).fetchone()
    return json.loads(row[0]) if row else None


def asset_for(conn, host_id):
    row = conn.execute("SELECT * FROM triage_asset_classes WHERE host_id=?", (host_id,)).fetchone()
    return (row["asset_class"], row["version"]) if row else ("unknown", 0)
