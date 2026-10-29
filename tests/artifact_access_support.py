"""Explicit test provisioning through real authenticated scope-management routes."""


def administrator(client, name="evidence-admin"):
    result = client.post(
        "/api/v1/analysts/enroll",
        json={"analyst_id": name, "role": "artifact_admin"},
        headers={"X-Panopticon-Analyst-Enrollment-Token": "test-artifact-admin-token"},
    )
    assert result.status_code == 200, result.text
    return {"Authorization": "Bearer " + result.json()["access_token"]}


def grant_reader(
    client, reader, *, admin=None, request_id="scope-test-1", host_id="host-1", alert_id="alert-1"
):
    analyst_id = client.get("/api/v1/analysts/me", headers=reader).json()["analyst_id"]
    result = client.post(
        "/api/v1/artifact-access/grants",
        headers=admin or administrator(client),
        json={
            "schema_version": "1",
            "policy_version": 1,
            "request_id": request_id,
            "analyst_id": analyst_id,
            "host_id": host_id,
            "alert_id": alert_id,
            "reason": "Explicit access to this test case and endpoint",
        },
    )
    assert result.status_code == 200, result.text
    return result.json()
