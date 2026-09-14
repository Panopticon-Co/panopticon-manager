"""Authenticated bootstrap enrollment for endpoint agents.

Phase 13 (docs/adr/004-agent-enrollment-identity.md): enrollment now proves
cryptographic possession of an ECDSA P-256 keypair generated on the endpoint,
not just knowledge of the fleet-wide bootstrap token. See
panopticon-contracts/schema/enrollment_request.schema.json for the canonical
wire shape."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel, ConfigDict, Field

from manager.auth import enroll, issue_enrollment_challenge

router = APIRouter()


class EnrollmentChallengeResponse(BaseModel):
    nonce: str
    expires_at: str


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=128)
    host_id: str = Field(min_length=1, max_length=128)
    public_key: str = Field(min_length=60, max_length=100)
    nonce: str = Field(min_length=40, max_length=48)
    signature: str = Field(min_length=86, max_length=90)


class EnrollmentResponse(BaseModel):
    agent_id: str
    access_token: str
    token_type: str = "Bearer"


@router.post("/api/v1/agents/enrollment-challenge", response_model=EnrollmentChallengeResponse)
async def enrollment_challenge() -> EnrollmentChallengeResponse:
    """No authentication required: a nonce alone proves nothing and is
    useless without a subsequent valid bootstrap token plus a real
    signature, so gating this endpoint would add no security -- it would
    only make legitimate enrollment need one more authenticated round trip."""
    nonce, expires_at = issue_enrollment_challenge()
    return EnrollmentChallengeResponse(nonce=nonce, expires_at=expires_at)


@router.post("/api/v1/agents/enroll", response_model=EnrollmentResponse)
async def enrollment(
    request: EnrollmentRequest, x_panopticon_enrollment_token: str = Header(...)
) -> EnrollmentResponse:
    token = enroll(
        request.agent_id,
        request.host_id,
        x_panopticon_enrollment_token,
        public_key=request.public_key,
        nonce=request.nonce,
        signature=request.signature,
    )
    return EnrollmentResponse(agent_id=request.agent_id, access_token=token)
