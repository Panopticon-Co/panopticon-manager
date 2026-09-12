"""Authenticated bootstrap enrollment for endpoint agents."""

from __future__ import annotations

from fastapi import APIRouter, Header
from pydantic import BaseModel, ConfigDict, Field

from manager.auth import enroll

router = APIRouter()


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str = Field(min_length=1, max_length=128)
    host_id: str = Field(min_length=1, max_length=128)


class EnrollmentResponse(BaseModel):
    agent_id: str
    access_token: str
    token_type: str = "Bearer"


@router.post("/api/v1/agents/enroll", response_model=EnrollmentResponse)
async def enrollment(
    request: EnrollmentRequest, x_panopticon_enrollment_token: str = Header(...)
) -> EnrollmentResponse:
    token = enroll(request.agent_id, request.host_id, x_panopticon_enrollment_token)
    return EnrollmentResponse(agent_id=request.agent_id, access_token=token)
