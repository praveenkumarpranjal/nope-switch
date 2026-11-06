from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, HttpUrl, field_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Enforcement(StrEnum):
    SEMGREP = "semgrep"
    TEST = "test"
    CI = "ci"


class ScarStatus(StrEnum):
    PROPOSED = "proposed"
    VALIDATED = "validated"
    APPROVED = "approved"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    CHALLENGED = "challenged"


class CreateScarRequest(BaseModel):
    title: str = Field(min_length=8, max_length=160)
    incident_summary: str = Field(min_length=12, max_length=4000)
    invariant: str = Field(min_length=8, max_length=2000)
    rationale: str = Field(min_length=8, max_length=4000)
    remediation: str = Field(min_length=8, max_length=4000)
    incident_url: HttpUrl | None = None
    repository: str = Field(min_length=2, max_length=200)
    scope: str = Field(min_length=2, max_length=200)
    severity: Severity = Severity.HIGH
    enforcement: Enforcement = Enforcement.SEMGREP
    origin: str = Field(min_length=2, max_length=400)
    proposed_by: str = Field(min_length=2, max_length=200)

    @field_validator("title", "incident_summary", "invariant", "rationale", "remediation", "origin", "proposed_by")
    @classmethod
    def strip_and_reject_control_chars(cls, value: str) -> str:
        cleaned = value.strip()
        if any(ord(char) < 9 or 13 < ord(char) < 32 for char in cleaned):
            raise ValueError("control characters are not allowed")
        return cleaned


class ScarExample(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9._-]{1,80}$")
    content: str = Field(min_length=1, max_length=500_000)


class ValidateScarRequest(BaseModel):
    rule_yaml: str = Field(min_length=20, max_length=250_000)
    bad_examples: list[ScarExample] = Field(min_length=1, max_length=20)
    good_examples: list[ScarExample] = Field(max_length=20)
    target_path: str | None = Field(default=None, max_length=2000)


class ApprovalRequest(BaseModel):
    approver: str = Field(min_length=2, max_length=200)
    reason: str = Field(min_length=8, max_length=2000)


class BreakGlassActivationRequest(BaseModel):
    reason: str = Field(
        min_length=10, max_length=2000, description="Mandatory rationale explaining why GitOps PR merge was bypassed"
    )
    authorized_by: str = Field(min_length=2, max_length=200, description="Authorized administrator identity")


class ChallengeRequest(BaseModel):
    challenger: str = Field(min_length=2, max_length=200)
    reason: str = Field(min_length=12, max_length=4000)
    requested_by: str = Field(min_length=2, max_length=200)
    proposed_rule_yaml: str | None = Field(default=None, max_length=250_000)
    bad_examples: list[ScarExample] = Field(default_factory=list, max_length=20)
    good_examples: list[ScarExample] = Field(default_factory=list, max_length=20)
    expires_in_days: int = Field(default=14, ge=1, le=90)


class ScarResponse(BaseModel):
    id: str
    number: int
    title: str
    incident_summary: str
    invariant: str
    rationale: str
    remediation: str
    incident_url: str | None
    repository: str
    scope: str
    severity: Severity
    enforcement: Enforcement
    origin: str
    proposed_by: str
    status: ScarStatus
    active: bool
    approved_by: str | None
    created_at: datetime
    updated_at: datetime


class ValidationResponse(BaseModel):
    passed: bool
    bad_findings: list[str]
    good_findings: list[str]
    rule_errors: list[str]
    target_findings: list[str]
    total_bad_examples: int
    total_good_examples: int
