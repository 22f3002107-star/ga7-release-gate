import re
from typing import List, Literal, Optional
from pydantic import BaseModel
from fastapi import FastAPI

app = FastAPI()

class ActionItem(BaseModel):
    owner: str
    name: str
    ref: str

class WorkflowSchema(BaseModel):
    trigger: str
    permissions: dict
    testsPassed: bool
    matrixComplete: bool
    failFast: bool
    actions: List[ActionItem]
    environmentApproval: Optional[bool] = None

class ImageSchema(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: Literal["none", "buildkit", "arg", "copy"]
    criticalVulnerabilities: int
    digestPinned: bool

class ReleaseGateRequest(BaseModel):
    target: Literal["preview", "production"]
    event: str
    ref: str
    workflow: WorkflowSchema
    image: ImageSchema

@app.post("/release-gate")
def release_gate(payload: ReleaseGateRequest):
    violations = []
    wf = payload.workflow
    img = payload.image

    # 1. Permissions Check
    expected_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if wf.permissions != expected_perms:
        violations.append("EXCESS_PERMISSION")

    # 2. PR Trigger Check
    if wf.trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests & Matrix Completion Check
    if not wf.testsPassed or not wf.matrixComplete or wf.failFast:
        violations.append("TESTS_INCOMPLETE")

    # 4. Third-Party Action Pinning Check (40-char lowercase Hex SHA)
    sha_regex = re.compile(r"^[0-9a-f]{40}$")
    for action in wf.actions:
        if action.owner != "actions":
            if not sha_regex.match(action.ref):
                violations.append("MUTABLE_ACTION")
                break

    # 5. Multi-stage Image Check
    if not img.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Root Runtime Check
    if img.runsAsRoot:
        violations.append("ROOT_RUNTIME")

    # 7. Secret Leak Check
    if img.secretMode in ["arg", "copy"]:
        violations.append("SECRET_IN_LAYER")

    # 8. Critical Vulnerability Check
    if img.criticalVulnerabilities > 0:
        violations.append("CRITICAL_CVE")

    # 9. Image Digest Pinning Check
    if not img.digestPinned:
        violations.append("UNPINNED_IMAGE")

    # 10 & 11. Production Context Verification
    if payload.target == "production":
        if payload.event != "push" or payload.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if getattr(wf, "environmentApproval", None) is not True:
            violations.append("APPROVAL_REQUIRED")

    # Decision Matrix logic
    decision = "block" if violations else "promote"
    
    return {
        "decision": decision,
        "violations": violations
    }
