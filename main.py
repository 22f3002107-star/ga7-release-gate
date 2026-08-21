import re
from typing import List, Literal, Optional
from pydantic import BaseModel
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# =====================================================================
# ASSIGNMENT 1: CI/CD Container Release Gate (POST /release-gate)
# =====================================================================

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

    # 4. Third-Party Action Pinning Check
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

    decision = "block" if violations else "promote"
    return {"decision": decision, "violations": violations}


# =====================================================================
# ASSIGNMENT 2: LLM Action Firewall (POST /action-firewall)
# =====================================================================

ASSIGNED_TENANT = "tenant-5jyfvhd"
ASSIGNED_EMAIL_DOMAIN = "notify-9rd3i5t.example"

def check_html_safety(html_content: str) -> bool:
    lower_html = html_content.lower()
    if "<script" in lower_html or "<iframe" in lower_html:
        return False
    if "javascript:" in lower_html:
        return False
    if re.search(r"\bon[a-z]+\s*=", lower_html):
        return False
    return True

@app.post("/action-firewall")
async def action_firewall(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    if not isinstance(payload, dict):
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        
    required_top = ["provenance", "humanApproved", "action"]
    if not all(k in payload for k in required_top):
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    provenance = payload.get("provenance")
    human_approved = payload.get("humanApproved")
    action = payload.get("action")

    if provenance not in ["trusted", "untrusted"] or not isinstance(human_approved, bool) or not isinstance(action, dict):
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    if "tool" not in action or "args" not in action:
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    tool_name = action.get("tool")
    args = action.get("args")

    if not isinstance(tool_name, str) or not isinstance(args, dict):
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    allowed_tools = ["search", "lookup_record", "send_email", "render_html"]
    if tool_name not in allowed_tools:
        return JSONResponse({"decision": "block", "reason": "TOOL_NOT_ALLOWED"})

    if tool_name == "search":
        if list(args.keys()) != ["query"]:
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        query = args.get("query")
        if not isinstance(query, str) or len(query) < 1 or len(query) > 200:
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    elif tool_name == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        tenant_id = args.get("tenantId")
        record_id = args.get("recordId")
        if not isinstance(tenant_id, str) or not isinstance(record_id, str) or record_id == "":
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        
        if tenant_id != ASSIGNED_TENANT:
            return JSONResponse({"decision": "block", "reason": "TENANT_SCOPE"})

    elif tool_name == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        to_email = args.get("to")
        subject = args.get("subject")
        body = args.get("body")
        if not isinstance(to_email, str) or not isinstance(subject, str) or not isinstance(body, str):
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

        if "@" not in to_email:
            return JSONResponse({"decision": "block", "reason": "EGRESS_DENIED"})
        domain = to_email.split("@")[-1].strip()
        if domain != ASSIGNED_EMAIL_DOMAIN:
            return JSONResponse({"decision": "block", "reason": "EGRESS_DENIED"})

        if not human_approved:
            return JSONResponse({"decision": "block", "reason": "APPROVAL_REQUIRED"})

    elif tool_name == "render_html":
        if list(args.keys()) != ["html"]:
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        html_str = args.get("html")
        if not isinstance(html_str, str):
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

        if not check_html_safety(html_str):
            return JSONResponse({"decision": "block", "reason": "UNSAFE_OUTPUT"})

    return JSONResponse({"decision": "allow", "reason": "ALLOW"})
