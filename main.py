import re
from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, ValidationError
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# ==========================================
# PART 1: CI/CD Container Release Gate
# ==========================================
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

    expected = {"contents": "read", "packages": "write", "id-token": "none"}
    if wf.permissions != expected:
        violations.append("EXCESS_PERMISSION")

    if wf.trigger == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    if not wf.testsPassed or not wf.matrixComplete or wf.failFast:
        violations.append("TESTS_INCOMPLETE")

    sha_regex = re.compile(r"^[0-9a-f]{40}$")
    for action in wf.actions:
        if action.owner != "actions":
            if not sha_regex.match(action.ref):
                violations.append("MUTABLE_ACTION")
                break

    if not img.multiStage:
        violations.append("SINGLE_STAGE_IMAGE")
    if img.runsAsRoot:
        violations.append("ROOT_RUNTIME")
    if img.secretMode in ["arg", "copy"]:
        violations.append("SECRET_IN_LAYER")
    if img.criticalVulnerabilities > 0:
        violations.append("CRITICAL_CVE")
    if not img.digestPinned:
        violations.append("UNPINNED_IMAGE")

    if payload.target == "production":
        if payload.event != "push" or payload.ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if getattr(wf, "environmentApproval", None) is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "block" if violations else "promote"
    return {"decision": decision, "violations": violations}

# ==========================================
# PART 2: LLM Action Firewall
# ==========================================
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
        p = await request.json()
    except Exception:
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    if not isinstance(p, dict):
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
    if not all(k in p for k in ["provenance", "humanApproved", "action"]):
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    prov, appr, act = p.get("provenance"), p.get("humanApproved"), p.get("action")
    if prov not in ["trusted", "untrusted"] or not isinstance(appr, bool) or not isinstance(act, dict):
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    if "tool" not in act or "args" not in act:
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    t_name, args = act.get("tool"), act.get("args")
    if not isinstance(t_name, str) or not isinstance(args, dict):
        return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    if t_name not in ["search", "lookup_record", "send_email", "render_html"]:
        return JSONResponse({"decision": "block", "reason": "TOOL_NOT_ALLOWED"})

    if t_name == "search":
        if list(args.keys()) != ["query"]:
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        q = args.get("query")
        if not isinstance(q, str) or len(q) < 1 or len(q) > 200:
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})

    elif t_name == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        tid, rid = args.get("tenantId"), args.get("recordId")
        if not isinstance(tid, str) or not isinstance(rid, str) or rid == "":
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        if tid != ASSIGNED_TENANT:
            return JSONResponse({"decision": "block", "reason": "TENANT_SCOPE"})

    elif t_name == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        to_em = args.get("to")
        if not all(isinstance(args.get(k), str) for k in ["to", "subject", "body"]):
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        if "@" not in to_em or to_em.split("@")[-1].strip() != ASSIGNED_EMAIL_DOMAIN:
            return JSONResponse({"decision": "block", "reason": "EGRESS_DENIED"})
        if not appr:
            return JSONResponse({"decision": "block", "reason": "APPROVAL_REQUIRED"})

    elif t_name == "render_html":
        if list(args.keys()) != ["html"] or not isinstance(args.get("html"), str):
            return JSONResponse({"decision": "block", "reason": "INVALID_SCHEMA"})
        if not check_html_safety(args.get("html")):
            return JSONResponse({"decision": "block", "reason": "UNSAFE_OUTPUT"})

    return JSONResponse({"decision": "allow", "reason": "ALLOW"})

# ==========================================
# PART 3: Terraform Plan Policy Gate (Strict)
# ==========================================
ASSIGNED_ENV = "prod-ftxjgi"
REQ_LABELS = {"owner": "student-v7dyr", "environment": "production", "cost_center": "cc-o9sl"}

class TFStateModel(BaseModel):
    backend: str
    locked: bool

class TFResourceModel(BaseModel):
    address: str
    type: str
    action: str
    labels: Dict[str, Any]
    secret: Optional[str]
    forceDestroy: bool

class TFPlanRequest(BaseModel):
    environment: str
    state: TFStateModel
    providerVersion: str
    destroyApproved: bool
    resource: TFResourceModel

@app.post("/terraform/plan")
async def terraform_plan(request: Request):
    try:
        raw_body = await request.json()
        p = TFPlanRequest(**raw_body)
    except Exception:
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    # Check allowed action types from rule 1 enum definition
    if p.resource.action not in ["create", "update", "delete"]:
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    # Ensure label values are strictly primitive string format
    if not all(isinstance(v, str) for v in p.resource.labels.values()):
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    if p.environment != ASSIGNED_ENV:
        return JSONResponse({"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"})

    if p.state.backend not in ["gcs", "s3", "azurerm", "remote"] or p.state.locked is not True:
        return JSONResponse({"decision": "reject", "reason": "STATE_UNSAFE"})

    pv_s = p.providerVersion.strip()
    pinned = False
    if re.match(r"^(=)?\s*\d+\.\d+\.\d+$", pv_s):
        pinned = True
    elif re.match(r"^~\>\s*\d+\.\d+(\.\d+)?$", pv_s):
        pinned = True
    if not pinned or any(x in pv_s for x in [">=", "*", "latest"]):
        return JSONResponse({"decision": "reject", "reason": "UNPINNED_PROVIDER"})

    for k, v in REQ_LABELS.items():
        if p.resource.labels.get(k) != v:
            return JSONResponse({"decision": "reject", "reason": "MISSING_LABELS"})

    if p.resource.secret is not None:
        if not p.resource.secret.startswith("secret://") or len(p.resource.secret) <= len("secret://"):
            return JSONResponse({"decision": "reject", "reason": "PLAINTEXT_SECRET"})

    if p.resource.action == "delete" and p.resource.type in ["storage_bucket", "sql_database", "persistent_disk"]:
        if not p.destroyApproved:
            return JSONResponse({"decision": "reject", "reason": "DELETE_NOT_APPROVED"})

    if p.resource.type == "storage_bucket" and p.resource.forceDestroy is True:
        return JSONResponse({"decision": "reject", "reason": "FORCE_DESTROY"})

    return JSONResponse({"decision": "approve", "reason": "APPROVE"})
