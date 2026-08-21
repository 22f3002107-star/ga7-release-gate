import re
from typing import List, Literal, Optional
from pydantic import BaseModel
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
# PART 3: Terraform Plan Policy Gate
# ==========================================
ASSIGNED_ENV = "prod-ftxjgi"
REQ_LABELS = {"owner": "student-v7dyr", "environment": "production", "cost_center": "cc-o9sl"}

@app.post("/terraform/plan")
async def terraform_plan(request: Request):
    try:
        p = await request.json()
    except Exception:
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    if not isinstance(p, dict):
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})
    req_k = ["environment", "state", "providerVersion", "destroyApproved", "resource"]
    if not all(k in p for k in req_k):
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    env, state, pv, d_appr, res = p.get("environment"), p.get("state"), p.get("providerVersion"), p.get("destroyApproved"), p.get("resource")
    if not isinstance(env, str) or not isinstance(state, dict) or not isinstance(pv, str) or not isinstance(d_appr, bool) or not isinstance(res, dict):
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    if "backend" not in state or "locked" not in state:
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})
    bnd, lck = state.get("backend"), state.get("locked")
    if not isinstance(bnd, str) or not isinstance(lck, bool):
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    res_k = ["address", "type", "action", "labels", "secret", "forceDestroy"]
    if not all(k in res for k in res_k):
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    addr, r_type, act, lbs, sec, fd = res.get("address"), res.get("type"), res.get("action"), res.get("labels"), res.get("secret"), res.get("forceDestroy")
    if not isinstance(addr, str) or not isinstance(r_type, str) or not isinstance(act, str) or not isinstance(lbs, dict) or not isinstance(fd, bool):
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    # Strict labels internal type validation (String keys & values check)
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in lbs.items()):
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    if sec is not None and not isinstance(sec, str):
        return JSONResponse({"decision": "reject", "reason": "INVALID_PLAN"})

    if env != ASSIGNED_ENV:
        return JSONResponse({"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"})

    if bnd not in ["gcs", "s3", "azurerm", "remote"] or lck is not True:
        return JSONResponse({"decision": "reject", "reason": "STATE_UNSAFE"})

    pv_s = pv.strip()
    pinned = False
    if re.match(r"^(=)?\s*\d+\.\d+\.\d+$", pv_s):
        pinned = True
    elif re.match(r"^~\>\s*\d+\.\d+(\.\d+)?$", pv_s):
        pinned = True
    if not pinned or any(x in pv_s for x in [">=", "*", "latest"]):
        return JSONResponse({"decision": "reject", "reason": "UNPINNED_PROVIDER"})

    for k, v in REQ_LABELS.items():
        if lbs.get(k) != v:
            return JSONResponse({"decision": "reject", "reason": "MISSING_LABELS"})

    if sec is not None:
        if not sec.startswith("secret://") or len(sec) <= len("secret://"):
            return JSONResponse({"decision": "reject", "reason": "PLAINTEXT_SECRET"})

    if act == "delete" and r_type in ["storage_bucket", "sql_database", "persistent_disk"]:
        if not d_appr:
            return JSONResponse({"decision": "reject", "reason": "DELETE_NOT_APPROVED"})

    if r_type == "storage_bucket" and fd is True:
        return JSONResponse({"decision": "reject", "reason": "FORCE_DESTROY"})

    return JSONResponse({"decision": "approve", "reason": "APPROVE"})
