import re
import html
from urllib.parse import (
    unquote,
    urlparse
)
from typing import (
    List,
    Literal,
    Optional,
    Dict,
    Any
)
from pydantic import BaseModel
from fastapi import (
    FastAPI,
    Request
)
from fastapi.responses import (
    JSONResponse
)

app = FastAPI()

# PART 1: RELEASE GATE
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
    environmentApproval: (
        Optional[bool]
    ) = None

class ImageSchema(BaseModel):
    multiStage: bool
    runsAsRoot: bool
    secretMode: Literal[
        "none", "buildkit",
        "arg", "copy"
    ]
    criticalVulnerabilities: int
    digestPinned: bool

class ReleaseGateRequest(BaseModel):
    target: Literal[
        "preview", "production"
    ]
    event: str
    ref: str
    workflow: WorkflowSchema
    image: ImageSchema

@app.post("/release-gate")
def release_gate(
    payload: ReleaseGateRequest
):
    violations = []
    wf = payload.workflow
    img = payload.image
    exp = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }
    if wf.permissions != exp:
        violations.append(
            "EXCESS_PERMISSION"
        )
    if wf.trigger == (
        "pull_request_target"
    ):
        violations.append(
            "UNSAFE_PR_TRIGGER"
        )
    if (
        not wf.testsPassed
        or not wf.matrixComplete
        or wf.failFast
    ):
        violations.append(
            "TESTS_INCOMPLETE"
        )
    sha_regex = re.compile(
        r"^[0-9a-f]{40}$"
    )
    for act in wf.actions:
        if (
            act.owner != "actions"
            and not sha_regex.match(
                act.ref
            )
        ):
            violations.append(
                "MUTABLE_ACTION"
            )
            break
    if not img.multiStage:
        violations.append(
            "SINGLE_STAGE_IMAGE"
        )
    if img.runsAsRoot:
        violations.append(
            "ROOT_RUNTIME"
        )
    if img.secretMode in [
        "arg", "copy"
    ]:
        violations.append(
            "SECRET_IN_LAYER"
        )
    if (
        img.criticalVulnerabilities
        > 0
    ):
        violations.append(
            "CRITICAL_CVE"
        )
    if not img.digestPinned:
        violations.append(
            "UNPINNED_IMAGE"
        )
    if (
        payload.target
        == "production"
    ):
        if (
            payload.event != "push"
            or payload.ref
            != "refs/heads/main"
        ):
            violations.append(
                "INVALID_PRODUCTION_REF"
            )
        if (
            getattr(
                wf,
                "environmentApproval",
                None
            )
            is not True
        ):
            violations.append(
                "APPROVAL_REQUIRED"
            )
    dec = (
        "block"
        if violations
        else "promote"
    )
    return {
        "decision": dec,
        "violations": violations
    }

# PART 2: FIREWALL
ASSIGNED_TENANT = "tenant-5jyfvhd"
ASSIGNED_EMAIL_DOMAIN = (
    "notify-9rd3i5t.example"
)

def check_html_safety(
    html_content: str
) -> bool:
    low = html_content.lower()
    if (
        "<script" in low
        or "<iframe" in low
    ):
        return False
    if "javascript:" in low:
        return False
    if re.search(
        r"\bon[a-z]+\s*=", low
    ):
        return False
    return True

@app.post("/action-firewall")
async def action_firewall(
    request: Request
):
    try:
        p = await request.json()
    except Exception:
        return JSONResponse({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })
    if not isinstance(p, dict):
        return JSONResponse({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })
    req_t = [
        "provenance",
        "humanApproved",
        "action"
    ]
    if not all(
        k in p for k in req_t
    ):
        return JSONResponse({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })
    prov = p.get("provenance")
    appr = p.get("humanApproved")
    act = p.get("action")
    if (
        prov not in [
            "trusted", "untrusted"
        ]
        or not isinstance(appr, bool)
        or not isinstance(act, dict)
    ):
        return JSONResponse({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })
    if (
        "tool" not in act
        or "args" not in act
    ):
        return JSONResponse({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })
    t_name = act.get("tool")
    args = act.get("args")
    if (
        not isinstance(t_name, str)
        or not isinstance(args, dict)
    ):
        return JSONResponse({
            "decision": "block",
            "reason": "INVALID_SCHEMA"
        })
    all_t = [
        "search", "lookup_record",
        "send_email", "render_html"
    ]
    if t_name not in all_t:
        return JSONResponse({
            "decision": "block",
            "reason": "TOOL_NOT_ALLOWED"
        })
    if t_name == "search":
        if list(args.keys()) != [
            "query"
        ]:
            return JSONResponse({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })
        q = args.get("query")
        if (
            not isinstance(q, str)
            or len(q) < 1
            or len(q) > 200
        ):
            return JSONResponse({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })
    elif t_name == "lookup_record":
        if set(args.keys()) != {
            "tenantId", "recordId"
        }:
            return JSONResponse({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })
        tid = args.get("tenantId")
        rid = args.get("recordId")
        if (
            not isinstance(tid, str)
            or not isinstance(rid, str)
            or rid == ""
        ):
            return JSONResponse({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })
        if tid != ASSIGNED_TENANT:
            return JSONResponse({
                "decision": "block",
                "reason": "TENANT_SCOPE"
            })
    elif t_name == "send_email":
        if set(args.keys()) != {
            "to", "subject", "body"
        }:
            return JSONResponse({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })
        to_em = args.get("to")
        if not all(
            isinstance(
                args.get(k), str
            )
            for k in [
                "to", "subject", "body"
            ]
        ):
            return JSONResponse({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })
        if (
            "@" not in to_em
            or to_em.split(
                "@"
            )[-1].strip()
            != ASSIGNED_EMAIL_DOMAIN
        ):
            return JSONResponse({
                "decision": "block",
                "reason": "EGRESS_DENIED"
            })
        if not appr:
            return JSONResponse({
                "decision": "block",
                "reason": "APPROVAL_REQUIRED"
            })
    elif t_name == "render_html":
        if (
            list(args.keys())
            != ["html"]
            or not isinstance(
                args.get("html"), str
            )
        ):
            return JSONResponse({
                "decision": "block",
                "reason": "INVALID_SCHEMA"
            })
        if not check_html_safety(
            args.get("html")
        ):
            return JSONResponse({
                "decision": "block",
                "reason": "UNSAFE_OUTPUT"
            })
    return JSONResponse({
        "decision": "allow",
        "reason": "ALLOW"
    })
# PART 3: TERRAFORM
ASSIGNED_ENV = "prod-ftxjgi"
REQ_LABELS = {
    "owner": "student-v7dyr",
    "environment": "production",
    "cost_center": "cc-o9sl"
}

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
async def terraform_plan(
    request: Request
):
    try:
        raw_body = (
            await request.json()
        )
        p = TFPlanRequest(
            **raw_body
        )
    except Exception:
        return JSONResponse({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })
    if (
        p.resource.action not in [
            "create", "update",
            "delete"
        ]
        or not all(
            isinstance(v, str)
            for v in (
                p.resource
                .labels.values()
            )
        )
    ):
        return JSONResponse({
            "decision": "reject",
            "reason": "INVALID_PLAN"
        })
    if (
        p.environment
        != ASSIGNED_ENV
    ):
        return JSONResponse({
            "decision": "reject",
            "reason": "ENVIRONMENT_MISMATCH"
        })
    if (
        p.state.backend not in [
            "gcs", "s3",
            "azurerm", "remote"
        ]
        or p.state.locked is not True
    ):
        return JSONResponse({
            "decision": "reject",
            "reason": "STATE_UNSAFE"
        })
    pv_s = (
        p.providerVersion.strip()
    )
    pinned = False
    if re.match(
        r"^(=)?\s*\d+\.\d+\.\d+$",
        pv_s
    ):
        pinned = True
    elif re.match(
        r"^~\>\s*\d+\.\d+(\.\d+)?$",
        pv_s
    ):
        pinned = True
    if (
        not pinned
        or any(
            x in pv_s
            for x in [
                ">=", "*",
                "latest"
            ]
        )
    ):
        return JSONResponse({
            "decision": "reject",
            "reason": "UNPINNED_PROVIDER"
        })
    for k, v in REQ_LABELS.items():
        if (
            p.resource.labels.get(k)
            != v
        ):
            return JSONResponse({
                "decision": "reject",
                "reason": "MISSING_LABELS"
            })
    if p.resource.secret is not None:
        if (
            not p.resource
            .secret.startswith(
                "secret://"
            )
            or len(
                p.resource.secret
            )
            <= len("secret://")
        ):
            return JSONResponse({
                "decision": "reject",
                "reason": "PLAINTEXT_SECRET"
            })
    if (
        p.resource.action == "delete"
        and p.resource.type in [
            "storage_bucket",
            "sql_database",
            "persistent_disk"
        ]
    ):
        if not p.destroyApproved:
            return JSONResponse({
                "decision": "reject",
                "reason": "DELETE_NOT_APPROVED"
            })
    if (
        p.resource.type
        == "storage_bucket"
        and p.resource.forceDestroy
        is True
    ):
        return JSONResponse({
            "decision": "reject",
            "reason": "FORCE_DESTROY"
        })
    return JSONResponse({
        "decision": "approve",
        "reason": "APPROVE"
    })
# PART 4: SANITIZE OUTPUT
ALLOWED_HOSTS = [
    "cdn-3u2rvuu.example",
    "app-x8k3oyw.example"
]

def single_decode(text: str) -> str:
    try:
        text = unquote(text)
        text = html.unescape(text)
        def replace_unicode(match):
            val = int(
                match.group(1), 16
            )
            if 0xD800 <= val <= 0xDFFF:
                return match.group(0)
            return chr(val)
        text = re.sub(
            r'\\u([0-9a-fA-F]{4})',
            replace_unicode,
            text
        )
    except Exception:
        pass
    return text

def extract_urls(
    channel: str,
    text: str
) -> List[str]:
    urls = []
    try:
        if channel == "html":
            found = re.findall(
                r'(?:src|href)\s*=\s*'
                r'["\']([^"\']+)["\']',
                text,
                re.IGNORECASE
            )
            urls.extend(found)
        elif channel == "markdown":
            found = re.findall(
                r'\]\(([^)]+)\)',
                text
            )
            urls.extend(found)
        elif channel == "url":
            urls.append(text.strip())
    except Exception:
        pass
    return urls

def evaluate_rules(
    channel: str,
    output: str
) -> Optional[str]:
    try:
        if channel == "html":
            if re.search(
                r'<\s*(script|iframe'
                r'|object|embed)\b',
                output,
                re.IGNORECASE
            ):
                return "SCRIPT_TAG"
            if re.search(
                r'\bon[a-zA-Z]+\s*=',
                output
            ):
                return "EVENT_HANDLER"

        if channel in [
            "html", "markdown", "url"
        ]:
            # Strict validation handling for optional whitespace injection before colons
            if re.search(
                r'(javascript|data'
                r'|vbscript)\s*:',
                output,
                re.IGNORECASE
            ):
                return "DANGEROUS_SCHEME"
            
            ext_urls = (
                extract_urls(
                    channel, output
                )
            )
            for u in ext_urls:
                u_clean = u.strip()
                if u_clean.startswith(
                    "//"
                ):
                    u_clean = (
                        "https:"
                        + u_clean
                    )
                if re.match(
                    r'^[a-zA-Z]'
                    r'[a-zA-Z0-9+.-]*'
                    r'://',
                    u_clean
                ):
                    try:
                        parsed = (
                            urlparse(
                                u_clean
                            )
                        )
                        if (
                            parsed.scheme
                            .lower()
                            not in [
                                "http",
                                "https"
                            ]
                        ):
                            return (
                                "DANGEROUS_SCHEME"
                            )
                    except Exception:
                        return (
                            "DANGEROUS_SCHEME"
                        )

        if channel in [
            "html", "markdown", "url"
        ]:
            ext_urls = (
                extract_urls(
                    channel, output
                )
            )
            for u in ext_urls:
                u_clean = u.strip()
                if u_clean.startswith(
                    "//"
                ):
                    u_clean = (
                        "https:"
                        + u_clean
                    )
                if re.match(
                    r'^[a-zA-Z]'
                    r'[a-zA-Z0-9+.-]*'
                    r'://',
                    u_clean
                ):
                    try:
                        parsed = (
                            urlparse(
                                u_clean
                            )
                        )
                        hostname = (
                            parsed
                            .hostname
                        )
                        if hostname:
                            hostname = (
                                hostname
                                .lower()
                            )
                            if (
                                hostname
                                not in
                                ALLOWED_HOSTS
                            ):
                                return (
                                    "EXTERNAL_EXFIL"
                                )
                        else:
                            return (
                                "EXTERNAL_EXFIL"
                            )
                    except Exception:
                        return (
                            "EXTERNAL_EXFIL"
                        )

        if channel == "sql":
            lower_out = output.lower()
            sql_triggers = [
                "'", '"', ";", "--",
                "/*", "union", "or 1=1"
            ]
            if any(
                t in lower_out
                for t in sql_triggers
            ):
                return "SQL_METACHAR"

        if channel == "shell":
            shell_triggers = [
                ";", "&", "|", "`",
                "<", ">", "$(", "${"
            ]
            if any(
                t in output
                for t in shell_triggers
            ):
                return "SHELL_METACHAR"
    except Exception:
        return "INVALID_SCHEMA"
    return None

@app.post("/sanitize-output")
async def sanitize_output(
    request: Request
):
    try:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({
                "safe": False,
                "reason": "INVALID_SCHEMA"
            })

        if (
            not isinstance(body, dict)
            or "channel" not in body
            or "output" not in body
        ):
            return JSONResponse({
                "safe": False,
                "reason": "INVALID_SCHEMA"
            })
            
        channel = body.get("channel")
        output = body.get("output")
        
        if channel not in [
            "html", "markdown", "url",
            "sql", "shell"
        ]:
            return JSONResponse({
                "safe": False,
                "reason": "INVALID_SCHEMA"
            })
        if (
            not isinstance(output, str)
            or len(output) > 20000
        ):
            return JSONResponse({
                "safe": False,
                "reason": "INVALID_SCHEMA"
            })

        decoded_output = (
            single_decode(output)
        )
        if decoded_output != output:
            tripped_reason = (
                evaluate_rules(
                    channel,
                    decoded_output
                )
            )
            if tripped_reason is not None:
                return JSONResponse({
                    "safe": False,
                    "reason": (
                        "ENCODED_PAYLOAD"
                    )
                })

        tripped_reason = (
            evaluate_rules(
                channel,
                output
            )
        )
        if tripped_reason is not None:
            return JSONResponse({
                "safe": False,
                "reason": tripped_reason
            })
        return JSONResponse({
            "safe": True,
            "reason": "SAFE"
        })
    except Exception:
        return JSONResponse({
            "safe": False,
            "reason": "INVALID_SCHEMA"
        })
        # PART 5: CORROBORATE ENGINE (Inequality Fixed)
def parse_iso(dt_str: str) -> Optional[datetime]:
    try:
        # Handles both native Z and offset formats robustly
        dt_str = dt_str.replace("Z", "+00:00")
        return datetime.fromisoformat(dt_str)
    except Exception:
        return None

@app.post("/corroborate")
async def corroborate_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    # Rule 1: Strict Top-Level Structural Validation
    if not isinstance(body, dict):
        return JSONResponse({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })
        
    req_t = ["claim", "asOf", "stalenessDays", "sources"]
    if not all(k in body for k in req_t):
        return JSONResponse({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    claim = body.get("claim")
    as_of_str = body.get("asOf")
    st_days = body.get("stalenessDays")
    sources = body.get("sources")

    if (
        not isinstance(claim, dict)
        or not isinstance(as_of_str, str)
        or not isinstance(sources, list)
    ):
        return JSONResponse({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })
        
    if (
        not isinstance(st_days, (int, float))
        or isinstance(st_days, bool)
    ):
        return JSONResponse({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    if not all(k in claim for k in ["subject", "predicate", "value"]):
        return JSONResponse({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })
        
    if not all(isinstance(claim.get(k), str) for k in ["subject", "predicate", "value"]):
        return JSONResponse({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    cl_val = claim.get("value")
    as_of_dt = parse_iso(as_of_str)
    if as_of_dt is None:
        return JSONResponse({
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        })

    v_types = {"dns", "ct_log", "registry", "archive", "scan"}
    p_sources = []
    
    for s in sources:
        if not isinstance(s, dict):
            continue
        s_k = ["id", "origin", "value", "observedAt", "type"]
        if not all(k in s for k in s_k) or not all(isinstance(s.get(k), str) for k in s_k):
            continue
        if s.get("type") not in v_types:
            continue
            
        obs_dt = parse_iso(s.get("observedAt"))
        if obs_dt is None:
            continue
            
        # Strict representation of: asOf - observedAt <= stalenessDays
        delta = as_of_dt - obs_dt
        days_diff = delta.total_seconds() / 86400.0
        if days_diff > float(st_days):
            continue

        # Flexible authoritative boolean parsing
        is_auth = s.get("authoritative") in [True, "true", "True"]

        p_sources.append({
            "id": s.get("id"),
            "origin": s.get("origin"),
            "value": s.get("value"),
            "type": s.get("type"),
            "auth": is_auth
        })

    # Rule 2: Contradicted Verification
    contra_ids = []
    for s in p_sources:
        if s["auth"] and s["value"] != cl_val:
            contra_ids.append(s["id"])
            
    if contra_ids:
        contra_ids = list(set(contra_ids))
        contra_ids.sort()
        return JSONResponse({
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": contra_ids
        })

    # Rule 3: Supported Verification
    m_sources = [s for s in p_sources if s["value"] == cl_val]
    
    origin_map = {}
    for s in m_sources:
        ori = s["origin"]
        if ori not in origin_map:
            origin_map[ori] = s
        else:
            if s["id"] < origin_map[ori]["id"]:
                origin_map[ori] = s

    reps = list(origin_map.values())

    if len(reps) >= 2:
        dist_types = {s["type"] for s in reps}
        conf = "high" if len(dist_types) >= 2 else "medium"
        rep_ids = [s["id"] for s in reps]
        rep_ids.sort()
        return JSONResponse({
            "verdict": "supported",
            "confidence": conf,
            "corroboratingSources": rep_ids
        })

    # Rule 4: Unverified Fallback State Controls
    return JSONResponse({
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    })

    

 
