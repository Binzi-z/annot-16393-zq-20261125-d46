"""额外的端到端小场景：同字段双合法来源、旧权限 vs 新版页。"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canon import hash_obj
from .model import (
    ALTERNATE_GRANT,
    REVOKED_GRANT,
    Grant,
    SourceCandidate,
    authorize,
    resolve_field_sources,
)
from .reconcile import (
    commit_marker_path,
    denial_marker_path,
    ensure_receipts,
    pending_path,
    promote_committed,
    publish_index_and_pointer,
)
from .service import AuditService, build_pending, source_descriptors
from .workspace import Workspace

DUAL_CODE = "RPT-DUAL-0004"
NEWPAGE_DENIED_CODE = "RPT-NEW-0005"
DUAL_SEQ = 10
DENIAL_SEQ = 20


def prepared(root: str | Path, *, armed_fault: str | None = None) -> AuditService:
    svc = AuditService(root, armed_fault=armed_fault)
    svc.bootstrap_trust_and_sources().seed_historical()
    return svc


def publish_dual_source_report(root: str | Path) -> dict[str, Any]:
    """同一字段由两个一致的合法来源(SRC-A/SRC-B)证明，双来源都被摘要绑定。

    使用 G-NEW v5 授权，页版本 3（也顺带证明新权限可覆盖新版页）。
    """
    ws = Workspace(root)
    policy = ws.read_json(ws.policy_file)
    descs = source_descriptors()

    indicator = "sha256:9f2c1a7e4b8d6051c0a3f9e27b6d4815"
    vd = hash_obj({"field": "indicator_hash", "value": indicator})

    # 先用纯规则核心判定这是 ok_dual_agree
    resolution = resolve_field_sources([
        SourceCandidate("SRC-A", legal=True, revoked=False, agrees=True),
        SourceCandidate("SRC-B", legal=True, revoked=False, agrees=True),
    ])
    assert resolution.status == "ok_dual_agree"

    dual_atts = [
        {"source_id": "SRC-A", "source_version": descs["SRC-A"]["source_version"],
         "digest": descs["SRC-A"]["digest"], "role": "primary",
         "attests_field": "indicator_hash", "value_digest": vd},
        {"source_id": "SRC-B", "source_version": descs["SRC-B"]["source_version"],
         "digest": descs["SRC-B"]["digest"], "role": "corroborating",
         "attests_field": "indicator_hash", "value_digest": vd},
    ]
    page_inputs = [
        {"version": 3,
         "fields": {"indicator_hash": indicator, "verdict": "benign",
                    "note": "same field attested by two legal sources"},
         "sources": dual_atts},
        {"version": 3,
         "fields": {"summary": "dual-source appendix"},
         "sources": [dual_atts[0]]},
    ]
    pending = build_pending(
        code=DUAL_CODE, watermark=policy["watermark"],
        page_inputs=page_inputs)
    ws.atomic_write_json(pending_path(ws, DUAL_CODE), pending)

    gd = policy["grants"][ALTERNATE_GRANT]
    auth = {
        "kind": "commit-auth",
        "code": DUAL_CODE,
        "body_hash": pending["body_hash"],
        "commit_seq": DUAL_SEQ,
        "watermark": policy["watermark"],
        "grant_id": ALTERNATE_GRANT,
        "grant_snapshot": gd,
        "decision_status": "active",
        "dual_source_resolution": resolution.status,
    }
    ws.atomic_write_json(commit_marker_path(ws, DUAL_CODE), auth)
    promote_committed(ws, DUAL_CODE)
    ensure_receipts(ws)
    pending_path(ws, DUAL_CODE).unlink(missing_ok=True)
    publish_index_and_pointer(ws, policy, updated_seq=DUAL_SEQ)
    return {"code": DUAL_CODE, "resolution": resolution.status,
            "chosen_sources": resolution.chosen}


def record_old_permission_new_page_denial(root: str | Path) -> dict[str, Any]:
    """G-OLD(v2) 试图授权 v4 新页：必须被版本规则拒绝，只留 denial，不进 export。"""
    ws = Workspace(root)
    policy = ws.read_json(ws.policy_file)
    gd = policy["grants"][REVOKED_GRANT]
    grant = Grant(
        grant_id=REVOKED_GRANT, perm_version=gd["perm_version"],
        scope=tuple(gd.get("scope", [])),
    )
    decision = authorize(
        grant=grant, code=NEWPAGE_DENIED_CODE, page_version=4,
        commit_seq=DENIAL_SEQ, watermark=policy["watermark"])
    assert not decision["allowed"]
    assert decision["reason"] == "permission_version_too_old"
    ws.atomic_write_json(denial_marker_path(ws, NEWPAGE_DENIED_CODE), {
        "kind": "denial",
        "code": NEWPAGE_DENIED_CODE,
        "at_seq": DENIAL_SEQ,
        "reason": decision["reason"],
        "decision": decision,
    })

    # 对照：同一新版页交给 G-NEW v5（未撤销）应当被允许
    gn = policy["grants"][ALTERNATE_GRANT]
    allowed = authorize(
        grant=Grant(ALTERNATE_GRANT, gn["perm_version"],
                    tuple(gn.get("scope", []))),
        code="RPT-NEW-0006", page_version=4,
        commit_seq=DENIAL_SEQ + 1, watermark=policy["watermark"])
    assert allowed["allowed"] and allowed["status"] == "active"
    return {"denied": decision, "control_allowed": allowed}
