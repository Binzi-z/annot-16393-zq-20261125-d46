"""纯领域规则：报告边界、授权版本、补记撤销的祖父条款、双来源解析。

本模块不碰磁盘、不起线程，方便被管道和穷举器共同调用；
``verify.py`` 出于"独立验证"的定位没有 import 本模块，而是按磁盘原始
字典把同一组规则重新实现了一遍，以免共享实现错误导致"自我证明"。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .canon import sha256_bytes


def digest_value(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


# ---------------------------------------------------------------------------
# 授权与撤销
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Grant:
    grant_id: str
    perm_version: int          # 权限版本；必须 >= 页版本才能授权该页
    scope: tuple[str, ...] = ()
    revoked: bool = False
    rev_seq: int | None = None  # 撤销承诺在单调序列中的位置

    def covers_code(self, code: str) -> bool:
        return not self.scope or any(
            code == s or code.startswith(s + "-") for s in self.scope
        )


def authorize(
    *,
    grant: Grant | None,
    code: str,
    page_version: int,
    commit_seq: int | None,
    watermark: int,
) -> dict[str, Any]:
    """返回授权结论。

    规则（按判定顺序）：
    1. 必须存在且 scope 覆盖该代号；
    2. ``perm_version >= page_version`` —— 旧版权限不能授权新版页；
    3. 授权未撤销 -> active；
    4. 已撤销 -> 仅当有承诺序号、``commit_seq <= watermark`` 且
       ``commit_seq < rev_seq``（撤销承诺落盘前已承诺）时，作为
       冻结水位内的历史报告 *祖父式* 保留；否则拒绝。
    """
    if grant is None:
        return {"allowed": False, "reason": "no_grant"}
    if not grant.covers_code(code):
        return {"allowed": False, "reason": "scope_mismatch"}
    if grant.perm_version < page_version:
        return {
            "allowed": False,
            "reason": "permission_version_too_old",
            "perm_version": grant.perm_version,
            "page_version": page_version,
        }
    if not grant.revoked:
        return {"allowed": True, "status": "active"}

    if (
        commit_seq is not None
        and grant.rev_seq is not None
        and commit_seq <= watermark
        and commit_seq < grant.rev_seq
    ):
        return {
            "allowed": True,
            "status": "historical_grandfathered",
            "commit_seq": commit_seq,
            "rev_seq": grant.rev_seq,
            "watermark": watermark,
        }
    return {
        "allowed": False,
        "reason": "grant_revoked_outside_watermark",
        "commit_seq": commit_seq,
        "rev_seq": grant.rev_seq,
        "watermark": watermark,
    }


# ---------------------------------------------------------------------------
# 同一字段的双（合法）来源
# ---------------------------------------------------------------------------

# 每个来源候选的状态轴，供穷举使用
LEGAL_STATES = ("legal", "illegal")
REVOKED_STATES = ("active", "revoked")
AGREE_STATES = ("agree", "disagree")


@dataclass(frozen=True)
class SourceCandidate:
    source_id: str
    legal: bool = True
    revoked: bool = False
    agrees: bool = True          # 该来源对字段值的证明是否与当前值一致
    self_consistent: bool = True  # 来源摘要/签名是否自洽

    @property
    def usable(self) -> bool:
        return (
            self.legal
            and not self.revoked
            and self.agrees
            and self.self_consistent
        )


@dataclass
class Resolution:
    status: str
    chosen: list[str] = field(default_factory=list)
    alternate_legal_source: str | None = None
    reason: str | None = None

    @property
    def committable(self) -> bool:
        return self.status in {"ok_single", "ok_dual_agree"}


def resolve_field_sources(candidates: list[SourceCandidate]) -> Resolution:
    """解析一个字段的一或两个来源。

    - 两个都合法、未撤销、自洽且彼此一致 -> ``ok_dual_agree``；
    - 仅一个可用，另一个不是 *合法且未撤销但冲突* 的来源 -> ``ok_single``
      （若另一个是合法替代来源但状态不可用，记录 alternate）；
    - 存在两个合法、未撤销、自洽来源却意见不一致 -> ``conflict``，不可提交；
    - 没有任何可用来源 -> 拒绝（说明原因）。
    """
    if not candidates:
        return Resolution(status="denied", reason="no_source")

    live_legal = [
        c for c in candidates
        if c.legal and not c.revoked and c.self_consistent
    ]
    # 两个合法未撤销来源互相矛盾：哪怕其中一个恰好等于当前值，也按冲突处理，
    # 因为审计导出不能在两个合法事实源之间静默二选一。
    if len(live_legal) >= 2 and not all(c.agrees for c in live_legal):
        return Resolution(
            status="conflict",
            reason="legal_sources_disagree",
            chosen=[c.source_id for c in live_legal if c.agrees],
        )

    usable = [c for c in candidates if c.usable]
    if not usable:
        if any(not c.legal for c in candidates):
            reason = "source_not_legal"
        elif any(c.revoked for c in candidates):
            reason = "source_revoked"
        elif any(not c.self_consistent for c in candidates):
            reason = "source_digest_invalid"
        else:
            reason = "source_value_mismatch"
        return Resolution(status="denied", reason=reason)

    chosen = [c.source_id for c in usable]
    other = [c for c in candidates if c not in usable]
    alternate = None
    for c in other:
        # "另有合法来源"：它本身是合法的，只是被撤销/不一致等挡住；
        # 若主来源不可用，这个合法替代可以兜底（由调用方按 same-value 使用）。
        if c.legal and not c.revoked:
            alternate = c.source_id

    if len(usable) >= 2:
        return Resolution(status="ok_dual_agree", chosen=chosen)
    return Resolution(
        status="ok_single",
        chosen=chosen,
        alternate_legal_source=alternate,
    )


# ---------------------------------------------------------------------------
# 小样本夹具
# ---------------------------------------------------------------------------

SMALL_WATERMARK = 100

# 撤销来源特有的"面包屑"引用：它只允许留在控制面台账里，
# 绝不能进入离线导出边界（尤其不能被未承诺报告带走）。
REVOCATION_SOURCE_REF = (
    "urn:revocation-source/REV-GOLD-2026/crumb-7f3a91e2"
)
REVOKED_GRANT = "G-OLD"
ALTERNATE_GRANT = "G-NEW"


def small_policy() -> dict[str, Any]:
    """冻结策略（信任锚）。watermark 固定，撤销发生在并发阶段。"""
    return {
        "policy_version": 1,
        "watermark": SMALL_WATERMARK,
        "forbidden_revocation_ref": REVOCATION_SOURCE_REF,
        "grants": {
            REVOKED_GRANT: {
                "grant_id": REVOKED_GRANT,
                "perm_version": 2,
                "scope": ["RPT-HIST", "RPT-RACE", "RPT-DUAL"],
            },
            ALTERNATE_GRANT: {
                "grant_id": ALTERNATE_GRANT,
                "perm_version": 5,
                "scope": ["RPT-DUAL", "RPT-NEW", "RPT-RACE"],
            },
        },
        "legal_sources": {
            "SRC-A": {"source_version": 1},
            "SRC-B": {"source_version": 2},
        },
    }


def page_spec(code: str, pages: list[tuple[int, dict[str, str]]],
               grant_id: str) -> dict[str, Any]:
    """构造报告规格。pages: [(version, {field: value}), ...]（页号自增）。"""
    return {
        "code": code,
        "grant_id": grant_id,
        "pages": [
            {"page_no": i + 1, "version": ver, "fields": dict(fields)}
            for i, (ver, fields) in enumerate(pages)
        ],
    }


def historical_fixtures() -> list[dict[str, Any]]:
    """两份在撤销前就已承诺、必须始终可复核的历史报告。"""
    return [
        page_spec(
            "RPT-HIST-0001",
            [(1, {"summary": "baseline telemetry", "severity": "low"}),
             (2, {"summary": "follow-up trace", "severity": "low"})],
            REVOKED_GRANT,
        ),
        page_spec(
            "RPT-HIST-0002",
            [(1, {"summary": "edge auth anomaly", "severity": "medium"})],
            REVOKED_GRANT,
        ),
    ]


def race_fixture() -> dict[str, Any]:
    """并发阶段被打包的候选报告：页版本 2，恰好落在 G-OLD 权限版本内。

    它能否导出完全取决于"打包承诺"与"撤销承诺"在线性化序列中的先后。
    """
    return page_spec(
        "RPT-RACE-0003",
        [(2, {"summary": "in-flight finding", "severity": "high"}),
         (2, {"summary": "evidence appendix", "severity": "high"})],
        REVOKED_GRANT,
    )
