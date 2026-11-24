"""小样本穷举：短交错、两类屏障故障前缀、双来源状态矩阵、授权边界矩阵。"""

from __future__ import annotations

import tempfile
import traceback
from pathlib import Path
from typing import Any, Callable

from .model import (
    AGREE_STATES,
    LEGAL_STATES,
    REVOKED_STATES,
    Grant,
    SourceCandidate,
    authorize,
    resolve_field_sources,
)
from .service import AuditService, SimulatedCrash, recover
from .verify import verify_root
from .workspace import Workspace

N_R = 4  # 撤销线程步数
N_P = 6  # 打包线程步数
RACE_CODE = "RPT-RACE-0003"


# ---------------------------------------------------------------------------
# 交错生成
# ---------------------------------------------------------------------------

def all_merges(n_r: int = N_R, n_p: int = N_P) -> list[list[tuple[str, int]]]:
    """生成两个保序步骤序列的全部交错（共 C(n_r+n_p, n_r) 种）。"""
    out: list[list[tuple[str, int]]] = []
    seq: list[tuple[str, int]] = []

    def rec(ri: int, pi: int) -> None:
        if ri == n_r and pi == n_p:
            out.append(list(seq))
            return
        if ri < n_r:
            seq.append(("R", ri))
            rec(ri + 1, pi)
            seq.pop()
        if pi < n_p:
            seq.append(("P", pi))
            rec(ri, pi + 1)
            seq.pop()

    rec(0, 0)
    return out


def execute_merge(root: str | Path, merge: list[tuple[str, int]], *,
                  fault: str | None = None) -> dict[str, Any]:
    svc = AuditService(root, armed_fault=fault)
    svc.bootstrap_trust_and_sources().seed_historical()
    crashed: dict[str, Any] | None = None
    exec_error: str | None = None
    for side, idx in merge:
        try:
            svc.run_step(side, idx)
        except SimulatedCrash as c:
            crashed = {"fault": c.fault, "reaped": c.reaped_handles,
                       "at": [side, idx]}
            break
        except Exception as exc:  # noqa: BLE001
            exec_error = f"{type(exc).__name__}: {exc}\n" + traceback.format_exc()
            break
    return {
        "crashed": crashed,
        "exec_error": exec_error,
        "step_log": list(svc.step_log),
        "committed": svc.c_committed,
        "denied": svc.c_denied,
    }


def _new_temp(prefix: str) -> str:
    return tempfile.mkdtemp(prefix=prefix)


def exhaustive_interleavings(*, keep_failures: bool = True) -> dict[str, Any]:
    merges = all_merges()
    modes = ("clean", "A", "B")
    summary: dict[str, Any] = {
        "step_counts": {"R": N_R, "P": N_P},
        "total_merges": len(merges),
        "by_mode": {},
        "failures": [],
    }

    for mode in modes:
        m = {
            "runs": 0, "verified": 0, "race_published": 0, "race_absent": 0,
            "race_grandfathered": 0, "rolled_forward": 0,
            "receipts_reconstructed": 0, "temp_archives_removed": 0,
            "index_changed": 0, "pointer_changed": 0,
            "distinct_barrier_prefixes": set(),
            "reaped_open_handles": 0,
        }
        fault = None if mode == "clean" else mode
        for i, merge in enumerate(merges):
            root = _new_temp(f"audit_exh_{mode}_{i}_")
            m["runs"] += 1
            try:
                ex = execute_merge(root, merge, fault=fault)
                if ex["exec_error"]:
                    raise RuntimeError(ex["exec_error"])
                if mode == "clean":
                    if ex["crashed"] is not None:
                        raise AssertionError("unexpected crash in clean mode")
                else:
                    if ex["crashed"] is None or ex["crashed"]["fault"] != mode:
                        raise AssertionError(
                            f"fault {mode} did not fire: {ex['crashed']}")
                    m["distinct_barrier_prefixes"].add(tuple(ex["step_log"]))
                    m["reaped_open_handles"] += ex["crashed"]["reaped"]

                rec = recover(root)
                ver = verify_root(root)
                if not ver["ok"]:
                    raise AssertionError(
                        "verify violations: " + "; ".join(ver["violations"][:8]))

                m["verified"] += 1
                codes = [c for c in ver["stats"]["grandfathered"]] + \
                        [c for c in ver["stats"]["active"]]
                if RACE_CODE in codes:
                    m["race_published"] += 1
                else:
                    m["race_absent"] += 1
                if RACE_CODE in ver["stats"]["grandfathered"]:
                    m["race_grandfathered"] += 1
                m["rolled_forward"] += len(rec["rolled_forward"])
                m["receipts_reconstructed"] += len(rec["reconstructed_receipts"])
                m["temp_archives_removed"] += len(rec["removed_temp_archives"])
                m["index_changed"] += int(rec["index_changed"])
                m["pointer_changed"] += int(rec["pointer_changed"])
                Workspace.robust_rmtree(root)
            except Exception as exc:  # noqa: BLE001
                tb = traceback.format_exc()
                summary["failures"].append({
                    "mode": mode, "merge_index": i, "root": root,
                    "error": f"{type(exc).__name__}: {exc}",
                    "traceback": tb[-2000:],
                })
                if not keep_failures:
                    Workspace.robust_rmtree(root)

        m["distinct_barrier_prefixes"] = len(m["distinct_barrier_prefixes"])
        summary["by_mode"][mode] = m

    summary["all_verified"] = (
        not summary["failures"]
        and all(x["verified"] == x["runs"] for x in summary["by_mode"].values())
    )
    return summary


# ---------------------------------------------------------------------------
# 双来源穷举
# ---------------------------------------------------------------------------

def _source_states() -> list[tuple[bool, bool, bool, bool]]:
    # (legal, revoked, agrees, self_consistent)
    states = []
    for legal in LEGAL_STATES:
        for revoked in REVOKED_STATES:
            for agree in AGREE_STATES:
                for consistent in ("consistent", "corrupt"):
                    states.append((
                        legal == "legal",
                        revoked == "revoked",
                        agree == "agree",
                        consistent == "consistent",
                    ))
    return states


def dual_source_matrix() -> dict[str, Any]:
    states = _source_states()
    singles = 0
    pairs = 0
    counts: dict[str, int] = {}
    invariants_held = True
    witness_cases: dict[str, Any] = {}

    def check(cands: list[SourceCandidate]) -> None:
        nonlocal invariants_held
        r = resolve_field_sources(cands)
        counts[r.status] = counts.get(r.status, 0) + 1
        usable = [c for c in cands if c.usable]
        if r.committable and not usable:
            invariants_held = False
        if r.status == "ok_dual_agree" and len(r.chosen) < 2:
            invariants_held = False
        if r.status == "conflict":
            live_legal = [c for c in cands
                          if c.legal and not c.revoked and c.self_consistent]
            if not (len(live_legal) >= 2
                    and not all(c.agrees for c in live_legal)):
                invariants_held = False
        # 被选来源必须个个可用
        by_id = {c.source_id: c for c in cands}
        for sid in r.chosen:
            if not by_id[sid].usable:
                invariants_held = False

    for st in states:
        singles += 1
        check([SourceCandidate("A", *st)])
    for a in states:
        for b in states:
            pairs += 1
            check([SourceCandidate("A", *a), SourceCandidate("B", *b)])

    # 关键见证组合
    witnesses = {
        "dual_legal_agree": resolve_field_sources([
            SourceCandidate("A"), SourceCandidate("B")]),
        "one_revoked_one_legal": resolve_field_sources([
            SourceCandidate("A", revoked=True), SourceCandidate("B")]),
        "dual_legal_conflict": resolve_field_sources([
            SourceCandidate("A", agrees=True),
            SourceCandidate("B", agrees=False)]),
        "both_illegal": resolve_field_sources([
            SourceCandidate("A", legal=False),
            SourceCandidate("B", legal=False)]),
        "corrupt_plus_good": resolve_field_sources([
            SourceCandidate("A", self_consistent=False),
            SourceCandidate("B")]),
    }
    witness_cases = {k: {"status": v.status, "chosen": v.chosen,
                         "reason": v.reason} for k, v in witnesses.items()}
    expected = {
        "dual_legal_agree": "ok_dual_agree",
        "one_revoked_one_legal": "ok_single",
        "dual_legal_conflict": "conflict",
        "both_illegal": "denied",
        "corrupt_plus_good": "ok_single",
    }
    witnesses_ok = all(
        witness_cases[k]["status"] == want for k, want in expected.items())

    return {
        "single_source_cases": singles,
        "ordered_pair_cases": pairs,
        "resolution_counts": counts,
        "invariants_held": invariants_held,
        "witnesses": witness_cases,
        "witnesses_as_expected": witnesses_ok,
        "exhaustive_ok": invariants_held and witnesses_ok,
    }


# ---------------------------------------------------------------------------
# 授权版本 / 撤销 / 水位边界矩阵
# ---------------------------------------------------------------------------

def authorization_matrix() -> dict[str, Any]:
    rows = 0
    violations: list[str] = []
    bucket: dict[str, int] = {}
    watermark = 10

    # perm_version 0..5 × page_version 1..6 × revoked? × 时序 cseq/rev
    for perm in range(0, 6):
        for page_ver in range(1, 7):
            for revoked in (False, True):
                for cseq in range(1, 14):
                    rev_seq = 8 if revoked else None
                    g = Grant("G", perm_version=perm,
                              revoked=revoked, rev_seq=rev_seq)
                    d = authorize(
                        grant=g, code="RPT-X-1", page_version=page_ver,
                        commit_seq=cseq, watermark=watermark)
                    rows += 1
                    key = d.get("status") if d["allowed"] else d["reason"]
                    bucket[key] = bucket.get(key, 0) + 1

                    # 不变量 1：旧权限永不能授权新版页
                    if page_ver > perm and d["allowed"]:
                        violations.append(
                            f"version rule broken perm={perm} page={page_ver}")
                    # 不变量 2：撤销授权只有 cseq<rev_seq 且 <=W 才可 grandfather
                    if revoked and d["allowed"]:
                        if not (cseq < rev_seq and cseq <= watermark
                                and d["status"] == "historical_grandfathered"):
                            violations.append(
                                f"grandfather broken cseq={cseq} rev={rev_seq}")
                    # 不变量 3：未撤销且版本够 -> active
                    if not revoked and page_ver <= perm:
                        if not (d["allowed"] and d["status"] == "active"):
                            violations.append(
                                f"active expected perm={perm} page={page_ver}")
                    # 水位之外一律不得作为历史报告
                    if d["allowed"] and d.get("status") == \
                            "historical_grandfathered" and cseq > watermark:
                        violations.append("watermark boundary broken")

    # 精确水位边界见证：cseq == W 允许 grandfather；W+1 拒绝
    at_edge = authorize(
        grant=Grant("G", 5, revoked=True, rev_seq=watermark + 5),
        code="RPT-X-1", page_version=1, commit_seq=watermark,
        watermark=watermark)
    beyond_edge = authorize(
        grant=Grant("G", 5, revoked=True, rev_seq=watermark + 5),
        code="RPT-X-1", page_version=1, commit_seq=watermark + 1,
        watermark=watermark)
    edge_ok = (at_edge["allowed"]
               and not beyond_edge["allowed"]
               and beyond_edge["reason"] == "grant_revoked_outside_watermark")

    return {
        "cases": rows,
        "buckets": bucket,
        "violations": violations[:10],
        "watermark_edge_ok": edge_ok,
        "matrix_ok": not violations and edge_ok,
    }
