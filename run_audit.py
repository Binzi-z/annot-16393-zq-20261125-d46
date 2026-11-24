"""一键离线审计：穷举交错 + 双线程故障重演 + 双来源/版本矩阵 + 十万记录缓冲。

用法（Windows，仅 Python 3.12 标准库）::

    python run_audit.py

产物写入 ``artifacts/audit-report.json`` 与 ``artifacts/audit-report.txt``，
并保留四个可用 ``python audit_export/verify.py <workspace>`` 独立复核的工作区。
任何不变量失败都会以非 0 退出码结束。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

# Windows 控制台尽量用 UTF-8 输出
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001
    pass

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from audit_export.concurrency import run_pair  # noqa: E402
from audit_export.enumerate import (  # noqa: E402
    all_merges,
    authorization_matrix,
    dual_source_matrix,
    exhaustive_interleavings,
    execute_merge,
)
from audit_export.scenarios import (  # noqa: E402
    publish_dual_source_report,
    record_old_permission_new_page_denial,
)
from audit_export.service import recover  # noqa: E402
from audit_export.scale import run_scale_validation  # noqa: E402
from audit_export.verify import verify_root  # noqa: E402

ART = ROOT / "artifacts"


def _rm(p: Path) -> None:
    from audit_export.workspace import Workspace
    Workspace.robust_rmtree(p)


def persistent_demos() -> dict:
    out: dict[str, Any] = {}

    # 1) 承诺先于撤销 -> RACE 作为历史报告祖父式保留；再加双来源/版本场景
    committed = ART / "demo-committed"
    _rm(committed)
    schedule_commit_first = [
        ("P", 0), ("P", 1),                       # p1,p2 -> 先承诺 cseq=3
        ("R", 0), ("R", 1), ("R", 2), ("R", 3),   # 撤销 rev_seq=4
        ("P", 2), ("P", 3), ("P", 4), ("P", 5),   # 晋升/索引/回执/清理
    ]
    ex = execute_merge(committed, schedule_commit_first)
    dual = publish_dual_source_report(committed)
    denial = record_old_permission_new_page_denial(committed)
    rec = recover(committed)
    ver = verify_root(committed)
    out["commit_first_grandfathered"] = {
        "path": str(committed), "execute_error": ex["exec_error"],
        "dual_source": dual, "version_denial_reason":
            denial["denied"]["reason"],
        "recovery": rec, "verify_ok": ver["ok"],
        "violations": ver["violations"], "stats": ver["stats"],
    }

    # 2) 撤销先于承诺 -> RACE 被拒绝，export 中零痕迹
    denied = ART / "demo-revoked-first"
    _rm(denied)
    schedule_revoke_first = [
        ("R", 0), ("R", 1), ("R", 2), ("R", 3),
        ("P", 0), ("P", 1), ("P", 2), ("P", 3), ("P", 4), ("P", 5),
    ]
    ex2 = execute_merge(denied, schedule_revoke_first)
    rec2 = recover(denied)
    ver2 = verify_root(denied)
    out["revoke_first_absent"] = {
        "path": str(denied), "execute_error": ex2["exec_error"],
        "packager_decision": ex2["denied"],
        "recovery_removed_pending": rec2["removed_uncommitted_pending"],
        "verify_ok": ver2["ok"], "violations": ver2["violations"],
        "stats": ver2["stats"],
    }
    return out


def threaded_fault_demos() -> dict:
    out: dict[str, Any] = {}
    for fault, name in (("A", "fault-A-revocation-committed-archive-open"),
                        ("B", "fault-B-promoted-receipt-lost")):
        root = ART / name
        _rm(root)
        # 带轻微抖动，促成真实线程交错；正确性不依赖时序
        res = run_pair(fault, root, jitter=0.0005)
        out[f"fault_{fault}"] = {"path": str(root), **res}
    return out


def main() -> int:
    ART.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    report: dict[str, Any] = {}

    print(">>> [1/5] persistent happy-path / grandfather demos ...")
    report["persistent_demos"] = persistent_demos()

    print(">>> [2/5] real two-thread barrier fault replays ...")
    report["threaded_faults"] = threaded_fault_demos()

    print(">>> [3/5] exhaustive short interleavings (clean + fault A/B) ...")
    t0 = time.perf_counter()
    report["exhaustive"] = exhaustive_interleavings()
    report["exhaustive"]["elapsed_seconds"] = round(time.perf_counter() - t0, 2)
    report["exhaustive"]["merge_count_formula"] = \
        f"C({4 + 6},{4})={len(all_merges())}"

    print(">>> [4/5] dual-source + authorization matrices ...")
    report["dual_source_matrix"] = dual_source_matrix()
    report["authorization_matrix"] = authorization_matrix()

    print(">>> [5/5] 100k records / 8 MiB hard buffer validation ...")
    report["scale"] = run_scale_validation()

    report["elapsed_total_seconds"] = round(time.perf_counter() - started, 2)

    # 顶层总判定
    pd_ok = all(d.get("verify_ok") for d in
                report["persistent_demos"].values())
    tf_ok = all(f["verification_ok"] and not f["thread_errors"]
                and f["joined_cleanly"]
                for f in report["threaded_faults"].values())
    report["overall_ok"] = bool(
        pd_ok
        and tf_ok
        and report["exhaustive"]["all_verified"]
        and report["dual_source_matrix"]["exhaustive_ok"]
        and report["authorization_matrix"]["matrix_ok"]
        and report["scale"]["ok"]
    )

    (ART / "audit-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    (ART / "audit-report.txt").write_text(
        render_text(report), encoding="utf-8")

    print(render_text(report))
    print(f"\nJSON report: {ART / 'audit-report.json'}")
    return 0 if report["overall_ok"] else 1


def render_text(r: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("审计导出/恢复/独立验证 — 运行摘要")
    lines.append("=" * 72)

    ex = r["exhaustive"]
    lines.append(
        f"[交错穷举] 合并数 {ex['total_merges']} (=C(10,4)) × 3 模式 "
        f"clean/A/B；全部验证通过={ex['all_verified']}；"
        f"用时 {ex.get('elapsed_seconds')}s")
    for mode, m in ex["by_mode"].items():
        lines.append(
            f"   - 模式 {mode:5s}: {m['verified']}/{m['runs']} verified, "
            f"race_pub={m['race_published']} "
            f"(grandfather={m['race_grandfathered']}), "
            f"race_absent={m['race_absent']}, "
            f"rollforward={m['rolled_forward']}, "
            f"receipts_rebuilt={m['receipts_reconstructed']}, "
            f"tmp_arc_removed={m['temp_archives_removed']}, "
            f"idx_changed={m['index_changed']}, "
            f"ptr_changed={m['pointer_changed']}, "
            f"barrier_prefixes={m['distinct_barrier_prefixes']}")
    if ex["failures"]:
        lines.append(f"   !! {len(ex['failures'])} 个失败，见 JSON")

    dm = r["dual_source_matrix"]
    lines.append(
        f"[双来源穷举] 单来源 {dm['single_source_cases']} + "
        f"有序双来源对 {dm['ordered_pair_cases']}；"
        f"不变量成立={dm['invariants_held']}；"
        f"见证符合预期={dm['witnesses_as_expected']}")
    lines.append(f"   分布 {dm['resolution_counts']}")

    am = r["authorization_matrix"]
    lines.append(
        f"[授权矩阵] {am['cases']} 个 perm×page×revoke×seq 组合；"
        f"matrix_ok={am['matrix_ok']}；水位边界见证={am['watermark_edge_ok']}")

    sc = r["scale"]
    c = sc["counts"]
    lines.append(
        f"[记录计数] 全量更新={c['full_records']} 条；"
        f"局部更新={c['partial_update_records']} 条 "
        f"(改 {c['partial_updated_records']} + 增 {c['partial_inserted_records']})")
    b = sc["buffers"]
    cats = b["categories"]
    lines.append(
        f"[8MiB 硬缓冲] limit={b['limit_bytes']} B；"
        f"聚合峰值={b['aggregate_peak_bytes']} B "
        f"({b['aggregate_peak_mib']} MiB)；"
        f"从未超限={b['hard_limit_never_exceeded']}")
    lines.append(
        f"   输入 peak={cats['input']['peak_bytes']} B；"
        f"待提交页 peak={cats['pending_pages']['peak_bytes']} B；"
        f"索引队列 peak={cats['index_queue']['peak_bytes']} B")
    fd = sc["failure_drill"]
    h = fd["held_at_failure"]
    lines.append(
        f"   失败后尚持有: input={h['input_bytes']}, "
        f"pending={h['pending_pages_bytes']}, index={h['index_queue_bytes']}, "
        f"total={h['total_bytes']} B；恢复释放="
        f"{fd['recovery_released_bytes']} B；"
        f"恢复后活缓冲={fd['post_recovery_live_bytes']} B "
        f"(balanced={fd['balanced_after_recovery']})")
    hp = sc["hard_limit_probe"]
    lines.append(
        f"   硬顶探针: 8MiB放行={hp['eight_mib_allocations_ok']}, "
        f"第9字节拒={hp['one_byte_ninth_rejected']}, "
        f"跨类超额拒={hp['cross_category_overcommit_rejected']}, "
        f"单次>8MiB拒={hp['single_oversized_rejected']}, ok={hp['probe_ok']}")

    for key, td in r["threaded_faults"].items():
        lines.append(
            f"[双线程 {key}] trigger={td['trigger_side']}, "
            f"reaped_fd={td['reaped_handles']}, "
            f"joined={td['joined_cleanly']}, "
            f"thread_errors={len(td['thread_errors'])}, "
            f"verify_ok={td['verification_ok']}")

    for key, pd_ in r["persistent_demos"].items():
        lines.append(
            f"[持久演示 {key}] verify_ok={pd_['verify_ok']}, "
            f"codes={pd_['stats']['codes']}, "
            f"grandfathered={pd_['stats']['grandfathered']}")

    lines.append("-" * 72)
    lines.append(f"OVERALL_OK = {r['overall_ok']}  "
                 f"(elapsed {r['elapsed_total_seconds']}s)")
    lines.append("=" * 72)
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
