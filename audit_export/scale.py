"""十万条合成记录下验证 8 MiB 硬缓冲与全量/局部更新计数。

计量是"真实字节"：每条记录/页/索引项都实际做 canonical JSON 编码并按
``len(bytes)`` 记账，而不是拍脑袋常数。记录流式分块通过三类缓冲，每块在
提交/刷索引后如数释放，因此处理十万条之后活缓冲仍为 0，而聚合峰值被硬池
限制在 8 MiB 以内。另做：

- 硬顶探针：恰好 8 MiB 放行，第 8 MiB 之后的 1 字节与单次 8 MiB+1 申请都被拒；
- 故障演练：在三类缓冲都持有一个在途块时注入失败，登记
  ``retained_after_failure``，再由恢复如数释放并验证归零。
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterator

from . import HARD_BUFFER_LIMIT
from .buffers import (
    INDEX_Q,
    INPUT,
    PENDING,
    BufferPool,
    HardBufferLimitError,
)
from .canon import canonical_bytes

FULL_RECORDS = 100_000
PARTIAL_UPDATED = 500      # i % 200 == 0 -> 500 条
PARTIAL_INSERTED = 750     # 新增 id 100000..100749
PARTIAL_RECORDS = PARTIAL_UPDATED + PARTIAL_INSERTED  # 1250

# 自设的在途块聚合预算，留出到 8 MiB 硬顶的安全余量；真正的保证仍来自 BufferPool
CHUNK_TRIPLE_BUDGET = 6 * 1024 * 1024
_SEVERITY = ("low", "medium", "high", "critical")


def _record(i: int, *, version: int = 1) -> dict[str, Any]:
    payload_len = 128 + (i * 37) % 256  # 128..383 字节，确定性变化
    return {
        "id": i,
        "code": f"SR-{i:06d}",
        "version": version,
        "severity": _SEVERITY[i % 4],
        "tenant": f"tenant-{i % 64:02d}",
        "payload": "Q" * payload_len,
    }


def _sizes_for(i: int, *, version: int = 1) -> tuple[int, int, int]:
    rec = _record(i, version=version)
    raw = canonical_bytes(rec)
    raw_len = len(raw)

    digest = hashlib.sha256(raw).hexdigest()
    page = {
        "code": rec["code"], "page_no": 1, "version": version,
        "fields": {"severity": rec["severity"], "tenant": rec["tenant"],
                   "payload": rec["payload"]},
        "sources": [
            {"source_id": "SRC-A", "digest": digest},
            {"source_id": "SRC-B", "digest": digest},
        ],
    }
    page_len = len(canonical_bytes(page))

    entry = {
        "code": rec["code"], "commit_seq": i + 1,
        "package_sha256": digest,
        "pages": [{"path": f"pages/{rec['code']}/p1.json",
                   "sha256": digest, "source_digest": digest}],
    }
    idx_len = len(canonical_bytes(entry))
    return raw_len, page_len, idx_len


def _iter_full() -> Iterator[tuple[int, int]]:
    for i in range(FULL_RECORDS):
        yield _sizes_for(i)


def _iter_partial() -> Iterator[tuple[int, int]]:
    # 500 条局部修改（新版本）
    for k in range(PARTIAL_UPDATED):
        i = k * 200
        yield _sizes_for(i, version=2)
    # 750 条新增
    for j in range(PARTIAL_INSERTED):
        yield _sizes_for(FULL_RECORDS + j)


def _drain_stream(pool: BufferPool, stream: Iterator[tuple[int, int]],
                  *, label: str) -> dict[str, Any]:
    processed = 0
    chunks = 0
    max_chunk_records = 0
    cur_n = 0
    cur_in = cur_pen = cur_idx = 0

    def flush() -> None:
        nonlocal chunks, cur_n, cur_in, cur_pen, cur_idx, max_chunk_records
        if cur_n == 0:
            return
        # 三类缓冲同时在途（最保守的峰值模型）
        pool.acquire(INPUT, cur_in, items=cur_n)
        pool.acquire(PENDING, cur_pen, items=cur_n)
        pool.acquire(INDEX_Q, cur_idx, items=cur_n)
        pool.assert_invariant()
        # 承诺 + 刷索引后逐级释放
        pool.release(INPUT, cur_in, items=cur_n)
        pool.release(PENDING, cur_pen, items=cur_n)
        pool.release(INDEX_Q, cur_idx, items=cur_n)
        chunks += 1
        max_chunk_records = max(max_chunk_records, cur_n)
        cur_n = 0
        cur_in = cur_pen = cur_idx = 0

    for inb, penb, idxb in stream:
        if cur_n and (cur_in + inb + cur_pen + penb + cur_idx + idxb
                      > CHUNK_TRIPLE_BUDGET):
            flush()
        cur_n += 1
        cur_in += inb
        cur_pen += penb
        cur_idx += idxb
        processed += 1
    flush()
    return {"label": label, "records": processed, "chunks": chunks,
            "max_chunk_records": max_chunk_records}


def hard_limit_probe() -> dict[str, Any]:
    pool = BufferPool()
    mib = 1024 * 1024
    eight_ok = 0
    for _ in range(8):
        pool.acquire(INPUT, mib)
        eight_ok += 1
    live_at_eight = pool.total_live()

    ninth_rejected = False
    try:
        pool.acquire(INPUT, 1)
    except HardBufferLimitError:
        ninth_rejected = True

    cross_category_rejected = False
    try:
        pool.acquire(PENDING, 1)
    except HardBufferLimitError:
        cross_category_rejected = True

    big_rejected = False
    big_detail = None
    p2 = BufferPool()
    try:
        p2.acquire(INPUT, HARD_BUFFER_LIMIT + 1)
    except HardBufferLimitError as e:
        big_rejected = True
        big_detail = {"requested": e.requested, "limit": e.limit}

    return {
        "limit_bytes": HARD_BUFFER_LIMIT,
        "eight_mib_allocations_ok": eight_ok,
        "live_at_eight_bytes": live_at_eight,
        "one_byte_ninth_rejected": ninth_rejected,
        "cross_category_overcommit_rejected": cross_category_rejected,
        "single_oversized_rejected": big_rejected,
        "oversized_detail": big_detail,
        "probe_ok": (
            eight_ok == 8 and live_at_eight == HARD_BUFFER_LIMIT
            and ninth_rejected and cross_category_rejected and big_rejected
        ),
    }


def failure_drill(pool: BufferPool) -> dict[str, Any]:
    """在三类缓冲都持有一个在途块时注入失败，登记并恢复释放。"""
    assert pool.total_live() == 0, "pool must be balanced before failure drill"
    n = 2000
    in_b = pen_b = idx_b = 0
    for i in range(n):
        a, b, c = _sizes_for(i)
        in_b += a
        pen_b += b
        idx_b += c
    pool.acquire(INPUT, in_b, items=n)
    pool.acquire(PENDING, pen_b, items=n)
    pool.acquire(INDEX_Q, idx_b, items=n)
    held_total = pool.total_live()
    assert held_total <= HARD_BUFFER_LIMIT

    injected = RuntimeError("injected failure: commit io error mid-flight")
    retained = pool.mark_failure_retained(injected)
    before = {
        "input_bytes": retained["by_category"][INPUT]["bytes"],
        "pending_pages_bytes": retained["by_category"][PENDING]["bytes"],
        "index_queue_bytes": retained["by_category"][INDEX_Q]["bytes"],
        "total_bytes": retained["total_bytes"],
    }
    recovery = pool.recover_failed_buffers()
    after_live = pool.total_live()
    return {
        "injected_error": str(injected),
        "records_in_flight": n,
        "held_at_failure": before,
        "within_hard_limit": before["total_bytes"] <= HARD_BUFFER_LIMIT,
        "recovery_released_bytes": recovery["released_total_bytes"],
        "post_recovery_live_bytes": after_live,
        "balanced_after_recovery": recovery["balanced"] and after_live == 0,
    }


def run_scale_validation() -> dict[str, Any]:
    pool = BufferPool()

    full = _drain_stream(pool, _iter_full(), label="full")
    after_full_live = pool.total_live()

    partial = _drain_stream(pool, _iter_partial(), label="partial")
    after_partial_live = pool.total_live()

    totals = {
        "full_records": FULL_RECORDS,
        "partial_update_records": PARTIAL_RECORDS,
        "partial_updated_records": PARTIAL_UPDATED,
        "partial_inserted_records": PARTIAL_INSERTED,
        "full_chunk_count": full["chunks"],
        "partial_chunk_count": partial["chunks"],
        "max_chunk_records": full["max_chunk_records"],
        "live_bytes_after_full": after_full_live,
        "live_bytes_after_partial": after_partial_live,
    }

    drill = failure_drill(pool)
    probe = hard_limit_probe()
    rep = pool.report()

    scale_ok = (
        full["records"] == FULL_RECORDS
        and partial["records"] == PARTIAL_RECORDS
        and after_full_live == 0
        and after_partial_live == 0
        and rep["hard_limit_never_exceeded"]
        and rep["aggregate_peak_bytes"] <= HARD_BUFFER_LIMIT
        and drill["balanced_after_recovery"]
        and drill["within_hard_limit"]
        and probe["probe_ok"]
    )
    return {
        "ok": scale_ok,
        "counts": totals,
        "hard_limit_probe": probe,
        "failure_drill": drill,
        "buffers": rep,
    }
