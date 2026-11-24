"""8 MiB 硬缓冲池与分类核算。

三类在途活缓冲：

- ``input``         输入：从合成记录源读出、尚未解析完的原始字节
- ``pending_pages`` 待提交页：已渲染、等待承诺/晋升的页
- ``index_queue``   索引队列：等待并入 index.json 的索引项

第四类 *不是* 额外容量，而是故障时刻的留痕：

- ``retained_after_failure`` 失败抛出后调用方仍持有、尚未释放的缓冲快照，
  恢复路径必须如数释放，使所有活缓冲归零。

硬限制按三类活缓冲的 **合计** 计算（因此每一类自身也必然 <= 8 MiB）。
任何会使合计超过 8 MiB 的申请都被拒绝，绝不静默突破。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from . import HARD_BUFFER_LIMIT

INPUT = "input"
PENDING = "pending_pages"
INDEX_Q = "index_queue"
LIVE_CATEGORIES = (INPUT, PENDING, INDEX_Q)


class HardBufferLimitError(RuntimeError):
    def __init__(self, *, category: str, requested: int, live_total: int,
                 limit: int) -> None:
        super().__init__(
            f"hard buffer limit exceeded: acquire {requested} B on "
            f"'{category}' with live_total={live_total} B -> "
            f"{live_total + requested} B > limit={limit} B"
        )
        self.category = category
        self.requested = requested
        self.live_total = live_total
        self.limit = limit


@dataclass
class _Cat:
    live: int = 0
    peak: int = 0
    peak_items: int = 0
    acquisitions: int = 0
    bytes_acquired: int = 0
    items_live: int = 0
    items_peak: int = 0


@dataclass
class BufferPool:
    limit: int = HARD_BUFFER_LIMIT
    _cats: dict[str, _Cat] = field(default_factory=dict)
    _aggregate_peak: int = 0
    # 可重入：report() 持锁时会复用 category_report() 再次取同一把锁
    _lock: threading.RLock = field(default_factory=threading.RLock)
    retained_after_failure: dict | None = None
    failure_count: int = 0

    def __post_init__(self) -> None:
        for name in LIVE_CATEGORIES:
            self._cats[name] = _Cat()

    # -- 核心计量 -----------------------------------------------------------
    def total_live(self) -> int:
        with self._lock:
            return sum(c.live for c in self._cats.values())

    def acquire(self, category: str, num_bytes: int, *, items: int = 1) -> int:
        if category not in self._cats:
            raise KeyError(f"unknown buffer category {category!r}")
        if num_bytes < 0:
            raise ValueError("num_bytes must be non-negative")
        with self._lock:
            cat = self._cats[category]
            live_total = sum(c.live for c in self._cats.values())
            if live_total + num_bytes > self.limit:
                raise HardBufferLimitError(
                    category=category,
                    requested=num_bytes,
                    live_total=live_total,
                    limit=self.limit,
                )
            cat.live += num_bytes
            cat.items_live += items
            cat.acquisitions += 1
            cat.bytes_acquired += num_bytes
            cat.peak = max(cat.peak, cat.live)
            cat.items_peak = max(cat.items_peak, cat.items_live)
            live_total = sum(c.live for c in self._cats.values())
            self._aggregate_peak = max(self._aggregate_peak, live_total)
            return cat.live

    def release(self, category: str, num_bytes: int, *, items: int = 1) -> None:
        with self._lock:
            cat = self._cats[category]
            if num_bytes > cat.live:
                # 记账错误必须暴露，不能靠钳制掩盖。
                raise AssertionError(
                    f"release {num_bytes} B but category {category!r} only "
                    f"holds {cat.live} B"
                )
            if items > cat.items_live:
                raise AssertionError(
                    f"release {items} items but {category!r} holds "
                    f"{cat.items_live}"
                )
            cat.live -= num_bytes
            cat.items_live -= items

    # -- 故障留痕与恢复 -----------------------------------------------------
    def mark_failure_retained(self, error: BaseException | str) -> dict:
        """故障抛出后，把当前仍持有的活缓冲登记为'失败后尚持有'。

        不清零——这些字节在恢复释放前确实仍被持有。
        """
        with self._lock:
            self.failure_count += 1
            snap = {
                "error": str(error),
                "limit_bytes": self.limit,
                "by_category": {
                    name: {
                        "bytes": self._cats[name].live,
                        "items": self._cats[name].items_live,
                    }
                    for name in LIVE_CATEGORIES
                },
                "total_bytes": sum(c.live for c in self._cats.values()),
            }
            self.retained_after_failure = snap
            return snap

    def recover_failed_buffers(self) -> dict:
        """恢复路径如数释放故障后仍持有的缓冲；返回释放凭证。"""
        with self._lock:
            released = {}
            for name in LIVE_CATEGORIES:
                cat = self._cats[name]
                released[name] = {"bytes": cat.live, "items": cat.items_live}
                cat.live = 0
                cat.items_live = 0
            total = sum(v["bytes"] for v in released.values())
            if self.retained_after_failure is not None:
                self.retained_after_failure["released_by_recovery"] = released
                self.retained_after_failure["released_total_bytes"] = total
            live_total = sum(c.live for c in self._cats.values())
            return {
                "released": released,
                "released_total_bytes": total,
                "post_recovery_live_total": live_total,
                "balanced": live_total == 0,
            }

    # -- 报告 ---------------------------------------------------------------
    def category_report(self, name: str) -> dict:
        with self._lock:
            c = self._cats[name]
            return {
                "live_bytes": c.live,
                "peak_bytes": c.peak,
                "peak_items": c.items_peak,
                "live_items": c.items_live,
                "acquisitions": c.acquisitions,
                "bytes_acquired_total": c.bytes_acquired,
            }

    def report(self) -> dict:
        with self._lock:
            agg_peak = self._aggregate_peak
            live_total = sum(c.live for c in self._cats.values())
            return {
                "limit_bytes": self.limit,
                "limit_mib": self.limit / (1024 * 1024),
                "aggregate_peak_bytes": agg_peak,
                "aggregate_peak_mib": round(agg_peak / (1024 * 1024), 3),
                "live_total_bytes": live_total,
                "hard_limit_never_exceeded": agg_peak <= self.limit,
                "categories": {
                    name: self.category_report(name) for name in LIVE_CATEGORIES
                },
                "retained_after_failure": self.retained_after_failure,
                "failure_count": self.failure_count,
            }

    def assert_invariant(self) -> None:
        live = self.total_live()
        assert live <= self.limit, f"live {live} > hard limit {self.limit}"
