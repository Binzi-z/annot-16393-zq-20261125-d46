"""两个真实线程同时推进撤销(R)与打包(P)，并用"静止屏障"重演两类故障。

与 ``enumerate.py`` 的脚本化穷举互补：这里 R/P 是两个独立 OS 线程，靠
``threading.Barrier`` 同时起步、靠 Condition 实现的 *quiescent barrier*
在故障点等待另一线程到达步骤边界（不在任何文件 IO 中途杀进程），随后一次性
回收所有托管 fd，模拟进程死亡。主线程 join 后再做纯磁盘恢复与独立验证。
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from .service import AuditService, FAULT_LABELS, recover
from .verify import verify_root


class ThreadedFaultReplay:
    def __init__(self, fault: str, *, jitter: float = 0.0) -> None:
        assert fault in FAULT_LABELS
        self.fault = fault
        self.label = FAULT_LABELS[fault]
        self.jitter = jitter

        self.start_barrier = threading.Barrier(2)
        self.cond = threading.Condition()
        self.crash_requested = False
        self.in_step = {"R": False, "P": False}
        self.errors: list[str] = []
        self.reaped_handles = 0
        self.trigger_side: str | None = None
        self.joined_cleanly = True

    def run(self, root: str | Path) -> dict[str, Any]:
        svc = AuditService(root, armed_fault=None)
        svc.bootstrap_trust_and_sources().seed_historical()

        def worker(side: str) -> None:
            other = "P" if side == "R" else "R"
            steps = (svc.revoker_steps() if side == "R"
                     else svc.packager_steps())
            try:
                try:
                    self.start_barrier.wait(timeout=10)
                except threading.BrokenBarrierError:
                    pass

                for name, fn in steps:
                    with self.cond:
                        if self.crash_requested or svc.dead:
                            return
                        self.in_step[side] = True

                    if self.jitter:
                        time.sleep(self.jitter)

                    try:
                        fn()
                    except Exception as exc:  # noqa: BLE001
                        with self.cond:
                            self.in_step[side] = False
                        from .service import ServiceCrashed
                        if isinstance(exc, ServiceCrashed):
                            return
                        self.errors.append(f"{side} {name}: {exc!r}")
                        return

                    with self.cond:
                        self.in_step[side] = False
                        if name == self.label and not self.crash_requested:
                            self.crash_requested = True
                            self.trigger_side = side
                        self.cond.notify_all()

                    if name == self.label and self.trigger_side == side:
                        # 等待另一线程完成当前步骤；此后它在看到
                        # crash_requested 前不可能再启动新步骤。
                        with self.cond:
                            self.cond.wait_for(
                                lambda: not self.in_step[other], timeout=10)
                        svc.dead = True
                        self.reaped_handles = svc.ws.reap_handles_like_kill()
                        with self.cond:
                            self.cond.notify_all()
                        return

                    with self.cond:
                        if self.crash_requested:
                            return
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"{side} fatal: {exc!r}")

        tr = threading.Thread(target=worker, args=("R",), name="revoker")
        tp = threading.Thread(target=worker, args=("P",), name="packager")
        tr.start()
        tp.start()
        tr.join(timeout=20)
        tp.join(timeout=20)
        self.joined_cleanly = not (tr.is_alive() or tp.is_alive())

        recovery = recover(root)
        verification = verify_root(root)
        return {
            "fault": self.fault,
            "fault_label": self.label,
            "jitter": self.jitter,
            "trigger_side": self.trigger_side,
            "reaped_handles": self.reaped_handles,
            "joined_cleanly": self.joined_cleanly,
            "thread_errors": self.errors,
            "recovery": recovery,
            "verification_ok": verification["ok"],
            "violations": verification["violations"],
            "stats": verification["stats"],
        }


def run_pair(fault: str, root: str | Path, *, jitter: float = 0.0) -> dict:
    return ThreadedFaultReplay(fault, jitter=jitter).run(root)
