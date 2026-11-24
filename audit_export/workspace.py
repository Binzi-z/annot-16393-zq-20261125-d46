"""磁盘工作区布局与 Windows/NTFS 安全的原子原语。

原子晋升统一走 "同目录临时文件 + flush/fsync + ``os.replace``"。
``os.replace`` 在 Windows 上对同卷目标是原子替换，可用于把
``*.part`` 晋升为正式包 / 索引 / 发布指针。

撤销临时归档故意用裸 fd 维护一个 "未关闭句柄" 集合；故障注入时
:meth:`Workspace.reap_handles_like_kill` 用 ``os.close`` 模拟进程死亡后
内核回收句柄（应用层的 close/finalize/rename 全部没有发生）。
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .canon import canonical_bytes


class Workspace:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        # 故障模拟时需要被"内核回收"的裸 fd
        self.open_fds: set[int] = set()

    # -- 目录布局 -----------------------------------------------------------
    @property
    def policy_file(self) -> Path:
        return self.root / "policy.json"

    @property
    def control(self) -> Path:
        return self.root / "control"

    @property
    def wal_dir(self) -> Path:
        return self.control / "wal"

    @property
    def tmp_dir(self) -> Path:
        return self.control / "tmp"

    @property
    def revocation_file(self) -> Path:
        return self.control / "revocation.json"

    @property
    def cache_dir(self) -> Path:
        return self.root / "cache" / "sources"

    @property
    def staging_dir(self) -> Path:
        return self.root / "staging"

    @property
    def export(self) -> Path:
        return self.root / "export"

    @property
    def pages_dir(self) -> Path:
        return self.export / "pages"

    @property
    def packages_dir(self) -> Path:
        return self.export / "packages"

    @property
    def receipts_dir(self) -> Path:
        return self.export / "receipts"

    @property
    def index_file(self) -> Path:
        return self.export / "index.json"

    @property
    def pointer_file(self) -> Path:
        return self.export / "publish-pointer.json"

    @property
    def frozen_policy_file(self) -> Path:
        return self.export / "frozen-policy.json"

    def ensure_layout(self) -> "Workspace":
        for d in (
            self.root, self.control, self.wal_dir, self.tmp_dir,
            self.cache_dir, self.staging_dir, self.export,
            self.pages_dir, self.packages_dir, self.receipts_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)
        return self

    # -- 路径辅助 -----------------------------------------------------------
    def abs(self, rel: str) -> Path:
        return self.root / rel

    def rel(self, path: str | Path) -> str:
        return Path(path).relative_to(self.root).as_posix()

    # -- 基础 IO ------------------------------------------------------------
    def write_json(self, path: str | Path, obj: Any) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_bytes(obj))
        return path

    def read_json(self, path: str | Path) -> Any:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def exists(self, path: str | Path) -> bool:
        return Path(path).exists()

    def atomic_write_bytes(self, final_path: str | Path,
                           data: bytes) -> Path:
        """同目录 mkstemp -> 写 -> fsync -> ``os.replace`` 原子晋升。"""
        final_path = Path(final_path)
        final_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=final_path.name + ".", suffix=".part",
            dir=str(final_path.parent),
        )
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, final_path)  # Windows 同卷原子替换
        except BaseException:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass
            raise
        return final_path

    def atomic_write_json(self, final_path: str | Path, obj: Any) -> Path:
        return self.atomic_write_bytes(final_path, canonical_bytes(obj))

    # -- 撤销临时归档的"未关闭句柄" ----------------------------------------
    def open_tracked_part(self, path: str | Path) -> tuple[int, Path]:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(str(path), flags, 0o644)
        self.open_fds.add(fd)
        return fd, path

    @staticmethod
    def tracked_write(fd: int, data: bytes) -> int:
        return os.write(fd, data)

    def tracked_fsync(self, fd: int) -> None:
        os.fsync(fd)

    def close_tracked(self, fd: int) -> None:
        os.close(fd)
        self.open_fds.discard(fd)

    def reap_handles_like_kill(self) -> int:
        """模拟进程被杀死：内核关闭所有仍打开的 fd（应用收尾全部跳过）。

        返回被内核回收的句柄数。刻意不执行 close 之外的任何协议动作。
        """
        n = 0
        for fd in list(self.open_fds):
            try:
                os.close(fd)
                n += 1
            except OSError:
                pass
            finally:
                self.open_fds.discard(fd)
        return n

    # -- 扫描 ---------------------------------------------------------------
    def iter_files(self, base: str | Path) -> Iterable[Path]:
        base = Path(base)
        if not base.exists():
            return []
        return (p for p in base.rglob("*") if p.is_file())

    def export_posix_files(self) -> list[str]:
        if not self.export.exists():
            return []
        return sorted(
            p.relative_to(self.export).as_posix()
            for p in self.export.rglob("*") if p.is_file()
        )

    # -- 清理（测试用，Windows 只读位兜底） --------------------------------
    @staticmethod
    def robust_rmtree(path: str | Path) -> None:
        path = Path(path)
        if not path.exists():
            return

        def _on_error(func, p, _exc):  # noqa: ANN001
            try:
                os.chmod(p, stat.S_IWRITE)
                func(p)
            except OSError:
                pass

        shutil.rmtree(path, onerror=_on_error)  # type: ignore[arg-type]
