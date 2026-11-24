"""撤销线程与打包线程共享的原子步骤、故障注入和崩溃恢复。

两个线程各自运行一个很短的保序步骤程序：

撤销 R：r1 承诺撤销 → r2 写临时归档(句柄仍开) →【故障 A 屏障】
        → r3 关句柄并原子转正归档 → r4 发布撤销记录
打包 P：p1 准备干净 pending 页集(+可能沾上面包屑的 staging 草稿)
        → p2 授权并写 commit 标记(与 r1 在线性化锁上决胜)
        → p3 晋升实际页与包 → p4 更新索引与发布指针
        →【故障 B 屏障】→ p5 回执 → p6 清理

"崩溃"用 :meth:`Workspace.reap_handles_like_kill` 模拟进程死亡时的句柄回收，
应用层收尾/改名/回执全部跳过。:meth:`AuditService.recover` 只依据磁盘恢复。
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Callable

from .canon import canonical_bytes, hash_obj, sha256_bytes
from .model import (
    REVOCATION_SOURCE_REF,
    Grant,
    authorize,
    historical_fixtures,
    race_fixture,
    small_policy,
)
from .reconcile import (
    commit_marker_path,
    denial_marker_path,
    package_rel_path,
    pending_path,
    policy_hash,
    promote_committed,
    public_policy,
    publish_index_and_pointer,
    receipt_rel_path,
    ensure_receipts,
)
from .workspace import Workspace

FAULT_LABELS = {"A": "r2_archive_open", "B": "p4_publish"}


class SimulatedCrash(RuntimeError):
    def __init__(self, fault: str, reaped_handles: int) -> None:
        super().__init__(f"simulated crash fault {fault}")
        self.fault = fault
        self.reaped_handles = reaped_handles


class ServiceCrashed(RuntimeError):
    pass


def source_descriptors() -> dict[str, dict[str, Any]]:
    """本地合成来源的描述符（含自摘要），同时写入 cache/sources。"""
    a = {"source_id": "SRC-A", "source_version": 1,
         "payload": "synthetic-telemetry-source-A"}
    b = {"source_id": "SRC-B", "source_version": 2,
         "payload": "synthetic-telemetry-source-B"}
    a["digest"] = hash_obj({"source_id": a["source_id"], "payload": a["payload"]})
    b["digest"] = hash_obj({"source_id": b["source_id"], "payload": b["payload"]})
    return {"SRC-A": a, "SRC-B": b}


def build_pending(
    *,
    code: str,
    watermark: int,
    page_inputs: list[dict[str, Any]],
) -> dict[str, Any]:
    """根据 ``page_inputs`` 构造可持久化的 pending 页集与 body 承诺。

    page_inputs: [{"version":int,"fields":{...},"sources":[attestation,...]}]
    """
    page_files: list[dict[str, Any]] = []
    commitments: list[dict[str, Any]] = []
    for i, pin in enumerate(page_inputs, start=1):
        from .canon import canonical_bytes, page_source_digest, sha256_bytes

        atts = pin["sources"]
        sd = page_source_digest(
            page_no=i, version=pin["version"],
            fields=pin["fields"], sources=atts,
        )
        content = {
            "page_no": i,
            "version": pin["version"],
            "fields": pin["fields"],
            "sources": atts,
            "source_digest": sd,
        }
        rel = f"pages/{code}/p{i}.json"
        data = canonical_bytes(content)
        sha = sha256_bytes(data)
        page_files.append({"rel_path": rel, "content": content})
        commitments.append({
            "page_no": i,
            "version": pin["version"],
            "path": rel,
            "sha256": sha,
            "source_digest": sd,
        })
    body = {"code": code, "watermark": watermark, "pages": commitments}
    return {
        "code": code,
        "watermark": watermark,
        "body": body,
        "body_hash": hash_obj(body),
        "page_files": page_files,
    }


def spec_to_page_inputs(spec: dict[str, Any],
                        descs: dict[str, dict[str, Any]],
                        source_ids: list[str] | None = None
                        ) -> list[dict[str, Any]]:
    ids = source_ids or ["SRC-A"]
    atts = [{
        "source_id": sid,
        "source_version": descs[sid]["source_version"],
        "digest": descs[sid]["digest"],
        "role": "primary" if j == 0 else "corroborating",
    } for j, sid in enumerate(ids)]
    return [
        {"version": p["version"], "fields": p["fields"], "sources": list(atts)}
        for p in spec["pages"]
    ]


class AuditService:
    def __init__(self, root: str | Path, *,
                 policy: dict[str, Any] | None = None,
                 race: dict[str, Any] | None = None,
                 armed_fault: str | None = None) -> None:
        self.ws = Workspace(root).ensure_layout()
        self.policy = policy or small_policy()
        self.race = race or race_fixture()
        self.armed_fault = armed_fault
        self.label_to_fault = {v: k for k, v in FAULT_LABELS.items()}

        self.lock = threading.RLock()
        self.descs = source_descriptors()
        self._seq = self._scan_seq()
        self._rev_seq = self._scan_rev_seq()
        self.dead = False
        self.reap_count = 0
        self.step_log: list[str] = []

        self._rev_fd: int | None = None
        self._rev_part: Path | None = None
        self._rev_marker: dict[str, Any] | None = None
        if self._rev_seq is not None:
            mp = self.ws.wal_dir / "rev-REV-GOLD.commit"
            if mp.exists():
                self._rev_marker = self.ws.read_json(mp)

        self.c_committed = commit_marker_path(self.ws, self.race["code"]).exists()
        self.c_denied: dict[str, Any] | None = None
        self.c_auth: dict[str, Any] | None = None
        if self.c_committed:
            self.c_auth = self.ws.read_json(
                commit_marker_path(self.ws, self.race["code"]))

    # ------------------------------------------------------------------ setup
    def bootstrap_trust_and_sources(self) -> "AuditService":
        self.ws.write_json(self.ws.policy_file, self.policy)
        self.ws.atomic_write_json(
            self.ws.frozen_policy_file, public_policy(self.policy))
        for sid, desc in self.descs.items():
            self.ws.write_json(self.ws.cache_dir / f"{sid}.json", desc)
        return self

    def seed_historical(self) -> "AuditService":
        """把两份历史报告以 seq=1,2 完整发布（撤销发生之前）。"""
        for idx, spec in enumerate(historical_fixtures(), start=1):
            with self.lock:
                seq = idx  # 固定 1、2
            page_inputs = spec_to_page_inputs(spec, self.descs)
            pending = build_pending(
                code=spec["code"], watermark=self.policy["watermark"],
                page_inputs=page_inputs)
            self.ws.atomic_write_json(pending_path(self.ws, spec["code"]), pending)
            gd = self.policy["grants"][spec["grant_id"]]
            auth = {
                "kind": "commit-auth",
                "code": spec["code"],
                "body_hash": pending["body_hash"],
                "commit_seq": seq,
                "watermark": self.policy["watermark"],
                "grant_id": spec["grant_id"],
                "grant_snapshot": gd,
                "decision_status": "active",
            }
            self.ws.atomic_write_json(
                commit_marker_path(self.ws, spec["code"]), auth)
            promote_committed(self.ws, spec["code"])
            ensure_receipts(self.ws)
            pending_path(self.ws, spec["code"]).unlink(missing_ok=True)
        with self.lock:
            self._seq = max(self._seq, 2)
        publish_index_and_pointer(self.ws, self.policy, updated_seq=2)
        return self

    # ------------------------------------------------------------------ seq
    def _scan_seq(self) -> int:
        m = 0
        if self.ws.wal_dir.exists():
            for f in self.ws.wal_dir.glob("*.json"):
                try:
                    d = self.ws.read_json(f)
                except Exception:
                    continue
                m = max(m, int(d.get("commit_seq", 0) or 0),
                        int(d.get("rev_seq", 0) or 0),
                        int(d.get("at_seq", 0) or 0))
        return m

    def _scan_rev_seq(self) -> int | None:
        if not self.ws.wal_dir.exists():
            return None
        for f in self.ws.wal_dir.glob("rev-*.commit"):
            return int(self.ws.read_json(f)["rev_seq"])
        return None

    def _next_seq(self) -> int:
        with self.lock:
            self._seq += 1
            return self._seq

    def _check_dead(self) -> None:
        if self.dead:
            raise ServiceCrashed("service already simulated-crashed")

    # ------------------------------------------------------- fault / barrier
    def post_step(self, step_name: str) -> None:
        """每个原子步骤后的屏障检查点；命中武装故障则模拟进程死亡。"""
        self.step_log.append(step_name)
        if self.armed_fault and FAULT_LABELS[self.armed_fault] == step_name:
            self.simulate_crash(self.armed_fault)

    def simulate_crash(self, fault: str) -> None:
        self.dead = True
        self.reap_count = self.ws.reap_handles_like_kill()
        raise SimulatedCrash(fault, self.reap_count)

    # ============================================================ R 撤销线程
    def r1_commit_revocation(self) -> str:
        self._check_dead()
        with self.lock:
            if self._rev_seq is not None:
                return "noop"
            rseq = self._next_seq()
            marker = {
                "kind": "revocation-commit",
                "rev_id": "REV-GOLD",
                "grant_id": "G-OLD",
                "rev_seq": rseq,
                "as_of_watermark": self.policy["watermark"],
                # 控制面合法持有的撤销来源引用（面包屑），禁止进入 export/
                "source_ref": REVOCATION_SOURCE_REF,
                "committed": True,
            }
            self.ws.atomic_write_json(
                self.ws.wal_dir / "rev-REV-GOLD.commit", marker)
            self._rev_seq = rseq
            self._rev_marker = marker
            return "committed"

    def r2_archive_open(self) -> str:
        self._check_dead()
        marker = self._rev_marker
        if marker is None:
            mp = self.ws.wal_dir / "rev-REV-GOLD.commit"
            marker = self.ws.read_json(mp) if mp.exists() else None
        if marker is None:
            return "no-revocation"
        evidence = b"REVOCATION-EVIDENCE\n" + hash_obj(marker).encode() + b"\n"
        evidence += REVOCATION_SOURCE_REF.encode() + b"\n"
        evidence += canonical_bytes(marker)
        fd, part = self.ws.open_tracked_part(
            self.ws.tmp_dir / "rev-archive-GOLD.part")
        self.ws.tracked_write(fd, evidence)
        self.ws.tracked_fsync(fd)
        self._rev_fd = fd
        self._rev_part = part
        return "open"

    def r3_archive_finalize(self) -> str:
        self._check_dead()
        if self._rev_fd is None:
            return "noop"
        self.ws.tracked_fsync(self._rev_fd)
        self.ws.close_tracked(self._rev_fd)
        self._rev_fd = None
        final = self.ws.control / "rev-archive-GOLD.arc"
        os.replace(self._rev_part, final)
        self._rev_part = None
        return "finalized"

    def r4_publish_revocation(self) -> str:
        self._check_dead()
        marker = self._rev_marker
        if marker is None:
            mp = self.ws.wal_dir / "rev-REV-GOLD.commit"
            if not mp.exists():
                return "noop"
            marker = self.ws.read_json(mp)
        arc = self.ws.control / "rev-archive-GOLD.arc"
        rec = dict(marker)
        rec["kind"] = "revocation"
        rec["archive"] = self.ws.rel(arc) if arc.exists() else None
        self.ws.atomic_write_json(self.ws.revocation_file, rec)
        return "published"

    # ============================================================ P 打包线程
    def p1_prepare(self) -> str:
        self._check_dead()
        code = self.race["code"]
        # 校验本地合成来源缓存
        for sid in ("SRC-A",):
            desc = self.descs[sid]
            on_disk = self.ws.read_json(self.ws.cache_dir / f"{sid}.json")
            if on_disk["digest"] != desc["digest"]:
                raise ValueError("source cache digest mismatch")

        pending = build_pending(
            code=code, watermark=self.policy["watermark"],
            page_inputs=spec_to_page_inputs(self.race, self.descs),
        )
        self.ws.atomic_write_json(pending_path(self.ws, code), pending)

        # 仅写 staging 的工作草稿：若撤销已承诺，它会带上撤销来源引用。
        # 这份草稿永远不会被晋升，p6/恢复会删除整个 staging。
        draft: dict[str, Any] = {"code": code, "stage": "draft"}
        if self._rev_seq is not None:
            draft["revocation_notice"] = {"source_ref": REVOCATION_SOURCE_REF}
        sdir = self.ws.staging_dir / f"{code}-tok"
        self.ws.write_json(sdir / "draft.json", draft)
        return "prepared"

    def p2_authorize_commit(self) -> str:
        self._check_dead()
        code = self.race["code"]
        with self.lock:
            if self.c_committed:
                return "noop-committed"
            if self.c_denied is not None:
                return "noop-denied"
            pending = self.ws.read_json(pending_path(self.ws, code))
            cseq = self._next_seq()
            rev_seq = self._rev_seq  # 关键：与 r1 在同一把锁上线性化
            gd = self.policy["grants"][self.race["grant_id"]]
            grant = Grant(
                grant_id=self.race["grant_id"],
                perm_version=gd["perm_version"],
                scope=tuple(gd.get("scope", [])),
                revoked=rev_seq is not None,
                rev_seq=rev_seq,
            )
            max_ver = max(p["version"] for p in self.race["pages"])
            decision = authorize(
                grant=grant, code=code, page_version=max_ver,
                commit_seq=cseq, watermark=self.policy["watermark"])

            if decision["allowed"]:
                auth = {
                    "kind": "commit-auth",
                    "code": code,
                    "body_hash": pending["body_hash"],
                    "commit_seq": cseq,
                    "watermark": self.policy["watermark"],
                    "grant_id": self.race["grant_id"],
                    "grant_snapshot": gd,
                    "decision_status": decision["status"],
                }
                self.ws.atomic_write_json(commit_marker_path(self.ws, code), auth)
                self.c_committed = True
                self.c_auth = auth
                return "committed:" + decision["status"]

            dmarker = {
                "kind": "denial",
                "code": code,
                "at_seq": cseq,
                "reason": decision["reason"],
                "decision": decision,
            }
            self.ws.atomic_write_json(denial_marker_path(self.ws, code), dmarker)
            self.c_denied = decision
            return "denied:" + decision["reason"]

    def p3_promote(self) -> str:
        self._check_dead()
        if not self.c_committed:
            return "skip"
        promote_committed(self.ws, self.race["code"])
        return "promoted"

    def p4_publish(self) -> str:
        self._check_dead()
        seq = self.c_auth["commit_seq"] if self.c_auth else self._seq
        publish_index_and_pointer(self.ws, self.policy, updated_seq=seq)
        return "published"

    def p5_receipt(self) -> str:
        self._check_dead()
        if not self.c_committed:
            return "skip"
        ensure_receipts(self.ws)
        return "receipted"

    def p6_cleanup(self) -> str:
        # 清理是尽力而为：即使 dead（故障线程之外）也允许在正常程序里调用？
        # 脚本化故障后不会再调用本步；正常路径 dead=False。
        code = self.race["code"]
        Workspace.robust_rmtree(self.ws.staging_dir / f"{code}-tok")
        pending_path(self.ws, code).unlink(missing_ok=True)
        return "cleaned"

    # ------------------------------------------------------------- step lists
    def revoker_steps(self) -> list[tuple[str, Callable[[], str]]]:
        return [
            ("r1_commit_revocation", self.r1_commit_revocation),
            ("r2_archive_open", self.r2_archive_open),
            ("r3_archive_finalize", self.r3_archive_finalize),
            ("r4_publish_revocation", self.r4_publish_revocation),
        ]

    def packager_steps(self) -> list[tuple[str, Callable[[], str]]]:
        return [
            ("p1_prepare", self.p1_prepare),
            ("p2_authorize_commit", self.p2_authorize_commit),
            ("p3_promote", self.p3_promote),
            ("p4_publish", self.p4_publish),
            ("p5_receipt", self.p5_receipt),
            ("p6_cleanup", self.p6_cleanup),
        ]

    def run_step(self, side: str, index: int) -> str:
        steps = self.revoker_steps() if side == "R" else self.packager_steps()
        name, fn = steps[index]
        result = fn()
        self.post_step(name)
        return result


# ===========================================================================
# 恢复（只依赖磁盘 + policy.json，不依赖原 AuditService 运行态）
# ===========================================================================

def recover(root: str | Path) -> dict[str, Any]:
    """崩溃恢复 / 最终对账。返回采取的动作清单（幂等，可重复执行）。"""
    ws = Workspace(root)
    rep: dict[str, Any] = {
        "removed_temp_archives": [],
        "removed_uncommitted_packages": [],
        "removed_uncommitted_pending": [],
        "removed_staging": [],
        "removed_stray_export_parts": [],
        "removed_stale_receipts": [],
        "rolled_forward": [],
        "reconstructed_receipts": [],
        "wrote_revocation_record": False,
        "restored_frozen_policy": False,
        "index_changed": False,
        "pointer_changed": False,
    }
    policy = ws.read_json(ws.policy_file)
    ws.ensure_layout()

    # 0) 新进程里不应再有 fd；若有遗留集合也仅本对象为空。Windows 上真正的
    #    句柄已由 simulate_crash -> reap 关闭（模拟内核回收）。

    # 1) 撤销控制面：commit 标记是权威；未转正的 *.part 临时归档一律丢弃。
    rev_markers = sorted(ws.wal_dir.glob("rev-*.commit")) if ws.wal_dir.exists() else []
    rev_marker = ws.read_json(rev_markers[0]) if rev_markers else None
    for part in ws.tmp_dir.glob("*.part"):
        part.unlink(missing_ok=True)
        rep["removed_temp_archives"].append(ws.rel(part))
    if rev_marker is not None and not ws.revocation_file.exists():
        rec = dict(rev_marker)
        rec["kind"] = "revocation"
        arc = ws.control / "rev-archive-GOLD.arc"
        rec["archive"] = ws.rel(arc) if arc.exists() else None
        ws.atomic_write_json(ws.revocation_file, rec)
        rep["wrote_revocation_record"] = True

    # 2) 导出目录里的游离 *.part 绝不能进入边界
    for part in ws.export.rglob("*.part") if ws.export.exists() else []:
        part.unlink(missing_ok=True)
        rep["removed_stray_export_parts"].append(ws.rel(part))

    commit_codes = {
        p.name[len("commit-"):-len(".json")]
        for p in ws.wal_dir.glob("commit-*.json")
    } if ws.wal_dir.exists() else set()
    denied_codes = {
        p.name[len("denial-"):-len(".json")]
        for p in ws.wal_dir.glob("denial-*.json")
    } if ws.wal_dir.exists() else set()

    # 3) 删除"无 commit 标记或被拒绝"却已晋升的包（及其页目录/回执）
    if ws.packages_dir.exists():
        for pkg_path in list(ws.packages_dir.glob("*.json")):
            code = ws.read_json(pkg_path)["code"]
            if code not in commit_codes or code in denied_codes:
                pkg_path.unlink(missing_ok=True)
                Workspace.robust_rmtree(ws.pages_dir / code)
                rp = ws.abs(receipt_rel_path(code))
                if rp.exists():
                    rp.unlink(missing_ok=True)
                rep["removed_uncommitted_packages"].append(code)

    # 4) pending：有 commit 但缺包 -> 前滚晋升；无 commit -> 未承诺，丢弃
    pdir = ws.control / "pending"
    if pdir.exists():
        for pp in list(pdir.glob("*.pending.json")):
            pending = ws.read_json(pp)
            code = pending["code"]
            pkg = ws.abs(package_rel_path(code))
            if code in commit_codes and code not in denied_codes:
                if not pkg.exists():
                    promote_committed(ws, code)
                    rep["rolled_forward"].append(code)
            else:
                rep["removed_uncommitted_pending"].append(code)
            pp.unlink(missing_ok=True)

    # 5) 清掉与实际包不匹配的陈旧回执，再补齐缺失/损坏回执
    live_codes = {
        ws.read_json(p)["code"] for p in ws.packages_dir.glob("*.json")
    } if ws.packages_dir.exists() else set()
    if ws.receipts_dir.exists():
        for rp in list(ws.receipts_dir.glob("*.receipt")):
            code = rp.name[: -len(".receipt")]
            if code not in live_codes:
                rp.unlink(missing_ok=True)
                rep["removed_stale_receipts"].append(code)
    rep["reconstructed_receipts"] = ensure_receipts(ws)

    # 6) staging 整个是草稿，恢复后不留
    if ws.staging_dir.exists():
        for child in list(ws.staging_dir.iterdir()):
            rep["removed_staging"].append(child.name)
        Workspace.robust_rmtree(ws.staging_dir)

    # 7) frozen-policy 必须在位且为规范公共视图
    fp = ws.frozen_policy_file
    want_fp = canonical_bytes(public_policy(policy))
    if not fp.exists() or fp.read_bytes() != want_fp:
        ws.atomic_write_bytes(fp, want_fp)
        rep["restored_frozen_policy"] = True

    # 8) 最小化、幂等地对账 index 与 pointer（已正确就不重写）
    index = _build_index_disk(ws, policy)
    want_index = canonical_bytes(index)
    if not ws.index_file.exists() or ws.index_file.read_bytes() != want_index:
        ws.atomic_write_bytes(ws.index_file, want_index)
        rep["index_changed"] = True
    index_sha = sha256_bytes(want_index)
    want_pointer = {
        "kind": "publish-pointer",
        "index_path": "index.json",
        "index_sha256": index_sha,
        "watermark": policy["watermark"],
        "policy_hash": policy_hash(policy),
    }
    pointer_ok = False
    if ws.pointer_file.exists():
        try:
            cur = ws.read_json(ws.pointer_file)
            pointer_ok = (
                cur.get("index_path") == "index.json"
                and cur.get("index_sha256") == index_sha
                and cur.get("watermark") == policy["watermark"]
                and cur.get("policy_hash") == policy_hash(policy)
            )
        except Exception:
            pointer_ok = False
    if not pointer_ok:
        ws.atomic_write_json(ws.pointer_file, want_pointer)
        rep["pointer_changed"] = True

    rep["published_codes"] = sorted(live_codes)
    return rep


def _build_index_disk(ws: Workspace, policy: dict[str, Any]) -> dict[str, Any]:
    # 延迟引用 reconcile.build_index，保持恢复逻辑单一来源
    from .reconcile import build_index
    return build_index(ws, policy)
