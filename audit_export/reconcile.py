"""晋升 / 索引 / 发布指针 / 回执的磁盘对账逻辑。

打包线程的正式步骤与崩溃恢复 **共用** 这些函数，因此正常路径写出的
index/pointer 与恢复重建出的逐字节一致（恢复幂等、可重入）。
注意：独立验证器 ``verify.py`` 不复用这里的判断，只从磁盘重算。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canon import canonical_bytes, hash_obj, sha256_bytes
from .workspace import Workspace

KIND_INDEX = "audit-index"
KIND_POINTER = "publish-pointer"
KIND_RECEIPT = "export-receipt"
KIND_PACKAGE = "audit-package"
KIND_COMMIT = "commit-auth"


def public_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """导出边界内允许出现的策略视图：剔除撤销来源面包屑等控制面秘密引用。"""
    return {k: v for k, v in sorted(policy.items())
            if k != "forbidden_revocation_ref"}


def policy_hash(policy: dict[str, Any]) -> str:
    return hash_obj(public_policy(policy))


def page_rel_path(code: str, page_no: int) -> str:
    return f"pages/{code}/p{page_no}.json"


def package_rel_path(code: str) -> str:
    return f"packages/{code}.json"


def receipt_rel_path(code: str) -> str:
    return f"receipts/{code}.receipt"


def pending_path(ws: Workspace, code: str) -> Path:
    return ws.control / "pending" / f"{code}.pending.json"


def commit_marker_path(ws: Workspace, code: str) -> Path:
    return ws.wal_dir / f"commit-{code}.json"


def denial_marker_path(ws: Workspace, code: str) -> Path:
    return ws.wal_dir / f"denial-{code}.json"


def expected_receipt(auth: dict[str, Any], package_sha: str) -> dict[str, Any]:
    return {
        "kind": KIND_RECEIPT,
        "code": auth["code"],
        "commit_seq": auth["commit_seq"],
        "auth_hash": hash_obj(auth),
        "package_sha256": package_sha,
        "acknowledged": True,
    }


def promote_committed(ws: Workspace, code: str) -> dict[str, Any]:
    """根据持久化的 pending 页集 + commit 授权，原子晋升实际页与包。

    正常打包 P3 与崩溃恢复前滚走的是同一条代码路径。
    返回 ``{"package_sha256", "auth_hash", "page_count"}``。
    """
    pending = ws.read_json(pending_path(ws, code))
    marker_file = commit_marker_path(ws, code)
    auth = ws.read_json(marker_file)
    if auth.get("kind") != KIND_COMMIT or auth.get("code") != code:
        raise ValueError(f"bad commit marker for {code}")
    if auth["body_hash"] != pending["body_hash"]:
        raise ValueError(f"pending body_hash mismatch for {code}")
    if hash_obj(pending["body"]) != pending["body_hash"]:
        raise ValueError(f"pending body self-hash invalid for {code}")

    # 1) 实际分页文件（canonical 字节，落盘摘要 == 预计算 sha256）
    for pf in pending["page_files"]:
        rel = pf["rel_path"]
        content = pf["content"]
        data = canonical_bytes(content)
        want_sha = sha256_bytes(data)
        comm = next(p for p in pending["body"]["pages"] if p["path"] == rel)
        if comm["sha256"] != want_sha:
            raise ValueError(f"page commitment sha mismatch for {rel}")
        ws.atomic_write_bytes(ws.abs(rel), data)

    # 2) 原子晋升包文件
    package = {
        "kind": KIND_PACKAGE,
        "code": code,
        "watermark": auth["watermark"],
        "body": pending["body"],
        "body_hash": pending["body_hash"],
        "auth": auth,
        "auth_hash": hash_obj(auth),
    }
    pkg_path = ws.abs(package_rel_path(code))
    ws.atomic_write_json(pkg_path, package)
    package_sha = sha256_bytes(pkg_path.read_bytes())
    return {
        "package_sha256": package_sha,
        "auth_hash": hash_obj(auth),
        "page_count": len(pending["body"]["pages"]),
    }


def _commit_auth_map(ws: Workspace) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if not ws.wal_dir.exists():
        return out
    for mp in sorted(ws.wal_dir.glob("commit-*.json")):
        auth = ws.read_json(mp)
        out[auth["code"]] = auth
    return out


def build_index(ws: Workspace, policy: dict[str, Any]) -> dict[str, Any]:
    """从磁盘上 *实际存在* 的包 + commit 标记构造规范索引。"""
    auths = _commit_auth_map(ws)
    entries: list[dict[str, Any]] = []
    for pkg_path in sorted(ws.packages_dir.glob("*.json")):
        pkg = ws.read_json(pkg_path)
        code = pkg["code"]
        if code not in auths:
            # 对账函数不负责删除；调用方应先清理无 commit 的包。
            continue
        package_sha = sha256_bytes(pkg_path.read_bytes())
        auth = pkg["auth"]
        entries.append({
            "code": code,
            "watermark": pkg["watermark"],
            "package_path": package_rel_path(code),
            "package_sha256": package_sha,
            "auth_hash": hash_obj(auth),
            "commit_seq": auth["commit_seq"],
            "status": auth.get("decision_status"),
            "pages": pkg["body"]["pages"],
        })
    entries.sort(key=lambda e: e["code"])
    return {
        "kind": KIND_INDEX,
        "watermark": policy["watermark"],
        "policy_hash": policy_hash(policy),
        "entries": entries,
    }


def publish_index_and_pointer(
    ws: Workspace, policy: dict[str, Any], *, updated_seq: int = 0
) -> dict[str, Any]:
    """规范地写 index.json 并原子移动发布指针（指针最后更新）。"""
    index = build_index(ws, policy)
    ws.atomic_write_json(ws.index_file, index)
    index_sha = sha256_bytes(ws.index_file.read_bytes())
    pointer = {
        "kind": KIND_POINTER,
        "index_path": "index.json",
        "index_sha256": index_sha,
        "watermark": policy["watermark"],
        "policy_hash": policy_hash(policy),
        "updated_seq": updated_seq,
    }
    ws.atomic_write_json(ws.pointer_file, pointer)
    return {"index": index, "index_sha256": index_sha, "pointer": pointer}


def ensure_receipts(ws: Workspace) -> list[str]:
    """为每个实际包补齐（或校正）回执；返回被新写/重写的代号列表。"""
    rewritten: list[str] = []
    for pkg_path in sorted(ws.packages_dir.glob("*.json")):
        pkg = ws.read_json(pkg_path)
        code = pkg["code"]
        package_sha = sha256_bytes(pkg_path.read_bytes())
        receipt = expected_receipt(pkg["auth"], package_sha)
        rp = ws.abs(receipt_rel_path(code))
        want = canonical_bytes(receipt)
        if not rp.exists() or rp.read_bytes() != want:
            ws.atomic_write_bytes(rp, want)
            rewritten.append(code)
    return rewritten
