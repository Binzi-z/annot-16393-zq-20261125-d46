"""独立离线验证器（**不依赖** service/model/reconcile 的任何判断）。

本文件刻意自包含哈希/规范化原语，只相信从磁盘重新读到的字节，因此可以把
这一个文件单独拷贝到任意装有 Python 3.12 标准库的 Windows 机器上，对一个
工作区根目录执行::

    python verify.py <workspace-root>

它校验五件事必须同时成立：

1. 发布指针 ``publish-pointer.json`` 承诺的 index 摘要 == index.json 实际字节；
2. index 中每个包/每页的摘要 == 磁盘实际文件，且逐页来源摘要可重算；
3. 实际 export/ 文件集合 == 索引/回执推导出的期望集合（无未承诺孤儿、
   无 ``*.part``、无草稿、无额外引用）；
4. 授权版本 >= 页版本，且撤销授权只通过 "水位内 + 先于撤销承诺" 的祖父条款；
5. 撤销来源的面包屑引用在整个 export/ 树中 *零字节出现*（不泄漏）。
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# ---- 自包含原语（必须与 audit_export/canon.py 的线格式一致） -------------

_MIB = 1 << 20


def _canon(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _h(obj: Any) -> str:
    return hashlib.sha256(_canon(obj)).hexdigest()


def _file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(_MIB)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _page_digest(*, page_no: int, version: int, fields: dict,
                 sources: list) -> str:
    return _h({
        "page_no": page_no, "version": version,
        "fields": fields, "sources": sources,
    })


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


RECEIPT_KIND = "export-receipt"


def verify_root(root: str | Path) -> dict[str, Any]:
    root = Path(root)
    v: list[str] = []          # 违规项
    notes: list[str] = []
    stats: dict[str, Any] = {
        "codes": 0, "pages": 0, "files_in_export": 0,
        "grandfathered": [], "active": [],
    }

    def fail(msg: str) -> None:
        v.append(msg)

    # ---------------------------------------------------------------- policy
    policy_file = root / "policy.json"
    policy: dict[str, Any] | None = None
    forbidden_ref: str | None = None
    watermark: int | None = None
    if policy_file.exists():
        policy = _load_json(policy_file)
        watermark = policy.get("watermark")
        forbidden_ref = policy.get("forbidden_revocation_ref")
    else:
        fail("policy.json missing (trust anchor)")

    export = root / "export"
    if not export.is_dir():
        fail("export/ directory missing")
        return {"ok": False, "violations": v, "notes": notes, "stats": stats}

    # 撤销台账（权威是 WAL commit 标记）
    revoked_grant: str | None = None
    rev_seq: int | None = None
    wal = root / "control" / "wal"
    rev_markers = sorted(wal.glob("rev-*.commit")) if wal.exists() else []
    if rev_markers:
        try:
            rm = _load_json(rev_markers[0])
            revoked_grant = rm.get("grant_id")
            rev_seq = int(rm["rev_seq"])
            if len(rev_markers) > 1:
                fail(f"multiple revocation commit markers: {len(rev_markers)}")
        except Exception as exc:  # noqa: BLE001
            fail(f"cannot parse revocation marker: {exc}")

    # --------------------------------------------------------- frozen policy
    fp_file = export / "frozen-policy.json"
    policy_hash: str | None = None
    if not fp_file.exists():
        fail("export/frozen-policy.json missing")
    elif policy is not None:
        fp = _load_json(fp_file)
        public = {k: val for k, val in policy.items()
                  if k != "forbidden_revocation_ref"}
        if fp != public:
            fail("frozen-policy.json != redacted public policy view")
        policy_hash = _h(public)
        if _file_sha(fp_file) != _h(fp):
            fail("frozen-policy.json is not canonical bytes")

    # ---------------------------------------------------------------- pointer
    pointer_file = export / "publish-pointer.json"
    index_file = export / "index.json"
    pointer: dict[str, Any] | None = None
    index: dict[str, Any] | None = None
    index_sha: str | None = None

    if not pointer_file.exists():
        fail("publish-pointer.json missing")
    else:
        pointer = _load_json(pointer_file)
        if pointer.get("kind") != "publish-pointer":
            fail("pointer kind mismatch")
        if pointer.get("index_path") != "index.json":
            fail(f"pointer index_path unsafe/unexpected: "
                 f"{pointer.get('index_path')!r}")
        if not index_file.exists():
            fail("index.json missing (pointed-to file absent)")
        else:
            index_sha = _file_sha(index_file)
            if pointer.get("index_sha256") != index_sha:
                fail("pointer.index_sha256 does not match actual index.json bytes")
            index = _load_json(index_file)
            if _h(index) != pointer.get("index_sha256"):
                fail("pointer index hash != canonical re-hash of parsed index")
            if index is not None:
                if index.get("kind") != "audit-index":
                    fail("index kind mismatch")
                if watermark is not None and index.get("watermark") != watermark:
                    fail("index watermark != policy watermark")
                if policy_hash and index.get("policy_hash") != policy_hash:
                    fail("index policy_hash mismatch")
            if watermark is not None and pointer.get("watermark") != watermark:
                fail("pointer watermark != policy watermark")
            if policy_hash and pointer.get("policy_hash") != policy_hash:
                fail("pointer policy_hash mismatch")

    # ------------------------------------------------------------------ index
    entries: list[dict[str, Any]] = []
    if index is not None:
        entries = index.get("entries", [])
        codes = [e.get("code") for e in entries]
        if codes != sorted(codes):
            fail("index entries not sorted by code")
        if len(codes) != len(set(codes)):
            fail("index has duplicate codes")
        stats["codes"] = len(codes)

    expected_export_files = {
        "index.json", "publish-pointer.json", "frozen-policy.json",
    }

    for e in entries:
        code = e.get("code", "<unknown>")
        pkg_rel = e.get("package_path", f"packages/{code}.json")

        # 路径安全：不得越界
        if ".." in Path(pkg_rel).parts or pkg_rel.startswith(("/", "\\")):
            fail(f"[{code}] unsafe package path {pkg_rel!r}")
            continue

        pkg_path = export / pkg_rel
        expected_export_files.add(pkg_rel.replace("\\", "/"))
        if not pkg_path.exists():
            fail(f"[{code}] package file missing: {pkg_rel}")
            continue

        actual_pkg_sha = _file_sha(pkg_path)
        if e.get("package_sha256") != actual_pkg_sha:
            fail(f"[{code}] index package_sha256 != actual package bytes")

        pkg = _load_json(pkg_path)
        if pkg.get("kind") != "audit-package":
            fail(f"[{code}] package kind mismatch")
        if pkg.get("code") != code:
            fail(f"[{code}] package code mismatch: {pkg.get('code')}")
        if watermark is not None and pkg.get("watermark") != watermark:
            fail(f"[{code}] package watermark != frozen watermark")

        auth = pkg.get("auth", {})
        if _h(auth) != pkg.get("auth_hash"):
            fail(f"[{code}] auth_hash does not recompute")
        if e.get("auth_hash") != pkg.get("auth_hash"):
            fail(f"[{code}] index auth_hash != package auth_hash")
        if _h(pkg.get("body")) != pkg.get("body_hash"):
            fail(f"[{code}] body_hash does not recompute")

        # commit 标记必须在控制面真实存在且与包内授权一致
        cm = root / "control" / "wal" / f"commit-{code}.json"
        if not cm.exists():
            fail(f"[{code}] promised package lacks durable commit marker")
        else:
            cm_obj = _load_json(cm)
            if cm_obj != auth:
                fail(f"[{code}] commit marker != packaged auth")

        # ------------------------------------------------------- 授权/版本规则
        snap = auth.get("grant_snapshot", {}) or {}
        perm_ver = int(snap.get("perm_version", -1))
        page_versions = [int(p.get("version", -1))
                         for p in pkg.get("body", {}).get("pages", [])]
        max_pv = max(page_versions, default=-1)
        stats["pages"] += len(page_versions)
        if max_pv > perm_ver:
            fail(f"[{code}] OLD PERMISSION v{perm_ver} AUTHORIZES NEW PAGE "
                 f"v{max_pv}")
        if watermark is not None and int(auth.get("commit_seq", 1 << 60)) > watermark:
            fail(f"[{code}] commit_seq {auth.get('commit_seq')} beyond frozen "
                 f"watermark {watermark}")

        grant_id = auth.get("grant_id")
        if revoked_grant and grant_id == revoked_grant:
            cseq = int(auth.get("commit_seq", -1))
            if rev_seq is None:
                fail(f"[{code}] revoked grant present but rev_seq unknown")
            elif not (cseq < rev_seq):
                fail(f"[{code}] REVOKED GRANT AUTHORIZES POST-REVOCATION "
                     f"commit cseq={cseq} >= rev_seq={rev_seq}")
            else:
                stats["grandfathered"].append(code)
                notes.append(
                    f"{code}: historical/grandfathered "
                    f"(commit_seq={cseq} < rev_seq={rev_seq} <= W={watermark})")
        else:
            stats["active"].append(code)

        # ------------------------------------------------------------ 逐页核对
        index_pages = e.get("pages", [])
        body_pages = pkg.get("body", {}).get("pages", [])
        if index_pages != body_pages:
            fail(f"[{code}] index page commitments != package body pages")

        for pc in body_pages:
            prel = pc.get("path", "")
            if ".." in Path(prel).parts:
                fail(f"[{code}] unsafe page path {prel!r}")
                continue
            page_path = export / prel
            expected_export_files.add(prel.replace("\\", "/"))
            if not page_path.exists():
                fail(f"[{code}] page missing: {prel}")
                continue
            if _file_sha(page_path) != pc.get("sha256"):
                fail(f"[{code}] page sha256 mismatch on disk: {prel}")
            page = _load_json(page_path)
            sd = _page_digest(
                page_no=page.get("page_no"), version=page.get("version"),
                fields=page.get("fields"), sources=page.get("sources"),
            )
            if sd != page.get("source_digest"):
                fail(f"[{code}] page source_digest does not recompute: {prel}")
            if sd != pc.get("source_digest"):
                fail(f"[{code}] commitment source_digest mismatch: {prel}")
            if _h(page) == pc.get("sha256"):
                # 规范化重哈希与文件摘要一致（文件即 canonical 字节）
                pass
            elif _file_sha(page_path) == _h(page):
                pass
            else:
                fail(f"[{code}] page bytes are not canonical: {prel}")

        # --------------------------------------------------------------- 回执
        rcpt_rel = f"receipts/{code}.receipt"
        rcpt_path = export / rcpt_rel
        expected_export_files.add(rcpt_rel)
        if not rcpt_path.exists():
            fail(f"[{code}] receipt missing after promotion")
        else:
            rcpt = _load_json(rcpt_path)
            expected_rcpt = {
                "kind": RECEIPT_KIND,
                "code": code,
                "commit_seq": auth.get("commit_seq"),
                "auth_hash": pkg.get("auth_hash"),
                "package_sha256": actual_pkg_sha,
                "acknowledged": True,
            }
            if rcpt != expected_rcpt:
                fail(f"[{code}] receipt does not match promoted package/auth")

    # --------------------------------------------- 实际文件集合 == 期望集合
    actual_files: set[str] = set()
    for p in export.rglob("*"):
        if p.is_file():
            rel = p.relative_to(export).as_posix()
            actual_files.add(rel)
    stats["files_in_export"] = len(actual_files)

    extra = sorted(actual_files - expected_export_files)
    missing = sorted(expected_export_files - actual_files)
    for x in extra:
        fail(f"UNEXPECTED/UNCOMMITTED FILE IN EXPORT BOUNDARY: {x}")
    for x in missing:
        fail(f"EXPECTED FILE MISSING: {x}")

    # 任何 *.part / 临时 / 草稿路径都不得存在于 export
    for rel in actual_files:
        base = rel.rsplit("/", 1)[-1]
        if base.endswith(".part") or ".part." in base:
            fail(f"temporary .part file survives in export: {rel}")
        if "staging" in rel or rel.endswith(".tmp"):
            fail(f"staging/temp artifact in export: {rel}")

    # --------------------------------------------- 撤销来源面包屑零泄漏扫描
    leak_hits: list[str] = []
    needles: list[bytes] = []
    if forbidden_ref:
        needles.append(forbidden_ref.encode("utf-8"))
    needles += [b"rev-archive-GOLD", b"REVOCATION-EVIDENCE"]
    for rel in sorted(actual_files):
        data = (export / rel).read_bytes()
        for needle in needles:
            if needle and needle in data:
                leak_hits.append(f"{rel} contains {needle[:24]!r}")
    if leak_hits:
        for hit in leak_hits:
            fail("REVOCATION-SOURCE LEAK: " + hit)
    stats["leak_scan_clean"] = not leak_hits

    ok = not v
    return {
        "ok": ok,
        "violations": v,
        "notes": notes,
        "stats": stats,
        "pointer_index_sha256": index_sha,
        "policy_hash": policy_hash,
        "revoked_grant": revoked_grant,
        "rev_seq": rev_seq,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python verify.py <workspace-root>", file=sys.stderr)
        return 2
    report = verify_root(argv[1])
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["ok"]:
        s = report["stats"]
        print(
            f"\nVERIFIED OK: {s['codes']} packages, {s['pages']} pages, "
            f"{s['files_in_export']} export files, "
            f"{len(s['grandfathered'])} grandfathered; leak scan clean.",
            file=sys.stderr,
        )
        return 0
    print(f"\nVERIFY FAILED with {len(report['violations'])} violation(s):",
          file=sys.stderr)
    for x in report["violations"]:
        print("  - " + x, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
