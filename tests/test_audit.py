"""端到端不变量测试（仅标准库 unittest）。

运行（在仓库根目录）::

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit_export.buffers import BufferPool, HardBufferLimitError  # noqa: E402
from audit_export.concurrency import run_pair  # noqa: E402
from audit_export.enumerate import (  # noqa: E402
    all_merges,
    authorization_matrix,
    dual_source_matrix,
    exhaustive_interleavings,
    execute_merge,
)
from audit_export.model import (  # noqa: E402
    Grant,
    SourceCandidate,
    authorize,
    resolve_field_sources,
)
from audit_export.scenarios import prepared  # noqa: E402
from audit_export.service import recover  # noqa: E402
from audit_export.verify import verify_root  # noqa: E402
from run_audit import persistent_demos  # noqa: E402  (确保运行器可导入)


def fresh_root() -> Path:
    return Path(tempfile.mkdtemp(prefix="audit_test_"))


class VerifiedWorkspace(unittest.TestCase):
    def setUp(self) -> None:
        self.root = fresh_root()
        self.svc = prepared(self.root)

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def assertVerified(self) -> dict:
        rec = recover(self.root)
        rep = verify_root(self.root)
        self.assertTrue(rep["ok"], msg="; ".join(rep["violations"]))
        return {"recovery": rec, "verify": rep}


class TestDomainRules(unittest.TestCase):
    def test_old_permission_cannot_authorize_new_page(self) -> None:
        g = Grant("G", perm_version=2)
        no = authorize(grant=g, code="RPT-X-1", page_version=3,
                       commit_seq=1, watermark=100)
        self.assertFalse(no["allowed"])
        self.assertEqual(no["reason"], "permission_version_too_old")
        yes = authorize(grant=Grant("G", 5), code="RPT-X-1", page_version=3,
                        commit_seq=1, watermark=100)
        self.assertTrue(yes["allowed"])

    def test_revocation_grandfather_boundary(self) -> None:
        # 撤销 rev_seq=8；水位 W=10
        def dec(cseq: int):
            return authorize(
                grant=Grant("G", 5, revoked=True, rev_seq=8),
                code="RPT-HIST-1", page_version=1,
                commit_seq=cseq, watermark=10)

        self.assertTrue(dec(7)["allowed"])       # 先于撤销承诺
        self.assertFalse(dec(8)["allowed"])      # 不严格小于
        self.assertFalse(dec(50)["allowed"])    # 越过水位
        # 先于撤销但越过水位仍拒绝（水位是硬边界）
        self.assertFalse(dec(12)["allowed"])

    def test_dual_source_witnesses(self) -> None:
        self.assertEqual(resolve_field_sources([
            SourceCandidate("A"), SourceCandidate("B")]).status,
            "ok_dual_agree")
        self.assertEqual(resolve_field_sources([
            SourceCandidate("A", revoked=True),
            SourceCandidate("B")]).status, "ok_single")
        self.assertEqual(resolve_field_sources([
            SourceCandidate("A"),
            SourceCandidate("B", agrees=False)]).status, "conflict")
        r = resolve_field_sources([
            SourceCandidate("A", legal=False),
            SourceCandidate("B", legal=False)])
        self.assertEqual(r.status, "denied")
        self.assertFalse(r.committable)

    def test_matrices(self) -> None:
        self.assertTrue(dual_source_matrix()["exhaustive_ok"])
        am = authorization_matrix()
        self.assertTrue(am["matrix_ok"], msg=am["violations"])


class TestBuffers(unittest.TestCase):
    def test_hard_limit_rejects_overcommit(self) -> None:
        pool = BufferPool()
        mib = 1 << 20
        for _ in range(8):
            pool.acquire("input", mib)
        with self.assertRaises(HardBufferLimitError):
            pool.acquire("input", 1)
        with self.assertRaises(HardBufferLimitError):
            BufferPool().acquire("pending_pages", 8 * mib + 1)

    def test_failure_retention_then_recovery_balances(self) -> None:
        from audit_export.scale import failure_drill
        pool = BufferPool()
        out = failure_drill(pool)
        self.assertTrue(out["balanced_after_recovery"])
        self.assertEqual(pool.total_live(), 0)
        self.assertGreater(out["held_at_failure"]["total_bytes"], 0)


class TestEndToEnd(VerifiedWorkspace):
    def test_seeded_historical_verifies(self) -> None:
        out = self.assertVerified()
        codes = out["verify"]["stats"]["codes"]
        self.assertEqual(codes, 2)

    def test_commit_first_is_grandfathered(self) -> None:
        schedule = [
            ("P", 0), ("P", 1),
            ("R", 0), ("R", 1), ("R", 2), ("R", 3),
            ("P", 2), ("P", 3), ("P", 4), ("P", 5),
        ]
        ex = execute_merge(self.root, schedule)
        self.assertIsNone(ex["exec_error"])
        out = self.assertVerified()
        self.assertIn("RPT-RACE-0003",
                      out["verify"]["stats"]["grandfathered"])

    def test_revoke_first_race_absent_and_clean(self) -> None:
        schedule = [
            ("R", 0), ("R", 1), ("R", 2), ("R", 3),
            ("P", 0), ("P", 1), ("P", 2), ("P", 3), ("P", 4), ("P", 5),
        ]
        execute_merge(self.root, schedule)
        out = self.assertVerified()
        stats = out["verify"]["stats"]
        allcodes = stats["grandfathered"] + stats["active"]
        self.assertNotIn("RPT-RACE-0003", allcodes)

    def test_fault_a_scripted_recovers(self) -> None:
        # 取一个把 r2 放在最后的交错前缀：直接跑一个含故障武装的完整 merge
        merge = all_merges()[0]
        ex = execute_merge(self.root, merge, fault="A")
        self.assertIsNotNone(ex["crashed"])
        self.assertEqual(ex["crashed"]["fault"], "A")
        out = self.assertVerified()
        self.assertGreaterEqual(
            len(out["recovery"]["removed_temp_archives"]), 1)

    def test_fault_b_scripted_recovers(self) -> None:
        # 显式构造"已承诺并晋升、但 p5 回执尚未写"的 B 屏障前缀：
        # p1,p2(承诺) -> p3(晋升) -> p4(索引/指针) 之后立即被 B 击中。
        merge_b = [("P", 0), ("P", 1), ("P", 2), ("P", 3)]
        ex = execute_merge(self.root, merge_b, fault="B")
        self.assertIsNotNone(ex["crashed"])
        self.assertEqual(ex["crashed"]["fault"], "B")
        out = self.assertVerified()
        self.assertGreaterEqual(
            len(out["recovery"]["reconstructed_receipts"]), 1)
        self.assertIn("RPT-RACE-0003",
                      out["verify"]["stats"]["active"]
                      + out["verify"]["stats"]["grandfathered"])

    def test_threaded_fault_a_and_b(self) -> None:
        for fault in ("A", "B"):
            root = fresh_root()
            try:
                res = run_pair(fault, root)
                self.assertTrue(res["joined_cleanly"])
                self.assertEqual(res["thread_errors"], [])
                self.assertTrue(res["verification_ok"],
                                msg="; ".join(res["violations"]))
            finally:
                shutil.rmtree(root, ignore_errors=True)


class TestVerifierTeeth(VerifiedWorkspace):
    """独立验证器必须真的能抓出各类不一致与泄漏。"""

    def _tamper_and_expect_failure(self, fn) -> None:
        recover(self.root)
        fn(self.root)
        rep = verify_root(self.root)
        self.assertFalse(rep["ok"], msg="tamper should be detected")
        self.assertTrue(rep["violations"])

    def test_detect_page_byte_tamper(self) -> None:
        def tamper(root: Path) -> None:
            p = root / "export/pages/RPT-HIST-0001/p1.json"
            with open(p, "ab") as fh:
                fh.write(b" ")
        self._tamper_and_expect_failure(tamper)

    def test_detect_extra_uncommitted_file(self) -> None:
        def tamper(root: Path) -> None:
            (root / "export/packages/evil-uncommitted.json").write_text(
                json.dumps({"kind": "audit-package", "code": "EVIL"}),
                encoding="utf-8")
        self._tamper_and_expect_failure(tamper)

    def test_detect_revocation_ref_leak(self) -> None:
        from audit_export.model import REVOCATION_SOURCE_REF

        def tamper(root: Path) -> None:
            (root / "export/LEAK.txt").write_text(
                "leftover " + REVOCATION_SOURCE_REF, encoding="utf-8")
        rep_ok_before = verify_root(self.root)["ok"]
        self.assertTrue(rep_ok_before)
        self._tamper_and_expect_failure(tamper)

    def test_detect_missing_receipt(self) -> None:
        def tamper(root: Path) -> None:
            (root / "export/receipts/RPT-HIST-0001.receipt").unlink()
        self._tamper_and_expect_failure(tamper)

    def test_detect_pointer_hash_mismatch(self) -> None:
        def tamper(root: Path) -> None:
            pp = root / "export/publish-pointer.json"
            d = json.loads(pp.read_text(encoding="utf-8"))
            d["index_sha256"] = "0" * 64
            pp.write_text(json.dumps(d), encoding="utf-8")
        self._tamper_and_expect_failure(tamper)

    def test_standalone_cli_exit_codes(self) -> None:
        recover(self.root)
        cli = ROOT / "audit_export" / "verify.py"
        good = subprocess.run(
            [sys.executable, str(cli), str(self.root)],
            capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, msg=good.stderr)

        (self.root / "export/index.json").write_bytes(b"{}")
        bad = subprocess.run(
            [sys.executable, str(cli), str(self.root)],
            capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)


class TestExhaustiveAndScale(unittest.TestCase):
    def test_merge_count_is_210(self) -> None:
        self.assertEqual(len(all_merges()), 210)

    def test_all_short_interleavings_verify(self) -> None:
        res = exhaustive_interleavings()
        self.assertTrue(res["all_verified"],
                        msg=json.dumps(res["failures"][:2], ensure_ascii=False))
        for mode in ("clean", "A", "B"):
            m = res["by_mode"][mode]
            self.assertEqual(m["verified"], m["runs"])
            self.assertEqual(m["runs"], 210)

    def test_scale_validation(self) -> None:
        from audit_export.scale import run_scale_validation
        res = run_scale_validation()
        self.assertTrue(res["ok"], msg=json.dumps(
            {k: res[k] for k in ("counts",)}, default=str))
        self.assertEqual(res["counts"]["full_records"], 100_000)
        self.assertEqual(res["counts"]["partial_update_records"], 1250)


if __name__ == "__main__":
    unittest.main(verbosity=2)
