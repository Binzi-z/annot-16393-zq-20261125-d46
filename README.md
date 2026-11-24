# 撤销后的审计报告自洽检查（离线导出 + 独立验证）

仅使用 **Windows + Python 3.12 标准库**，全部数据为本地合成。一键运行：

```bat
python run_audit.py
```

它会：构造持久演示工作区 → 用**两个真实线程**重演两类屏障故障 →
**穷举 210 种短交错 ×（正常 / 故障 A / 故障 B）**并逐一恢复、独立验证 →
穷举双来源与授权版本/水位矩阵 → 用 **100 000 条**合成记录验证 **8 MiB 硬缓冲**，
最后把完整 JSON 与文本摘要写到 `artifacts/audit-report.json` / `.txt`。
任一不变量失败，进程以非 0 退出。

测试：

```bat
python -m unittest discover -s tests -v
```

独立验证器可单独拷贝到任意机器，只依赖标准库、只读磁盘：

```bat
python audit_export\verify.py artifacts\demo-committed
```

---

## 题面要求 → 实现位置

| 题面要求 | 实现 / 校验 |
| --- | --- |
| 导出以**报告代号、逐页来源摘要、冻结水位**为边界 | `audit_export/canon.py: page_source_digest`；`service.build_pending` 把 `code/watermark/每页 source_digest+sha256` 绑定进 `body_hash`/`auth_hash` |
| 允许同一字段**另有合法来源** | `model.resolve_field_sources`（`ok_dual_agree/ok_single/conflict/denied`）；`scenarios.publish_dual_source_report` 端到端导出双来源报告 |
| **旧版权限不能授权新版页** | `model.authorize` 的 `perm_version >= page_version`；`enumerate.authorization_matrix` 全组合穷举；`scenarios.record_old_permission_new_page_denial` |
| 一条授权被**补记撤销**，历史报告仍可复核 | 撤销承诺标记 `control/wal/rev-REV-GOLD.commit` 带单调 `rev_seq`；祖父条款 `commit_seq < rev_seq 且 commit_seq <= watermark`；两份历史报告固定 seq=1,2 |
| **未承诺报告不泄露撤销来源引用** | 撤销来源面包屑 `REVOCATION_SOURCE_REF` 只允许存在于控制面；验证器对整个 `export/` 树做**原始字节零出现扫描**，并做"实际文件集合 == 期望集合"，任何草稿/`*.part`/额外包都判违规 |
| **两个线程**同时推进撤销和打包 | `audit_export/concurrency.py`：`threading.Barrier(2)` 同时起步 + Condition 静止屏障，R/P 两个 OS 线程 |
| 故障 A：**撤销已承诺但临时归档未关** | `r1_commit_revocation`（WAL 承诺）→ `r2_archive_open`（裸 fd 写 `control/tmp/rev-archive-GOLD.part` 且不关闭）→ 屏障；`Workspace.reap_handles_like_kill` 模拟内核回收句柄 |
| 故障 B：**原子晋升后回执不见了** | `p3_promote`/`p4_publish` 用同目录临时文件 + `os.replace` 原子晋升包/索引/指针，屏障设在 `p4_publish` 之后、`p5_receipt` 之前 |
| 屏障重演 + **穷举短交错** | `enumerate.all_merges` 生成保序交错共 `C(10,4)=210`；`exhaustive_interleavings` 对 clean/A/B 各 210 个逐一演完→恢复→独立验证 |
| **双来源**穷举 | `enumerate.dual_source_matrix`：16 种单来源状态 + 256 个有序双来源状态 |
| 恢复后**实际文件、索引、发布指针一致** | `service.recover`（只凭磁盘，幂等前滚/清理/重建回执/对账 index+pointer）+ `verify.verify_root`（重算全部摘要并比对文件集合与指针） |
| 十万条记录验证 **8 MiB 硬缓冲** | `audit_export/scale.py` + `buffers.BufferPool`（聚合硬顶，超额即 `HardBufferLimitError`） |
| 分别记入**输入 / 待提交页 / 索引队列 / 失败后尚持有**缓冲 | `BufferPool` 三分类峰值/当前值；`mark_failure_retained` 登记失败瞬间四类口径，`recover_failed_buffers` 如数释放并验证归零 |
| 报告**全量与局部更新记录数** | 全量 `100000`；局部 `1250`（500 条改版本 + 750 条新增） |

## 目录与磁盘布局

```
<workspace>/
  policy.json                     # 信任锚：watermark、权限版本、合法来源、禁用面包屑
  control/
    wal/rev-REV-GOLD.commit       # 撤销的持久承诺（权威）
    wal/commit-<CODE>.json        # 每份已承诺报告的授权
    wal/denial-<CODE>.json        # 被拒（旧权限/撤销后）记录
    tmp/rev-archive-GOLD.part     # 故障 A 的未转正临时归档（恢复时删除）
    pending/<CODE>.pending.json   # 待提交页集（崩溃前滚依据）
    rev-archive-GOLD.arc          # 正常关闭并 os.replace 后的归档
    revocation.json
  cache/sources/SRC-*.json        # 本地合成来源缓存
  staging/<CODE>-tok/draft.json   # 可能沾上面包屑的草稿，绝不晋升，恢复必删
  export/                         # ★ 离线导出边界（独立验证只依赖这里 + 信任锚/WAL）
    frozen-policy.json
    index.json
    publish-pointer.json
    packages/<CODE>.json
    pages/<CODE>/p<n>.json
    receipts/<CODE>.receipt
```

## 一致性与安全不变量（验证器逐条强制）

1. `publish-pointer.json.index_sha256 == sha256(实际 index.json 字节)`，且与规范化重哈希一致。
2. 每个 index 条目的 `package_sha256`、每页 `sha256` 都等于磁盘实际文件；`source_digest` 可由页号/版本/字段/来源证明重算。
3. 实际 `export/` 文件集合 **恰好等于** 索引+包+回执推导出的期望集合：多一个未承诺文件、少一个回执都失败。
4. `max(page_version) <= grant_snapshot.perm_version`；水位 `commit_seq <= W`；命中被撤销授权时必须 `commit_seq < rev_seq`。
5. 每份已发布包都有逐字节一致的 `control/wal/commit-<CODE>.json`。
6. 撤销来源面包屑与临时归档标记在所有 `export/` 文件中**零字节出现**。

> 说明：这里的 SHA-256 链提供防篡改自洽性，不是数字签名；题面限定标准库与本地合成，
> 信任锚 `policy.json` 假定由审计终端本地保护。验证器刻意不 import 导出/恢复的判断代码，
> 只复用同一套规范化 JSON 线格式并重算，以满足“独立验证”。
