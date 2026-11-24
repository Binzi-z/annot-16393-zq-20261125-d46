"""确定性规范化编码与摘要原语。

导出、恢复、独立验证三方都使用同一套 *无状态* 规范化规则，
但验证器不会调用导出方的任何有状态代码——它只复用本文件的纯函数
（甚至可以把这几个函数直接复制走仍能独立工作）。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

CHUNK = 1 << 20  # 1 MiB 文件摘要分块


def canonical_bytes(obj: Any) -> bytes:
    """返回规范 JSON 字节：键排序、无空白、非 ASCII 原样、LF 无关。"""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_bytes(canonical_bytes(obj))


def digest_file(path: str | Path) -> str:
    """分块流式计算磁盘实际文件的 SHA-256（独立验证的关键）。"""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def page_source_digest(*, page_no: int, version: int, fields: dict,
                       sources: list[dict]) -> str:
    """逐页来源摘要：把页号、页版本、字段值与实际采用的来源证明绑定。

    任何正文字节、版本号或来源引用被改动，摘要都会变化。
    """
    payload = {
        "page_no": page_no,
        "version": version,
        "fields": fields,
        "sources": sources,
    }
    return hash_obj(payload)
