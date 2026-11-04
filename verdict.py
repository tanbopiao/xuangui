# -*- coding: utf-8 -*-
"""玄圭裁决内核：超认知第二层（网关裁决层）的裁决与提纯实现。

规格依据（208 号压缩锁档版）：
- 去纠缠过滤，剥离冗余残影，提纯拓扑、因果、逻辑不变量；
- 三裁决与玉衡治理围栏同脉：ALLOW / DENY / ESCALATE；
- 提纯度是渐近观测量（可剥离 ≠ 可完全解耦），如实标注证据边界。

设计原则（继承玄圭本体）：
- 规范化先行：任何字节级花招在规范化面前无效；
- 拒绝即证据：每一次裁决产出结构化证据；
- 只增不覆盖：裁决只描述当前输入，不改写历史。
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

ALLOW = "ALLOW"
DENY = "DENY"
ESCALATE = "ESCALATE"

# 内部保留字段：出现在种子中即视为残影或需升级
_PRIVILEGED_KEYS = ("key", "secret", "token", "credential", "password", "mac", "signature")
_LOGIC_OPS = {"and", "or", "not", "all", "any", "if", "then", "else", "implies", "forall", "exists"}


def _nfkc_key(key: str) -> str:
    """键别名规范化：NFKC 归一 + 小写 + 连字符/下划线归一。"""
    return unicodedata.normalize("NFKC", key).strip().lower().replace("-", "_")


def _walk(node: Any, depth: int = 0):
    """深度遍历，产出 (路径, 值, 深度)。"""
    if depth > 64:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            yield f"{k}", v, depth
            yield from _walk(v, depth + 1)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield f"[{i}]", v, depth + 1
            yield from _walk(v, depth + 1)


def _detect_encoding_trick(value: Any) -> str | None:
    """识别种子值中的编码混淆变体（与 trustgate_core 探针同族）。"""
    if not isinstance(value, str) or not value:
        return None
    charset = set(value)
    if all(c in "0123456789abcdefABCDEF" for c in value) and len(value) >= 32:
        return "hex"
    if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in value) \
            and len(value) >= 8 and len(value) % 4 == 0:
        import base64
        try:
            base64.b64decode(value, validate=True)
            return "base64"
        except Exception:
            pass
    return None


# 常见包装键：只有经这些键包裹的单键字典才视为嵌套包装
WRAPPER_KEYS = {"payload", "wrapped", "wrapper", "content", "data", "envelope", "seed", "body", "inner"}


def _strip_wrappers(node: Any, residue: list, depth: int = 0) -> Any:
    """剥离嵌套包装（仅经常见包装键包裹的单键字典层层展开）。"""
    if depth > 64:
        return node
    if isinstance(node, dict) and len(node) == 1:
        wrapper = next(iter(node))
        inner = next(iter(node.values()))
        if _nfkc_key(wrapper) in WRAPPER_KEYS and isinstance(inner, (dict, list)):
            residue.append({"type": "nested_wrapper", "at": wrapper, "boundary": "直接观察"})
            return _strip_wrappers(inner, residue, depth + 1)
    return node


def _extract_invariants(seed: dict) -> dict:
    """从规范化种子提取三类不变量。"""
    topological = sorted({_nfkc_key(k) for k in seed.keys()})
    causal = [v.get("ts") or v.get("time") for _, v, _d in _walk(seed)
              if isinstance(v, dict) and ("ts" in v or "time" in v)]
    logical = sorted({_nfkc_key(k) for k, v, _ in _walk(seed)
                      if isinstance(k, str) and _nfkc_key(k) in _LOGIC_OPS})
    return {"topological": topological, "causal": causal, "logical": logical}


def adjudicate(seed: dict, escalate_keys: tuple = _PRIVILEGED_KEYS) -> dict:
    """对一条认知种子执行裁决：三态判定 + 残影剥离 + 不变量提纯。

    返回结构：
        verdict   ALLOW / DENY / ESCALATE
        purified  提纯产物（拓扑/因果/逻辑不变量）
        residue   剥离的残影清单（每条注明证据边界）
        purity    提纯度 ∈ [0,1]（渐近观测量）
        evidence  裁决依据与证据边界声明
    """
    residue: list = []
    if not isinstance(seed, dict):
        return {
            "verdict": DENY,
            "purified": None,
            "residue": [{"type": "not_a_structured_seed", "boundary": "直接观察"}],
            "purity": 0.0,
            "evidence": {"basis": "种子不是结构化对象，无法提纯", "boundary": "直接观察"},
        }

    # 一、编码混淆检测（命中即 DENY——混淆即伪装，规范化面前一律不可信）
    for path, value, _ in _walk(seed):
        trick = _detect_encoding_trick(value)
        if trick:
            return {
                "verdict": DENY,
                "purified": None,
                "residue": [{"type": f"encoding_trick:{trick}", "at": path, "boundary": "直接观察"}],
                "purity": 0.0,
                "evidence": {"basis": f"检测到 {trick} 编码混淆，视为伪装", "boundary": "直接观察"},
            }

    # 二、嵌套包装剥离
    stripped = _strip_wrappers(seed, residue)

    # 三、键别名规范化与残影记录
    normalized: dict = {}
    for k, v in stripped.items():
        nk = _nfkc_key(k)
        if nk != k:
            residue.append({"type": "key_alias", "at": k, "boundary": "直接观察"})
        if isinstance(v, dict):
            v = {kk: vv for kk, vv in v.items()}
        normalized[nk] = v

    # 四、残影检测：疑似内部保留字段
    privileged_hits = [k for k in normalized if k in _PRIVILEGED_KEYS]

    # 五、不变量提纯
    purified = _extract_invariants(normalized)

    # 六、裁决
    if privileged_hits:
        verdict = ESCALATE
        basis = f"含需上级裁定字段：{','.join(sorted(privileged_hits))}（超出自治边界）"
        boundary = "直接观察"
    elif residue:
        verdict = ALLOW
        basis = f"剥离 {len(residue)} 处残影后提纯通过"
        boundary = "直接观察"
    else:
        verdict = ALLOW
        basis = "规范化后无残影，直接提纯通过"
        boundary = "直接观察"

    # 七、提纯度（渐近观测量：可剥离 ≠ 可完全解耦）
    total_units = len(normalized) + len(residue)
    purity = len(normalized) / total_units if total_units else 0.0
    purity = round(purity, 4)

    return {
        "verdict": verdict,
        "purified": purified,
        "residue": residue,
        "purity": purity,
        "evidence": {
            "basis": basis,
            "boundary": boundary,
            "purity_note": "提纯度为渐近观测量，可剥离不等于可完全解耦（208 号定义）",
        },
    }


def bench_adjudicate(seed: dict, threads: int = 8, rounds: int = 100) -> dict:
    """多线程基准：并发裁决确定性与无串扰验证。

    返回：一致率（各线程结果是否逐位一致）、吞吐（裁决/秒）、是否通过。
    """
    import time as _time
    import threading

    results: dict = {}
    lock = threading.Lock()
    start = _time.perf_counter()

    def worker(tid: int) -> None:
        local = tuple(
            json.dumps(adjudicate(seed), sort_keys=True, ensure_ascii=False) for _ in range(rounds)
        )
        with lock:
            results[tid] = local

    workers = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    elapsed = _time.perf_counter() - start

    distinct = len(set(results.values())) if results else 1
    consistent = distinct == 1
    return {
        "threads": threads,
        "rounds": rounds,
        "distinct_results": distinct,
        "consistent": consistent,
        "throughput": round(threads * rounds / elapsed, 1) if elapsed > 0 else None,
        "evidence": {"boundary": "直接观察", "note": "一致=并发裁决无串扰；吞吐为单机观测值"},
    }
