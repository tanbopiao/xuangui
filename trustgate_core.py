# -*- coding: utf-8 -*-
"""axiom-mcp 核心层：回执验签三件套（HMAC + 锚点 + 探针）。

设计原则（继承 AxiomGate）：
- 规范化先行：任何字节级花招在规范化面前无效。
- 拒绝即证据：每一次拒绝都产出结构化证据，注明证据边界（直接观察/推断）。
- 只增不覆盖：判定结果只描述当前输入，不改写历史。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

# 证据边界常量
DIRECT = "直接观察"
INFERENCE = "推断"

# 编码混淆探针：这些形式的输入一律不可信
REJECTED_ENCODINGS = ("hex", "base64", "double_base64", "nested")


def _canonical(payload: Any) -> bytes:
    """规范化序列化：键排序、不转义中文、紧凑分隔。"""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def make_receipt(payload: dict, key: bytes, anchor: str | None = None,
                 ts: str | None = None) -> dict:
    """签发回执：payload + 时间戳 + HMAC-SHA256（可选外部锚点）。"""
    body = _canonical(payload)
    ts = ts or str(int(time.time()))
    mac = hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    # 负载快照：与调用方及后续回执彻底隔离，杜绝别名污染
    snapshot = json.loads(body.decode("utf-8"))
    receipt = {"payload": snapshot, "ts": ts, "mac": mac}
    if anchor is not None:
        receipt["anchor"] = anchor
    return receipt


def _looks_like_encoding_trick(mac: str, payload: Any) -> str | None:
    """识别编码混淆变体，返回变体名或 None。"""
    if not isinstance(mac, str):
        return None
    # hex 长度异常（如 sha512 装在 sha256 字段）
    if len(mac) not in (64,) and all(c in "0123456789abcdefABCDEF" for c in mac) and len(mac) > 0:
        return "hex"
    # base64 / 双重 base64 的 mac
    if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in mac) \
            and "=" in mac:
        try:
            once = base64.b64decode(mac, validate=True)
            if all(c in "0123456789abcdefABCDEF" for c in once.decode("ascii", errors="ignore")):
                return "base64"
            base64.b64decode(once, validate=True)
            return "double_base64"
        except Exception:
            pass
    # 嵌套回执：payload 里再包一层 receipt
    if isinstance(payload, dict) and ("mac" in payload or "receipt" in payload):
        return "nested"
    return None


def verify_receipt(receipt: dict, key: bytes, expected_anchor: str | None = None,
                   freshness_seconds: int | None = None) -> dict:
    """验证回执，返回 {verdict, reasons[], evidence[]}。任何异常形状一律拒绝。"""
    reasons: list[str] = []
    evidence: list[dict] = []

    if not isinstance(receipt, dict):
        return {"verdict": "REJECTED", "reasons": ["结构非对象"], "evidence": [
            {"layer": DIRECT, "detail": f"收到类型 {type(receipt).__name__}"}]}

    payload = receipt.get("payload")
    ts = receipt.get("ts")
    mac = receipt.get("mac")

    trick = _looks_like_encoding_trick(mac, payload) if mac is not None else "nested"
    if trick:
        return {"verdict": "REJECTED",
                "reasons": [f"编码混淆变体被规范化层拒绝：{trick}"],
                "evidence": [{"layer": DIRECT, "detail": f"mac/payload 形状属于 {trick} 变体"}]}

    if not isinstance(payload, dict) or not isinstance(ts, str) or not isinstance(mac, str):
        return {"verdict": "REJECTED", "reasons": ["字段缺失或类型非法"], "evidence": [
            {"layer": DIRECT, "detail": "payload/ts/mac 必须为对象/字符串/字符串"}]}

    # 时间新鲜度（可选）
    if freshness_seconds is not None:
        try:
            age = int(time.time()) - int(ts)
            if age > freshness_seconds or age < -freshness_seconds:
                reasons.append(f"时间戳超出新鲜度窗口 {freshness_seconds}s（age={age}s）")
                evidence.append({"layer": DIRECT, "detail": f"ts={ts}"})
        except ValueError:
            reasons.append("时间戳不是数字")
            evidence.append({"layer": DIRECT, "detail": f"ts={ts!r}"})

    # HMAC 严格验签：对规范化字节重算，常数时间比较
    expected = hmac.new(key, ts.encode() + b"." + _canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        reasons.append("HMAC 验签失败")
        evidence.append({"layer": DIRECT, "detail": "重算 mac 与回执 mac 不一致"})

    # 外部锚点比对
    if expected_anchor is not None:
        got = receipt.get("anchor")
        if got != expected_anchor:
            reasons.append("外部锚点不匹配")
            evidence.append({"layer": DIRECT, "detail": "回执锚点与期望锚点不一致"})
        else:
            evidence.append({"layer": DIRECT, "detail": f"锚点一致（{expected_anchor}）"})

    verdict = "ACCEPTED" if not reasons else "REJECTED"
    if verdict == "ACCEPTED":
        evidence.append({"layer": DIRECT,
                         "detail": "规范化重算 HMAC 通过" + ("，锚点通过" if expected_anchor else "")})
        evidence.append({"layer": INFERENCE,
                         "detail": "密钥未泄露且传输未篡改的置信度较高，但非绝对证明"})
    return {"verdict": verdict, "reasons": reasons, "evidence": evidence}


def run_probes(key: bytes, expected_anchor: str | None = None) -> dict:
    """红队探针组：对自己打一遍已知攻击形状，全部拒绝才算健康。"""
    probe_payload = {"action": "grant", "subject": "probe", "amount": 1}
    good = make_receipt(probe_payload, key, anchor=expected_anchor)

    tampered = make_receipt(probe_payload, key, anchor=expected_anchor)
    tampered["payload"]["amount"] = 999  # 签发后改内容

    anchorswap = make_receipt(probe_payload, key, anchor="anchor-A")
    if expected_anchor in (None, "anchor-A"):
        anchorswap["anchor"] = "anchor-B"

    expired = make_receipt(probe_payload, key, ts=str(int(time.time()) - 10_000))

    cases = [
        ("正常回执放行", good, "ACCEPTED"),
        ("内容篡改拒绝", tampered, "REJECTED"),
        ("Base64 包装 mac 拒绝", {**good, "mac": base64.b64encode(good["mac"].encode()).decode()}, "REJECTED"),
        ("双重 Base64 payload 拒绝", {**good, "payload": base64.b64encode(base64.b64encode(
            _canonical(probe_payload)).decode().encode()).decode()}, "REJECTED"),
        ("嵌套回执拒绝", {"payload": {"receipt": good}, "ts": good["ts"], "mac": good["mac"]}, "REJECTED"),
        ("锚点调包拒绝", anchorswap, "REJECTED") if expected_anchor else None,
        ("过期时间戳拒绝", expired, "REJECTED"),
    ]
    results = []
    for case in cases:
        if case is None:
            continue
        name, rcpt, expect = case
        got = verify_receipt(rcpt, key, expected_anchor=expected_anchor, freshness_seconds=600)
        results.append({"probe": name, "expected": expect, "actual": got["verdict"],
                        "pass": got["verdict"] == expect,
                        "evidence": got["evidence"][:1]})
    return {"total": len(results), "passed": sum(1 for r in results if r["pass"]),
            "results": results}


def health_report(key: bytes, expected_anchor: str | None = None) -> dict:
    """体检报告：探针结果 + 证据边界声明。"""
    probes = run_probes(key, expected_anchor=expected_anchor)
    return {
        "service": "axiom-mcp",
        "version": "0.1.0",
        "probes_total": probes["total"],
        "probes_passed": probes["passed"],
        "healthy": probes["passed"] == probes["total"],
        "evidence_boundary": "本报告所有判定基于当次输入的直接观察与规范化重算（HMAC-SHA256）；"
                             "不包含对历史状态的断言；推荐推断仅作参考。",
    }
