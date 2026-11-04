# -*- coding: utf-8 -*-
"""xuangui 服务器：零依赖的 MCP stdio 服务器（JSON-RPC 2.0）。

接入方式（任何支持 MCP 的智能体）：
    {"command": "python3", "args": ["<路径>/server.py"], "env": {"AXIOM_KEY": "<密钥hex>"}}

工具清单：
- xuangui_adjudicate        裁决认知种子（三态判定 + 残影剥离 + 不变量提纯）
- xuangui_bench_adjudicate  多线程裁决基准（并发一致性 + 吞吐）
- xuangui_verify_receipt    验证一条回执（HMAC + 时间新鲜度 + 外部锚点）
- xuangui_run_probes        对本服务跑红队探针组
- xuangui_health_report     生成体检报告（含证据边界声明）
- xuangui_make_receipt      签发回执（演示/测试）

密钥来源：环境变量 AXIOM_KEY（hex，32 字节=64 个十六进制字符），缺省时使用内置演示密钥并明确标注。
"""
from __future__ import annotations

import json
import os
import sys

from trustgate_core import health_report, make_receipt, run_probes, verify_receipt

from verdict import adjudicate, bench_adjudicate

SERVER_INFO = {"name": "xuangui", "version": "0.2.0"}

TOOLS = [
    {
        "name": "xuangui_adjudicate",
        "description": "裁决认知种子：三态判定（ALLOW/DENY/ESCALATE）+ 残影剥离（编码混淆/嵌套包装/键别名）+ 不变量提纯（拓扑/因果/逻辑），提纯度为渐近观测量。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "seed": {"type": "object", "description": "待裁决的认知种子（结构化对象）"},
            },
            "required": ["seed"],
        },
    },
    {
        "name": "xuangui_bench_adjudicate",
        "description": "多线程裁决基准：并发一致性（无串扰）与吞吐观测。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "seed": {"type": "object", "description": "基准种子"},
                "threads": {"type": "integer", "description": "线程数（默认 8）"},
                "rounds": {"type": "integer", "description": "每线程轮次（默认 100）"},
            },
            "required": ["seed"],
        },
    },
    {
        "name": "xuangui_verify_receipt",
        "description": "验证回执：HMAC-SHA256 严格验签 + 时间新鲜度 + 外部锚点比对，编码混淆一律拒绝。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "receipt": {"type": "object", "description": "待验证回执"},
                "anchor": {"type": "string", "description": "期望的外部锚点（可选）"},
                "freshness_seconds": {"type": "integer", "description": "新鲜度窗口秒数（可选）"},
            },
            "required": ["receipt"],
        },
    },
    {
        "name": "xuangui_run_probes",
        "description": "对本服务密钥跑红队探针组（篡改/编码混淆/嵌套/锚点调包/过期），全部拒绝才算健康。",
        "inputSchema": {
            "type": "object",
            "properties": {"anchor": {"type": "string", "description": "期望锚点（可选）"}},
        },
    },
    {
        "name": "xuangui_health_report",
        "description": "生成体检报告：探针统计 + 证据边界声明。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "xuangui_make_receipt",
        "description": "签发回执（演示/测试用）：payload + HMAC + 可选锚点。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {"type": "object", "description": "业务负载"},
                "anchor": {"type": "string", "description": "外部锚点（可选）"},
            },
            "required": ["payload"],
        },
    },
]

DEMO_KEY = bytes.fromhex("00" * 32)  # 演示密钥：仅当环境未配置 AXIOM_KEY 时使用


def get_key() -> tuple[bytes, bool]:
    raw = os.environ.get("AXIOM_KEY", "")
    if raw:
        try:
            return bytes.fromhex(raw), True
        except ValueError:
            pass
    return DEMO_KEY, False


# ---------- 工具实现 ----------

def tool_verify_receipt(args: dict) -> dict:
    key, _ = get_key()
    result = verify_receipt(
        args.get("receipt", {}),
        key,
        expected_anchor=args.get("anchor"),
        freshness_seconds=args.get("freshness_seconds"),
    )
    return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}


def tool_run_probes(args: dict) -> dict:
    key, _ = get_key()
    result = run_probes(key, expected_anchor=args.get("anchor"))
    return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}


def tool_health_report(args: dict) -> dict:
    key, using_demo = get_key()
    result = health_report(key)
    result["key_source"] = "环境变量 AXIOM_KEY" if using_demo else "内置演示密钥（请尽快配置 AXIOM_KEY）"
    return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}


def tool_adjudicate(args: dict) -> dict:
    result = adjudicate(args.get("seed", {}))
    return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}


def tool_bench_adjudicate(args: dict) -> dict:
    result = bench_adjudicate(
        args.get("seed", {}),
        threads=int(args.get("threads", 8)),
        rounds=int(args.get("rounds", 100)),
    )
    return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}


def tool_make_receipt(args: dict) -> dict:
    key, _ = get_key()
    receipt = make_receipt(args.get("payload", {}), key, anchor=args.get("anchor"))
    return {"content": [{"type": "text", "text": json.dumps(receipt, ensure_ascii=False)}]}


HANDLERS = {
    "xuangui_adjudicate": tool_adjudicate,
    "xuangui_bench_adjudicate": tool_bench_adjudicate,
    "xuangui_verify_receipt": tool_verify_receipt,
    "xuangui_run_probes": tool_run_probes,
    "xuangui_health_report": tool_health_report,
    "xuangui_make_receipt": tool_make_receipt,
}

# ---------- JSON-RPC / MCP 协议层 ----------

def handle_request(req: dict) -> dict | None:
    """处理单条 JSON-RPC 请求，返回响应（通知返回 None）。"""
    method = req.get("method")
    req_id = req.get("id")

    def reply(result=None, error=None):
        if req_id is None:
            return None
        resp = {"jsonrpc": "2.0", "id": req_id}
        if error is not None:
            resp["error"] = error
        else:
            resp["result"] = result
        return resp

    if method == "initialize":
        return reply({"protocolVersion": "2024-11-05",
                      "capabilities": {"tools": {}},
                      "serverInfo": SERVER_INFO})
    if method in ("notifications/initialized", "initialized"):
        return None  # 通知，不回复
    if method == "tools/list":
        return reply({"tools": TOOLS})
    if method == "tools/call":
        params = req.get("params", {})
        name = params.get("name")
        handler = HANDLERS.get(name)
        if handler is None:
            return reply(error={"code": -32602, "message": f"未知工具：{name}"})
        return reply({"content": handler(params.get("arguments", {}))["content"],
                      "isError": False})
    return reply(error={"code": -32601, "message": f"未知方法：{method}"})


def serve(stdin=None, stdout=None) -> int:
    """主循环：逐行读 JSON，写响应。返回处理的请求数。"""
    fin = stdin if stdin is not None else sys.stdin
    fout = stdout if stdout is not None else sys.stdout
    count = 0
    for line in fin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            fout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32700, "message": "解析失败"}},
                                  ensure_ascii=False) + "\n")
            fout.flush()
            continue
        resp = handle_request(req)
        count += 1
        if resp is not None:
            fout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            fout.flush()
    return count


if __name__ == "__main__":
    serve()
