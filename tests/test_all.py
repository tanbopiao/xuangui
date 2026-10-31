# -*- coding: utf-8 -*-
"""xuangui 全量用例：核心层 + 协议层 + 红队探针。零第三方依赖，直接 python3 -m unittest 运行。"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from trustgate_core import (DIRECT, INFERENCE, make_receipt, run_probes,
                            verify_receipt)

KEY = bytes.fromhex("11" * 32)
ANCHOR = "anchor-2026-11-01"


def rpc(req: dict) -> dict | None:
    from server import handle_request
    return handle_request(req)


class CoreTests(unittest.TestCase):
    def test_01_roundtrip_accepted(self):
        r = make_receipt({"a": 1}, KEY)
        self.assertEqual(verify_receipt(r, KEY)["verdict"], "ACCEPTED")

    def test_02_tamper_rejected(self):
        r = make_receipt({"a": 1}, KEY)
        r["payload"]["a"] = 2
        self.assertEqual(verify_receipt(r, KEY)["verdict"], "REJECTED")

    def test_03_wrong_key_rejected(self):
        r = make_receipt({"a": 1}, KEY)
        self.assertEqual(verify_receipt(r, bytes.fromhex("22" * 32))["verdict"], "REJECTED")

    def test_04_base64_mac_rejected(self):
        import base64
        r = make_receipt({"a": 1}, KEY)
        r["mac"] = base64.b64encode(r["mac"].encode()).decode()
        self.assertEqual(verify_receipt(r, KEY)["verdict"], "REJECTED")

    def test_05_double_base64_payload_rejected(self):
        import base64
        from trustgate_core import _canonical
        r = make_receipt({"a": 1}, KEY)
        r["payload"] = base64.b64encode(base64.b64encode(_canonical(r["payload"])).decode().encode()).decode()
        self.assertEqual(verify_receipt(r, KEY)["verdict"], "REJECTED")

    def test_06_nested_receipt_rejected(self):
        outer = make_receipt({"a": 1}, KEY)
        nested = {"payload": {"receipt": outer}, "ts": outer["ts"], "mac": outer["mac"]}
        self.assertEqual(verify_receipt(nested, KEY)["verdict"], "REJECTED")

    def test_07_anchor_mismatch_rejected(self):
        r = make_receipt({"a": 1}, KEY, anchor="A")
        self.assertEqual(verify_receipt(r, KEY, expected_anchor="B")["verdict"], "REJECTED")

    def test_08_anchor_match_accepted(self):
        r = make_receipt({"a": 1}, KEY, anchor=ANCHOR)
        res = verify_receipt(r, KEY, expected_anchor=ANCHOR)
        self.assertEqual(res["verdict"], "ACCEPTED")
        self.assertTrue(any(e["layer"] == DIRECT for e in res["evidence"]))

    def test_09_expired_rejected(self):
        old = str(int(time.time()) - 9999)
        r = make_receipt({"a": 1}, KEY, ts=old)
        self.assertEqual(
            verify_receipt(r, KEY, freshness_seconds=600)["verdict"], "REJECTED")

    def test_10_future_ts_rejected(self):
        future = str(int(time.time()) + 9999)
        r = make_receipt({"a": 1}, KEY, ts=future)
        self.assertEqual(
            verify_receipt(r, KEY, freshness_seconds=600)["verdict"], "REJECTED")

    def test_11_noncanonical_key_order_still_accepted(self):
        """键顺序不同不影响验签（规范化先行）。"""
        r = make_receipt({"a": 1, "b": {"c": 2, "d": 3}}, KEY)
        r["payload"] = {"b": {"d": 3, "c": 2}, "a": 1}  # 相同内容不同顺序
        self.assertEqual(verify_receipt(r, KEY)["verdict"], "ACCEPTED")

    def test_12_unicode_payload_stable(self):
        r = make_receipt({"名": "元极恒一", "量": 1}, KEY)
        self.assertEqual(verify_receipt(r, KEY)["verdict"], "ACCEPTED")

    def test_13_non_object_rejected(self):
        self.assertEqual(verify_receipt("伪回执", KEY)["verdict"], "REJECTED")
        self.assertEqual(verify_receipt(None, KEY)["verdict"], "REJECTED")


class ProbeTests(unittest.TestCase):
    def test_14_all_probes_pass(self):
        res = run_probes(KEY, expected_anchor=ANCHOR)
        self.assertEqual(res["passed"], res["total"],
                         f"未全绿：{[r for r in res['results'] if not r['pass']]}")
        self.assertGreaterEqual(res["total"], 6)

    def test_15_health_report_shape(self):
        from trustgate_core import health_report
        rep = health_report(KEY, expected_anchor=ANCHOR)
        self.assertTrue(rep["healthy"])
        self.assertIn("直接观察", rep["evidence_boundary"])
        self.assertIn(INFERENCE, rep["evidence_boundary"])


class ProtocolTests(unittest.TestCase):
    def test_16_initialize_handshake(self):
        resp = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(resp["result"]["serverInfo"]["name"], "xuangui")

    def test_17_tools_listed(self):
        resp = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertTrue({"xuangui_verify_receipt", "xuangui_run_probes",
                         "xuangui_health_report", "xuangui_make_receipt"} <= names)

    def test_18_make_and_verify_roundtrip_via_tools(self):
        made = rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "xuangui_make_receipt",
            "arguments": {"payload": {"k": "v"}, "anchor": ANCHOR}}})
        receipt = json.loads(made["result"]["content"][0]["text"])
        self.assertEqual(receipt["anchor"], ANCHOR)

    def test_19_unknown_tool_error(self):
        resp = rpc({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": {"name": "nope"}})
        self.assertEqual(resp["error"]["code"], -32602)

    def test_20_unknown_method_error(self):
        resp = rpc({"jsonrpc": "2.0", "id": 5, "method": "no/method"})
        self.assertEqual(resp["error"]["code"], -32601)

    def test_21_notification_silent(self):
        self.assertIsNone(rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_22_stdio_end_to_end(self):
        """真子进程：初始化→列工具→探针调用，全程 stdio。"""
        init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        listed = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        probes = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                             "params": {"name": "xuangui_run_probes", "arguments": {}}})
        script = f"import sys; sys.path.insert(0, {os.path.dirname(os.path.abspath(__file__))!r}); from server import serve; serve()"
        proc = subprocess.run([sys.executable, "-c", script],
                              input="\n".join([init, listed, probes]) + "\n",
                              capture_output=True, text=True, timeout=30)
        lines = [json.loads(l) for l in proc.stdout.strip().splitlines()]
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0]["result"]["serverInfo"]["name"], "xuangui")
        probe_result = json.loads(lines[2]["result"]["content"][0]["text"])
        self.assertEqual(probe_result["passed"], probe_result["total"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
