# -*- coding: utf-8 -*-
"""玄圭裁决内核用例：三裁决 / 残影剥离 / 不变量提纯 / 提纯度 / 并发基准。"""
from __future__ import annotations

import unittest

from verdict import ALLOW, DENY, ESCALATE, adjudicate, bench_adjudicate


class TestVerdict(unittest.TestCase):
    def test_clean_seed_allow_purity_full(self):
        r = adjudicate({"concept": "seed-reflow", "weight": 1})
        self.assertEqual(r["verdict"], ALLOW)
        self.assertEqual(r["residue"], [])
        self.assertEqual(r["purity"], 1.0)
        self.assertIn("topological", r["purified"])

    def test_non_structured_seed_deny(self):
        r = adjudicate([1, 2, 3])
        self.assertEqual(r["verdict"], DENY)
        self.assertEqual(r["purity"], 0.0)

    def test_hex_encoding_trick_deny(self):
        r = adjudicate({"note": "a" * 40})
        self.assertEqual(r["verdict"], DENY)
        self.assertEqual(r["residue"][0]["type"], "encoding_trick:hex")

    def test_base64_trick_deny(self):
        r = adjudicate({"blob": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd3eHl6"})
        self.assertEqual(r["verdict"], DENY)

    def test_nested_wrapper_stripped(self):
        r = adjudicate({"payload": {"wrapped": {"idea": "x"}}})
        self.assertEqual(r["verdict"], ALLOW)
        types = {res["type"] for res in r["residue"]}
        self.assertIn("nested_wrapper", types)
        self.assertGreater(r["purity"], 0.0)
        self.assertLess(r["purity"], 1.0)

    def test_key_alias_normalized(self):
        r = adjudicate({"ConCept-Name": "v"})
        self.assertIn("key_alias", {res["type"] for res in r["residue"]})
        self.assertIn("concept_name", r["purified"]["topological"])

    def test_privileged_key_escalate(self):
        r = adjudicate({"idea": "x", "token": "abc"})
        self.assertEqual(r["verdict"], ESCALATE)
        self.assertIn("token", r["evidence"]["basis"])

    def test_causal_invariants_extracted(self):
        r = adjudicate({"event": {"ts": "1700000000", "kind": "a"},
                        "later": {"ts": "1700000001", "kind": "b"}})
        self.assertEqual(len(r["purified"]["causal"]), 2)

    def test_logical_invariants_extracted(self):
        r = adjudicate({"all": True, "If": "then-x", "plain": 1})
        self.assertIn("all", r["purified"]["logical"])
        self.assertIn("if", r["purified"]["logical"])

    def test_evidence_boundary_declared(self):
        r = adjudicate({"idea": "x"})
        self.assertIn("boundary", r["evidence"])
        self.assertIn("purity_note", r["evidence"])

    def test_idempotent_same_input_same_output(self):
        seed = {"concept": "s", "note": [{"ts": "1"}]}
        import json
        self.assertEqual(json.dumps(adjudicate(seed), sort_keys=True),
                         json.dumps(adjudicate(seed), sort_keys=True))

    def test_purity_bounds(self):
        self.assertLessEqual(adjudicate({"wrapped": {"x": 1}})["purity"], 1.0)
        self.assertGreaterEqual(adjudicate({"wrapped": {"x": 1}})["purity"], 0.0)


class TestBench(unittest.TestCase):
    def test_concurrent_no_interference(self):
        seed = {"concept": "bench", "note": {"ts": "1"}}
        r = bench_adjudicate(seed, threads=8, rounds=50)
        self.assertTrue(r["consistent"], f"distinct={r['distinct_results']}")
        self.assertGreater(r["throughput"], 0)

    def test_bench_escalate_seed_consistent(self):
        r = bench_adjudicate({"token": "t"}, threads=4, rounds=20)
        self.assertTrue(r["consistent"])


if __name__ == "__main__":
    unittest.main()
