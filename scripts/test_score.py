#!/usr/bin/env python3
"""Regression tests for scoring public trace shapes without rebuilding guests."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import score


class TraceShapeTests(unittest.TestCase):
    def score_shapes(self, shapes):
        summary = {"failures": [], "distinct_padded_cycles": [24],
                   "distinct_padded_counts": shapes, "distinct_witness_log_size": [8]}
        runs = [(0, [{"failures": []}]),
                (0, [{"cycles": 10}, {"cycles": 11}, summary])]
        output = io.StringIO()
        argv = ["score.py", str(score.ROOT / "evm/bytecode/bytecode.hex"), "--hidden-seeds"]
        with patch("sys.argv", argv), patch.object(score, "run_json_lines", side_effect=runs), \
                patch.object(score, "build_guest"), contextlib.redirect_stdout(output):
            code = score.main()
        return code, json.loads(output.getvalue())

    def test_equal_totals_do_not_hide_different_public_table_sizes(self):
        code, result = self.score_shapes([[8, 16], [16, 8]])
        self.assertEqual(code, 1)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["padded_cycles"], [24])
        self.assertEqual(result["padded_counts"], [[8, 16], [16, 8]])

    def test_one_public_table_shape_passes(self):
        code, result = self.score_shapes([[8, 16]])
        self.assertEqual(code, 0)
        self.assertTrue(result["accepted"])


if __name__ == "__main__":
    unittest.main()
