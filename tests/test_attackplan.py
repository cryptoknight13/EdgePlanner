"""iEXAM plan stage on iEXAM's own bundled example network (no LLM). Needs the built planners."""
import shutil
import tempfile
import unittest
from pathlib import Path

import attackplan

EXAMPLE = attackplan.IEXAM / "input_data" / "test-network-simple"
PLANNERS = (attackplan.IEXAM / "Backend" / "downward" / "builds" / "release" / "bin" / "downward").exists()


@unittest.skipUnless(PLANNERS, "planners not built (iexam/scripts/fetch_planners.sh --build)")
class Plan(unittest.TestCase):
    def test_simple_network(self):
        with tempfile.TemporaryDirectory() as t:
            run_dir = Path(t) / "20260101T000000Z"
            shutil.copytree(EXAMPLE, run_dir / "iexam")
            result = attackplan.run(run_dir, k=2, targets=["Admin Server"], explain=False)
        g = result["attack_graph"]
        self.assertEqual(len(g["nodes"]), 7)
        self.assertEqual(len(g["attack_edges"]), 7)  # one CVE on each edge target
        t = result["targets"][0]
        self.assertNotIn("error", t)
        # Two attack paths reach the Admin Server; the shortest (via Mail -> FTP) has 4 steps.
        self.assertEqual(t["optimal"]["step_count"], 4)
        self.assertEqual(t["optimal"]["highlights"]["goal_node_id"], "n6")
        self.assertEqual(t["topk"]["k_returned"], 2)


if __name__ == "__main__":
    unittest.main()
