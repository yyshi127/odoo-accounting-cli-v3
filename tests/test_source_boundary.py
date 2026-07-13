import unittest
from pathlib import Path

from tools.check_source_boundary import leaked_paths


class SourceBoundaryTest(unittest.TestCase):
    def test_v3_source_does_not_leak_into_v2_or_snapshots(self) -> None:
        workspace = Path(__file__).resolve().parents[2]
        self.assertEqual(leaked_paths(workspace), [])


if __name__ == "__main__":
    unittest.main()
