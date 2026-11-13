import unittest

import sslyze_inventory


class EnvironmentTest(unittest.TestCase):
    def test_environment_reads_trust_store_hashes(self):
        info = sslyze_inventory.environment()
        self.assertTrue(info)


if __name__ == "__main__":
    unittest.main()
