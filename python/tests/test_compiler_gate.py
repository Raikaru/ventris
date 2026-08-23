import unittest

from tools.compiler_gate import _lcs_ratio, _mnemonics, _ratio_floor
from tools.corpus_smoke import ManifestFunction, SmokeError


class CompilerGateTests(unittest.TestCase):
    def test_objdump_parser_normalizes_control_flow_aliases(self):
        disassembly = """
00000000 <candidate>:
       0:       addiu   $sp, $sp, -16
       4:       move    $2, $4
       8:       beqz    $2, 0x10
       c:       jr      $ra
"""
        self.assertEqual(_mnemonics(disassembly), ["addiu", "addu", "beq", "jr"])

    def test_lcs_ratio_rewards_ordered_overlap(self):
        self.assertEqual(_lcs_ratio([], []), 1.0)
        self.assertEqual(_lcs_ratio(["jr"], []), 0.0)
        self.assertEqual(_lcs_ratio(["lw", "addu", "jr"], ["lw", "jr"]), 0.8)
    def test_function_baseline_is_the_regression_floor(self):
        function = ManifestFunction(
            name="f",
            address="0x1000",
            size=4,
            semantic=None,
            source_path="f.c",
            compiler_baseline={"minimum_mnemonic_lcs_ratio": 0.5},
        )
        self.assertEqual(_ratio_floor(function, None), 0.5)
        self.assertEqual(_ratio_floor(function, 0.4), 0.5)
        self.assertEqual(_ratio_floor(function, 0.7), 0.7)

    def test_invalid_function_baseline_is_rejected(self):
        function = ManifestFunction(
            name="f",
            address="0x1000",
            size=4,
            semantic=None,
            source_path="f.c",
            compiler_baseline={"minimum_mnemonic_lcs_ratio": 2},
        )
        with self.assertRaises(SmokeError):
            _ratio_floor(function, None)



if __name__ == "__main__":
    unittest.main()
