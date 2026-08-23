import unittest

from ventris.compiler_gate import _lcs_ratio, _mnemonics


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


if __name__ == "__main__":
    unittest.main()
