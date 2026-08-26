"""Call-site counting in `tools/quality_census.py`.

The census compares our rendered C against Ghidra's, so a call spelling only one
of the two renderers uses scores as a difference that is not there. Both of these
are one call:

    (**(code **)(*param_1 + 0x40))()      Ghidra, through a function-pointer field
    (0x700016cc & 0xfffffffffffffffe)()   ours, through a folded constant

Counting identifiers alone saw neither, which scored `changeGroupID` as a spurious
call; recognising only the dereference form then scored `vm_boot` and `preamble` as
a lost one each.
"""

import unittest

from tools import quality_census


class IndirectCallCount(unittest.TestCase):
    def test_a_call_through_a_dereferenced_pointer_counts(self) -> None:
        body = "  (**(code **)(*param_1 + 0x40))();\n"
        self.assertEqual(quality_census.indirect_call_count(body), 1)

    def test_a_call_through_a_folded_constant_counts(self) -> None:
        body = "  (0x700016cc & 0xfffffffffffffffe)();\n"
        self.assertEqual(quality_census.indirect_call_count(body), 1)

    def test_a_cast_is_not_a_call(self) -> None:
        body = "  x = (uint8_t)(y + 1);\n  z = (int)(w);\n"
        self.assertEqual(quality_census.indirect_call_count(body), 0)

    def test_a_conditional_is_not_a_call(self) -> None:
        body = "  if ((a & 1) && (b | 2)) {\n  }\n"
        self.assertEqual(quality_census.indirect_call_count(body), 0)

    def test_both_renderings_of_one_call_agree(self) -> None:
        theirs = "void f(void)\n{\n  setCopReg(0, 1);\n  (*(code *)&DAT_700016cc)();\n}\n"
        ours = (
            "void f(void)\n{\n  setCopReg(0, 1);\n"
            "  (0x700016cc & 0xfffffffffffffffe)();\n}\n"
        )
        self.assertEqual(
            quality_census.call_site_count(theirs),
            quality_census.call_site_count(ours),
        )
        self.assertEqual(quality_census.call_site_count(ours), 2)


if __name__ == "__main__":
    unittest.main()
