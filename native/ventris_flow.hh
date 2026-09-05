#ifndef VENTRIS_FLOW_HH
#define VENTRIS_FLOW_HH

#include "sleigh.hh"

namespace ghidra {

// SleighInstructionPrototype.walkTemplates/flowListToFlowType/convertFlowFlags
// (Ghidra 12.1.3, Apache-2.0). Capture templates during normal p-code
// generation: resolved p-code alone loses J_START/J_NEXT and intra-instruction
// labels.
struct InstructionFlow {
  enum {
    RETURN = 0x01,
    CALL_INDIRECT = 0x02,
    BRANCH_INDIRECT = 0x04,
    CALL = 0x08,
    JUMPOUT = 0x10,
    NO_FALLTHRU = 0x20,
    BRANCH_TO_END = 0x40,
    LABEL = 0x100
  };
  struct Type {
    const char *kind;
    bool fallthrough;
    bool terminal;
    bool conditional;
  };
  int4 flags = 0;
  vector<Address> targets;
  vector<int4> delaySlots;

  void clear() {
    flags = 0;
    targets.clear();
    delaySlots.clear();
  }

  void note(int4 value) { flags = (flags & ~(NO_FALLTHRU | LABEL)) | value; }

  void record(OpTpl *op, const ParserWalker &walker) {
    int4 value;
    switch (op->getOpcode()) {
    case CPUI_BRANCHIND:
      value = BRANCH_INDIRECT | NO_FALLTHRU;
      break;
    case CPUI_BRANCH: {
      auto type = op->getIn(0)->getOffset().getType();
      if (type == ConstTpl::j_next)
        value = BRANCH_TO_END;
      else if (type == ConstTpl::j_start || type == ConstTpl::j_relative)
        value = NO_FALLTHRU;
      else
        value = JUMPOUT | NO_FALLTHRU;
      break;
    }
    case CPUI_CBRANCH: {
      auto type = op->getIn(0)->getOffset().getType();
      if (type == ConstTpl::j_next)
        value = BRANCH_TO_END;
      else if (type == ConstTpl::j_start || type == ConstTpl::j_relative)
        value = 0;
      else
        value = JUMPOUT;
      break;
    }
    case CPUI_CALL:
      value = CALL;
      break;
    case CPUI_CALLIND:
      value = CALL_INDIRECT;
      break;
    case CPUI_RETURN:
      value = RETURN | NO_FALLTHRU;
      break;
    default:
      return;
    }
    note(value);
    if ((value & (JUMPOUT | CALL)) != 0) {
      const VarnodeTpl *target = op->getIn(0);
      if (!target->isDynamic(walker)) {
        AddrSpace *space = target->getSpace().fixSpace(walker);
        if (space->getType() == IPTR_PROCESSOR)
          targets.emplace_back(
              space, space->wrapOffset(target->getOffset().fix(walker)));
      }
    }
  }

  Type type() const {
    int4 value = flags;
    if ((value & LABEL) != 0)
      value |= BRANCH_TO_END;
    value &= ~LABEL;
    switch (value) {
    case 0:
    case BRANCH_TO_END:
    case NO_FALLTHRU | BRANCH_TO_END:
      return {"FALLTHROUGH", true, false, false};
    case CALL:
    case CALL | NO_FALLTHRU | BRANCH_TO_END | RETURN:
      return {"CALL", true, false, false};
    case CALL | NO_FALLTHRU | RETURN:
      return {"CALL", false, true, false};
    case CALL_INDIRECT | NO_FALLTHRU | RETURN:
      return {"CALLIND", false, true, false};
    case CALL | BRANCH_TO_END:
      return {"CALL", true, false, true};
    case CALL | NO_FALLTHRU | JUMPOUT:
    case BRANCH_INDIRECT | NO_FALLTHRU:
    case JUMPOUT | NO_FALLTHRU | BRANCH_INDIRECT:
      return {"BRANCHIND", false, false, false};
    case CALL_INDIRECT:
      return {"CALLIND", true, false, false};
    case BRANCH_INDIRECT | BRANCH_TO_END:
    case BRANCH_INDIRECT | NO_FALLTHRU | BRANCH_TO_END:
    case BRANCH_INDIRECT | JUMPOUT | NO_FALLTHRU | BRANCH_TO_END:
      return {"BRANCHIND", true, false, true};
    case CALL_INDIRECT | BRANCH_TO_END:
    case CALL_INDIRECT | NO_FALLTHRU | BRANCH_TO_END:
      return {"CALLIND", true, false, true};
    case RETURN | NO_FALLTHRU:
    case NO_FALLTHRU:
      return {"RETURN", false, true, false};
    case RETURN | BRANCH_TO_END:
    case RETURN | NO_FALLTHRU | BRANCH_TO_END:
      return {"RETURN", true, true, true};
    case JUMPOUT:
    case JUMPOUT | NO_FALLTHRU | BRANCH_TO_END:
    case BRANCH_TO_END | JUMPOUT:
      return {"CBRANCH", true, false, true};
    case JUMPOUT | NO_FALLTHRU:
      return {"BRANCH", false, false, false};
    case JUMPOUT | NO_FALLTHRU | RETURN:
      return {"BRANCH", false, true, false};
    case BRANCH_INDIRECT | NO_FALLTHRU | RETURN:
      return {"BRANCHIND", false, true, false};
    default:
      return {"BAD", false, false, false};
    }
  }
};

} // namespace ghidra
#endif
