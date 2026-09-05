// Ventris linkage evidence over SLEIGH p-code, not instruction encodings.
// Register-use rules follow Ghidra CreateThunkFunctionCmd (Apache-2.0).
#ifndef VENTRIS_LINKAGE_HH
#define VENTRIS_LINKAGE_HH
#include "ifacedecomp.hh"
#include <array>

namespace ghidra {

class VentrisLinkageEmit : public PcodeEmit {
  enum Kind { Unknown, Constant, Slot };
  struct Value {
    Kind kind;
    uintb value;
  };
  struct Cell {
    VarnodeData var;
    Value value;
    bool used;
  };
  Architecture &arch;
  std::array<Cell, 64> cells;
  size_t count;

  bool memory(AddrSpace *space) const {
    return space == arch.getDefaultCodeSpace() ||
           space == arch.getDefaultDataSpace();
  }
  static uintb mask(uint4 size) {
    return size == sizeof(uintb) ? ~uintb(0) : (uintb(1) << (size * 8)) - 1;
  }
  Value get(const VarnodeData &var, bool consume) {
    if (var.size == 0 || var.size > sizeof(uintb)) {
      bad = true;
      return {Unknown, 0};
    }
    if (var.space->getType() == IPTR_CONSTANT)
      return {Constant, var.offset};
    if (memory(var.space))
      return {Slot, var.offset};
    for (size_t i = 0; i < count; ++i) {
      if (cells[i].var == var) {
        if (consume)
          cells[i].used = true;
        return cells[i].value;
      }
    }
    bad = true;
    return {Unknown, 0};
  }
  void put(const VarnodeData &var, Value value) {
    if (var.size == 0 || var.size > sizeof(uintb) || memory(var.space) ||
        var.space->getType() == IPTR_CONSTANT) {
      bad = true;
      return;
    }
    if (value.kind == Constant)
      value.value &= mask(var.size);
    for (size_t i = 0; i < count; ++i) {
      Cell &cell = cells[i];
      if (cell.var == var) {
        cell.value = value;
        cell.used = false;
        return;
      }
      if (cell.var.space == var.space &&
          (cell.var.offset <= var.offset
               ? var.offset - cell.var.offset < cell.var.size
               : cell.var.offset - var.offset < var.size)) {
        // Partial register aliases need an explicit value merge; never retain
        // stale bits.
        bad = true;
        return;
      }
    }
    if (count == cells.size()) {
      bad = true;
      return;
    }
    cells[count++] = {var, value, false};
  }

public:
  bool bad, terminal;
  size_t operations;
  uintb slot;
  explicit VentrisLinkageEmit(Architecture &conf)
      : arch(conf), count(0), bad(false), terminal(false), operations(0),
        slot(0) {}

  void beginInstruction(void) {
    operations = 0;
    for (size_t i = 0; i < count;) {
      if (cells[i].var.space->getType() == IPTR_INTERNAL)
        cells[i] = cells[--count];
      else
        ++i;
    }
  }
  bool complete(bool table) const {
    if (bad || !terminal)
      return false;
    for (size_t i = 0; !table && i < count; ++i) {
      if (cells[i].var.space->getType() != IPTR_INTERNAL &&
          cells[i].var.size > 1 && !cells[i].used)
        return false;
    }
    return true;
  }
  virtual void dump(const Address &, OpCode opcode, VarnodeData *out,
                    VarnodeData *vars, int4 size) {
    ++operations;
    if (bad)
      return;
    if (terminal || operations > 128) {
      bad = true;
      return;
    }
    if (opcode == CPUI_COPY && out != (VarnodeData *)0 && size == 1 &&
        *out == vars[0])
      return;
    if (opcode == CPUI_BRANCHIND && size == 1) {
      Value target = get(vars[0], true);
      if (target.kind != Slot)
        bad = true;
      else {
        terminal = true;
        slot = target.value;
      }
      return;
    }
    if (out == (VarnodeData *)0 || out->size == 0 ||
        out->size > sizeof(uintb)) {
      bad = true;
      return; // Includes stores, calls, returns and other control flow.
    }
    if (opcode == CPUI_LOAD && size == 2) {
      AddrSpace *space = vars[0].getSpaceFromConst();
      Value address = get(vars[1], out->size >= vars[1].size);
      if (!memory(space) || address.kind != Constant ||
          space->getWordSize() == 0 ||
          address.value > ~uintb(0) / space->getWordSize()) {
        bad = true;
        return;
      }
      put(*out, {Slot, AddrSpace::addressToByte(address.value,
                                                space->getWordSize())});
      return;
    }
    if (size < 1 || size > 2 || opcode >= arch.inst.size() ||
        arch.inst[opcode] == (TypeOp *)0) {
      bad = true;
      return;
    }
    Value left = get(vars[0], out->size >= vars[0].size);
    if (opcode == CPUI_COPY && size == 1) {
      if (out->size != vars[0].size) {
        bad = true;
        return;
      }
      put(*out, left);
      return;
    }
    Value right = size == 2 ? get(vars[1], out->size >= vars[1].size)
                            : Value{Constant, 0};
    if (bad)
      return;
    // Processor alignment masking does not change the identity of the loaded
    // pointer slot.
    uintb alignment = arch.translate->getAlignment();
    if (opcode == CPUI_INT_AND && left.kind == Slot && right.kind == Constant &&
        out->size == vars[0].size && alignment != 0 &&
        (alignment & (alignment - 1)) == 0 &&
        right.value == (mask(vars[0].size) & ~(alignment - 1))) {
      put(*out, left);
      return;
    }
    OpBehavior *behavior = arch.inst[opcode]->getBehavior();
    if (left.kind != Constant || right.kind != Constant ||
        behavior->isSpecial() || behavior->isUnary() != (size == 1)) {
      bad = true;
      return;
    }
    uintb value =
        size == 1 ? behavior->evaluateUnary(out->size, vars[0].size, left.value)
                  : behavior->evaluateBinary(out->size, vars[0].size,
                                             left.value, right.value);
    put(*out, {Constant, value});
  }
};

class IfcLinkage : public IfaceDecompCommand {
public:
  virtual void execute(istream &input) {
    if (dcp->conf == (Architecture *)0)
      throw IfaceExecutionError("No architecture loaded");
    input >> ws;
    bool table = input.peek() == '-';
    if (table) {
      string option;
      input >> option;
      if (option != "--table")
        throw IfaceExecutionError("Unknown linkage option");
    }
    while (true) {
      input >> ws;
      if (input.eof())
        break;
      int4 ignored;
      Address start = parse_machaddr(input, ignored, *dcp->conf->types);
      if (start.isInvalid())
        break;
      Address current = start;
      VentrisLinkageEmit emit(*dcp->conf);
      uint4 length = 0;
      try {
        for (int4 i = 0; i < 8 && !emit.bad && !emit.terminal; ++i) {
          emit.beginInstruction();
          int4 size = dcp->conf->translate->oneInstruction(emit, current);
          if (size <= 0 || (emit.operations == 0 && i != 0)) {
            emit.bad = true;
            break;
          }
          Address next = current + size;
          if (next.getOffset() <= current.getOffset()) {
            emit.bad = true;
            break;
          }
          length += size;
          current = next;
        }
      } catch (LowlevelError &) {
        emit.bad = true;
      }
      bool valid = emit.complete(table);
      *status->fileoptr << "LINKAGE {\"address\":" << dec << start.getOffset()
                        << ",\"length\":" << (valid ? length : 0)
                        << ",\"slot\":";
      if (valid)
        *status->fileoptr << emit.slot;
      else
        *status->fileoptr << "null";
      *status->fileoptr << "}" << endl;
    }
  }
};

} // namespace ghidra
#endif
