// Native counterpart of ConstantPropagationContextEvaluator policy, using
// Funcdata raw flow and OpBehavior from the pinned Ghidra 12.1.3 sources.
#ifndef VENTRIS_CONSTANTS_HH
#define VENTRIS_CONSTANTS_HH

#include "ifacedecomp.hh"
#include "ventris_constant_state.hh"
#include <algorithm>
#include <deque>
#include <tuple>

namespace ghidra {
namespace ventris_constants {

struct Region {
  Word start, end;
  unsigned flags;
  bool contains(Word address, int size = 1) const {
    return size > 0 && address >= start && address < end && Word(size) <= end - address;
  }
};

struct Fact {
  Word pc, value;
  const Varnode *varnode;
  std::tuple<Word, int, Word, int, Word> key() const {
    return std::make_tuple(pc, varnode->getSpace()->getIndex(),
                          varnode->getOffset(), varnode->getSize(), value);
  }
};

struct Snapshot {
  State registers, memory;
  std::map<Location, unsigned char> modified;
  bool unknownWrites = false, callWrites = false;
  Snapshot(bool big, int unique) : registers(big, unique), memory(big) {}

  bool merge(const Snapshot &other) {
    bool changed = registers.merge(other.registers);
    changed |= memory.merge(other.memory);
    changed |= (!unknownWrites && other.unknownWrites) || (!callWrites && other.callWrites);
    unknownWrites |= other.unknownWrites;
    callWrites |= other.callWrites;
    if (unknownWrites) {
      modified.clear(); // Initial-image fallback is already disabled everywhere.
      return changed;
    }
    for (const auto &entry : other.modified) {
      auto position = modified.lower_bound(entry.first);
      if (position == modified.end() || position->first.space != entry.first.space ||
          position->first.offset != entry.first.offset) {
        modified.emplace_hint(position, entry);
        changed = true;
      } else if ((position->second | entry.second) != position->second) {
        position->second |= entry.second;
        changed = true;
      }
    }
    return changed;
  }

  void markWritten(int space, Word offset, int size) {
    while (size > 0) {
      unsigned first = unsigned(offset & 7);
      int count = std::min(size, 8 - int(first));
      modified[Location{space, offset & ~Word(7)}] |= ((1u << count) - 1) << first;
      offset += Word(count);
      size -= count;
    }
  }
};

class Propagation {
  Architecture &arch;
  Funcdata &function;
  const std::vector<Region> &regions;
  AddrSpace *dataSpace, *codeSpace;
  const VarnodeData *stackRegister = nullptr;
  Word first, end;
  int pointerSize, uniqueSpace, spaceCount, stackBase = -1;
  bool bigEndian, trustWritable;
  std::size_t operations = 0;

  bool memorySpace(const AddrSpace *space) const {
    return space == dataSpace || space == codeSpace;
  }

  const Region *region(Word address, int size = 1) const {
    for (const Region &candidate : regions)
      if (candidate.contains(address, size))
        return &candidate;
    return nullptr;
  }

  bool location(AddrSpace *space, Value pointer, Location &result) const {
    int size = pointer.size;
    if (size < 1 || size > 8 || !memorySpace(space) || space->getWordSize() == 0)
      return false;
    Word offset;
    if (pointer.base >= 0) {
      if (pointer.base > (std::numeric_limits<int>::max() - spaceCount) / spaceCount)
        return false;
      result.space = -1 - (pointer.base * spaceCount + space->getIndex());
      // Bias the virtual origin so ordinary negative stack offsets do not
      // straddle the storage map's unsigned boundary. Never emit this value.
      offset = (pointer.bits + (Word(1) << (size * 8 - 1))) & widthMask(size);
    } else {
      if (!pointer.complete(size))
        return false;
      result.space = space->getIndex();
      offset = pointer.bits;
    }
    if (offset > ~Word(0) / space->getWordSize())
      return false;
    result.offset = AddrSpace::addressToByte(offset, space->getWordSize());
    return true;
  }

  void forgetMemory(Snapshot &state, bool call) const {
    state.memory = State(bigEndian);
    if (call)
      state.callWrites = true;
    else {
      state.unknownWrites = true;
      state.modified.clear();
    }
  }

  Value load(Snapshot &state, AddrSpace *space, Value pointer, int size) const {
    Location address;
    if (size < 1 || size > 8 || !location(space, pointer, address) ||
        Word(size - 1) > ~Word(0) - address.offset)
      return Value();
    Value value = state.memory.get(address.space, address.offset, size);
    if (value.base >= 0 || value.complete(size) || address.space < 0 || state.unknownWrites)
      return value;
    const Region *mapping = region(address.offset, size);
    if (mapping == nullptr || (mapping->flags & 2) == 0 ||
        ((mapping->flags & 1) != 0 && (!trustWritable || state.callWrites)) ||
        (size != 1 && size != 2 && size != 4 && size != 8))
      return value;
    uint1 bytes[8];
    try {
      arch.loader->loadFill(bytes, size, Address(space, address.offset));
    } catch (DataUnavailError &) {
      return value;
    }
    Word initial = 0, available = 0;
    Word previousCell = 0;
    auto dirty = state.modified.end();
    for (int byte = 0; byte < size; ++byte) {
      unsigned shift = unsigned(space->isBigEndian() ? size - 1 - byte : byte) * 8;
      initial |= Word(bytes[byte]) << shift;
      Word at = address.offset + Word(byte);
      Word cell = at & ~Word(7);
      if (byte == 0 || cell != previousCell) {
        dirty = state.modified.find(Location{address.space, cell});
        previousCell = cell;
      }
      if (dirty == state.modified.end() || (dirty->second & (1u << (at & 7))) == 0)
        available |= Word(0xff) << shift;
    }
    // VarnodeContext does not trust zero read from the initial image.
    if (initial == 0)
      return value;
    available &= ~value.known;
    return Value(value.bits | (initial & available), value.known | available, -1, size);
  }

  Value get(Snapshot &state, const Varnode *varnode) const {
    AddrSpace *space = varnode->getSpace();
    if (space->getType() == IPTR_CONSTANT)
      return Value::constant(varnode->getOffset(), varnode->getSize());
    if (memorySpace(space)) {
      Word words = varnode->getOffset() / space->getWordSize();
      if (words * space->getWordSize() != varnode->getOffset())
        return Value();
      return load(state, space, Value::constant(words, space->getAddrSize()), varnode->getSize());
    }
    return state.registers.get(space->getIndex(), varnode->getOffset(), varnode->getSize());
  }

  void store(Snapshot &state, AddrSpace *space, Value pointer, int size, Value value) const {
    Location address;
    if (size < 1 || size > 8 || !location(space, pointer, address) ||
        Word(size - 1) > ~Word(0) - address.offset) {
      forgetMemory(state, false);
      return;
    }
    bool stack = address.space < 0 && (-1 - address.space) / spaceCount == stackBase;
    if (address.space < 0 && !stack)
      forgetMemory(state, false); // An opaque incoming pointer may alias any memory.
    else {
      // A concrete store or a frame-relative store can invalidate aliases
      // held through other opaque incoming pointers.
      bool mapped = address.space >= 0 && region(address.offset, size) != nullptr;
      state.memory.retain([&](int id, Word, int) {
        return id >= 0 || ((stack || mapped) && (-1 - id) / spaceCount == stackBase);
      });
    }
    state.memory.put(address.space, address.offset, size, value);
    if (!state.unknownWrites && address.space >= 0)
      state.markWritten(address.space, address.offset, size);
  }

  Value evaluate(Snapshot &state, const PcodeOp &op) const {
    const Varnode *output = op.getOut();
    if (output == nullptr || output->getSize() < 1 || output->getSize() > 8)
      return Value();
    int size = output->getSize(), inputs = op.numInput();
    OpCode code = op.code();
    if (code == CPUI_LOAD && inputs == 2)
      return load(state, op.getIn(0)->getSpaceFromConst(), get(state, op.getIn(1)), size);
    if (inputs < 1 || inputs > 2 || op.getIn(0)->getSize() > 8)
      return Value();
    Value left = get(state, op.getIn(0));
    if (code == CPUI_COPY)
      return size == op.getIn(0)->getSize() ? left : Value();
    Value right = inputs == 2 ? get(state, op.getIn(1)) : Value();
    if (inputs == 2 && op.getIn(1)->getSize() > 8)
      return Value();
    bool sameStorage = inputs == 2 && !memorySpace(op.getIn(0)->getSpace()) &&
        op.getIn(0)->getSpace() == op.getIn(1)->getSpace() &&
        op.getIn(0)->getOffset() == op.getIn(1)->getOffset() &&
        op.getIn(0)->getSize() == op.getIn(1)->getSize();
    if (sameStorage && (code == CPUI_INT_XOR || code == CPUI_INT_SUB))
      return Value::constant(0, size);
    if (size == op.getIn(0)->getSize() && inputs == 2) {
      if (left.base >= 0 && right.complete(op.getIn(1)->getSize()) &&
          (code == CPUI_INT_ADD || code == CPUI_INT_SUB))
        return Value::relative(left.base, code == CPUI_INT_ADD ? left.bits + right.bits :
                               left.bits - right.bits, size);
      if (right.base >= 0 && left.complete(op.getIn(0)->getSize()) && code == CPUI_INT_ADD)
        return Value::relative(right.base, left.bits + right.bits, size);
      if (left.base >= 0 && left.base == right.base && code == CPUI_INT_SUB)
        return Value::constant(left.bits - right.bits, size);
    }
    if (left.base < 0 && right.base < 0 && inputs == 2) {
      if (code == CPUI_INT_AND)
        return Value(left.bits & right.bits, ((left.known & right.known) |
                     (left.known & ~left.bits) | (right.known & ~right.bits)) & widthMask(size));
      if (code == CPUI_INT_OR)
        return Value(left.bits | right.bits, ((left.known & right.known) |
                     (left.known & left.bits) | (right.known & right.bits)) & widthMask(size));
      if (code == CPUI_INT_XOR)
        return Value(left.bits ^ right.bits, left.known & right.known & widthMask(size));
    }
    if (!left.complete(op.getIn(0)->getSize()) ||
        (inputs == 2 && !right.complete(op.getIn(1)->getSize())))
      return Value();
    OpBehavior *behavior = op.getOpcode()->getBehavior();
    if (behavior->isSpecial() || behavior->isUnary() != (inputs == 1))
      return Value();
    return Value::constant(inputs == 1 ?
        behavior->evaluateUnary(size, op.getIn(0)->getSize(), left.bits) :
        behavior->evaluateBinary(size, op.getIn(0)->getSize(), left.bits, right.bits), size);
  }

  void observe(std::vector<Fact> *facts, const PcodeOp &op, Value value) const {
    const Varnode *output = op.getOut();
    if (facts == nullptr || output == nullptr || output->getSize() != pointerSize ||
        !value.complete(pointerSize) || memorySpace(output->getSpace()))
      return;
    Word scale = dataSpace->getWordSize();
    if (scale == 0 || value.bits > dataSpace->getHighest() / scale)
      return;
    Word target = AddrSpace::addressToByte(value.bits, scale);
    if (target < 1024 || dataSpace->getHighest() - target < 256 ||
        target == 0xffff || target == 0xffffffff || region(target) == nullptr)
      return;
    facts->push_back(Fact{op.getAddr().getOffset(), value.bits, output});
  }

  int transfer(const BlockBasic &block, Snapshot &state, std::vector<Fact> *facts) {
    int branch = -1;
    for (auto it = block.beginOp(); it != block.endOp(); ++it) {
      const PcodeOp &op = **it;
      if (++operations > 1000000)
        throw LowlevelError("Constant propagation exceeds one million p-code operations");
      if (op.getAddr().getOffset() < first || op.getAddr().getOffset() >= end)
        return -2;
      state.registers.beginInstruction(op.getAddr().getSpace()->getIndex(), op.getAddr().getOffset());
      OpCode code = op.code();
      if (code == CPUI_CBRANCH && op.numInput() == 2) {
        Value condition = get(state, op.getIn(1));
        if (condition.complete(op.getIn(1)->getSize()))
          branch = condition.bits != 0 ? 1 : 0;
      } else if (code == CPUI_STORE && op.numInput() == 3) {
        store(state, op.getIn(0)->getSpaceFromConst(), get(state, op.getIn(1)),
              op.getIn(2)->getSize(), get(state, op.getIn(2)));
      } else if (code == CPUI_CALL || code == CPUI_CALLIND) {
        const FuncCallSpecs *call = function.getCallSpecs(&op);
        bool hasModel = call != nullptr && call->hasModel();
        Value stackValue = stackRegister == nullptr ? Value() :
            state.registers.get(stackRegister->space->getIndex(), stackRegister->offset,
                                stackRegister->size);
        state.registers.retain([&](int space, Word offset, int size) {
          if (space == uniqueSpace)
            return true;
          Address storage(arch.getSpace(space), offset);
          uint4 effect = hasModel ? call->hasEffect(storage, size) :
              arch.defaultfp->hasEffect(storage, size);
          return effect == EffectRecord::unaffected;
        });
        forgetMemory(state, true);
        if (stackRegister != nullptr) {
          int extraPop = hasModel ? call->getExtraPop() : arch.defaultfp->getExtraPop();
          int size = stackRegister->size;
          Value restored;
          if (extraPop != ProtoModel::extrapop_unknown) {
            Word amount = static_cast<Word>(static_cast<std::int64_t>(extraPop));
            if (stackValue.base >= 0)
              restored = Value::relative(stackValue.base, stackValue.bits + amount, size);
            else if (stackValue.complete(size))
              restored = Value::constant(stackValue.bits + amount, size);
            else if (extraPop == 0)
              restored = stackValue;
          }
          // CALL's raw p-code includes its push; the callee's RET does not
          // occur in this function's flow. Apply the prototype's stack pop.
          state.registers.put(stackRegister->space->getIndex(), stackRegister->offset,
                              size, restored);
        }
      } else if (code == CPUI_CALLOTHER) {
        state.registers.retain([&](int space, Word, int) { return space == uniqueSpace; });
        forgetMemory(state, false);
      }
      if (op.getOut() != nullptr) {
        Value value = code == CPUI_CALLOTHER ? Value() : evaluate(state, op);
        const Varnode *output = op.getOut();
        if (memorySpace(output->getSpace())) {
          AddrSpace *space = output->getSpace();
          store(state, space, Value::constant(output->getOffset() / space->getWordSize(),
                space->getAddrSize()), output->getSize(), value);
        } else {
          state.registers.put(output->getSpace()->getIndex(), output->getOffset(),
                              output->getSize(), value);
        }
        observe(facts, op, value);
      }
    }
    return branch;
  }

  Snapshot initialState() {
    Snapshot initial(bigEndian, uniqueSpace);
    std::map<Location, int> registers;
    const BlockGraph &graph = function.getBasicBlocks();
    for (int index = 0; index < graph.getSize(); ++index) {
      const auto *block = static_cast<const BlockBasic *>(graph.getBlock(index));
      for (auto it = block->beginOp(); it != block->endOp(); ++it) {
        const PcodeOp &op = **it;
        for (int input = 0; input < op.numInput(); ++input) {
          const Varnode *value = op.getIn(input);
          if (value->getSpace()->getType() != IPTR_PROCESSOR || memorySpace(value->getSpace()) ||
              value->getSize() < 1 || value->getSize() > 8)
            continue;
          int &size = registers[Location{value->getSpace()->getIndex(), value->getOffset()}];
          size = std::max(size, int(value->getSize()));
        }
      }
    }
    int base = 0, previousSpace = -1;
    Word previousEnd = 0;
    for (const auto &entry : registers) {
      if (entry.first.space == previousSpace && entry.first.offset < previousEnd)
        continue;
      initial.registers.put(entry.first.space, entry.first.offset, entry.second,
                            Value::relative(base, 0, entry.second));
      if (stackRegister != nullptr && entry.first.space == stackRegister->space->getIndex() &&
          entry.first.offset == stackRegister->offset && entry.second == stackRegister->size)
        stackBase = base;
      ++base;
      previousSpace = entry.first.space;
      previousEnd = entry.first.offset + Word(entry.second);
    }
    return initial;
  }

public:
  Propagation(Architecture &architecture, Funcdata &data, const std::vector<Region> &mapped,
              Word start, Word finish, bool trust)
      : arch(architecture), function(data), regions(mapped),
        dataSpace(arch.getDefaultDataSpace()), codeSpace(arch.getDefaultCodeSpace()),
        first(start), end(finish), pointerSize(arch.types->getSizeOfPointer()),
        uniqueSpace(arch.getUniqueSpace()->getIndex()), spaceCount(arch.numSpaces()),
        bigEndian(dataSpace->isBigEndian()), trustWritable(trust) {
    AddrSpace *stack = arch.getStackSpace();
    if (stack != nullptr && stack->numSpacebase() != 0)
      stackRegister = &stack->getSpacebase(0);
  }

  std::vector<Fact> run() {
    const BlockGraph &graph = function.getBasicBlocks();
    if (graph.getSize() == 0 || function.hasBadData() || function.hasUnimplemented())
      throw LowlevelError("Constant propagation requires decodable function flow");
    struct Node {
      Snapshot input;
      bool queued = true;
      explicit Node(const Snapshot &state) : input(state) {}
    };
    // Raw-flow block indices can have gaps and entry insertion can reorder
    // the graph. Use block identity, not an assumed contiguous index.
    std::map<const BlockBasic *, Node> nodes;
    std::deque<const BlockBasic *> pending;
    const auto *entry = static_cast<const BlockBasic *>(graph.getBlock(0));
    nodes.emplace(entry, Node(initialState()));
    pending.push_back(entry);
    while (!pending.empty()) {
      const BlockBasic *block = pending.front();
      pending.pop_front();
      Node &node = nodes.find(block)->second;
      node.queued = false;
      Snapshot output = node.input;
      int choice = transfer(*block, output, nullptr);
      if (choice == -2)
        continue;
      for (int edge = 0; edge < block->sizeOut(); ++edge) {
        if (choice >= 0 && block->sizeOut() == 2 && edge != choice)
          continue;
        const auto *next = static_cast<const BlockBasic *>(block->getOut(edge));
        auto position = nodes.lower_bound(next);
        bool fresh = position == nodes.end() || position->first != next;
        if (fresh)
          position = nodes.emplace_hint(position, next, Node(output));
        else if (!position->second.input.merge(output))
          continue;
        if (fresh || !position->second.queued) {
          position->second.queued = true;
          pending.push_back(next);
        }
      }
    }
    std::vector<Fact> facts;
    for (const auto &entry : nodes) {
      Snapshot final = entry.second.input;
      transfer(*entry.first, final, &facts);
    }
    std::sort(facts.begin(), facts.end(), [](const Fact &a, const Fact &b) { return a.key() < b.key(); });
    facts.erase(std::unique(facts.begin(), facts.end(),
        [](const Fact &a, const Fact &b) { return a.key() == b.key(); }), facts.end());
    return facts;
  }
};

} // namespace ventris_constants

class IfcConstants : public IfaceDecompCommand {
  static void writeString(ostream &out, const string &value) {
    const char *digits = "0123456789abcdef";
    out << '"';
    for (unsigned char byte : value) {
      if (byte == '"' || byte == '\\')
        out << '\\' << char(byte);
      else if (byte < 0x20)
        out << "\\u00" << digits[byte >> 4] << digits[byte & 15];
      else
        out << char(byte);
    }
    out << '"';
  }

public:
  virtual void execute(istream &input) {
    if (dcp->conf == nullptr)
      throw IfaceExecutionError("No architecture loaded");
    uintb start, end;
    unsigned trust;
    input.unsetf(ios::basefield);
    if (!(input >> start >> end >> trust) || start >= end || trust > 1)
      throw IfaceParseError("Expected constants <start> <end-exclusive> <trust-writable:0|1> <start> <end> <flags> ...");
    vector<ventris_constants::Region> regions;
    while (true) {
      input >> ws;
      if (input.eof())
        break;
      ventris_constants::Region range;
      if (!(input >> range.start >> range.end >> range.flags) ||
          range.start >= range.end || range.flags > 7)
        throw IfaceParseError("Malformed constant-propagation mapping");
      regions.push_back(range);
    }
    if (regions.empty())
      throw IfaceParseError("Constant propagation requires mapped ranges");
    Architecture &arch = *dcp->conf;
    AddrSpace *space = arch.getDefaultCodeSpace();
    if (end - 1 > space->getHighest())
      throw IfaceParseError("Function range exceeds the code address space");
    const Address entry(space, start);
    // FlowInfo treats unresolved in-range calls as PIC branches. Register the
    // known entry temporarily so a recursive call keeps its continuation.
    // Preserve any existing function and remove only the symbol we create.
    struct EntrySymbol {
      Scope *owner;
      FunctionSymbol *added;
      ~EntrySymbol() {
        if (added != nullptr)
          owner->removeSymbol(added);
      }
    } symbol{arch.symboltab->getGlobalScope(), nullptr};
    if (symbol.owner->findFunction(entry) == nullptr)
      symbol.added = symbol.owner->addFunction(entry, "");
    Funcdata function("ventris_constants", "ventris_constants",
                      symbol.owner, entry, nullptr, 0);
    function.followFlow(entry, Address(space, end));
    ventris_constants::Propagation propagation(arch, function, regions, start, end, trust != 0);
    vector<ventris_constants::Fact> facts = propagation.run();
    ostream &out = *status->fileoptr;
    out << "CONSTANTS [" << dec;
    bool first = true;
    for (const auto &fact : facts) {
      if (!first)
        out << ',';
      first = false;
      out << "{\"pc\":" << fact.pc << ",\"value\":" << fact.value << ",\"varnode\":{\"space\":";
      writeString(out, fact.varnode->getSpace()->getName());
      out << ",\"offset\":" << fact.varnode->getOffset()
          << ",\"size\":" << fact.varnode->getSize() << "}}";
    }
    out << "]\n";
    out.flush();
  }
};

} // namespace ghidra
#endif
