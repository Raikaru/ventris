// Sparse known-bit storage for native function propagation.
// Register slices and joins follow VarnodeContext/RegisterValue semantics
// (Ghidra 12.1.3, Apache-2.0); absence means unknown, not zero.
#ifndef VENTRIS_CONSTANT_STATE_HH
#define VENTRIS_CONSTANT_STATE_HH

#include <cstdint>
#include <iterator>
#include <limits>
#include <map>
#include <stdexcept>

namespace ghidra {
namespace ventris_constants {

using Word = std::uint64_t;

inline Word widthMask(int size) {
  return size >= 8 ? ~Word(0) : size > 0 ? (Word(1) << (size * 8)) - 1 : 0;
}

struct Value {
  Word bits, known;
  int base, size;
  Value(Word value = 0, Word mask = 0, int origin = -1, int size = 0)
      : bits(value & mask), known(mask), base(origin), size(size) {}
  static Value constant(Word value, int size) { return Value(value, widthMask(size), -1, size); }
  static Value relative(int base, Word offset, int size) {
    return Value(offset, widthMask(size), base, size);
  }
  bool complete(int size) const {
    return base < 0 && size > 0 && size <= 8 &&
        (known & widthMask(size)) == widthMask(size);
  }
};

struct Location {
  int space;
  Word offset;
  bool operator<(const Location &other) const {
    return space < other.space || (space == other.space && offset < other.offset);
  }
};

class State {
  // One cell per aligned eight bytes, not one allocation per register byte.
  // Bits are stored in address order; get/put apply the language byte order.
  struct Bits {
    Word bits = 0, known = 0;
  };
  struct Relative {
    int base, size;
    Word offset;
  };
  std::map<Location, Bits> cells;
  // Relative values have no literal address bits. A partial overwrite loses
  // the relation rather than turning an offset into a reported pointer.
  std::map<Location, Relative> relations;
  bool bigEndian;
  int uniqueSpace, instructionSpace;
  Word instructionOffset;

  static Word lastByte(Word offset, int size) {
    if (size <= 0 || Word(size - 1) > std::numeric_limits<Word>::max() - offset)
      throw std::overflow_error("constant-state storage range wraps");
    return offset + Word(size - 1);
  }

  void killRelations(int space, Word offset, Word last) {
    auto it = relations.lower_bound(Location{space, offset});
    if (it != relations.begin()) {
      auto previous = std::prev(it);
      if (previous->first.space == space &&
          offset - previous->first.offset < Word(previous->second.size))
        it = previous;
    }
    while (it != relations.end() && it->first.space == space && it->first.offset <= last)
      it = relations.erase(it);
  }

public:
  State(bool big = false, int unique = -1)
      : bigEndian(big), uniqueSpace(unique), instructionSpace(-1), instructionOffset(0) {}

  Value get(int space, Word offset, int size) const {
    if (size <= 0 || size > 8 || Word(size - 1) > ~Word(0) - offset)
      return Value();
    auto relative = relations.find(Location{space, offset});
    if (relative != relations.end() && relative->second.size == size)
      return Value::relative(relative->second.base, relative->second.offset, size);
    Word bits = 0, known = 0, previous = 0;
    auto cell = cells.end();
    for (int i = 0; i < size; ++i) {
      Word at = offset + Word(i), base = at & ~Word(7);
      if (i == 0 || base != previous) {
        cell = cells.find(Location{space, base});
        previous = base;
      }
      if (cell == cells.end())
        continue;
      unsigned source = unsigned(at & 7) * 8;
      unsigned target = unsigned(bigEndian ? size - 1 - i : i) * 8;
      bits |= ((cell->second.bits >> source) & 0xff) << target;
      known |= ((cell->second.known >> source) & 0xff) << target;
    }
    return Value(bits, known, -1, size);
  }

  void kill(int space, Word offset, int size) {
    Word last = lastByte(offset, size);
    killRelations(space, offset, last);
    auto it = cells.lower_bound(Location{space, offset & ~Word(7)});
    while (it != cells.end() && it->first.space == space && it->first.offset <= last) {
      Word base = it->first.offset;
      unsigned first = offset > base ? unsigned(offset - base) : 0;
      unsigned final = last - base < 7 ? unsigned(last - base) : 7;
      Word mask = widthMask(int(final - first + 1)) << (first * 8);
      it->second.bits &= ~mask;
      it->second.known &= ~mask;
      if (it->second.known == 0)
        it = cells.erase(it);
      else
        ++it;
    }
  }

  void put(int space, Word offset, int size, Value value) {
    lastByte(offset, size);
    if (size > 8 || value.known == 0) {
      kill(space, offset, size);
      return;
    }
    if (value.base >= 0) {
      auto existing = relations.find(Location{space, offset});
      if (existing != relations.end() && existing->second.size == size &&
          value.size == size && value.known == widthMask(size)) {
        existing->second = Relative{value.base, size, value.bits};
        return;
      }
      kill(space, offset, size);
      if (value.size == size && value.known == widthMask(size))
        relations.emplace(Location{space, offset}, Relative{value.base, size, value.bits});
      return;
    }
    killRelations(space, offset, offset + Word(size - 1));
    Word previous = 0;
    auto cell = cells.end();
    auto hint = cells.end();
    for (int i = 0; i < size; ++i) {
      Word at = offset + Word(i), base = at & ~Word(7);
      if (i == 0 || base != previous) {
        hint = cells.lower_bound(Location{space, base});
        cell = hint != cells.end() && hint->first.space == space &&
            hint->first.offset == base ? hint : cells.end();
        previous = base;
      }
      unsigned source = unsigned(bigEndian ? size - 1 - i : i) * 8;
      if (cell == cells.end()) {
        if (((value.known >> source) & 0xff) == 0)
          continue;
        cell = cells.emplace_hint(hint, Location{space, base}, Bits());
      }
      unsigned target = unsigned(at & 7) * 8;
      Word mask = Word(0xff) << target;
      cell->second.bits = (cell->second.bits & ~mask) |
          (((value.bits >> source) & 0xff) << target);
      cell->second.known = (cell->second.known & ~mask) |
          (((value.known >> source) & 0xff) << target);
      if ((at & 7) == 7 || i == size - 1) {
        if (cell->second.known == 0) {
          cells.erase(cell);
          cell = cells.end();
        }
      }
    }
  }

  void clearSpace(int space) {
    auto begin = cells.lower_bound(Location{space, 0});
    auto end = cells.upper_bound(Location{space, ~Word(0)});
    cells.erase(begin, end);
    relations.erase(relations.lower_bound(Location{space, 0}),
                    relations.upper_bound(Location{space, ~Word(0)}));
  }

  template <typename Predicate>
  void retain(Predicate keep) {
    for (auto it = cells.begin(); it != cells.end();) {
      if (!keep(it->first.space, it->first.offset, 8)) {
        for (int byte = 0; byte < 8; ++byte) {
          Word mask = Word(0xff) << (byte * 8);
          if ((it->second.known & mask) != 0 &&
              !keep(it->first.space, it->first.offset + Word(byte), 1)) {
            it->second.bits &= ~mask;
            it->second.known &= ~mask;
          }
        }
      }
      if (it->second.known == 0)
        it = cells.erase(it);
      else
        ++it;
    }
    for (auto it = relations.begin(); it != relations.end();) {
      if (!keep(it->first.space, it->first.offset, it->second.size))
        it = relations.erase(it);
      else
        ++it;
    }
  }

  void beginInstruction(int space, Word offset) {
    if (space != instructionSpace || offset != instructionOffset) {
      if (uniqueSpace >= 0)
        clearSpace(uniqueSpace);
      instructionSpace = space;
      instructionOffset = offset;
    }
  }

  bool merge(const State &other) {
    bool changed = false;
    // A bit remains known only if every reached predecessor agrees on it.
    for (auto it = cells.begin(); it != cells.end();) {
      auto incoming = other.cells.find(it->first);
      Word mask = incoming == other.cells.end() ? 0 :
          it->second.known & incoming->second.known &
          ~(it->second.bits ^ incoming->second.bits);
      if (mask != it->second.known) {
        changed = true;
        it->second.known = mask;
        it->second.bits &= mask;
      }
      if (mask == 0)
        it = cells.erase(it);
      else
        ++it;
    }
    for (auto it = relations.begin(); it != relations.end();) {
      auto incoming = other.relations.find(it->first);
      if (incoming == other.relations.end() ||
          incoming->second.base != it->second.base ||
          incoming->second.size != it->second.size ||
          incoming->second.offset != it->second.offset) {
        changed = true;
        it = relations.erase(it);
      } else {
        ++it;
      }
    }
    if (instructionSpace != other.instructionSpace ||
        instructionOffset != other.instructionOffset) {
      if (uniqueSpace >= 0) {
        auto it = cells.lower_bound(Location{uniqueSpace, 0});
        changed |= it != cells.end() && it->first.space == uniqueSpace;
        auto relative = relations.lower_bound(Location{uniqueSpace, 0});
        changed |= relative != relations.end() && relative->first.space == uniqueSpace;
        clearSpace(uniqueSpace);
      }
      instructionSpace = -1;
      instructionOffset = 0;
    }
    return changed;
  }
};

} // namespace ventris_constants
} // namespace ghidra
#endif
