#ifndef VENTRIS_PATTERNS_HH
#define VENTRIS_PATTERNS_HH

#include "ifacedecomp.hh"
#include "loadimage.hh"
#include "sleigh_arch.hh"
#include "xml.hh"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <memory>

namespace ghidra {
namespace ventris_patterns {

// Ghidra BytePatterns XML matching only. A match does not create a function:
// consumers must enforce the ordered action prerequisites against program
// state.
inline const string *attribute(const Element &element, const char *name) {
  for (int4 i = 0; i < element.getNumAttributes(); ++i)
    if (element.getAttributeName(i) == name)
      return &element.getAttributeValue(i);
  return nullptr;
}

inline const string &required(const Element &element, const char *name) {
  const string *value = attribute(element, name);
  if (!value)
    throw IfaceExecutionError("Missing pattern attribute: " + string(name));
  return *value;
}

inline int hexDigit(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  throw IfaceExecutionError("Invalid hexadecimal pattern digit");
}
inline int4 integer(const Element &element, const char *name) {
  const string *source = attribute(element, name);
  if (!source || *source == "0")
    return 0;
  const string &text = *source;
  size_t position = 0;
  uint4 radix = 10;
  if (text.compare(0, 2, "0x") == 0) {
    position = 2;
    radix = 16;
  } else if (!text.empty() && text[0] == '0') {
    position = 1;
    radix = 8;
  }
  bool negative = position < text.size() && text[position] == '-';
  if (position < text.size() && (negative || text[position] == '+'))
    ++position;
  if (position == text.size())
    throw IfaceExecutionError("Invalid pattern integer: " + text);
  // SpecXmlUtils.decodeInt uses BigInteger.intValue: preserve the low 32 bits.
  uint4 value = 0;
  while (position < text.size()) {
    uint4 digit = hexDigit(text[position++]);
    if (digit >= radix)
      throw IfaceExecutionError("Invalid pattern integer: " + text);
    value = value * radix + digit;
  }
  if (negative)
    value = uint4(0) - value;
  return value <= static_cast<uint4>(std::numeric_limits<int4>::max())
             ? static_cast<int4>(value)
             : -1 - static_cast<int4>(~value);
}

inline string trimmed(const string &text) {
  size_t first = text.find_first_not_of(" \t\r\n");
  if (first == string::npos)
    return string();
  return text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}

inline void quoted(ostream &out, const string &text) {
  static const char digits[] = "0123456789abcdef";
  out << '"';
  for (unsigned char c : text) {
    if (c == '"' || c == '\\')
      out << '\\' << static_cast<char>(c);
    else if (c < 32)
      out << "\\u00" << digits[c >> 4] << digits[c & 15];
    else
      out << static_cast<char>(c);
  }
  out << '"';
}

inline bool languageMatches(const string &pattern, const string &language) {
  size_t p = 0, l = 0;
  for (;;) {
    p = pattern.find_first_not_of(':', p);
    l = language.find_first_not_of(':', l);
    if (p == string::npos || l == string::npos)
      return p == l;
    size_t pe = pattern.find(':', p), le = language.find(':', l);
    if (pe == string::npos)
      pe = pattern.size();
    if (le == string::npos)
      le = language.size();
    if (!(pe - p == 1 && pattern[p] == '*') &&
        pattern.compare(p, pe - p, language, l, le - l) != 0)
      return false;
    p = pe;
    l = le;
  }
}

struct DecisionNode {
  const Element *condition;
  const Element *file = nullptr;
  vector<DecisionNode> children;
  explicit DecisionNode(const Element *element = nullptr)
      : condition(element) {}
};

inline bool sameAttribute(const Element &a, const Element &b,
                          const char *name) {
  const string *av = attribute(a, name), *bv = attribute(b, name);
  return av && bv ? *av == *bv : av == bv;
}

inline void loadDecisions(DecisionNode &node, const Element &element) {
  for (const Element *child : element.getChildren()) {
    const string &kind = child->getName();
    if (kind == "patternfile") {
      if (node.file)
        throw IfaceExecutionError("Duplicate patternfile decision");
      node.file = child;
      continue;
    }
    if (kind != "language" && kind != "compiler")
      throw IfaceExecutionError("Unknown pattern constraint: " + kind);
    if (kind == "language")
      required(*child, "id");
    else if (!attribute(*child, "id") && !attribute(*child, "name"))
      throw IfaceExecutionError("Missing compiler constraint");
    auto existing =
        std::find_if(node.children.begin(), node.children.end(),
                     [&](const DecisionNode &other) {
                       return other.condition->getName() == kind &&
                              sameAttribute(*other.condition, *child, "id") &&
                              (kind == "language" ||
                               sameAttribute(*other.condition, *child, "name"));
                     });
    if (existing == node.children.end()) {
      node.children.emplace_back(child);
      existing = node.children.end() - 1;
    }
    loadDecisions(*existing, *child);
  }
}

inline bool selectFiles(const DecisionNode &node, const string &language,
                        const string &compiler, vector<string> &files) {
  if (node.condition) {
    if (node.condition->getName() == "language") {
      if (!languageMatches(required(*node.condition, "id"), language))
        return false;
    } else {
      const string *id = attribute(*node.condition, "id");
      if (id && *id != compiler)
        return false;
      // CompilerSpec ID is known; Program.getCompiler() producer metadata is
      // not.
      if (attribute(*node.condition, "name"))
        throw IfaceExecutionError(
            "Pattern selection requires compiler producer metadata");
    }
  }
  bool found = false;
  for (const DecisionNode &child : node.children)
    found |= selectFiles(child, language, compiler, files);
  if (!found && node.file) {
    files.push_back(trimmed(node.file->getContent()));
    found = true;
  }
  return found;
}

struct Byte {
  uint1 value, mask;
};
struct Sequence {
  vector<Byte> bytes;
  int4 mark = -1;
  int8 fixed = 0;
};
struct Alignment {
  uint4 offset, mask;
};
struct Rule {
  string file;
  vector<Alignment> alignment;
  vector<const Element *> actions;
};
struct Pattern {
  size_t pre, post, rule, anchor, length;
  int4 mark;
};

inline Sequence sequence(const Element &element) {
  if (element.getName() != "data" || !element.getChildren().empty())
    throw IfaceExecutionError("Expected pattern data");
  Sequence result;
  const string &text = element.getContent();
  int mode = -1;
  for (size_t i = 0; i < text.size();) {
    char c = text[i];
    if (std::isspace(static_cast<unsigned char>(c))) {
      mode = -1;
      ++i;
      continue;
    }
    if (c == '#') {
      i = text.find('\n', i);
      if (i == string::npos)
        break;
      continue;
    }
    if (mode == -1) {
      if (c == '*') {
        if (result.bytes.size() >
            static_cast<size_t>(std::numeric_limits<int4>::max()))
          throw IfaceExecutionError("Pattern mark exceeds native range");
        result.mark = static_cast<int4>(result.bytes.size());
        ++i;
        continue;
      }
      if (c == '0' && i + 1 < text.size() && text[i + 1] == 'x') {
        mode = 0;
        i += 2;
        continue;
      }
      if (c == '1' || c == '.')
        mode = 1;
      else if (c != '0')
        throw IfaceExecutionError("Invalid ditted pattern sequence");
    }
    size_t width = mode == 0 ? 2 : 8;
    if (width > text.size() - i)
      throw IfaceExecutionError("Incomplete pattern byte");
    unsigned value = 0, mask = 0;
    for (size_t j = 0; j < width; ++j) {
      unsigned shift = mode == 0 ? 4 : 1;
      value <<= shift;
      mask <<= shift;
      c = text[i++];
      if (c == '.')
        continue;
      if (mode != 0 && c != '0' && c != '1')
        throw IfaceExecutionError("Invalid binary pattern digit");
      value |= mode == 0 ? hexDigit(c) : c - '0';
      mask |= (1U << shift) - 1;
      result.fixed += shift;
    }
    result.bytes.push_back(
        {static_cast<uint1>(value), static_cast<uint1>(mask)});
  }
  return result;
}

class Search {
  DocumentStorage documents;
  vector<Sequence> sequences;
  vector<Rule> rules;
  vector<Pattern> patterns;
  std::array<vector<size_t>, 256> buckets;
  size_t longest = 0;

  size_t addSequence(const Element &element) {
    sequences.push_back(sequence(element));
    return sequences.size() - 1;
  }

  size_t addRule(const Element &element, size_t skip, const string &file) {
    Rule rule;
    rule.file = file;
    const auto &children = element.getChildren();
    for (size_t i = skip; i < children.size(); ++i) {
      const Element &child = *children[i];
      const string &kind = child.getName();
      if (!child.getChildren().empty())
        throw IfaceExecutionError("Nested pattern action");
      if (kind == "align") {
        uint4 offset = static_cast<uint4>(integer(child, "mark"));
        uint4 bits = static_cast<uint4>(integer(child, "bits"));
        rule.alignment.push_back({offset, (uint4(1) << (bits & 31)) - 1});
      } else if (kind == "funcstart" || kind == "possiblefuncstart" ||
                 kind == "codeboundary" || kind == "setcontext") {
        rule.actions.push_back(&child);
      } else {
        throw IfaceExecutionError("Unknown pattern subtag: " + kind);
      }
    }
    rules.push_back(std::move(rule));
    return rules.size() - 1;
  }

  const Byte &byteAt(const Pattern &pattern, size_t index) const {
    const auto &pre = sequences[pattern.pre].bytes;
    return index < pre.size()
               ? pre[index]
               : sequences[pattern.post].bytes[index - pre.size()];
  }

  void addPattern(size_t pre, size_t post, size_t rule, int4 mark) {
    size_t length = sequences[pre].bytes.size() + sequences[post].bytes.size();
    if (!length ||
        length > static_cast<size_t>(std::numeric_limits<int4>::max()) - 65536)
      throw IfaceExecutionError("Pattern length exceeds native loader range");
    Pattern pattern{pre, post, rule, 0, length, mark};
    int best = -1;
    for (size_t i = 0; i < length; ++i) {
      uint1 mask = byteAt(pattern, i).mask;
      int bits = 0;
      while (mask) {
        mask &= mask - 1;
        ++bits;
      }
      if (bits >= best) {
        best = bits;
        pattern.anchor = i;
      }
    }
    patterns.push_back(pattern);
    longest = std::max(longest, length);
  }

  void loadPatterns(const Element &root, const string &file) {
    if (root.getName() != "patternlist")
      throw IfaceExecutionError("Expected patternlist in " + file);
    for (const Element *element : root.getChildren()) {
      const auto &children = element->getChildren();
      if (element->getName() == "pattern") {
        if (children.empty())
          throw IfaceExecutionError("Missing pattern data");
        size_t post = addSequence(*children.front());
        int4 mark = integer(*element, "mark");
        if (sequences[post].mark >= 0)
          mark = sequences[post].mark;
        addPattern(0, post, addRule(*element, 1, file), mark);
      } else if (element->getName() == "patternpairs") {
        int4 totalBits = integer(*element, "totalbits");
        int4 postBits = integer(*element, "postbits");
        if (children.empty() || children.front()->getName() != "prepatterns")
          throw IfaceExecutionError("Missing prepatterns");
        vector<size_t> pre;
        for (const Element *data : children.front()->getChildren())
          pre.push_back(addSequence(*data));
        for (size_t i = 1; i < children.size(); ++i) {
          const Element &group = *children[i];
          if (group.getName() != "postpatterns")
            throw IfaceExecutionError("Expected postpatterns");
          vector<size_t> post;
          size_t count = 0;
          for (const Element *data : group.getChildren()) {
            if (data->getName() != "data")
              break;
            ++count;
            size_t index = addSequence(*data);
            if (sequences[index].fixed >= postBits)
              post.push_back(index);
          }
          size_t rule = addRule(group, count, file);
          // Share byte sequences and actions across the Cartesian product.
          for (size_t p : pre)
            for (size_t q : post)
              if (sequences[p].fixed + sequences[q].fixed >= totalBits)
                addPattern(p, q, rule,
                           static_cast<int4>(sequences[p].bytes.size()));
        }
      } else {
        throw IfaceExecutionError("Unknown patternlist element");
      }
    }
  }

  static bool matches(const Sequence &sequence, const uint1 *bytes) {
    for (const Byte &byte : sequence.bytes)
      if ((*bytes++ & byte.mask) != byte.value)
        return false;
    return true;
  }

public:
  explicit Search(const Architecture &architecture) {
    const string &id = architecture.archid;
    size_t split = id.rfind(':');
    const LanguageDescription *language = nullptr;
    for (const auto &description : SleighArchitecture::getDescriptions())
      if (id.compare(0, split, description.getId()) == 0) {
        language = &description;
        break;
      }
    if (!language || split == string::npos)
      throw IfaceExecutionError("Unknown pattern language");
    const string &compiler =
        language->getCompiler(id.substr(split + 1)).getId();
    const char *home = std::getenv("SLEIGHHOME");
    if (!home || !*home)
      throw IfaceExecutionError("Pattern selection requires SLEIGHHOME");
    vector<string> directories;
    FileManage::scanDirectoryRecursive(directories, "patterns",
                                       string(home) + "/Ghidra", 4);
    std::sort(directories.begin(), directories.end());
    DecisionNode decisions;
    bool found = false;
    for (const string &directory : directories) {
      std::ifstream input(directory + "/patternconstraints.xml");
      if (!input)
        continue;
      found = true;
      const Element &root = *documents.parseDocument(input)->getRoot();
      if (root.getName() != "patternconstraints")
        throw IfaceExecutionError("Expected patternconstraints");
      loadDecisions(decisions, root);
    }
    if (!found)
      throw IfaceExecutionError("No installed pattern constraints");
    vector<string> files;
    selectFiles(decisions, language->getId(), compiler, files);
    std::sort(files.begin(), files.end());
    files.erase(std::unique(files.begin(), files.end()), files.end());
    sequences.emplace_back(); // Empty pre-sequence for direct patterns.
    for (const string &file : files) {
      bool loaded = false;
      for (const string &directory : directories) {
        std::ifstream input(directory + "/" + file);
        if (!input)
          continue;
        loadPatterns(*documents.parseDocument(input)->getRoot(), file);
        loaded = true;
        break;
      }
      if (!loaded)
        throw IfaceExecutionError("Missing selected pattern file: " + file);
    }
    for (size_t i = 0; i < patterns.size(); ++i) {
      const Byte &anchor = byteAt(patterns[i], patterns[i].anchor);
      for (unsigned byte = 0; byte < 256; ++byte)
        if ((byte & anchor.mask) == anchor.value)
          buckets[byte].push_back(i);
    }
  }

  vector<std::pair<uintb, size_t>>
  scan(Architecture &architecture,
       const vector<std::pair<uintb, uintb>> &ranges) const {
    vector<std::pair<uintb, size_t>> hits;
    if (patterns.empty() || ranges.empty())
      return hits;
    const size_t window = 65536, capacity = window + longest - 1;
    std::unique_ptr<uint1[]> buffer(new uint1[capacity]);
    for (const auto &range : ranges) {
      for (uintb cursor = range.first; cursor < range.second;) {
        size_t starts =
            static_cast<size_t>(std::min<uintb>(window, range.second - cursor));
        size_t available = static_cast<size_t>(
            std::min<uintb>(capacity, range.second - cursor));
        architecture.loader->loadFill(
            buffer.get(), static_cast<int4>(available),
            Address(architecture.getDefaultCodeSpace(), cursor));
        for (size_t position = 0; position < available; ++position) {
          for (size_t index : buckets[buffer[position]]) {
            const Pattern &pattern = patterns[index];
            if (position < pattern.anchor)
              continue;
            size_t start = position - pattern.anchor;
            if (start >= starts || pattern.length > available - start)
              continue;
            const Rule &rule = rules[pattern.rule];
            uintb raw = cursor + start;
            bool aligned = true;
            for (const Alignment &alignment : rule.alignment)
              if ((static_cast<uint4>(raw) + alignment.offset) &
                  alignment.mask) {
                aligned = false;
                break;
              }
            if (!aligned ||
                !matches(sequences[pattern.pre], buffer.get() + start) ||
                !matches(sequences[pattern.post],
                         buffer.get() + start +
                             sequences[pattern.pre].bytes.size()))
              continue;
            uintb mark;
            if (pattern.mark < 0) {
              uintb back = static_cast<uintb>(-static_cast<int8>(pattern.mark));
              if (back > raw - range.first)
                continue;
              mark = raw - back;
            } else {
              if (static_cast<uintb>(pattern.mark) >= range.second - raw)
                continue;
              mark = raw + pattern.mark;
            }
            hits.emplace_back(mark, pattern.rule);
          }
        }
        cursor += starts;
      }
    }
    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());
    return hits;
  }

  void emit(ostream &out, int4 alignment,
            const vector<std::pair<uintb, size_t>> &hits) const {
    out << std::dec << "PATTERNS {\"alignment\":" << alignment
        << ",\"rules\":[";
    for (size_t i = 0; i < rules.size(); ++i) {
      if (i)
        out << ',';
      out << "{\"file\":";
      quoted(out, rules[i].file);
      out << ",\"actions\":[";
      for (size_t j = 0; j < rules[i].actions.size(); ++j) {
        if (j)
          out << ',';
        const Element &action = *rules[i].actions[j];
        out << "{\"kind\":";
        quoted(out, action.getName());
        out << ",\"attributes\":{";
        for (int4 k = 0; k < action.getNumAttributes(); ++k) {
          if (k)
            out << ',';
          quoted(out, action.getAttributeName(k));
          out << ':';
          quoted(out, action.getAttributeValue(k));
        }
        out << "}}";
      }
      out << "]}";
    }
    out << "],\"matches\":[";
    for (size_t i = 0; i < hits.size(); ++i) {
      if (i)
        out << ',';
      out << "{\"address\":" << hits[i].first << ",\"rule\":" << hits[i].second
          << '}';
    }
    out << "]}" << std::endl;
  }
};
} // namespace ventris_patterns

class IfcFunctionStarts : public IfaceDecompCommand {
public:
  virtual void execute(istream &input) {
    if (dcp->conf == nullptr)
      throw IfaceExecutionError("No architecture loaded");
    Architecture &architecture = *dcp->conf;
    vector<std::pair<uintb, uintb>> ranges;
    for (;;) {
      input >> std::ws;
      if (input.eof())
        break;
      int4 ignored;
      Address start = parse_machaddr(input, ignored, *architecture.types);
      input >> std::ws;
      if (input.eof())
        throw IfaceExecutionError("Missing pattern range end");
      Address end = parse_machaddr(input, ignored, *architecture.types);
      if (start.getSpace() != architecture.getDefaultCodeSpace() ||
          end.getSpace() != start.getSpace() ||
          end.getOffset() <= start.getOffset())
        throw IfaceExecutionError("Invalid pattern scan range");
      ranges.emplace_back(start.getOffset(), end.getOffset());
    }
    std::sort(ranges.begin(), ranges.end());
    size_t count = 0;
    for (const auto &range : ranges) {
      if (count && range.first <= ranges[count - 1].second)
        ranges[count - 1].second =
            std::max(ranges[count - 1].second, range.second);
      else
        ranges[count++] = range;
    }
    ranges.resize(count);
    ventris_patterns::Search search(architecture);
    auto hits = search.scan(architecture, ranges);
    search.emit(*status->fileoptr, architecture.translate->getAlignment(),
                hits);
  }
};
} // namespace ghidra
#endif
