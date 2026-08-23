use super::*;
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CScore {
    pub oracle_tokens: usize,
    pub candidate_tokens: usize,
    pub matched_tokens: usize,
    pub exact: bool,
}

impl CScore {
    pub fn ratio_milli(&self) -> usize {
        if self.oracle_tokens == 0 {
            return usize::from(self.candidate_tokens == 0) * 1000;
        }
        self.matched_tokens.saturating_mul(1000) / self.oracle_tokens
    }
}
fn c_body(text: &str) -> &str {
    text.find('{')
        .and_then(|start| text.rfind('}').map(|end| &text[start..=end]))
        .unwrap_or(text)
}

/// Compare the semantic body of two C renderings.
///
/// Function names, type names, and generated temporary names are intentionally
/// canonicalized: the native pipeline has no symbol database. Identifier
/// bindings remain consistent within each body, and numeric literals are
/// normalized by value. Keywords, operators, punctuation, and literal-vs-
/// identifier shape remain significant.
pub fn score_c(oracle: &str, candidate: &str) -> CScore {
    let oracle_tokens = canonical_c_tokens(c_body(oracle));
    let candidate_tokens = canonical_c_tokens(c_body(candidate));
    let mut row = vec![0usize; candidate_tokens.len() + 1];
    for left in &oracle_tokens {
        let mut diagonal = 0;
        for (index, right) in candidate_tokens.iter().enumerate() {
            let saved = row[index + 1];
            row[index + 1] = if left == right {
                diagonal + 1
            } else {
                row[index + 1].max(row[index])
            };
            diagonal = saved;
        }
    }
    let matched_tokens = *row.last().unwrap_or(&0);
    CScore {
        oracle_tokens: oracle_tokens.len(),
        candidate_tokens: candidate_tokens.len(),
        matched_tokens,
        exact: oracle_tokens == candidate_tokens,
    }
}

fn is_local_declaration(line: &str) -> bool {
    let line = line.trim();
    if !line.ends_with(';') || line.contains('(') || line.contains('=') {
        return false;
    }
    [
        "bool ",
        "char ",
        "double ",
        "float ",
        "int ",
        "long ",
        "short ",
        "uint",
        "int",
        "undefined",
        "size_t ",
        "uintptr_t ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}
fn canonical_number(value: &str) -> String {
    let trimmed = value.trim_end_matches(['u', 'U', 'l', 'L']);
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u128::from_str_radix(hex, 16).ok()
    } else if let Some(binary) = trimmed
        .strip_prefix("0b")
        .or_else(|| trimmed.strip_prefix("0B"))
    {
        u128::from_str_radix(binary, 2).ok()
    } else if let Some(octal) = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
    {
        u128::from_str_radix(octal, 8).ok()
    } else {
        trimmed.parse::<u128>().ok()
    };
    parsed.map_or_else(
        || format!("$number:{trimmed}"),
        |number| format!("$number:{number}"),
    )
}

fn canonical_c_tokens(text: &str) -> Vec<String> {
    const KEYWORDS: &[&str] = &[
        "if", "else", "for", "while", "switch", "case", "break", "continue", "return", "goto",
        "do", "sizeof", "true", "false",
    ];
    let normalized = text
        .lines()
        .filter(|line| !is_local_declaration(line))
        .collect::<Vec<_>>()
        .join("\n");
    let mut tokens = Vec::new();
    let mut identifiers = BTreeMap::<String, String>::new();
    let mut chars = normalized.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            let mut word = String::from(ch);
            while let Some(next) = chars.peek().copied() {
                if next.is_ascii_alphanumeric() || next == '_' {
                    word.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            if KEYWORDS.contains(&word.as_str()) {
                tokens.push(word);
            } else if let Some(canonical) = identifiers.get(&word) {
                tokens.push(canonical.clone());
            } else {
                let canonical = format!("$id{}", identifiers.len());
                identifiers.insert(word, canonical.clone());
                tokens.push(canonical);
            }
            continue;
        }
        if ch.is_ascii_digit() {
            let mut number = String::from(ch);
            while let Some(next) = chars.peek().copied() {
                if next.is_ascii_alphanumeric() || next == '_' {
                    number.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(canonical_number(&number));
            continue;
        }
        let mut operator = String::from(ch);
        if let Some(next) = chars.peek().copied() {
            if matches!(
                (ch, next),
                ('=', '=')
                    | ('!', '=')
                    | ('<', '=')
                    | ('>', '=')
                    | ('&', '&')
                    | ('|', '|')
                    | ('+', '+')
                    | ('-', '-')
                    | ('-', '>')
                    | ('<', '<')
                    | ('>', '>')
            ) {
                operator.push(next);
                chars.next();
            }
        }
        tokens.push(operator);
    }
    tokens
}
