use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    pub fn number(value: impl ToString) -> Self {
        Self::Number(value.to_string())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => value.parse().ok(),
            Self::String(value) => value.parse().ok(),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields.get(key),
            _ => None,
        }
    }
}

pub fn object(fields: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::Object(fields.into_iter().collect())
}

pub fn stringify(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => out.push_str(value),
        Value::String(value) => write_string(value, out),
        Value::Array(values) => {
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                write_value(value, out);
            }
            out.push(']');
        }
        Value::Object(fields) => {
            out.push('{');
            for (index, (key, value)) in fields.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(value, out);
            }
            out.push('}');
        }
    }
}

fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < '\u{20}' => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
}

pub fn parse(input: &str) -> Result<Value, String> {
    let mut parser = Parser {
        bytes: input.as_bytes(),
        position: 0,
    };
    let value = parser.value()?;
    parser.whitespace();
    if parser.position != parser.bytes.len() {
        return Err(format!("unexpected JSON input at byte {}", parser.position));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.position),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.position += 1;
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        self.whitespace();
        match self.bytes.get(self.position).copied() {
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(format!("unexpected JSON value at byte {}", self.position)),
            None => Err("unexpected end of JSON input".into()),
        }
    }

    fn literal(&mut self, expected: &[u8], value: Value) -> Result<Value, String> {
        let end = self
            .position
            .checked_add(expected.len())
            .ok_or_else(|| "JSON position overflow".to_string())?;
        if self.bytes.get(self.position..end) != Some(expected) {
            return Err(format!("invalid JSON literal at byte {}", self.position));
        }
        self.position = end;
        Ok(value)
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.position;
        if self.bytes.get(self.position) == Some(&b'-') {
            self.position += 1;
        }
        match self.bytes.get(self.position) {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.position += 1;
                while matches!(self.bytes.get(self.position), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return Err(format!("invalid JSON number at byte {start}")),
        }
        if self.bytes.get(self.position) == Some(&b'.') {
            self.position += 1;
            let fraction = self.position;
            while matches!(self.bytes.get(self.position), Some(b'0'..=b'9')) {
                self.position += 1;
            }
            if fraction == self.position {
                return Err(format!("invalid JSON fraction at byte {start}"));
            }
        }
        if matches!(self.bytes.get(self.position), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
                self.position += 1;
            }
            let exponent = self.position;
            while matches!(self.bytes.get(self.position), Some(b'0'..=b'9')) {
                self.position += 1;
            }
            if exponent == self.position {
                return Err(format!("invalid JSON exponent at byte {start}"));
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.position])
            .map_err(|_| format!("invalid JSON number at byte {start}"))?;
        Ok(Value::Number(text.into()))
    }

    fn string(&mut self) -> Result<String, String> {
        if self.bytes.get(self.position) != Some(&b'"') {
            return Err(format!("JSON string expected at byte {}", self.position));
        }
        self.position += 1;
        let mut out = String::new();
        loop {
            let byte = *self
                .bytes
                .get(self.position)
                .ok_or_else(|| "unterminated JSON string".to_string())?;
            self.position += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => out.push(self.escape()?),
                0..=0x1f => return Err("control character in JSON string".into()),
                byte if byte.is_ascii() => out.push(byte as char),
                _ => {
                    let start = self.position - 1;
                    let width = utf8_width(byte)
                        .ok_or_else(|| "invalid UTF-8 in JSON string".to_string())?;
                    let end = start + width;
                    let bytes = self
                        .bytes
                        .get(start..end)
                        .ok_or_else(|| "truncated UTF-8 in JSON string".to_string())?;
                    let text = std::str::from_utf8(bytes)
                        .map_err(|_| "invalid UTF-8 in JSON string".to_string())?;
                    out.push_str(text);
                    self.position = end;
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, String> {
        let byte = *self
            .bytes
            .get(self.position)
            .ok_or_else(|| "unterminated JSON escape".to_string())?;
        self.position += 1;
        match byte {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{08}'),
            b'f' => Ok('\u{0c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => {
                let code = self.hex_u16()?;
                char::from_u32(u32::from(code))
                    .ok_or_else(|| "invalid Unicode escape in JSON string".into())
            }
            _ => Err(format!("invalid JSON escape at byte {}", self.position - 1)),
        }
    }

    fn hex_u16(&mut self) -> Result<u16, String> {
        let end = self.position + 4;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| "truncated Unicode escape".to_string())?;
        self.position = end;
        let mut value = 0u16;
        for byte in bytes {
            value = value
                .checked_mul(16)
                .and_then(|value| value.checked_add(hex_digit(*byte)?))
                .ok_or_else(|| "invalid Unicode escape".to_string())?;
        }
        Ok(value)
    }

    fn array(&mut self) -> Result<Value, String> {
        self.position += 1;
        let mut values = Vec::new();
        self.whitespace();
        if self.bytes.get(self.position) == Some(&b']') {
            self.position += 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b']') => {
                    self.position += 1;
                    return Ok(Value::Array(values));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.position)),
            }
        }
    }

    fn object(&mut self) -> Result<Value, String> {
        self.position += 1;
        let mut fields = BTreeMap::new();
        self.whitespace();
        if self.bytes.get(self.position) == Some(&b'}') {
            self.position += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            if self.bytes.get(self.position) != Some(&b':') {
                return Err(format!("expected ':' at byte {}", self.position));
            }
            self.position += 1;
            let value = self.value()?;
            fields.insert(key, value);
            self.whitespace();
            match self.bytes.get(self.position) {
                Some(b',') => self.position += 1,
                Some(b'}') => {
                    self.position += 1;
                    return Ok(Value::Object(fields));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.position)),
            }
        }
    }
}

fn utf8_width(byte: u8) -> Option<usize> {
    match byte {
        0xC2..=0xDF => Some(2),
        0xE0..=0xEF => Some(3),
        0xF0..=0xF4 => Some(4),
        _ => None,
    }
}

fn hex_digit(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some(u16::from(byte - b'0')),
        b'a'..=b'f' => Some(u16::from(byte - b'a' + 10)),
        b'A'..=b'F' => Some(u16::from(byte - b'A' + 10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_nested_values_and_escapes() {
        let value = object([
            ("message".into(), Value::string("line\nquote \"x\"")),
            (
                "items".into(),
                Value::Array(vec![Value::Bool(true), Value::number(7)]),
            ),
        ]);
        assert_eq!(parse(&stringify(&value)).unwrap(), value);
    }

    #[test]
    fn rejects_trailing_input() {
        assert!(parse("true false").is_err());
    }
}
