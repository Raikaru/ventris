use std::fmt;

use ventris_target::TargetProfile;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PatternError {
    Empty,
    InvalidToken(String),
    LengthMismatch { bytes: usize, masks: usize },
    DuplicateId(String),
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("pattern must contain at least one byte"),
            Self::InvalidToken(token) => write!(f, "invalid pattern token {token:?}"),
            Self::LengthMismatch { bytes, masks } => {
                write!(
                    f,
                    "pattern bytes/masks length mismatch ({bytes} != {masks})"
                )
            }
            Self::DuplicateId(id) => write!(f, "pattern id {id:?} is already registered"),
        }
    }
}

impl std::error::Error for PatternError {}

/// A byte sequence with byte-level masks. A mask bit set to one participates
/// in matching; a zero mask byte is a full wildcard.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BytePattern {
    bytes: Vec<u8>,
    masks: Vec<u8>,
}

impl BytePattern {
    pub fn exact(bytes: impl Into<Vec<u8>>) -> Result<Self, PatternError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(PatternError::Empty);
        }
        let masks = vec![u8::MAX; bytes.len()];
        Ok(Self { bytes, masks })
    }

    pub fn masked(bytes: Vec<u8>, masks: Vec<u8>) -> Result<Self, PatternError> {
        if bytes.is_empty() {
            return Err(PatternError::Empty);
        }
        if bytes.len() != masks.len() {
            return Err(PatternError::LengthMismatch {
                bytes: bytes.len(),
                masks: masks.len(),
            });
        }
        Ok(Self { bytes, masks })
    }

    /// Parse conventional signatures such as `48 8B ?? ?? 89`.
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let mut bytes = Vec::new();
        let mut masks = Vec::new();
        for token in
            text.split(|character: char| character.is_ascii_whitespace() || character == ',')
        {
            if token.is_empty() {
                continue;
            }
            if matches!(token, "?" | "??" | "**") {
                bytes.push(0);
                masks.push(0);
                continue;
            }
            let token = token.strip_prefix("0x").unwrap_or(token);
            if token.len() != 2 {
                return Err(PatternError::InvalidToken(token.to_owned()));
            }
            let byte = u8::from_str_radix(token, 16)
                .map_err(|_| PatternError::InvalidToken(token.to_owned()))?;
            bytes.push(byte);
            masks.push(u8::MAX);
        }
        Self::masked(bytes, masks)
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn masks(&self) -> &[u8] {
        &self.masks
    }

    pub fn matches_at(&self, image: &[u8], offset: usize) -> bool {
        let Some(window) = image.get(offset..offset.saturating_add(self.len())) else {
            return false;
        };
        if window.len() != self.len() {
            return false;
        }
        self.bytes
            .iter()
            .zip(&self.masks)
            .zip(window)
            .all(|((&expected, &mask), &actual)| (actual & mask) == (expected & mask))
    }

    pub fn find_all(&self, image: &[u8]) -> Vec<usize> {
        if self.is_empty() || image.len() < self.len() {
            return Vec::new();
        }
        (0..=image.len() - self.len())
            .filter(|&offset| self.matches_at(image, offset))
            .collect()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PatternKind {
    Function,
    Data,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PatternDefinition {
    pub id: String,
    pub name: String,
    pub kind: PatternKind,
    pub target: Option<TargetProfile>,
    pub pattern: BytePattern,
}

impl PatternDefinition {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        kind: PatternKind,
        pattern: BytePattern,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            kind,
            target: None,
            pattern,
        }
    }

    pub fn for_target(mut self, target: TargetProfile) -> Self {
        self.target = Some(target);
        self
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PatternHit<'a> {
    pub definition: &'a PatternDefinition,
    pub offset: usize,
    pub address: u64,
}

#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct PatternLibrary {
    definitions: Vec<PatternDefinition>,
}

impl PatternLibrary {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, definition: PatternDefinition) -> Result<(), PatternError> {
        if self.definitions.iter().any(|item| item.id == definition.id) {
            return Err(PatternError::DuplicateId(definition.id));
        }
        self.definitions.push(definition);
        self.definitions
            .sort_by(|left, right| left.id.cmp(&right.id));
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&PatternDefinition> {
        self.definitions
            .iter()
            .find(|definition| definition.id == id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &PatternDefinition> {
        self.definitions.iter()
    }

    pub fn scan<'a>(
        &'a self,
        image: &[u8],
        base: u64,
        target: Option<TargetProfile>,
    ) -> Vec<PatternHit<'a>> {
        let mut hits = Vec::new();
        for definition in &self.definitions {
            if let Some(required) = definition.target {
                if target != Some(required) {
                    continue;
                }
            }
            for offset in definition.pattern.find_all(image) {
                hits.push(PatternHit {
                    definition,
                    offset,
                    address: base.saturating_add(offset as u64),
                });
            }
        }
        hits.sort_by(|left, right| {
            left.address
                .cmp(&right.address)
                .then_with(|| left.definition.id.cmp(&right.definition.id))
        });
        hits
    }

    pub fn first<'a>(
        &'a self,
        image: &[u8],
        base: u64,
        target: Option<TargetProfile>,
    ) -> Option<PatternHit<'a>> {
        self.scan(image, base, target).into_iter().next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_wildcard_patterns() {
        let pattern = BytePattern::parse("48 8B ??, 89").unwrap();
        assert_eq!(pattern.len(), 4);
        assert!(pattern.matches_at(&[0x00, 0x48, 0x8B, 0x41, 0x89], 1));
        assert_eq!(
            pattern.find_all(&[0x48, 0x8B, 0x41, 0x89, 0x48, 0x8B, 0x42, 0x89]),
            vec![0, 4]
        );
    }

    #[test]
    fn rejects_invalid_patterns_and_duplicate_ids() {
        assert!(matches!(BytePattern::parse(""), Err(PatternError::Empty)));
        assert!(matches!(
            BytePattern::parse("4"),
            Err(PatternError::InvalidToken(_))
        ));
        assert!(matches!(
            BytePattern::masked(vec![1], vec![]),
            Err(PatternError::LengthMismatch { .. })
        ));

        let pattern = BytePattern::exact([0x90]).unwrap();
        let mut library = PatternLibrary::new();
        library
            .insert(PatternDefinition::new(
                "nop",
                "nop",
                PatternKind::Function,
                pattern.clone(),
            ))
            .unwrap();
        assert!(matches!(
            library.insert(PatternDefinition::new(
                "nop",
                "again",
                PatternKind::Data,
                pattern
            )),
            Err(PatternError::DuplicateId(_))
        ));
    }

    #[test]
    fn scans_in_stable_address_order_and_filters_target_profiles() {
        let mut library = PatternLibrary::new();
        library
            .insert(
                PatternDefinition::new(
                    "ps2-call",
                    "PS2 call stub",
                    PatternKind::Function,
                    BytePattern::exact([0x01, 0x02]).unwrap(),
                )
                .for_target(TargetProfile::Ps2),
            )
            .unwrap();
        library
            .insert(PatternDefinition::new(
                "generic",
                "generic marker",
                PatternKind::Data,
                BytePattern::exact([0x02]).unwrap(),
            ))
            .unwrap();

        let hits = library.scan(&[0x00, 0x01, 0x02], 0x8000, Some(TargetProfile::Ps2));
        assert_eq!(
            hits.iter()
                .map(|hit| hit.definition.id.as_str())
                .collect::<Vec<_>>(),
            vec!["ps2-call", "generic"]
        );
        assert_eq!(hits[0].address, 0x8001);
        assert_eq!(
            library
                .scan(&[0x01, 0x02], 0, Some(TargetProfile::Ps1))
                .len(),
            1
        );
        assert_eq!(library.scan(&[0x01, 0x02], 0, None).len(), 1);
    }
}
