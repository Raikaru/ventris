use std::collections::BTreeMap;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AssetKind {
    Texture,
    Model,
    Animation,
    Sound,
    Table,
    Script,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GameAsset {
    pub id: String,
    pub name: String,
    pub kind: AssetKind,
    pub address: Option<u64>,
    pub size: Option<u64>,
    pub source: String,
    pub properties: BTreeMap<String, String>,
}

impl GameAsset {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        kind: AssetKind,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            kind,
            address: None,
            size: None,
            source: source.into(),
            properties: BTreeMap::new(),
        }
    }

    pub fn at(mut self, address: u64, size: u64) -> Self {
        self.address = Some(address);
        self.size = Some(size);
        self
    }

    pub fn property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GameScript {
    pub id: String,
    pub name: String,
    pub entry: Option<u64>,
    pub source: String,
    pub language: Option<String>,
    pub properties: BTreeMap<String, String>,
}

impl GameScript {
    pub fn new(id: impl Into<String>, name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            entry: None,
            source: source.into(),
            language: None,
            properties: BTreeMap::new(),
        }
    }

    pub fn entry(mut self, address: u64) -> Self {
        self.entry = Some(address);
        self
    }

    pub fn language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AssetTarget {
    Asset(String),
    Script(String),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AssetLinkKind {
    References,
    Loads,
    Defines,
    Calls,
    Generates,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssetLink {
    pub code_address: u64,
    pub target: AssetTarget,
    pub kind: AssetLinkKind,
    pub confidence: u8,
    pub note: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AssetError {
    EmptyId,
    DuplicateAsset(String),
    DuplicateScript(String),
    UnknownAsset(String),
    UnknownScript(String),
    InvalidConfidence(u8),
}

impl std::fmt::Display for AssetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyId => f.write_str("asset or script id must not be empty"),
            Self::DuplicateAsset(id) => write!(f, "asset {id:?} is already registered"),
            Self::DuplicateScript(id) => write!(f, "script {id:?} is already registered"),
            Self::UnknownAsset(id) => write!(f, "unknown asset {id:?}"),
            Self::UnknownScript(id) => write!(f, "unknown script {id:?}"),
            Self::InvalidConfidence(value) => {
                write!(f, "confidence must be between 0 and 100, got {value}")
            }
        }
    }
}

impl std::error::Error for AssetError {}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct AssetCatalog {
    pub assets: Vec<GameAsset>,
    pub scripts: Vec<GameScript>,
    pub links: Vec<AssetLink>,
}

impl AssetCatalog {
    pub fn register_asset(&mut self, asset: GameAsset) -> Result<(), AssetError> {
        if asset.id.is_empty() {
            return Err(AssetError::EmptyId);
        }
        if self.assets.iter().any(|item| item.id == asset.id) {
            return Err(AssetError::DuplicateAsset(asset.id));
        }
        self.assets.push(asset);
        self.assets.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(())
    }

    pub fn register_script(&mut self, script: GameScript) -> Result<(), AssetError> {
        if script.id.is_empty() {
            return Err(AssetError::EmptyId);
        }
        if self.scripts.iter().any(|item| item.id == script.id) {
            return Err(AssetError::DuplicateScript(script.id));
        }
        self.scripts.push(script);
        self.scripts.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(())
    }

    pub fn asset(&self, id: &str) -> Option<&GameAsset> {
        self.assets.iter().find(|asset| asset.id == id)
    }

    pub fn script(&self, id: &str) -> Option<&GameScript> {
        self.scripts.iter().find(|script| script.id == id)
    }

    pub fn link(
        &mut self,
        code_address: u64,
        target: AssetTarget,
        kind: AssetLinkKind,
        confidence: u8,
        note: Option<String>,
    ) -> Result<(), AssetError> {
        if confidence > 100 {
            return Err(AssetError::InvalidConfidence(confidence));
        }
        match &target {
            AssetTarget::Asset(id) if self.asset(id).is_none() => {
                return Err(AssetError::UnknownAsset(id.clone()));
            }
            AssetTarget::Script(id) if self.script(id).is_none() => {
                return Err(AssetError::UnknownScript(id.clone()));
            }
            _ => {}
        }
        let link = AssetLink {
            code_address,
            target,
            kind,
            confidence,
            note,
        };
        if !self.links.contains(&link) {
            self.links.push(link);
            self.links.sort_by(|left, right| {
                left.code_address
                    .cmp(&right.code_address)
                    .then_with(|| format!("{:?}", left.target).cmp(&format!("{:?}", right.target)))
            });
        }
        Ok(())
    }

    pub fn links_for_code(&self, code_address: u64) -> impl Iterator<Item = &AssetLink> {
        self.links
            .iter()
            .filter(move |link| link.code_address == code_address)
    }

    pub fn links_for_asset<'a>(&'a self, id: &'a str) -> impl Iterator<Item = &'a AssetLink> + 'a {
        self.links
            .iter()
            .filter(move |link| matches!(&link.target, AssetTarget::Asset(target) if target == id))
    }

    pub fn links_for_script<'a>(&'a self, id: &'a str) -> impl Iterator<Item = &'a AssetLink> + 'a {
        self.links
            .iter()
            .filter(move |link| matches!(&link.target, AssetTarget::Script(target) if target == id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_functions_to_assets_and_scripts_with_validation() {
        let mut catalog = AssetCatalog::default();
        catalog
            .register_asset(
                GameAsset::new("hero", "Hero model", AssetKind::Model, "assets.tbl")
                    .at(0x5000, 0x120)
                    .property("format", "mdl"),
            )
            .unwrap();
        catalog
            .register_script(
                GameScript::new("battle-start", "Battle start", "scripts/battle.lua")
                    .entry(0x7000)
                    .language("lua"),
            )
            .unwrap();
        catalog
            .link(
                0x1000,
                AssetTarget::Asset("hero".into()),
                AssetLinkKind::Loads,
                90,
                Some("loader resolves model table entry".into()),
            )
            .unwrap();
        catalog
            .link(
                0x1004,
                AssetTarget::Script("battle-start".into()),
                AssetLinkKind::Calls,
                80,
                None,
            )
            .unwrap();
        assert_eq!(catalog.asset("hero").unwrap().properties["format"], "mdl");
        assert_eq!(catalog.script("battle-start").unwrap().entry, Some(0x7000));
        assert_eq!(catalog.links_for_code(0x1000).count(), 1);
        assert_eq!(catalog.links_for_asset("hero").count(), 1);
        assert_eq!(catalog.links_for_script("battle-start").count(), 1);
        assert!(matches!(
            catalog.link(
                0x1008,
                AssetTarget::Asset("missing".into()),
                AssetLinkKind::References,
                100,
                None
            ),
            Err(AssetError::UnknownAsset(_))
        ));
    }

    #[test]
    fn rejects_duplicate_ids_and_invalid_confidence() {
        let mut catalog = AssetCatalog::default();
        catalog
            .register_asset(GameAsset::new("x", "x", AssetKind::Unknown, "x"))
            .unwrap();
        assert!(matches!(
            catalog.register_asset(GameAsset::new("x", "x2", AssetKind::Unknown, "x2")),
            Err(AssetError::DuplicateAsset(_))
        ));
        assert!(matches!(
            catalog.link(
                1,
                AssetTarget::Asset("x".into()),
                AssetLinkKind::References,
                101,
                None
            ),
            Err(AssetError::InvalidConfidence(101))
        ));
    }
}
