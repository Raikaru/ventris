use std::collections::BTreeMap;

use ventris_target::TargetProfile;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RevisionRegion {
    pub name: String,
    pub address: u64,
    pub bytes: Vec<u8>,
}

impl RevisionRegion {
    pub fn new(name: impl Into<String>, address: u64, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            address,
            bytes: bytes.into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BinaryRevision {
    pub id: String,
    pub label: String,
    pub source: String,
    pub target: Option<TargetProfile>,
    pub regions: Vec<RevisionRegion>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RevisionError {
    EmptyId,
    DuplicateRegion(String),
}

impl std::fmt::Display for RevisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyId => f.write_str("revision id must not be empty"),
            Self::DuplicateRegion(name) => {
                write!(f, "revision region {name:?} is already registered")
            }
        }
    }
}

impl std::error::Error for RevisionError {}

impl BinaryRevision {
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        source: impl Into<String>,
        target: Option<TargetProfile>,
    ) -> Result<Self, RevisionError> {
        let id = id.into();
        if id.is_empty() {
            return Err(RevisionError::EmptyId);
        }
        Ok(Self {
            id,
            label: label.into(),
            source: source.into(),
            target,
            regions: Vec::new(),
        })
    }

    pub fn add_region(&mut self, region: RevisionRegion) -> Result<(), RevisionError> {
        if self.regions.iter().any(|item| item.name == region.name) {
            return Err(RevisionError::DuplicateRegion(region.name));
        }
        self.regions.push(region);
        self.regions
            .sort_by(|left, right| left.name.cmp(&right.name));
        Ok(())
    }

    pub fn region(&self, name: &str) -> Option<&RevisionRegion> {
        self.regions.iter().find(|region| region.name == name)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum RegionChangeKind {
    Added,
    Removed,
    Modified,
    Unchanged,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ByteDiffHunk {
    /// Offset relative to the region start, not a file offset.
    pub offset: u64,
    pub address_before: Option<u64>,
    pub address_after: Option<u64>,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegionDiff {
    pub name: String,
    pub kind: RegionChangeKind,
    pub address_before: Option<u64>,
    pub address_after: Option<u64>,
    pub before_size: usize,
    pub after_size: usize,
    pub changed_bytes: usize,
    pub hunks: Vec<ByteDiffHunk>,
}

impl RegionDiff {
    pub fn is_changed(&self) -> bool {
        !matches!(self.kind, RegionChangeKind::Unchanged)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BinaryDiff {
    pub before_id: String,
    pub after_id: String,
    pub target_before: Option<TargetProfile>,
    pub target_after: Option<TargetProfile>,
    pub regions: Vec<RegionDiff>,
    pub changed_regions: usize,
    pub changed_bytes: usize,
}

impl BinaryDiff {
    pub fn is_identical(&self) -> bool {
        self.changed_regions == 0
    }

    pub fn region(&self, name: &str) -> Option<&RegionDiff> {
        self.regions.iter().find(|region| region.name == name)
    }
}

pub fn diff_revisions(before: &BinaryRevision, after: &BinaryRevision) -> BinaryDiff {
    let before_regions = before
        .regions
        .iter()
        .map(|region| (region.name.as_str(), region))
        .collect::<BTreeMap<_, _>>();
    let after_regions = after
        .regions
        .iter()
        .map(|region| (region.name.as_str(), region))
        .collect::<BTreeMap<_, _>>();
    let mut names = before_regions.keys().copied().collect::<Vec<_>>();
    names.extend(after_regions.keys().copied());
    names.sort_unstable();
    names.dedup();

    let regions = names
        .into_iter()
        .map(
            |name| match (before_regions.get(name), after_regions.get(name)) {
                (Some(before), Some(after)) => diff_region(before, after),
                (Some(before), None) => RegionDiff {
                    name: name.to_owned(),
                    kind: RegionChangeKind::Removed,
                    address_before: Some(before.address),
                    address_after: None,
                    before_size: before.bytes.len(),
                    after_size: 0,
                    changed_bytes: before.bytes.len(),
                    hunks: vec![ByteDiffHunk {
                        offset: 0,
                        address_before: Some(before.address),
                        address_after: None,
                        before: before.bytes.clone(),
                        after: Vec::new(),
                    }],
                },
                (None, Some(after)) => RegionDiff {
                    name: name.to_owned(),
                    kind: RegionChangeKind::Added,
                    address_before: None,
                    address_after: Some(after.address),
                    before_size: 0,
                    after_size: after.bytes.len(),
                    changed_bytes: after.bytes.len(),
                    hunks: vec![ByteDiffHunk {
                        offset: 0,
                        address_before: None,
                        address_after: Some(after.address),
                        before: Vec::new(),
                        after: after.bytes.clone(),
                    }],
                },
                (None, None) => unreachable!("region name came from one of the two maps"),
            },
        )
        .collect::<Vec<_>>();

    let changed_regions = regions.iter().filter(|region| region.is_changed()).count();
    let changed_bytes = regions.iter().map(|region| region.changed_bytes).sum();
    BinaryDiff {
        before_id: before.id.clone(),
        after_id: after.id.clone(),
        target_before: before.target,
        target_after: after.target,
        regions,
        changed_regions,
        changed_bytes,
    }
}

fn diff_region(before: &RevisionRegion, after: &RevisionRegion) -> RegionDiff {
    let common = before.bytes.len().min(after.bytes.len());
    let mut hunks = Vec::new();
    let mut changed_bytes = 0;
    let mut index = 0;
    while index < common {
        if before.bytes[index] == after.bytes[index] {
            index += 1;
            continue;
        }
        let start = index;
        while index < common && before.bytes[index] != after.bytes[index] {
            index += 1;
        }
        changed_bytes += index - start;
        hunks.push(ByteDiffHunk {
            offset: start as u64,
            address_before: before.address.checked_add(start as u64),
            address_after: after.address.checked_add(start as u64),
            before: before.bytes[start..index].to_vec(),
            after: after.bytes[start..index].to_vec(),
        });
    }
    if before.bytes.len() != after.bytes.len() {
        let start = common;
        let before_tail = before.bytes[start..].to_vec();
        let after_tail = after.bytes[start..].to_vec();
        changed_bytes += before_tail.len().max(after_tail.len());
        hunks.push(ByteDiffHunk {
            offset: start as u64,
            address_before: before.address.checked_add(start as u64),
            address_after: after.address.checked_add(start as u64),
            before: before_tail,
            after: after_tail,
        });
    }
    let kind = if hunks.is_empty() && before.address == after.address {
        RegionChangeKind::Unchanged
    } else {
        RegionChangeKind::Modified
    };
    RegionDiff {
        name: before.name.clone(),
        kind,
        address_before: Some(before.address),
        address_after: Some(after.address),
        before_size: before.bytes.len(),
        after_size: after.bytes.len(),
        changed_bytes,
        hunks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revision(id: &str, regions: impl IntoIterator<Item = RevisionRegion>) -> BinaryRevision {
        let mut revision =
            BinaryRevision::new(id, id, "fixture.bin", Some(TargetProfile::Ps2)).unwrap();
        for region in regions {
            revision.add_region(region).unwrap();
        }
        revision
    }

    #[test]
    fn rejects_duplicate_revision_regions() {
        assert!(matches!(
            BinaryRevision::new("", "", "", None),
            Err(RevisionError::EmptyId)
        ));
        let mut revision = revision("a", [RevisionRegion::new(".text", 0x1000, [1])]);
        assert!(matches!(
            revision.add_region(RevisionRegion::new(".text", 0x2000, [2])),
            Err(RevisionError::DuplicateRegion(_))
        ));
    }

    #[test]
    fn reports_added_removed_modified_and_unchanged_regions() {
        let before = revision(
            "old",
            [
                RevisionRegion::new(".data", 0x2000, [9]),
                RevisionRegion::new(".removed", 0x3000, [7, 8]),
                RevisionRegion::new(".text", 0x1000, [1, 2, 3, 4]),
            ],
        );
        let after = revision(
            "new",
            [
                RevisionRegion::new(".added", 0x4000, [5]),
                RevisionRegion::new(".data", 0x2000, [9]),
                RevisionRegion::new(".text", 0x1100, [1, 9, 3, 4, 6]),
            ],
        );

        let diff = diff_revisions(&before, &after);
        assert_eq!(diff.changed_regions, 3);
        assert_eq!(diff.changed_bytes, 5);
        assert!(!diff.is_identical());
        assert_eq!(
            diff.region(".data").unwrap().kind,
            RegionChangeKind::Unchanged
        );
        assert_eq!(diff.region(".added").unwrap().kind, RegionChangeKind::Added);
        assert_eq!(
            diff.region(".removed").unwrap().kind,
            RegionChangeKind::Removed
        );
        let text = diff.region(".text").unwrap();
        assert_eq!(text.kind, RegionChangeKind::Modified);
        assert_eq!(text.hunks.len(), 2);
        assert_eq!(text.hunks[0].offset, 1);
        assert_eq!(text.hunks[0].before, vec![2]);
        assert_eq!(text.hunks[0].after, vec![9]);
        assert_eq!(text.hunks[1].offset, 4);
        assert_eq!(text.hunks[1].before, Vec::<u8>::new());
        assert_eq!(text.hunks[1].after, vec![6]);
    }

    #[test]
    fn identical_region_diffs_have_no_hunks() {
        let before = revision("old", [RevisionRegion::new(".text", 0x1000, [1, 2])]);
        let after = revision("new", [RevisionRegion::new(".text", 0x1000, [1, 2])]);
        let diff = diff_revisions(&before, &after);
        assert!(diff.is_identical());
        assert_eq!(diff.changed_bytes, 0);
        assert!(diff.region(".text").unwrap().hunks.is_empty());
    }
}
