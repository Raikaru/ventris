//! Symbol storage and local-scope recovery, ported from Ghidra 12.1.3's
//! `Scope`, `ScopeInternal`, `ScopeLocal`, `Symbol`, and `SymbolEntry`.
//!
//! Source authority: `database.hh`/`database.cc` and `varmap.hh`/`varmap.cc`
//! at Ghidra commit `8b4c91d4d5bd154962b2fbade0df199585b98365`.
//!
//! The important invariant is that an address is not a symbol by itself.  A
//! [`SymbolEntry`] also has a code liveness range, so a stack slot can be
//! recycled without causing two unrelated locals to be joined.  `Scope` keeps
//! both indexes: storage for address queries and symbol/name membership for
//! multi-entry merging.  `ScopeLocal` adds the mapped/unmapped stack window
//! used by `ActionRestructureVarnode` and `ActionMappedLocalSync`.
//!
//! The graph does not yet expose Ghidra's `Architecture`, `Datatype` pointer
//! identity, `RangeList` over address spaces, `MapState`, `HighVariable`, or
//! linked-varnode attachment lists.  This module therefore stores the rich
//! graph [`DataType`] by value, represents code ranges with [`Liveness`], and
//! leaves graph mutation to the passes that own `Funcdata`.  Dynamic entries
//! are fully represented and iterable; resolving a dynamic hash to a Varnode
//! remains a `Funcdata` operation.

use std::collections::{BTreeMap, BTreeSet};

pub use super::guard::Location;
use super::typefactory::DataType;
use super::{Funcdata, SeqNum};
use crate::native::Type;

/// Stable identity for a [`Symbol`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(pub u64);

/// Stable identity for a [`SymbolEntry`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryId(pub u64);

/// A code address used when selecting a live symbol entry.
///
/// Ghidra's `Address` has an address-space component; the graph's operation
/// sequence already identifies the code address and order, while the storage
/// address-space component is carried by [`Location`].  Ordering includes the
/// p-code order so callers can distinguish two uses at one instruction address
/// when they provide that information.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UsePoint {
    pub address: u64,
    pub order: u32,
}

impl UsePoint {
    pub const fn new(address: u64, order: u32) -> Self {
        Self { address, order }
    }
}

impl From<u64> for UsePoint {
    fn from(address: u64) -> Self {
        Self { address, order: 0 }
    }
}

impl From<SeqNum> for UsePoint {
    fn from(seq: SeqNum) -> Self {
        Self {
            address: seq.address,
            order: seq.order,
        }
    }
}

impl From<&UsePoint> for UsePoint {
    fn from(point: &UsePoint) -> Self {
        *point
    }
}

impl From<&SeqNum> for UsePoint {
    fn from(seq: &SeqNum) -> Self {
        (*seq).into()
    }
}

/// One inclusive code-address range in a symbol's liveness set.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UseRange {
    pub start: UsePoint,
    pub end: UsePoint,
}

impl UseRange {
    pub fn new<S: Into<UsePoint>, E: Into<UsePoint>>(start: S, end: E) -> Self {
        let start = start.into();
        let end = end.into();
        if start <= end {
            Self { start, end }
        } else {
            Self {
                start: end,
                end: start,
            }
        }
    }

    pub fn contains<P: Into<UsePoint>>(&self, point: P) -> bool {
        let point = point.into();
        self.start <= point && point <= self.end
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    fn span(&self) -> u128 {
        let start = (u128::from(self.start.address) << 32) | u128::from(self.start.order);
        let end = (u128::from(self.end.address) << 32) | u128::from(self.end.order);
        end.saturating_sub(start)
    }
}

/// Code liveness for a [`SymbolEntry`].
///
/// An empty Ghidra `RangeList` means "valid everywhere" for an address-tied
/// symbol.  `All` has that same meaning.  Non-empty ranges are inclusive,
/// matching `RangeList::inRange`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Liveness {
    All,
    Ranges(Vec<UseRange>),
}

impl Default for Liveness {
    fn default() -> Self {
        Self::All
    }
}

impl Liveness {
    pub const fn all() -> Self {
        Self::All
    }

    pub fn at<P: Into<UsePoint>>(point: P) -> Self {
        let point = point.into();
        Self::Ranges(vec![UseRange::new(point, point)])
    }

    pub fn range<S: Into<UsePoint>, E: Into<UsePoint>>(start: S, end: E) -> Self {
        Self::Ranges(vec![UseRange::new(start, end)])
    }

    pub fn from_ranges(ranges: impl IntoIterator<Item = UseRange>) -> Self {
        let mut ranges: Vec<_> = ranges.into_iter().collect();
        ranges.sort_unstable();
        ranges.dedup();
        if ranges.is_empty() {
            Self::All
        } else {
            Self::Ranges(ranges)
        }
    }

    pub fn contains<P: Into<UsePoint>>(&self, point: P) -> bool {
        let point = point.into();
        match self {
            Self::All => true,
            Self::Ranges(ranges) => ranges.iter().any(|range| range.contains(point)),
        }
    }
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    pub fn first(&self) -> Option<UsePoint> {
        match self {
            Self::All => None,
            Self::Ranges(ranges) => ranges.first().map(|range| range.start),
        }
    }

    fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::All, _) | (_, Self::All) => true,
            (Self::Ranges(left), Self::Ranges(right)) => {
                left.iter().any(|a| right.iter().any(|b| a.overlaps(b)))
            }
        }
    }

    fn specificity(&self) -> u128 {
        match self {
            Self::All => u128::MAX,
            Self::Ranges(ranges) => ranges.iter().map(UseRange::span).min().unwrap_or(u128::MAX),
        }
    }
}

/// Storage range used for scope ownership, mapped windows, and read-only data.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageRange {
    pub space: u32,
    pub first: u64,
    pub last: u64,
}

impl StorageRange {
    pub fn new(space: u32, first: u64, size: u32) -> Option<Self> {
        (size != 0).then(|| Self {
            space,
            first,
            last: first.saturating_add(u64::from(size) - 1),
        })
    }

    pub const fn from_bounds(space: u32, first: u64, last: u64) -> Self {
        Self { space, first, last }
    }

    pub fn contains(&self, location: Location) -> bool {
        self.space == location.space
            && location.offset >= self.first
            && location
                .offset
                .saturating_add(u64::from(location.size).saturating_sub(1))
                <= self.last
    }

    pub fn intersects(&self, location: Location) -> bool {
        self.space == location.space
            && location.offset <= self.last
            && self.first
                <= location
                    .offset
                    .saturating_add(u64::from(location.size).saturating_sub(1))
    }

    pub fn size(&self) -> u32 {
        self.last
            .saturating_sub(self.first)
            .saturating_add(1)
            .min(u64::from(u32::MAX)) as u32
    }
}

/// Symbol categories used by the prototype and local-variable actions.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i16)]
pub enum SymbolCategory {
    #[default]
    NoCategory = -1,
    FunctionParameter = 0,
    Equate = 1,
    UnionFacet = 2,
    FakeInput = 3,
}

/// Boolean properties carried by a symbol or inherited by its entries.
///
/// The constants correspond to the Varnode properties read by the eight
/// consumers: `typelock`, `namelock`, `readonly`, `addrtied`, `volatil`,
/// `persist`, `indirectstorage`, `hiddenretparm`, `isolate`, and
/// `merge_problems`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SymbolFlags(pub u32);

impl SymbolFlags {
    pub const TYPE_LOCKED: Self = Self(1 << 0);
    pub const NAME_LOCKED: Self = Self(1 << 1);
    pub const READ_ONLY: Self = Self(1 << 2);
    pub const ADDRESS_TIED: Self = Self(1 << 3);
    pub const VOLATILE: Self = Self(1 << 4);
    pub const PERSISTENT: Self = Self(1 << 5);
    pub const INDIRECT_STORAGE: Self = Self(1 << 6);
    pub const HIDDEN_RETURN: Self = Self(1 << 7);
    pub const ISOLATED: Self = Self(1 << 8);
    pub const MERGE_PROBLEMS: Self = Self(1 << 9);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl std::ops::BitOr for SymbolFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

/// Properties specific to one storage mapping, mirroring `SymbolEntry`'s
/// `extraflags` field.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EntryFlags(pub u32);

impl EntryFlags {
    pub const PIECE_LOW: Self = Self(1 << 0);
    pub const PIECE_HIGH: Self = Self(1 << 1);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}
impl std::ops::BitOr for EntryFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// A symbol in a scope's name table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    id: SymbolId,
    name: String,
    display_name: String,
    ty: DataType,
    category: SymbolCategory,
    category_index: Option<u16>,
    flags: SymbolFlags,
    entries: Vec<EntryId>,
}

impl Symbol {
    pub fn new<N: Into<String>, T: Into<DataType>>(name: N, ty: T) -> Self {
        let name = name.into();
        Self {
            id: SymbolId::default(),
            display_name: name.clone(),
            name,
            ty: ty.into(),
            category: SymbolCategory::NoCategory,
            category_index: None,
            flags: SymbolFlags::default(),
            entries: Vec::new(),
        }
    }

    pub fn id(&self) -> SymbolId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn ty(&self) -> &DataType {
        &self.ty
    }

    /// Ghidra spelling retained as a readable Rust accessor for ported rules.
    pub fn get_type(&self) -> &DataType {
        self.ty()
    }

    pub fn category(&self) -> SymbolCategory {
        self.category
    }

    pub fn category_index(&self) -> Option<u16> {
        self.category_index
    }

    pub fn flags(&self) -> SymbolFlags {
        self.flags
    }

    pub fn is_type_locked(&self) -> bool {
        self.flags.contains(SymbolFlags::TYPE_LOCKED)
    }

    pub fn is_name_locked(&self) -> bool {
        self.flags.contains(SymbolFlags::NAME_LOCKED)
    }

    pub fn is_read_only(&self) -> bool {
        self.flags.contains(SymbolFlags::READ_ONLY)
    }

    pub fn is_address_tied(&self) -> bool {
        self.flags.contains(SymbolFlags::ADDRESS_TIED)
    }

    pub fn is_volatile(&self) -> bool {
        self.flags.contains(SymbolFlags::VOLATILE)
    }

    pub fn is_persistent(&self) -> bool {
        self.flags.contains(SymbolFlags::PERSISTENT)
    }

    pub fn is_indirect_storage(&self) -> bool {
        self.flags.contains(SymbolFlags::INDIRECT_STORAGE)
    }

    pub fn is_hidden_return(&self) -> bool {
        self.flags.contains(SymbolFlags::HIDDEN_RETURN)
    }

    /// Return the entry identity at a symbol-list position.  The owning
    /// [`Scope`] resolves it to a [`SymbolEntry`] with [`Scope::get_map_entry`].
    pub fn get_map_entry(&self, index: usize) -> Option<EntryId> {
        self.entries.get(index).copied()
    }

    pub fn is_multi_entry(&self) -> bool {
        self.entries.len() > 1
    }

    pub fn has_merge_problems(&self) -> bool {
        self.flags.contains(SymbolFlags::MERGE_PROBLEMS)
    }

    pub fn is_isolated(&self) -> bool {
        self.flags.contains(SymbolFlags::ISOLATED)
    }

    pub fn is_name_undefined(&self) -> bool {
        self.name.starts_with("$$undef") && self.name.len() == 15
    }

    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    pub fn entry_ids(&self) -> &[EntryId] {
        &self.entries
    }

    pub fn set_category(&mut self, category: SymbolCategory, index: Option<u16>) {
        self.category = category;
        self.category_index = index;
    }

    pub fn set_flags(&mut self, flags: SymbolFlags) {
        self.flags = flags;
    }

    pub fn set_flag(&mut self, flag: SymbolFlags, enabled: bool) {
        self.flags = if enabled {
            self.flags.union(flag)
        } else {
            self.flags.without(flag)
        };
    }

    pub fn set_merge_problems(&mut self) {
        self.flags = self.flags.union(SymbolFlags::MERGE_PROBLEMS);
    }

    pub fn set_isolated(&mut self, isolated: bool) {
        self.set_flag(SymbolFlags::ISOLATED, isolated);
        if isolated {
            self.set_flag(SymbolFlags::TYPE_LOCKED, true);
        }
    }

    fn set_id(&mut self, id: SymbolId) {
        self.id = id;
    }

    fn set_name(&mut self, name: String) {
        self.name = name.clone();
        self.display_name = name;
    }

    fn add_entry(&mut self, entry: EntryId) {
        if !self.entries.contains(&entry) {
            self.entries.push(entry);
        }
    }

    fn remove_entry(&mut self, entry: EntryId) {
        self.entries.retain(|candidate| *candidate != entry);
    }
}

/// One storage mapping of a symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolEntry {
    id: EntryId,
    symbol: SymbolId,
    storage: Option<Location>,
    dynamic_hash: Option<u64>,
    offset: u32,
    size: u32,
    use_range: Liveness,
    flags: EntryFlags,
}

impl SymbolEntry {
    pub fn new(symbol: SymbolId, storage: Location, use_range: Liveness) -> Self {
        Self {
            id: EntryId::default(),
            symbol,
            storage: Some(storage),
            dynamic_hash: None,
            offset: 0,
            size: storage.size,
            use_range,
            flags: EntryFlags::default(),
        }
    }

    pub fn dynamic(
        symbol: SymbolId,
        hash: u64,
        offset: u32,
        size: u32,
        use_range: Liveness,
    ) -> Self {
        Self {
            id: EntryId::default(),
            symbol,
            storage: None,
            dynamic_hash: Some(hash),
            offset,
            size,
            use_range,
            flags: EntryFlags::default(),
        }
    }

    pub fn id(&self) -> EntryId {
        self.id
    }

    pub fn symbol_id(&self) -> SymbolId {
        self.symbol
    }
    /// Ghidra-style alias for [`Self::symbol_id`].
    pub fn get_symbol(&self) -> SymbolId {
        self.symbol_id()
    }
    /// Ghidra-style alias used by `StringSequence`.
    pub fn get_addr(&self) -> Option<Location> {
        self.location()
    }

    /// The storage address, or `None` for a dynamic hash mapping.
    pub fn location(&self) -> Option<Location> {
        self.storage
    }

    /// Ghidra-style alias for [`Self::location`].
    pub fn get_location(&self) -> Option<Location> {
        self.location()
    }

    pub fn dynamic_hash(&self) -> Option<u64> {
        self.dynamic_hash
    }

    pub fn is_dynamic(&self) -> bool {
        self.dynamic_hash.is_some()
    }

    pub fn offset(&self) -> u32 {
        self.offset
    }

    pub fn get_offset(&self) -> u32 {
        self.offset()
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn get_size(&self) -> u32 {
        self.size()
    }

    pub fn first(&self) -> Option<u64> {
        self.storage.map(|location| location.offset)
    }

    pub fn get_first(&self) -> Option<u64> {
        self.first()
    }

    pub fn last(&self) -> Option<u64> {
        self.storage.map(|location| {
            location
                .offset
                .saturating_add(u64::from(location.size).saturating_sub(1))
        })
    }

    pub fn get_last(&self) -> Option<u64> {
        self.last()
    }

    pub fn get_use_limit(&self) -> &Liveness {
        self.use_range()
    }

    pub fn use_range(&self) -> &Liveness {
        &self.use_range
    }

    pub fn first_use_point(&self) -> Option<UsePoint> {
        self.use_range.first()
    }

    pub fn in_use<P: Into<UsePoint>>(&self, point: P) -> bool {
        self.use_range.contains(point)
    }

    pub fn flags(&self) -> EntryFlags {
        self.flags
    }

    pub fn is_piece(&self) -> bool {
        self.flags
            .contains(EntryFlags::PIECE_LOW | EntryFlags::PIECE_HIGH)
            || self.flags.contains(EntryFlags::PIECE_LOW)
            || self.flags.contains(EntryFlags::PIECE_HIGH)
    }

    pub fn set_flags(&mut self, flags: EntryFlags) {
        self.flags = flags;
    }

    pub fn set_use_range(&mut self, use_range: Liveness) {
        self.use_range = use_range;
    }

    pub fn set_storage(&mut self, storage: Location) {
        self.storage = Some(storage);
        self.dynamic_hash = None;
        self.size = storage.size;
    }

    fn set_id(&mut self, id: EntryId) {
        self.id = id;
    }
}

/// Alias verdict supplied by the standalone alias-analysis object.
///
/// `ScopeLocal` owns the mapped/unmapped question.  It must not reimplement
/// pointer gathering, so callers that have an [`AliasChecker`] pass it through
/// [`ScopeLocal::is_unmapped_unaliased_with_alias`].
pub trait AliasVerdict {
    fn has_local_alias(&mut self, data: &Funcdata, location: Location) -> bool;
}

/// The symbol table for one namespace or function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    name: String,
    symbols: BTreeMap<SymbolId, Symbol>,
    entries: BTreeMap<EntryId, SymbolEntry>,
    by_location: BTreeMap<Location, Vec<EntryId>>,
    dynamic_entries: Vec<EntryId>,
    multi_entry_names: BTreeMap<String, BTreeSet<SymbolId>>,
    owned_ranges: Vec<StorageRange>,
    read_only_ranges: Vec<StorageRange>,
    next_symbol: u64,
    next_entry: u64,
}

/// `ScopeInternal` is Ghidra's in-memory implementation of `Scope`; Rust's
/// owned map already provides that implementation directly.
pub type ScopeInternal = Scope;

impl Scope {
    pub fn new<N: Into<String>>(name: N) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn add_symbol<N: Into<String>, T: Into<DataType>>(&mut self, name: N, ty: T) -> SymbolId {
        self.insert_symbol(Symbol::new(name, ty))
    }

    pub fn add_symbol_with_category<N: Into<String>, T: Into<DataType>>(
        &mut self,
        name: N,
        ty: T,
        category: SymbolCategory,
        category_index: Option<u16>,
    ) -> SymbolId {
        let mut symbol = Symbol::new(name, ty);
        symbol.set_category(category, category_index);
        self.insert_symbol(symbol)
    }

    pub fn insert_symbol(&mut self, mut symbol: Symbol) -> SymbolId {
        let id = if symbol.id() == SymbolId::default() || self.symbols.contains_key(&symbol.id()) {
            self.next_symbol = self.next_symbol.saturating_add(1).max(1);
            SymbolId(self.next_symbol)
        } else {
            self.next_symbol = self.next_symbol.max(symbol.id().0);
            symbol.id()
        };
        symbol.set_id(id);
        self.symbols.insert(id, symbol);
        id
    }

    pub fn symbol(&self, id: SymbolId) -> Option<&Symbol> {
        self.symbols.get(&id)
    }

    pub fn symbol_mut(&mut self, id: SymbolId) -> Option<&mut Symbol> {
        self.symbols.get_mut(&id)
    }

    pub fn symbols(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols.values()
    }

    pub fn find_by_name(&self, name: &str) -> Vec<SymbolId> {
        self.symbols
            .values()
            .filter(|symbol| symbol.name() == name)
            .map(Symbol::id)
            .collect()
    }

    pub fn is_name_used(&self, name: &str) -> bool {
        self.symbols.values().any(|symbol| symbol.name() == name)
    }

    pub fn make_name_unique(&self, requested: &str) -> String {
        if !self.is_name_used(requested) {
            return requested.to_owned();
        }
        let mut index = 1u32;
        loop {
            let candidate = format!("{requested}_{index}");
            if !self.is_name_used(&candidate) {
                return candidate;
            }
            index = index.saturating_add(1);
        }
    }

    pub fn rename_symbol<N: Into<String>>(&mut self, id: SymbolId, name: N) -> bool {
        let name = name.into();
        let (old_name, new_name, was_multi) = {
            let Some(symbol) = self.symbols.get_mut(&id) else {
                return false;
            };
            let old_name = symbol.name().to_owned();
            let was_multi = symbol.is_multi_entry();
            symbol.set_name(name);
            (old_name, symbol.name().to_owned(), was_multi)
        };
        if was_multi {
            if let Some(ids) = self.multi_entry_names.get_mut(&old_name) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.multi_entry_names.remove(&old_name);
                }
            }
            self.multi_entry_names
                .entry(new_name)
                .or_default()
                .insert(id);
        }
        true
    }

    /// Add a fixed storage mapping.  The same `Location` may be inserted more
    /// than once when the liveness ranges do not overlap.
    pub fn add_map(
        &mut self,
        symbol: SymbolId,
        location: Location,
        use_range: Liveness,
    ) -> Option<EntryId> {
        self.symbols
            .contains_key(&symbol)
            .then(|| self.insert_entry(SymbolEntry::new(symbol, location, use_range)))
    }

    /// Convenience mapping for an address-tied symbol valid throughout code.
    pub fn add_map_point(&mut self, symbol: SymbolId, location: Location) -> Option<EntryId> {
        self.add_map(symbol, location, Liveness::All)
    }

    pub fn add_dynamic_map(
        &mut self,
        symbol: SymbolId,
        hash: u64,
        offset: u32,
        size: u32,
        use_range: Liveness,
    ) -> Option<EntryId> {
        self.symbols
            .contains_key(&symbol)
            .then(|| self.insert_entry(SymbolEntry::dynamic(symbol, hash, offset, size, use_range)))
    }

    pub fn insert_entry(&mut self, mut entry: SymbolEntry) -> EntryId {
        assert!(self.symbols.contains_key(&entry.symbol_id()));
        self.next_entry = self.next_entry.saturating_add(1).max(1);
        let id = EntryId(self.next_entry);
        entry.set_id(id);
        let symbol = entry.symbol_id();
        if let Some(location) = entry.location() {
            self.by_location.entry(location).or_default().push(id);
        } else {
            self.dynamic_entries.push(id);
        }
        self.entries.insert(id, entry);
        if let Some(symbol) = self.symbols.get_mut(&symbol) {
            symbol.add_entry(id);
        }
        self.refresh_multi_entry(symbol);
        id
    }

    pub fn entry(&self, id: EntryId) -> Option<&SymbolEntry> {
        self.entries.get(&id)
    }

    pub fn entry_mut(&mut self, id: EntryId) -> Option<&mut SymbolEntry> {
        self.entries.get_mut(&id)
    }

    pub fn entries(&self) -> impl Iterator<Item = &SymbolEntry> {
        self.entries.values()
    }

    pub fn entry_symbol(&self, entry: EntryId) -> Option<&Symbol> {
        self.entries
            .get(&entry)
            .and_then(|entry| self.symbol(entry.symbol_id()))
    }

    pub fn symbol_entries(&self, symbol: SymbolId) -> Vec<&SymbolEntry> {
        self.symbol(symbol)
            .map(|symbol| {
                symbol
                    .entry_ids()
                    .iter()
                    .filter_map(|entry| self.entry(*entry))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Return a symbol's entry by its stable position in the multi-entry list.
    pub fn get_map_entry(&self, symbol: SymbolId, index: usize) -> Option<&SymbolEntry> {
        self.symbol(symbol)
            .and_then(|symbol| symbol.entry_ids().get(index))
            .and_then(|entry| self.entry(*entry))
    }

    pub fn remove_entry(&mut self, id: EntryId) -> bool {
        let Some(entry) = self.entries.remove(&id) else {
            return false;
        };
        let symbol = entry.symbol_id();
        if let Some(location) = entry.location() {
            if let Some(ids) = self.by_location.get_mut(&location) {
                ids.retain(|candidate| *candidate != id);
                if ids.is_empty() {
                    self.by_location.remove(&location);
                }
            }
        } else {
            self.dynamic_entries.retain(|candidate| *candidate != id);
        }
        if let Some(symbol_ref) = self.symbols.get_mut(&symbol) {
            symbol_ref.remove_entry(id);
        }
        self.refresh_multi_entry(symbol);
        true
    }

    pub fn remove_symbol(&mut self, id: SymbolId) -> bool {
        let Some(symbol) = self.symbols.remove(&id) else {
            return false;
        };
        for entry in symbol.entry_ids().to_vec() {
            let _ = self.remove_entry(entry);
        }
        self.multi_entry_names.values_mut().for_each(|ids| {
            ids.remove(&id);
        });
        self.multi_entry_names.retain(|_, ids| !ids.is_empty());
        true
    }

    pub fn clear_category(&mut self, category: SymbolCategory) -> usize {
        let ids: Vec<_> = self
            .symbols
            .values()
            .filter(|symbol| symbol.category() == category)
            .map(Symbol::id)
            .collect();
        let count = ids.len();
        for id in ids {
            self.remove_symbol(id);
        }
        count
    }

    pub fn set_category(
        &mut self,
        id: SymbolId,
        category: SymbolCategory,
        category_index: Option<u16>,
    ) -> bool {
        self.symbol_mut(id)
            .map(|symbol| symbol.set_category(category, category_index))
            .is_some()
    }

    pub fn set_symbol_flags(&mut self, id: SymbolId, flags: SymbolFlags) -> bool {
        self.symbol_mut(id)
            .map(|symbol| symbol.set_flags(flags))
            .is_some()
    }

    pub fn set_entry_flags(&mut self, id: EntryId, flags: EntryFlags) -> bool {
        self.entry_mut(id)
            .map(|entry| entry.set_flags(flags))
            .is_some()
    }

    pub fn find_addr<P: Into<UsePoint>>(
        &self,
        location: Location,
        use_point: P,
    ) -> Option<&SymbolEntry> {
        let id = self.find_addr_id(location, use_point)?;
        self.entry(id)
    }

    pub fn find_addr_id<P: Into<UsePoint>>(
        &self,
        location: Location,
        use_point: P,
    ) -> Option<EntryId> {
        let point = use_point.into();
        let candidates = self.by_location.get(&location)?;
        self.best_candidate(candidates, point, None)
    }

    /// Ghidra-style spelling used by `RuleStringCopy` and future scope ports.
    pub fn query_by_addr<P: Into<UsePoint>>(
        &self,
        location: Location,
        use_point: P,
    ) -> Option<&SymbolEntry> {
        self.find_addr(location, use_point)
    }

    pub fn query_container<P: Into<UsePoint>>(
        &self,
        location: Location,
        use_point: P,
    ) -> Option<&SymbolEntry> {
        let point = use_point.into();
        let ids: Vec<_> = self
            .entries
            .values()
            .filter(|entry| {
                entry
                    .location()
                    .is_some_and(|storage| contains_location(storage, location))
                    && entry.in_use(point)
            })
            .map(SymbolEntry::id)
            .collect();
        let id = self.best_candidate(&ids, point, Some(location))?;
        self.entry(id)
    }

    pub fn query_container_id<P: Into<UsePoint>>(
        &self,
        location: Location,
        use_point: P,
    ) -> Option<EntryId> {
        self.query_container(location, use_point)
            .map(SymbolEntry::id)
    }

    pub fn find_overlap(&self, location: Location) -> Option<&SymbolEntry> {
        self.entries.values().find(|entry| {
            entry
                .location()
                .is_some_and(|storage| locations_overlap(storage, location))
        })
    }

    pub fn dynamic_entries(&self) -> Vec<&SymbolEntry> {
        self.dynamic_entries
            .iter()
            .filter_map(|id| self.entry(*id))
            .collect()
    }

    pub fn dynamic_entry_ids(&self) -> &[EntryId] {
        &self.dynamic_entries
    }

    pub fn find_dynamic<P: Into<UsePoint>>(&self, hash: u64, use_point: P) -> Option<&SymbolEntry> {
        let point = use_point.into();
        self.dynamic_entries
            .iter()
            .filter_map(|id| self.entry(*id))
            .filter(|entry| entry.dynamic_hash() == Some(hash) && entry.in_use(point))
            .min_by_key(|entry| (entry.use_range().specificity(), entry.id()))
    }

    pub fn multi_entry_ids(&self) -> Vec<SymbolId> {
        self.multi_entry_names
            .values()
            .flat_map(|ids| ids.iter().copied())
            .collect()
    }

    /// The name-tree equivalent consumed by `Merge::mergeMultiEntry`.
    pub fn multi_entry_symbols(&self) -> Vec<&Symbol> {
        self.multi_entry_ids()
            .iter()
            .filter_map(|id| self.symbol(*id))
            .collect()
    }

    pub fn begin_multi_entry(&self) -> Vec<SymbolId> {
        self.multi_entry_ids()
    }

    pub fn end_multi_entry(&self) -> usize {
        self.multi_entry_ids().len()
    }

    pub fn add_range(&mut self, range: StorageRange) {
        self.owned_ranges.push(range);
    }

    pub fn in_scope(&self, location: Location) -> bool {
        self.owned_ranges.is_empty()
            || self
                .owned_ranges
                .iter()
                .any(|range| range.contains(location))
    }

    pub fn add_read_only_range(&mut self, range: StorageRange) {
        self.read_only_ranges.push(range);
    }

    pub fn is_read_only<P: Into<UsePoint>>(&self, location: Location, use_point: P) -> bool {
        let point = use_point.into();
        if self
            .read_only_ranges
            .iter()
            .any(|range| range.contains(location))
        {
            return true;
        }
        self.query_container(location, point)
            .and_then(|entry| self.entry_symbol(entry.id()))
            .is_some_and(Symbol::is_read_only)
    }

    pub fn owned_ranges(&self) -> &[StorageRange] {
        &self.owned_ranges
    }

    fn refresh_multi_entry(&mut self, symbol_id: SymbolId) {
        let Some(symbol) = self.symbol(symbol_id) else {
            return;
        };
        let name = symbol.name().to_owned();
        let is_multi = symbol.is_multi_entry();
        if is_multi {
            self.multi_entry_names
                .entry(name)
                .or_default()
                .insert(symbol_id);
        } else if let Some(ids) = self.multi_entry_names.get_mut(&name) {
            ids.remove(&symbol_id);
            if ids.is_empty() {
                self.multi_entry_names.remove(&name);
            }
        }
    }

    fn best_candidate(
        &self,
        ids: &[EntryId],
        point: UsePoint,
        requested: Option<Location>,
    ) -> Option<EntryId> {
        ids.iter()
            .copied()
            .filter_map(|id| self.entry(id))
            .filter(|entry| entry.in_use(point))
            .filter(|entry| {
                requested.is_none_or(|location| {
                    entry
                        .location()
                        .is_some_and(|storage| contains_location(storage, location))
                })
            })
            .min_by_key(|entry| {
                let (size, offset) = entry
                    .location()
                    .map(|location| (location.size, location.offset))
                    .unwrap_or((u32::MAX, u64::MAX));
                (size, entry.use_range().specificity(), offset, entry.id())
            })
            .map(SymbolEntry::id)
    }
}

fn contains_location(container: Location, requested: Location) -> bool {
    container.space == requested.space
        && requested.offset >= container.offset
        && requested
            .offset
            .saturating_add(u64::from(requested.size).saturating_sub(1))
            <= container
                .offset
                .saturating_add(u64::from(container.size).saturating_sub(1))
}

fn locations_overlap(left: Location, right: Location) -> bool {
    left.space == right.space
        && left.offset
            <= right
                .offset
                .saturating_add(u64::from(right.size).saturating_sub(1))
        && right.offset
            <= left
                .offset
                .saturating_add(u64::from(left.size).saturating_sub(1))
}

/// Local variable scope for one function's stack/register storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeLocal {
    scope: Scope,
    space: u32,
    mapped_ranges: Vec<StorageRange>,
    unmapped_ranges: Vec<StorageRange>,
    parameter_ranges: Vec<StorageRange>,
    alias_verdicts: BTreeMap<Location, bool>,
    range_locked: bool,
    overlap_problems: bool,
    stack_grows_negative: bool,
    min_param_offset: Option<u64>,
    max_param_offset: Option<u64>,
}

impl ScopeLocal {
    pub fn new(space: u32) -> Self {
        Self::with_name("local", space)
    }

    pub fn with_name<N: Into<String>>(name: N, space: u32) -> Self {
        Self {
            scope: Scope::new(name),
            space,
            mapped_ranges: Vec::new(),
            unmapped_ranges: Vec::new(),
            parameter_ranges: Vec::new(),
            alias_verdicts: BTreeMap::new(),
            range_locked: false,
            overlap_problems: false,
            stack_grows_negative: false,
            min_param_offset: None,
            max_param_offset: None,
        }
    }

    pub fn from_scope(scope: Scope, space: u32) -> Self {
        Self {
            scope,
            space,
            mapped_ranges: Vec::new(),
            unmapped_ranges: Vec::new(),
            parameter_ranges: Vec::new(),
            alias_verdicts: BTreeMap::new(),
            range_locked: false,
            overlap_problems: false,
            stack_grows_negative: false,
            min_param_offset: None,
            max_param_offset: None,
        }
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn scope_mut(&mut self) -> &mut Scope {
        &mut self.scope
    }

    pub fn space(&self) -> u32 {
        self.space
    }

    pub fn get_space_id(&self) -> u32 {
        self.space()
    }

    pub fn set_stack_grows_negative(&mut self, value: bool) {
        self.stack_grows_negative = value;
    }

    pub fn stack_grows_negative(&self) -> bool {
        self.stack_grows_negative
    }

    pub fn set_range_locked(&mut self, locked: bool) {
        self.range_locked = locked;
    }

    pub fn is_range_locked(&self) -> bool {
        self.range_locked
    }

    pub fn mark_mapped(&mut self, space: u32, first: u64, size: u32) -> bool {
        if space != self.space {
            return false;
        }
        let Some(range) = StorageRange::new(space, first, size) else {
            return false;
        };
        self.mapped_ranges.push(range);
        true
    }

    pub fn mark_not_mapped(&mut self, space: u32, first: u64, size: u32, parameter: bool) {
        if space != self.space {
            return;
        }
        let Some(range) = StorageRange::new(space, first, size) else {
            return;
        };
        self.unmapped_ranges.push(range);
        if parameter {
            self.parameter_ranges.push(range);
            self.min_param_offset = Some(
                self.min_param_offset
                    .map_or(range.first, |old| old.min(range.first)),
            );
            self.max_param_offset = Some(
                self.max_param_offset
                    .map_or(range.last, |old| old.max(range.last)),
            );
        }

        let overlapping_symbols: Vec<_> = self
            .scope
            .entries()
            .filter_map(|entry| {
                let storage = entry.location()?;
                if !range.intersects(storage) {
                    return None;
                }
                let symbol = self.scope.entry_symbol(entry.id())?;
                (symbol.is_type_locked() || symbol.category() == SymbolCategory::FakeInput)
                    .then_some(None)
                    .or_else(|| Some(Some(symbol.id())))
            })
            .flatten()
            .collect();
        for symbol in overlapping_symbols {
            self.overlap_problems |= self.scope.symbol_entries(symbol).iter().any(|entry| {
                entry
                    .location()
                    .is_some_and(|location| range.intersects(location))
            });
            if !self.scope.symbol(symbol).is_some_and(|symbol| {
                symbol.is_type_locked() || symbol.category() == SymbolCategory::FakeInput
            }) {
                self.scope.remove_symbol(symbol);
            }
        }
    }

    pub fn reset_local_window(&mut self) {
        if self.range_locked {
            return;
        }
        self.unmapped_ranges.clear();
        self.parameter_ranges.clear();
        self.alias_verdicts.clear();
        self.min_param_offset = None;
        self.max_param_offset = None;
        self.overlap_problems = false;
    }

    pub fn is_mapped(&self, location: Location) -> bool {
        if location.space != self.space {
            return false;
        }
        if self
            .unmapped_ranges
            .iter()
            .any(|range| range.intersects(location))
        {
            return false;
        }
        if self.scope.entries().any(|entry| {
            entry
                .location()
                .is_some_and(|storage| contains_location(storage, location))
        }) {
            return true;
        }
        !self.mapped_ranges.is_empty()
            && self
                .mapped_ranges
                .iter()
                .any(|range| range.contains(location))
    }

    pub fn is_unmapped(&self, location: Location) -> bool {
        location.space == self.space && !self.is_mapped(location)
    }

    /// Return the Ghidra `isUnmappedUnaliased` result from the scope state
    /// already computed by alias analysis.  A stack parameter is deliberately
    /// not treated as unaliased: its storage is visible to a callee.
    pub fn is_unmapped_unaliased(&self, location: Location) -> bool {
        if !self.is_unmapped(location) || self.is_parameter_location(location) {
            return false;
        }
        !self
            .alias_verdicts
            .iter()
            .any(|(aliased, verdict)| *verdict && locations_overlap(*aliased, location))
    }

    /// Same decision, consuming the separate alias checker rather than
    /// duplicating pointer analysis in the scope object.
    pub fn is_unmapped_unaliased_with_alias(
        &self,
        data: &Funcdata,
        location: Location,
        checker: &mut dyn AliasVerdict,
    ) -> bool {
        self.is_unmapped(location)
            && !self.is_parameter_location(location)
            && !checker.has_local_alias(data, location)
    }

    pub fn set_alias_verdict(&mut self, location: Location, has_alias: bool) {
        self.alias_verdicts.insert(location, has_alias);
    }

    pub fn parameter_bounds(&self) -> Option<(u64, u64)> {
        self.min_param_offset.zip(self.max_param_offset)
    }

    pub fn is_parameter_location(&self, location: Location) -> bool {
        self.parameter_ranges
            .iter()
            .any(|range| range.intersects(location))
    }

    pub fn has_overlap_problems(&self) -> bool {
        self.overlap_problems
    }

    /// Ghidra's historical misspelling, kept for direct action ports.
    pub fn has_overlap_probems(&self) -> bool {
        self.has_overlap_problems()
    }

    /// Reconcile the symbol map's structural overlaps.  The graph currently
    /// has no `MapState`/Varnode layout input, so this performs the part that is
    /// sound from the symbol table alone and reports whether the overlap bit
    /// changed.  Alias-sensitive decisions belong to
    /// [`Self::is_unmapped_unaliased_with_alias`].
    pub fn restructure_varnode(&mut self, _aliasyes: bool) -> bool {
        let entries: Vec<_> = self
            .scope
            .entries()
            .filter_map(|entry| {
                Some((
                    entry.id(),
                    entry.symbol_id(),
                    entry.location()?,
                    entry.use_range().clone(),
                ))
            })
            .collect();
        let mut overlap = false;
        for (index, (_, symbol, left, left_use)) in entries.iter().enumerate() {
            for (_, other_symbol, right, right_use) in entries.iter().skip(index + 1) {
                if symbol != other_symbol
                    && locations_overlap(*left, *right)
                    && left_use.overlaps(right_use)
                {
                    overlap = true;
                }
            }
        }
        let changed = self.overlap_problems != overlap;
        self.overlap_problems = overlap;
        changed
    }
}

impl std::ops::Deref for ScopeLocal {
    type Target = Scope;

    fn deref(&self) -> &Self::Target {
        &self.scope
    }
}

impl std::ops::DerefMut for ScopeLocal {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.scope
    }
}

impl From<Type> for DataType {
    fn from(ty: Type) -> Self {
        match ty {
            Type::Unknown => DataType::Unknown(0),
            Type::Bool => DataType::Bool,
            Type::Unsigned(bits) => DataType::Int {
                bits,
                signed: false,
            },
            Type::Signed(bits) => DataType::Int { bits, signed: true },
            Type::Float(bits) => DataType::Float(bits),
            Type::Pointer(to) => DataType::Pointer {
                to: Box::new((*to).into()),
                bits: 0,
            },
            Type::Void => DataType::Void,
        }
    }
}

impl AliasVerdict for super::alias::AliasChecker {
    fn has_local_alias(&mut self, data: &Funcdata, location: Location) -> bool {
        self.has_local_alias(data, location)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn slot() -> Location {
        Location {
            space: REGISTER_SPACE,
            offset: 0x20,
            size: 4,
        }
    }

    #[test]
    fn lookup_uses_storage_and_use_point() {
        let mut scope = Scope::new("function");
        let first = scope.add_symbol("first", Type::Unsigned(32));
        let second = scope.add_symbol("second", Type::Unsigned(32));
        scope.add_map(first, slot(), Liveness::range(0x1000_u64, 0x10ff_u64));
        scope.add_map(second, slot(), Liveness::range(0x1100_u64, 0x11ff_u64));

        let first_entry = scope
            .find_addr(slot(), 0x1001_u64)
            .expect("first live range");
        let second_entry = scope
            .find_addr(slot(), 0x1101_u64)
            .expect("second live range");
        assert_eq!(
            scope.entry_symbol(first_entry.id()).unwrap().name(),
            "first"
        );
        assert_eq!(
            scope.entry_symbol(second_entry.id()).unwrap().name(),
            "second"
        );
        assert!(scope.find_addr(slot(), 0x1200_u64).is_none());
    }

    #[test]
    fn same_storage_entries_are_multi_entry_and_name_tree_is_sorted() {
        let mut scope = Scope::new("function");
        let first = scope.add_symbol("zeta", Type::Unsigned(32));
        let second = scope.add_symbol("alpha", Type::Unsigned(32));
        scope.add_map(first, slot(), Liveness::range(0x1000_u64, 0x10ff_u64));
        scope.add_map(first, slot(), Liveness::range(0x2000_u64, 0x20ff_u64));
        scope.add_map(second, slot(), Liveness::range(0x3000_u64, 0x30ff_u64));
        scope.add_map(second, slot(), Liveness::range(0x4000_u64, 0x40ff_u64));

        assert!(scope.symbol(first).unwrap().is_multi_entry());
        assert!(scope.symbol(second).unwrap().is_multi_entry());
        let names: Vec<_> = scope
            .multi_entry_symbols()
            .into_iter()
            .map(Symbol::name)
            .collect();
        assert_eq!(names, vec!["alpha", "zeta"]);
    }

    #[test]
    fn local_scope_tracks_unmapped_parameter_and_alias_state() {
        let mut local = ScopeLocal::new(REGISTER_SPACE);
        let location = slot();
        local.mark_not_mapped(REGISTER_SPACE, location.offset, location.size, false);
        assert!(local.is_unmapped_unaliased(location));
        local.set_alias_verdict(location, true);
        assert!(!local.is_unmapped_unaliased(location));
        local.mark_not_mapped(REGISTER_SPACE, 0x30, 4, true);
        assert!(!local.is_unmapped_unaliased(Location {
            space: REGISTER_SPACE,
            offset: 0x30,
            size: 4,
        }));
    }

    #[test]
    fn dynamic_entries_are_live_point_lookups() {
        let mut scope = Scope::new("function");
        let symbol = scope.add_symbol("dynamic", Type::Unsigned(32));
        scope.add_dynamic_map(symbol, 0xfeed, 0, 4, Liveness::range(0x10_u64, 0x20_u64));
        assert_eq!(
            scope.find_dynamic(0xfeed, 0x15).unwrap().symbol_id(),
            symbol
        );
        assert!(scope.find_dynamic(0xfeed, 0x30).is_none());
    }
}
