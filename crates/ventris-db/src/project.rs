use super::Authority;
use std::fs;
use std::io;
use std::path::Path;

const PROJECT_MAGIC: &[u8] = b"VENTRISPROJECT\0";
const PROJECT_VERSION: u32 = 1;
const MAX_ITEMS: u32 = 1_000_000;
const MAX_STRING: usize = 16 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Project {
    pub image: ProjectImage,
    pub functions: Vec<ProjectFunction>,
    pub data: Vec<ProjectData>,
    pub references: Vec<ProjectReference>,
    pub assertions: Vec<ProjectAssertion>,
    pub generations: Vec<ProjectGeneration>,
    pub cache: ProjectCache,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectImage {
    pub source: String,
    pub content_hash: u64,
    pub loader: String,
    pub target: Option<String>,
    pub base: Option<u64>,
    pub slice: Option<u64>,
    pub file_size: u64,
    pub normalized_size: u64,
    pub entry: Option<u64>,
    pub segments: Vec<ProjectSegment>,
    pub regions: Vec<ProjectRegion>,
    pub spaces: Vec<ProjectSpace>,
    pub symbols: Vec<ProjectSymbol>,
    pub relocations: Vec<ProjectRelocation>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectSegment {
    pub name: Option<String>,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub read: Option<bool>,
    pub write: Option<bool>,
    pub execute: Option<bool>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectRegion {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub allocated: bool,
    pub placement: ProjectPlacement,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum ProjectPlacement {
    #[default]
    Mapped,
    Aliased {
        segment: u32,
    },
    Unaddressed,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectSpace {
    pub id: u32,
    pub name: String,
    pub kind: String,
    pub base: u64,
    pub size: u64,
    pub overlay_of: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectSymbol {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub section: u16,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectRelocation {
    pub address: u64,
    pub symbol: Option<String>,
    pub kind: u32,
    pub addend: Option<i64>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectFunction {
    pub address: u64,
    pub size: u64,
    pub name: Option<String>,
    pub signature: Option<String>,
    pub comment: Option<String>,
    pub confidence: u8,
    pub source: Option<String>,
    pub generation: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectData {
    pub address: u64,
    pub size: u64,
    pub name: Option<String>,
    pub type_name: Option<String>,
    pub comment: Option<String>,
    pub confidence: u8,
    pub source: Option<String>,
    pub generation: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProjectReferenceKind {
    Call,
    Jump,
    Read,
    Write,
    String,
    FunctionPointer,
    Field,
}

impl Default for ProjectReferenceKind {
    fn default() -> Self {
        Self::Read
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectReference {
    pub from: u64,
    pub to: u64,
    pub kind: ProjectReferenceKind,
    pub offset: Option<i64>,
    pub confidence: u8,
    pub generation: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProjectAssertion {
    pub address: u64,
    pub kind: String,
    pub value: String,
    pub note: String,
    pub authority: Authority,
}

impl Default for ProjectAssertion {
    fn default() -> Self {
        Self {
            address: 0,
            kind: String::new(),
            value: String::new(),
            note: String::new(),
            authority: Authority::Human,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectGeneration {
    pub id: u32,
    pub analyzer_version: u32,
    pub config_digest: u64,
    pub human_log_digest: u64,
    pub status: String,
    pub function_count: u64,
    pub data_count: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ProjectCache {
    pub key_digest: u64,
    pub generation: u32,
    pub entries: u64,
    pub bytes: u64,
    pub budget: u64,
}

impl Project {
    pub fn new(image: ProjectImage) -> Self {
        Self {
            image,
            ..Self::default()
        }
    }

    pub fn function(&self, address: u64) -> Option<&ProjectFunction> {
        self.functions
            .binary_search_by_key(&address, |function| function.address)
            .ok()
            .and_then(|index| self.functions.get(index))
    }
    pub fn function_containing(&self, address: u64) -> Option<&ProjectFunction> {
        self.functions.iter().rev().find(|function| {
            function.address <= address
                && function
                    .address
                    .checked_add(function.size.max(1))
                    .is_some_and(|end| address < end)
        })
    }

    pub fn data_containing(&self, address: u64) -> Option<&ProjectData> {
        self.data.iter().rev().find(|item| {
            item.address <= address
                && item
                    .address
                    .checked_add(item.size.max(1))
                    .is_some_and(|end| address < end)
        })
    }

    pub fn references_to(&self, address: u64) -> impl Iterator<Item = &ProjectReference> {
        self.references
            .iter()
            .filter(move |reference| reference.to == address)
    }

    pub fn data_at(&self, address: u64) -> Option<&ProjectData> {
        self.data
            .binary_search_by_key(&address, |item| item.address)
            .ok()
            .and_then(|index| self.data.get(index))
    }

    pub fn references_from(&self, address: u64) -> impl Iterator<Item = &ProjectReference> {
        self.references
            .iter()
            .filter(move |reference| reference.from == address)
    }

    pub fn upsert_function(&mut self, function: ProjectFunction) {
        match self
            .functions
            .binary_search_by_key(&function.address, |item| item.address)
        {
            Ok(index) => self.functions[index] = function,
            Err(index) => self.functions.insert(index, function),
        }
    }

    pub fn upsert_data(&mut self, data: ProjectData) {
        match self
            .data
            .binary_search_by_key(&data.address, |item| item.address)
        {
            Ok(index) => self.data[index] = data,
            Err(index) => self.data.insert(index, data),
        }
    }

    pub fn add_reference(&mut self, reference: ProjectReference) {
        if !self.references.contains(&reference) {
            self.references.push(reference);
            self.references.sort_by_key(|item| {
                (
                    item.from,
                    item.to,
                    reference_kind_rank(&item.kind),
                    item.offset,
                )
            });
        }
    }

    pub fn add_assertion(&mut self, assertion: ProjectAssertion) {
        if !self.assertions.contains(&assertion) {
            self.assertions.push(assertion);
            self.assertions
                .sort_by_key(|item| (item.address, item.kind.clone(), item.value.clone()));
        }
    }

    pub fn record_generation(&mut self, generation: ProjectGeneration) {
        if let Some(existing) = self
            .generations
            .iter_mut()
            .find(|item| item.id == generation.id)
        {
            *existing = generation;
        } else {
            self.generations.push(generation);
        }
        self.generations.sort_by_key(|item| item.id);
    }

    pub fn normalize(&mut self) {
        self.functions.sort_by_key(|item| item.address);
        self.data.sort_by_key(|item| item.address);
        self.references.sort_by_key(|item| {
            (
                item.from,
                item.to,
                reference_kind_rank(&item.kind),
                item.offset,
            )
        });
        self.assertions
            .sort_by_key(|item| (item.address, item.kind.clone(), item.value.clone()));
        self.generations.sort_by_key(|item| item.id);
    }

    pub fn save_to(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let mut project = self.clone();
        project.normalize();
        let mut encoder = Encoder::default();
        encoder.bytes.extend_from_slice(PROJECT_MAGIC);
        encoder.u32(PROJECT_VERSION);
        encode_project(&mut encoder, &project)?;
        if let Some(parent) = path
            .as_ref()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, encoder.bytes)
    }

    pub fn load_from(path: impl AsRef<Path>) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        let mut decoder = Decoder::new(&bytes);
        if decoder.take(PROJECT_MAGIC.len())? != PROJECT_MAGIC {
            return Err(invalid_project("bad project magic"));
        }
        if decoder.u32()? != PROJECT_VERSION {
            return Err(invalid_project("unsupported project version"));
        }
        let mut project = decode_project(&mut decoder)?;
        if !decoder.is_empty() {
            return Err(invalid_project("trailing project bytes"));
        }
        project.normalize();
        Ok(project)
    }
}

fn reference_kind_rank(kind: &ProjectReferenceKind) -> u8 {
    match kind {
        ProjectReferenceKind::Call => 0,
        ProjectReferenceKind::Jump => 1,
        ProjectReferenceKind::Read => 2,
        ProjectReferenceKind::Write => 3,
        ProjectReferenceKind::String => 4,
        ProjectReferenceKind::FunctionPointer => 5,
        ProjectReferenceKind::Field => 6,
    }
}

fn encode_project(encoder: &mut Encoder, project: &Project) -> io::Result<()> {
    encode_image(encoder, &project.image)?;
    encode_vec(encoder, &project.functions, encode_function)?;
    encode_vec(encoder, &project.data, encode_data)?;
    encode_vec(encoder, &project.references, encode_reference)?;
    encode_vec(encoder, &project.assertions, encode_assertion)?;
    encode_vec(encoder, &project.generations, encode_generation)?;
    encoder.u64(project.cache.key_digest);
    encoder.u32(project.cache.generation);
    encoder.u64(project.cache.entries);
    encoder.u64(project.cache.bytes);
    encoder.u64(project.cache.budget);
    Ok(())
}

fn decode_project(decoder: &mut Decoder<'_>) -> io::Result<Project> {
    Ok(Project {
        image: decode_image(decoder)?,
        functions: decode_vec(decoder, decode_function)?,
        data: decode_vec(decoder, decode_data)?,
        references: decode_vec(decoder, decode_reference)?,
        assertions: decode_vec(decoder, decode_assertion)?,
        generations: decode_vec(decoder, decode_generation)?,
        cache: ProjectCache {
            key_digest: decoder.u64()?,
            generation: decoder.u32()?,
            entries: decoder.u64()?,
            bytes: decoder.u64()?,
            budget: decoder.u64()?,
        },
    })
}

fn encode_image(encoder: &mut Encoder, image: &ProjectImage) -> io::Result<()> {
    encoder.string(&image.source)?;
    encoder.u64(image.content_hash);
    encoder.string(&image.loader)?;
    encoder.option_string(image.target.as_deref())?;
    encoder.option_u64(image.base);
    encoder.option_u64(image.slice);
    encoder.u64(image.file_size);
    encoder.u64(image.normalized_size);
    encoder.option_u64(image.entry);
    encode_vec(encoder, &image.segments, encode_segment)?;
    encode_vec(encoder, &image.regions, encode_region)?;
    encode_vec(encoder, &image.spaces, encode_space)?;
    encode_vec(encoder, &image.symbols, encode_symbol)?;
    encode_vec(encoder, &image.relocations, encode_relocation)
}

fn decode_image(decoder: &mut Decoder<'_>) -> io::Result<ProjectImage> {
    Ok(ProjectImage {
        source: decoder.string()?,
        content_hash: decoder.u64()?,
        loader: decoder.string()?,
        target: decoder.option_string()?,
        base: decoder.option_u64()?,
        slice: decoder.option_u64()?,
        file_size: decoder.u64()?,
        normalized_size: decoder.u64()?,
        entry: decoder.option_u64()?,
        segments: decode_vec(decoder, decode_segment)?,
        regions: decode_vec(decoder, decode_region)?,
        spaces: decode_vec(decoder, decode_space)?,
        symbols: decode_vec(decoder, decode_symbol)?,
        relocations: decode_vec(decoder, decode_relocation)?,
    })
}

fn encode_segment(encoder: &mut Encoder, item: &ProjectSegment) -> io::Result<()> {
    encoder.option_string(item.name.as_deref())?;
    encoder.u64(item.address);
    encoder.u64(item.size);
    encoder.u64(item.file_offset);
    encoder.u64(item.file_size);
    encoder.option_bool(item.read);
    encoder.option_bool(item.write);
    encoder.option_bool(item.execute);
    Ok(())
}

fn decode_segment(decoder: &mut Decoder<'_>) -> io::Result<ProjectSegment> {
    Ok(ProjectSegment {
        name: decoder.option_string()?,
        address: decoder.u64()?,
        size: decoder.u64()?,
        file_offset: decoder.u64()?,
        file_size: decoder.u64()?,
        read: decoder.option_bool()?,
        write: decoder.option_bool()?,
        execute: decoder.option_bool()?,
    })
}

fn encode_region(encoder: &mut Encoder, item: &ProjectRegion) -> io::Result<()> {
    encoder.string(&item.name)?;
    encoder.u64(item.address);
    encoder.u64(item.size);
    encoder.bool(item.allocated);
    match item.placement {
        ProjectPlacement::Mapped => encoder.u8(0),
        ProjectPlacement::Aliased { segment } => {
            encoder.u8(1);
            encoder.u32(segment);
        }
        ProjectPlacement::Unaddressed => encoder.u8(2),
    }
    Ok(())
}

fn decode_region(decoder: &mut Decoder<'_>) -> io::Result<ProjectRegion> {
    let name = decoder.string()?;
    let address = decoder.u64()?;
    let size = decoder.u64()?;
    let allocated = decoder.bool()?;
    let placement = match decoder.u8()? {
        0 => ProjectPlacement::Mapped,
        1 => ProjectPlacement::Aliased {
            segment: decoder.u32()?,
        },
        2 => ProjectPlacement::Unaddressed,
        _ => return Err(invalid_project("unknown region placement")),
    };
    Ok(ProjectRegion {
        name,
        address,
        size,
        allocated,
        placement,
    })
}

fn encode_space(encoder: &mut Encoder, item: &ProjectSpace) -> io::Result<()> {
    encoder.u32(item.id);
    encoder.string(&item.name)?;
    encoder.string(&item.kind)?;
    encoder.u64(item.base);
    encoder.u64(item.size);
    encoder.option_u32(item.overlay_of);
    Ok(())
}

fn decode_space(decoder: &mut Decoder<'_>) -> io::Result<ProjectSpace> {
    Ok(ProjectSpace {
        id: decoder.u32()?,
        name: decoder.string()?,
        kind: decoder.string()?,
        base: decoder.u64()?,
        size: decoder.u64()?,
        overlay_of: decoder.option_u32()?,
    })
}

fn encode_symbol(encoder: &mut Encoder, item: &ProjectSymbol) -> io::Result<()> {
    encoder.u64(item.address);
    encoder.string(&item.name)?;
    encoder.u64(item.size);
    encoder.u16(item.section);
    Ok(())
}

fn decode_symbol(decoder: &mut Decoder<'_>) -> io::Result<ProjectSymbol> {
    Ok(ProjectSymbol {
        address: decoder.u64()?,
        name: decoder.string()?,
        size: decoder.u64()?,
        section: decoder.u16()?,
    })
}

fn encode_relocation(encoder: &mut Encoder, item: &ProjectRelocation) -> io::Result<()> {
    encoder.u64(item.address);
    encoder.option_string(item.symbol.as_deref())?;
    encoder.u32(item.kind);
    encoder.option_i64(item.addend);
    Ok(())
}

fn decode_relocation(decoder: &mut Decoder<'_>) -> io::Result<ProjectRelocation> {
    Ok(ProjectRelocation {
        address: decoder.u64()?,
        symbol: decoder.option_string()?,
        kind: decoder.u32()?,
        addend: decoder.option_i64()?,
    })
}

fn encode_function(encoder: &mut Encoder, item: &ProjectFunction) -> io::Result<()> {
    encoder.u64(item.address);
    encoder.u64(item.size);
    encoder.option_string(item.name.as_deref())?;
    encoder.option_string(item.signature.as_deref())?;
    encoder.option_string(item.comment.as_deref())?;
    encoder.u8(item.confidence);
    encoder.option_string(item.source.as_deref())?;
    encoder.u32(item.generation);
    Ok(())
}

fn decode_function(decoder: &mut Decoder<'_>) -> io::Result<ProjectFunction> {
    Ok(ProjectFunction {
        address: decoder.u64()?,
        size: decoder.u64()?,
        name: decoder.option_string()?,
        signature: decoder.option_string()?,
        comment: decoder.option_string()?,
        confidence: decoder.u8()?,
        source: decoder.option_string()?,
        generation: decoder.u32()?,
    })
}

fn encode_data(encoder: &mut Encoder, item: &ProjectData) -> io::Result<()> {
    encoder.u64(item.address);
    encoder.u64(item.size);
    encoder.option_string(item.name.as_deref())?;
    encoder.option_string(item.type_name.as_deref())?;
    encoder.option_string(item.comment.as_deref())?;
    encoder.u8(item.confidence);
    encoder.option_string(item.source.as_deref())?;
    encoder.u32(item.generation);
    Ok(())
}

fn decode_data(decoder: &mut Decoder<'_>) -> io::Result<ProjectData> {
    Ok(ProjectData {
        address: decoder.u64()?,
        size: decoder.u64()?,
        name: decoder.option_string()?,
        type_name: decoder.option_string()?,
        comment: decoder.option_string()?,
        confidence: decoder.u8()?,
        source: decoder.option_string()?,
        generation: decoder.u32()?,
    })
}

fn encode_reference(encoder: &mut Encoder, item: &ProjectReference) -> io::Result<()> {
    encoder.u64(item.from);
    encoder.u64(item.to);
    encoder.u8(reference_kind_rank(&item.kind));
    encoder.option_i64(item.offset);
    encoder.u8(item.confidence);
    encoder.u32(item.generation);
    Ok(())
}

fn decode_reference(decoder: &mut Decoder<'_>) -> io::Result<ProjectReference> {
    let from = decoder.u64()?;
    let to = decoder.u64()?;
    let kind = match decoder.u8()? {
        0 => ProjectReferenceKind::Call,
        1 => ProjectReferenceKind::Jump,
        2 => ProjectReferenceKind::Read,
        3 => ProjectReferenceKind::Write,
        4 => ProjectReferenceKind::String,
        5 => ProjectReferenceKind::FunctionPointer,
        6 => ProjectReferenceKind::Field,
        _ => return Err(invalid_project("unknown project reference kind")),
    };
    Ok(ProjectReference {
        from,
        to,
        kind,
        offset: decoder.option_i64()?,
        confidence: decoder.u8()?,
        generation: decoder.u32()?,
    })
}

fn encode_assertion(encoder: &mut Encoder, item: &ProjectAssertion) -> io::Result<()> {
    encoder.u64(item.address);
    encoder.string(&item.kind)?;
    encoder.string(&item.value)?;
    encoder.string(&item.note)?;
    encoder.u8(match item.authority {
        Authority::Human => 0,
        Authority::Machine => 1,
    });
    Ok(())
}

fn decode_assertion(decoder: &mut Decoder<'_>) -> io::Result<ProjectAssertion> {
    let address = decoder.u64()?;
    let kind = decoder.string()?;
    let value = decoder.string()?;
    let note = decoder.string()?;
    let authority = match decoder.u8()? {
        0 => Authority::Human,
        1 => Authority::Machine,
        _ => return Err(invalid_project("unknown project assertion authority")),
    };
    Ok(ProjectAssertion {
        address,
        kind,
        value,
        note,
        authority,
    })
}

fn encode_generation(encoder: &mut Encoder, item: &ProjectGeneration) -> io::Result<()> {
    encoder.u32(item.id);
    encoder.u32(item.analyzer_version);
    encoder.u64(item.config_digest);
    encoder.u64(item.human_log_digest);
    encoder.string(&item.status)?;
    encoder.u64(item.function_count);
    encoder.u64(item.data_count);
    Ok(())
}

fn decode_generation(decoder: &mut Decoder<'_>) -> io::Result<ProjectGeneration> {
    Ok(ProjectGeneration {
        id: decoder.u32()?,
        analyzer_version: decoder.u32()?,
        config_digest: decoder.u64()?,
        human_log_digest: decoder.u64()?,
        status: decoder.string()?,
        function_count: decoder.u64()?,
        data_count: decoder.u64()?,
    })
}

fn encode_vec<T>(
    encoder: &mut Encoder,
    items: &[T],
    mut encode: impl FnMut(&mut Encoder, &T) -> io::Result<()>,
) -> io::Result<()> {
    let count =
        u32::try_from(items.len()).map_err(|_| invalid_project("too many project records"))?;
    encoder.u32(count);
    for item in items {
        encode(encoder, item)?;
    }
    Ok(())
}

fn decode_vec<T>(
    decoder: &mut Decoder<'_>,
    mut decode: impl FnMut(&mut Decoder<'_>) -> io::Result<T>,
) -> io::Result<Vec<T>> {
    let count = decoder.u32()?;
    if count > MAX_ITEMS {
        return Err(invalid_project("project record count is too large"));
    }
    let mut items = Vec::with_capacity(count as usize);
    for _ in 0..count {
        items.push(decode(decoder)?);
    }
    Ok(items)
}

#[derive(Default)]
struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    fn option_bool(&mut self, value: Option<bool>) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                self.bool(value);
            }
        }
    }

    fn option_u32(&mut self, value: Option<u32>) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                self.u32(value);
            }
        }
    }

    fn option_u64(&mut self, value: Option<u64>) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                self.u64(value);
            }
        }
    }

    fn option_i64(&mut self, value: Option<i64>) {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                self.i64(value);
            }
        }
    }

    fn string(&mut self, value: &str) -> io::Result<()> {
        let value = value.as_bytes();
        let len = u32::try_from(value.len())
            .map_err(|_| invalid_project("project string is too long"))?;
        self.u32(len);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn option_string(&mut self, value: Option<&str>) -> io::Result<()> {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1);
                self.string(value)?;
            }
        }
        Ok(())
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| invalid_project("project length overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid_project("truncated project"))?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(*self.take(1)?.first().expect("checked width"))
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("checked width"),
        ))
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("checked width"),
        ))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("checked width"),
        ))
    }

    fn i64(&mut self) -> io::Result<i64> {
        Ok(i64::from_le_bytes(
            self.take(8)?.try_into().expect("checked width"),
        ))
    }

    fn bool(&mut self) -> io::Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid_project("invalid project boolean")),
        }
    }

    fn option_bool(&mut self) -> io::Result<Option<bool>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.bool()?)),
            _ => Err(invalid_project("invalid optional project boolean")),
        }
    }

    fn option_u32(&mut self) -> io::Result<Option<u32>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u32()?)),
            _ => Err(invalid_project("invalid optional project integer")),
        }
    }

    fn option_u64(&mut self) -> io::Result<Option<u64>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(invalid_project("invalid optional project integer")),
        }
    }

    fn option_i64(&mut self) -> io::Result<Option<i64>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.i64()?)),
            _ => Err(invalid_project("invalid optional project integer")),
        }
    }

    fn string(&mut self) -> io::Result<String> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| invalid_project("project string length overflow"))?;
        if length > MAX_STRING {
            return Err(invalid_project("project string is too long"));
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| invalid_project("project string is not UTF-8"))
    }

    fn option_string(&mut self) -> io::Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.string()?)),
            _ => Err(invalid_project("invalid optional project string")),
        }
    }
}

fn invalid_project(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> ProjectImage {
        ProjectImage {
            source: "game.elf".into(),
            content_hash: 0x1234,
            loader: "elf".into(),
            target: Some("ps2".into()),
            base: Some(0x1000),
            slice: None,
            file_size: 0x2000,
            normalized_size: 0x1800,
            entry: Some(0x1200),
            segments: vec![ProjectSegment {
                name: Some("text".into()),
                address: 0x1000,
                size: 0x400,
                file_offset: 0x100,
                file_size: 0x400,
                read: Some(true),
                write: Some(false),
                execute: Some(true),
            }],
            regions: vec![ProjectRegion {
                name: "overlay".into(),
                address: 0x1000,
                size: 0x20,
                allocated: false,
                placement: ProjectPlacement::Aliased { segment: 0 },
            }],
            spaces: vec![ProjectSpace {
                id: 1,
                name: "ram".into(),
                kind: "code".into(),
                base: 0x1000,
                size: 0x400,
                overlay_of: None,
            }],
            symbols: vec![ProjectSymbol {
                address: 0x1200,
                name: "main".into(),
                size: 32,
                section: 1,
            }],
            relocations: vec![ProjectRelocation {
                address: 0x1300,
                symbol: Some("main".into()),
                kind: 2,
                addend: Some(-4),
            }],
        }
    }

    #[test]
    fn project_round_trip_preserves_analysis_state() {
        let path = std::env::temp_dir().join(format!("ventris-project-{}.bin", std::process::id()));
        let mut project = Project::new(image());
        project.upsert_function(ProjectFunction {
            address: 0x1200,
            size: 32,
            name: Some("main".into()),
            signature: Some("int main(void)".into()),
            confidence: 100,
            source: Some("elf-symbol".into()),
            generation: 1,
            ..ProjectFunction::default()
        });
        project.upsert_data(ProjectData {
            address: 0x1400,
            size: 8,
            type_name: Some("struct Player".into()),
            ..ProjectData::default()
        });
        project.add_reference(ProjectReference {
            from: 0x1208,
            to: 0x1300,
            kind: ProjectReferenceKind::Call,
            confidence: 90,
            generation: 1,
            ..ProjectReference::default()
        });
        project.add_assertion(ProjectAssertion {
            address: 0x1200,
            kind: "function".into(),
            value: "entry".into(),
            note: "user selected".into(),
            authority: Authority::Human,
        });
        project.record_generation(ProjectGeneration {
            id: 1,
            analyzer_version: 5,
            status: "complete".into(),
            function_count: 1,
            ..ProjectGeneration::default()
        });
        project.cache = ProjectCache {
            key_digest: 0x55,
            generation: 1,
            entries: 2,
            bytes: 128,
            budget: 1024,
        };
        project.save_to(&path).unwrap();
        let restored = Project::load_from(&path).unwrap();
        assert_eq!(restored, project);
        assert_eq!(
            restored.function(0x1200).unwrap().name.as_deref(),
            Some("main")
        );
        assert_eq!(
            restored
                .function_containing(0x1210)
                .and_then(|function| function.name.as_deref()),
            Some("main")
        );
        assert_eq!(restored.data_containing(0x1404).unwrap().address, 0x1400);
        assert_eq!(restored.references_to(0x1300).count(), 1);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn project_rejects_trailing_bytes() {
        let path = std::env::temp_dir().join(format!(
            "ventris-project-invalid-{}.bin",
            std::process::id()
        ));
        let project = Project::new(ProjectImage::default());
        project.save_to(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(0);
        std::fs::write(&path, bytes).unwrap();
        assert!(Project::load_from(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
