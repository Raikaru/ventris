//! L0: image parsing. Pure function of bytes, and the only layer that is.
//!
//! Two rules this crate exists to enforce, both learned from a real binary.
//!
//! **1. L0 reports facts, never opinions.** There is deliberately no way to ask
//! an [`Image`] what processor it is for. `e_machine = 8` (MIPS) with
//! `e_flags = 0x20924000` is consistent with several languages, and choosing
//! among them is an L1 assertion. Guessing it wrong on `slus21621.elf` produced
//! **12,158** garbage functions where the right choice produced **45** real
//! ones. A loader that returns a language has already made that mistake
//! unrecoverable; see [`ElfFacts::consistent_languages`].
//!
//! **2. Overlays are derived, not inherited.** The same file explains where
//! Ghidra's `image::` overlay space came from: it has exactly one `PT_LOAD`
//! covering `0x100000..0x9acc80`, and a **non-ALLOC section literally named
//! `image` occupying the identical range**. Two things claim the same
//! addresses, so one of them must go somewhere else. That is a mechanical
//! condition on the file -- [`Placement::Aliases`] -- not a Ghidra quirk to be
//! copied. Recovering it here is what lets `resolve("0x0019d3f0")` refuse with
//! both candidates named instead of silently picking the dead one.
//!
//! Parsing is bounds-checked throughout, allocates nothing per byte, and has no
//! panicking paths: every read goes through [`Endian`] accessors that return
//! `Option`. Input is hostile by assumption.

#![forbid(unsafe_code)]

use ventris_addr::{Addr, SpaceKind, SpaceTable};
pub mod dwarf;
mod metadata;

pub use metadata::{ImageMetadata, ImageRelocation, ImageSymbol};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, d: &[u8], o: usize) -> Option<u16> {
        let end = o.checked_add(2)?;
        let b: [u8; 2] = d.get(o..end)?.try_into().ok()?;
        Some(match self {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
    }

    fn u32(self, d: &[u8], o: usize) -> Option<u32> {
        let end = o.checked_add(4)?;
        let b: [u8; 4] = d.get(o..end)?.try_into().ok()?;
        Some(match self {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    }

    fn u64(self, d: &[u8], o: usize) -> Option<u64> {
        let end = o.checked_add(8)?;
        let b: [u8; 8] = d.get(o..end)?.try_into().ok()?;
        Some(match self {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub enum Loader {
    #[default]
    Auto,
    Raw,
    Elf,
    Pe,
    MachO,
    Coff,
    IntelHex,
    MotorolaSrec,
    /// Nintendo 64 ROM with its 0x400-byte cartridge header.
    N64Rom,
    /// Nintendo GameCube/Wii DOL executable.
    Dol,
    /// Nintendo DS ARM9/ARM7 dual-image cartridge.
    NintendoDs,
    /// Nintendo 3DS NCCH/CXI executable container.
    Ncch,
    /// PSP ELF/PRX image (decryption is intentionally outside L0).
    PspPrx,
    /// Vita or PS3 SCE SELF with an unencrypted embedded ELF.
    VitaSelf,
    /// Wii U RPL/RPX section-loaded ELF.
    WiiURpl,
    /// Xbox 360 XEX2 executable.
    Xex,
    /// PS3 PPU/SPU SCE SELF with an unencrypted embedded ELF.
    Ps3Self,
}

impl Loader {
    pub fn name(self) -> &'static str {
        match self {
            Loader::Auto => "auto",
            Loader::Raw => "raw",
            Loader::Elf => "elf",
            Loader::Pe => "pe",
            Loader::MachO => "macho",
            Loader::Coff => "coff",
            Loader::IntelHex => "ihex",
            Loader::MotorolaSrec => "srec",
            Loader::N64Rom => "n64-rom",
            Loader::Dol => "dol",
            Loader::NintendoDs => "nds",
            Loader::Ncch => "ncch",
            Loader::PspPrx => "psp-prx",
            Loader::VitaSelf => "vita-self",
            Loader::WiiURpl => "wiiu-rpl",
            Loader::Xex => "xex",
            Loader::Ps3Self => "ps3-self",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "raw" | "binary" | "bin" => Some(Self::Raw),
            "elf" => Some(Self::Elf),
            "pe" | "pe32" | "pe32+" | "mz" => Some(Self::Pe),
            "macho" | "mach-o" | "mach_o" => Some(Self::MachO),
            "coff" => Some(Self::Coff),
            "ihex" | "intel-hex" | "intelhex" | "hex" => Some(Self::IntelHex),
            "srec" | "s-record" | "srecord" | "motorola" => Some(Self::MotorolaSrec),
            "n64" | "n64-rom" | "nintendo64" => Some(Self::N64Rom),
            "dol" | "dol-exe" | "gamecube-dol" => Some(Self::Dol),
            "nds" | "ds" | "nintendo-ds" => Some(Self::NintendoDs),
            "ncch" | "cxi" | "3ds" | "3ds-ncch" => Some(Self::Ncch),
            "psp" | "psp-prx" | "prx" => Some(Self::PspPrx),
            "vita" | "vita-self" | "self-vita" => Some(Self::VitaSelf),
            "wiiu" | "wii-u" | "rpl" | "rpx" | "wiiu-rpl" => Some(Self::WiiURpl),
            "xex" | "xex2" | "xbox360" => Some(Self::Xex),
            "ps3" | "ps3-self" | "self-ps3" => Some(Self::Ps3Self),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoadedImage {
    pub bytes: Vec<u8>,
    pub image: Image,
    pub loader: Loader,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FormatError {
    TooSmall,
    UnknownFormat,
    Truncated(&'static str),
    Malformed(&'static str),
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::TooSmall => write!(f, "input too small to identify"),
            FormatError::UnknownFormat => write!(f, "no recognised container magic"),
            FormatError::Truncated(w) => write!(f, "truncated: {w}"),
            FormatError::Malformed(w) => write!(f, "malformed: {w}"),
        }
    }
}

impl std::error::Error for FormatError {}

/// Permissions as the *file* states them. `None` means the container did not
/// say -- which is not hypothetical: the PS2 ELF's only `PT_LOAD` carries
/// `p_flags == 0`. Defaulting that to `rwx` would be inventing a fact, and
/// "executable" is exactly the kind of fact disassembly depends on.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct Perms {
    pub read: Option<bool>,
    pub write: Option<bool>,
    pub exec: Option<bool>,
}

impl Perms {
    pub fn unknown() -> Self {
        Self::default()
    }

    pub fn is_unknown(&self) -> bool {
        *self == Self::default()
    }
}

/// A run of addresses the container maps directly.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Segment {
    pub name: Option<String>,
    pub addr: u64,
    pub size: u64,
    pub file_off: u64,
    pub file_size: u64,
    pub perms: Perms,
}

impl Segment {
    pub fn end(&self) -> u64 {
        self.addr.saturating_add(self.size)
    }

    pub fn overlaps(&self, addr: u64, size: u64) -> bool {
        let (a, b) = (addr, addr.saturating_add(size));
        size != 0 && self.size != 0 && a < self.end() && self.addr < b
    }
}

/// Where an addressed, non-mapped part of the container has to live.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Placement {
    /// Its addresses are free; it can join the default space.
    Mapped,
    /// Its addresses are already claimed by segment `of`. **Requires an overlay
    /// space**, and is the reason a bare offset in such an image is ambiguous.
    Aliases { of: usize },
    /// Addressless (`addr == 0`): metadata, not memory.
    Unaddressed,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Region {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    /// ELF `SHF_ALLOC`. False plus a nonzero address is the interesting case.
    pub alloc: bool,
    pub placement: Placement,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ElfFacts {
    pub class_bits: u8,
    pub endian: Endian,
    pub obj_type: u16,
    pub machine: u16,
    pub flags: u32,
}

impl ElfFacts {
    /// Languages consistent with these facts. Plural on purpose.
    ///
    /// This is a *catalogue*, not a choice: L0 states what the file cannot rule
    /// out, and an L1 assertion picks one. A single-valued `language()` here is
    /// the API shape that let a MIPS64 guess stand in for `r5900`.
    pub fn consistent_languages(&self) -> Vec<&'static str> {
        let width = if self.class_bits == 64 { 64 } else { 32 };
        match self.machine {
            8 | 10 => {
                // Vendor cores share the machine id; the flags word narrows it
                // for some toolchains and not for others.
                let mut v = if self.endian == Endian::Little {
                    vec!["MIPS:LE:32:default", "r5900:LE:32:default"]
                } else {
                    vec!["MIPS:BE:32:default"]
                };
                if width == 64 {
                    v.push(if self.endian == Endian::Little {
                        "MIPS:LE:64:64-32R6addr"
                    } else {
                        "MIPS:BE:64:default"
                    });
                }
                v
            }
            3 => vec!["x86:LE:32:default"],
            62 => vec!["x86:LE:64:default"],
            40 => vec!["ARM:LE:32:v7", "ARM:LE:32:v8"],
            183 => vec!["AARCH64:LE:64:v8A"],
            20 | 21 => vec!["PowerPC:BE:32:default", "PowerPC:BE:64:default"],
            23 => vec!["SPU:BE:32:default"],
            243 => vec!["RISCV:LE:64:default"],
            _ => Vec::new(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PeFacts {
    pub machine: u16,
    /// PE32+ (`0x20b`) rather than PE32 (`0x10b`).
    pub plus: bool,
    pub image_base: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct MachFacts {
    pub class_bits: u8,
    pub endian: Endian,
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub file_type: u32,
    pub flags: u32,
}

impl MachFacts {
    /// Candidate processor languages, without pretending CPU subtype selection
    /// is an L0 fact.
    pub fn consistent_languages(&self) -> Vec<&'static str> {
        match (self.cpu_type, self.endian, self.class_bits) {
            (7, Endian::Little, _) => vec!["x86:LE:32:default"],
            (0x0100_0007, Endian::Little, 64) => vec!["x86:LE:64:default"],
            (12, Endian::Little, _) => vec!["ARM:LE:32:v7", "ARM:LE:32:v8"],
            (0x0100_000c, Endian::Little, 64) => vec!["AARCH64:LE:64:v8A"],
            (18, Endian::Big, _) => vec!["PowerPC:BE:32:default"],
            (0x0100_0012, Endian::Big, 64) => vec!["PowerPC:BE:64:default"],
            _ => Vec::new(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RawFacts {
    pub base: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CoffFacts {
    pub machine: u16,
    pub section_count: u16,
    pub characteristics: u16,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct IntelHexFacts {
    pub address_bits: u8,
    pub data_records: u32,
    pub start: Option<u64>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct MotorolaSrecFacts {
    pub address_bits: u8,
    pub data_records: u32,
    pub start: Option<u64>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct N64RomFacts {
    pub entry: u64,
    pub code_offset: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct DolSegmentFacts {
    pub file_offset: u64,
    pub address: u64,
    pub size: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct DolFacts {
    pub text: [DolSegmentFacts; 7],
    pub data: [DolSegmentFacts; 11],
    pub bss_address: u64,
    pub bss_size: u64,
    pub entry: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NintendoDsFacts {
    pub arm9_entry: u64,
    pub arm9_ram: u64,
    pub arm9_offset: u64,
    pub arm9_size: u64,
    pub arm7_entry: u64,
    pub arm7_ram: u64,
    pub arm7_offset: u64,
    pub arm7_size: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NcchFacts {
    pub flags: u8,
    pub exefs_offset: u64,
    pub exefs_size: u64,
    pub code_address: u64,
    pub code_size: u64,
    pub code_file_off: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PspPrxFacts {
    pub elf: ElfFacts,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SceSelfKind {
    Vita,
    Ps3,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SceSelfFacts {
    pub kind: SceSelfKind,
    pub version: u32,
    pub flags: u16,
    pub header_type: u16,
    pub header_size: u64,
    pub extracted_size: u64,
    pub info_offset: u64,
    pub elf_offset: u64,
    pub elf_filesize: u64,
    pub encrypted: bool,
    pub elf: ElfFacts,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct WiiURplFacts {
    pub elf: ElfFacts,
    pub compressed_sections: usize,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct XexFacts {
    pub version: u32,
    pub module_flags: u32,
    pub code_offset: u64,
    pub certificate_offset: u64,
    pub header_count: u32,
    pub image_base: Option<u64>,
    pub entry: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Format {
    Raw(RawFacts),
    Elf(ElfFacts),
    Pe(PeFacts),
    Mach(MachFacts),
    Coff(CoffFacts),
    IntelHex(IntelHexFacts),
    MotorolaSrec(MotorolaSrecFacts),
    N64Rom(N64RomFacts),
    Dol(DolFacts),
    NintendoDs(NintendoDsFacts),
    Ncch(NcchFacts),
    PspPrx(PspPrxFacts),
    SceSelf(SceSelfFacts),
    WiiURpl(WiiURplFacts),
    Xex(XexFacts),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Image {
    pub len: u64,
    pub format: Format,
    pub segments: Vec<Segment>,
    pub regions: Vec<Region>,
    /// Virtual address, already rebased for PE. `None` when the container has
    /// no entry point (a relocatable object).
    pub entry: Option<u64>,
    pub symbol_count: usize,
}

impl Image {
    pub fn parse(d: &[u8]) -> Result<Image, FormatError> {
        Self::load(d, Loader::Auto, None).map(|loaded| loaded.image)
    }

    /// Extract symbol and relocation facts from an ELF-backed image.
    ///
    /// The source bytes are required because `Image` intentionally stores only
    /// bounded container facts, not a copy of the input file.
    pub fn metadata(&self, source: &[u8]) -> Result<ImageMetadata, FormatError> {
        metadata::extract(source, &self.format)
    }

    /// Debug information, when the container carries any.
    ///
    /// Separate from `metadata` because a symbol table and a debug section
    /// answer different questions: one says where a name lives, the other says
    /// what its type is. An image with no debug sections returns an empty set
    /// rather than an error.
    pub fn debug_info(&self, source: &[u8]) -> Result<dwarf::DebugInfo, FormatError> {
        dwarf::extract(source, &self.format)
    }

    /// Load an image with an explicit loader or deterministic auto-detection.
    ///
    /// Text loaders return normalized, packed data in [`LoadedImage::bytes`].
    /// Their [`Segment::file_off`] values refer to that normalized buffer,
    /// while [`Image::len`] remains the source-file length.
    pub fn load(
        d: &[u8],
        loader: Loader,
        raw_base: Option<u64>,
    ) -> Result<LoadedImage, FormatError> {
        Self::load_with_slice(d, loader, raw_base, None)
    }

    /// Load an image, optionally selecting one slice from a universal Mach-O.
    ///
    /// Fat Mach-O files deliberately require an explicit slice index; choosing
    /// a CPU slice is an L1 assertion, not a file fact.
    pub fn load_with_slice(
        d: &[u8],
        loader: Loader,
        raw_base: Option<u64>,
        slice: Option<usize>,
    ) -> Result<LoadedImage, FormatError> {
        let loader = match loader {
            Loader::Auto => detect_loader(d, slice)?,
            loader => loader,
        };
        if slice.is_some() && loader != Loader::MachO {
            return Err(FormatError::Malformed(
                "slice selection requires a Mach-O image",
            ));
        }
        match loader {
            Loader::Auto => unreachable!("auto loader is resolved above"),
            Loader::Raw => load_raw(d, raw_base.unwrap_or(0)),
            Loader::Elf => loaded_container(d, loader, parse_elf(d)?),
            Loader::Pe => loaded_container(d, loader, parse_pe(d)?),
            Loader::MachO => {
                let selected = match slice {
                    Some(index) => fat_mach_o_slice(d, index)?,
                    None => d,
                };
                loaded_container(selected, loader, parse_mach_o(selected)?)
            }
            Loader::Coff => loaded_container(d, loader, parse_coff(d)?),
            Loader::IntelHex => parse_intel_hex(d),
            Loader::MotorolaSrec => parse_motorola_srec(d),
            Loader::N64Rom => loaded_container(d, loader, parse_n64_rom(d, raw_base)?),
            Loader::Dol => loaded_container(d, loader, parse_dol(d)?),
            Loader::NintendoDs => loaded_container(d, loader, parse_nintendo_ds(d)?),
            Loader::Ncch => loaded_container(d, loader, parse_ncch(d)?),
            Loader::PspPrx => loaded_container(d, loader, parse_psp_prx(d)?),
            Loader::VitaSelf => {
                loaded_container(d, loader, parse_sce_self(d, Some(SceSelfKind::Vita))?)
            }
            Loader::WiiURpl => loaded_container(d, loader, parse_wiiu_rpl(d)?),
            Loader::Xex => loaded_container(d, loader, parse_xex(d)?),
            Loader::Ps3Self => {
                loaded_container(d, loader, parse_sce_self(d, Some(SceSelfKind::Ps3))?)
            }
        }
    }

    /// Content hash. Separate from [`Image::parse`] because hashing megabytes is
    /// a decision, not a parsing cost -- a truncation sweep that re-hashes a
    /// 10 MB file per prefix is quadratic for no reason.
    /// Stable identity hash for the original file bytes.
    pub fn content_hash(d: &[u8]) -> u64 {
        ventris_addr::hash::stable64(d)
    }

    /// Regions that cannot join the default space.
    pub fn aliasing_regions(&self) -> impl Iterator<Item = &Region> {
        self.regions
            .iter()
            .filter(|r| matches!(r.placement, Placement::Aliases { .. }))
    }

    /// Build the address spaces this image implies: one default space for the
    /// mapped segments, plus one overlay per aliasing region.
    ///
    /// This is where L0 hands off to the address policy. On an image with an
    /// aliasing region, a bare offset inside the aliased range is genuinely
    /// ambiguous, and the resulting refusal is the intended behaviour.
    pub fn space_table(&self) -> SpaceTable {
        let mut t = SpaceTable::default();
        let default = t.add("ram", SpaceKind::Code, None);
        for s in &self.segments {
            t.map_range(default, s.addr, s.size);
        }
        for r in self.aliasing_regions() {
            let id = t.add(&r.name, SpaceKind::Overlay, Some(Addr::new(default, 0)));
            t.map_range(id, r.addr, r.size);
        }
        t
    }

    /// Return file-backed bytes at a virtual address.
    ///
    /// The returned slice never crosses a segment or the file-backed portion
    /// of one. Zero-filled BSS is intentionally not fabricated here: a lifter
    /// must distinguish bytes present in the image from bytes implied by its
    /// memory map.
    pub fn bytes_at<'a>(&self, d: &'a [u8], addr: u64, max: usize) -> Option<&'a [u8]> {
        let segment = self.segments.iter().find(|s| {
            s.file_size != 0 && addr >= s.addr && addr.saturating_sub(s.addr) < s.file_size
        })?;
        let delta = addr.checked_sub(segment.addr)?;
        let file_start = segment.file_off.checked_add(delta)?;
        let segment_end = segment.file_off.checked_add(segment.file_size)?;
        let file_start = usize::try_from(file_start).ok()?;
        let file_end = usize::try_from(segment_end).ok()?.min(d.len());
        if file_start >= file_end || file_start >= d.len() {
            return None;
        }
        let end = file_start.saturating_add(max).min(file_end);
        Some(&d[file_start..end])
    }

    /// Segments whose file-declared permissions make them executable.
    pub fn executable_segments(&self) -> impl Iterator<Item = &Segment> {
        self.segments.iter().filter(|s| s.perms.exec == Some(true))
    }
}

fn loaded_container(d: &[u8], loader: Loader, image: Image) -> Result<LoadedImage, FormatError> {
    Ok(LoadedImage {
        bytes: d.to_vec(),
        image,
        loader,
    })
}

fn detect_loader(d: &[u8], slice: Option<usize>) -> Result<Loader, FormatError> {
    if d.len() < 4 {
        return Err(FormatError::TooSmall);
    }
    if d.starts_with(b"XEX2") {
        return Ok(Loader::Xex);
    }
    if d.starts_with(&[0x80, 0x37, 0x12, 0x40]) {
        return Ok(Loader::N64Rom);
    }
    if d.len() >= 0x104 && d.get(0x100..0x104) == Some(b"NCCH") {
        return Ok(Loader::Ncch);
    }
    if d.starts_with(b"SCE\0") {
        return match detect_sce_kind(d)? {
            SceSelfKind::Vita => Ok(Loader::VitaSelf),
            SceSelfKind::Ps3 => Ok(Loader::Ps3Self),
        };
    }
    if d.starts_with(b"\x7fELF") {
        if slice.is_some() {
            return Err(FormatError::Malformed(
                "slice selection requires a Mach-O image",
            ));
        }
        return if looks_like_wiiu_rpl(d) {
            Ok(Loader::WiiURpl)
        } else {
            Ok(Loader::Elf)
        };
    }
    if d.starts_with(b"MZ") {
        if slice.is_some() {
            return Err(FormatError::Malformed(
                "slice selection requires a Mach-O image",
            ));
        }
        return Ok(Loader::Pe);
    }
    if is_mach_o_magic(d) {
        if slice.is_some() {
            return Err(FormatError::Malformed(
                "slice selection requires a fat Mach-O image",
            ));
        }
        return Ok(Loader::MachO);
    }
    if is_fat_mach_o_magic(d) {
        return if slice.is_some() {
            Ok(Loader::MachO)
        } else {
            Err(FormatError::Malformed(
                "fat Mach-O requires a selected slice",
            ))
        };
    }
    if slice.is_some() {
        return Err(FormatError::Malformed(
            "slice selection requires a Mach-O image",
        ));
    }
    let text = std::str::from_utf8(d).unwrap_or_default();
    let first = text.lines().map(str::trim).find(|line| !line.is_empty());
    if first.is_some_and(|line| line.starts_with(':')) {
        return Ok(Loader::IntelHex);
    }
    if first.is_some_and(|line| {
        let bytes = line.as_bytes();
        bytes.len() >= 2 && bytes[0] == b'S' && bytes[1].is_ascii_digit()
    }) {
        return Ok(Loader::MotorolaSrec);
    }
    if looks_like_coff(d) {
        return Ok(Loader::Coff);
    }
    Err(FormatError::UnknownFormat)
}

fn checked_range<'a>(
    d: &'a [u8],
    offset: u64,
    size: u64,
    what: &'static str,
) -> Result<&'a [u8], FormatError> {
    let start = usize::try_from(offset).map_err(|_| FormatError::Malformed(what))?;
    let len = usize::try_from(size).map_err(|_| FormatError::Malformed(what))?;
    let end = start.checked_add(len).ok_or(FormatError::Malformed(what))?;
    d.get(start..end).ok_or(FormatError::Truncated(what))
}

fn parse_n64_rom(d: &[u8], raw_base: Option<u64>) -> Result<Image, FormatError> {
    if d.len() < 0x404 {
        return Err(FormatError::Truncated("Nintendo 64 ROM header/code"));
    }
    if d.get(0..4) != Some(&[0x80, 0x37, 0x12, 0x40]) {
        return Err(FormatError::Malformed(
            "Nintendo 64 ROM is not big-endian (.z64)",
        ));
    }
    let header_entry = u64::from(
        Endian::Big
            .u32(d, 0x08)
            .ok_or(FormatError::Truncated("Nintendo 64 entry"))?,
    );
    let default_code_addr = 0x8000_0400;
    let code_addr = raw_base.unwrap_or(default_code_addr);
    let entry = raw_base
        .map(|base| base.saturating_add(header_entry.saturating_sub(default_code_addr)))
        .unwrap_or(header_entry);
    let code_size = u64::try_from(d.len() - 0x400).expect("usize fits u64");
    let segment = Segment {
        name: Some(".rom".into()),
        addr: code_addr,
        size: code_size,
        file_off: 0x400,
        file_size: code_size,
        perms: Perms::unknown(),
    };
    Ok(Image {
        len: d.len() as u64,
        format: Format::N64Rom(N64RomFacts {
            entry,
            code_offset: 0x400,
        }),
        segments: vec![segment],
        regions: Vec::new(),
        entry: Some(entry),
        symbol_count: 0,
    })
}

fn parse_dol_segment(
    d: &[u8],
    file_offset: u64,
    address: u64,
    size: u64,
    what: &'static str,
) -> Result<DolSegmentFacts, FormatError> {
    if size != 0 {
        if file_offset == 0 {
            return Err(FormatError::Malformed(what));
        }
        checked_range(d, file_offset, size, what)?;
    }
    Ok(DolSegmentFacts {
        file_offset,
        address,
        size,
    })
}

fn parse_dol(d: &[u8]) -> Result<Image, FormatError> {
    if d.len() < 0x100 {
        return Err(FormatError::Truncated("DOL header"));
    }
    let en = Endian::Big;
    let mut text = [DolSegmentFacts::default(); 7];
    let mut data = [DolSegmentFacts::default(); 11];
    let mut segments = Vec::with_capacity(19);
    for index in 0..7 {
        let file_offset = u64::from(
            en.u32(d, index * 4)
                .ok_or(FormatError::Truncated("DOL text offset"))?,
        );
        let address = u64::from(
            en.u32(d, 0x48 + index * 4)
                .ok_or(FormatError::Truncated("DOL text address"))?,
        );
        let size = u64::from(
            en.u32(d, 0x90 + index * 4)
                .ok_or(FormatError::Truncated("DOL text size"))?,
        );
        let fact = parse_dol_segment(d, file_offset, address, size, "DOL text section")?;
        text[index] = fact;
        if fact.size != 0 {
            segments.push(Segment {
                name: Some(format!(".text{index}")),
                addr: fact.address,
                size: fact.size,
                file_off: fact.file_offset,
                file_size: fact.size,
                perms: Perms {
                    read: Some(true),
                    write: Some(false),
                    exec: Some(true),
                },
            });
        }
    }
    for index in 0..11 {
        let file_offset = u64::from(
            en.u32(d, 0x1c + index * 4)
                .ok_or(FormatError::Truncated("DOL data offset"))?,
        );
        let address = u64::from(
            en.u32(d, 0x64 + index * 4)
                .ok_or(FormatError::Truncated("DOL data address"))?,
        );
        let size = u64::from(
            en.u32(d, 0xac + index * 4)
                .ok_or(FormatError::Truncated("DOL data size"))?,
        );
        let fact = parse_dol_segment(d, file_offset, address, size, "DOL data section")?;
        data[index] = fact;
        if fact.size != 0 {
            segments.push(Segment {
                name: Some(format!(".data{index}")),
                addr: fact.address,
                size: fact.size,
                file_off: fact.file_offset,
                file_size: fact.size,
                perms: Perms {
                    read: Some(true),
                    write: Some(true),
                    exec: Some(false),
                },
            });
        }
    }
    let bss_address = u64::from(
        en.u32(d, 0xd8)
            .ok_or(FormatError::Truncated("DOL BSS address"))?,
    );
    let bss_size = u64::from(
        en.u32(d, 0xdc)
            .ok_or(FormatError::Truncated("DOL BSS size"))?,
    );
    let entry = u64::from(en.u32(d, 0xe0).ok_or(FormatError::Truncated("DOL entry"))?);
    if bss_size != 0 {
        segments.push(Segment {
            name: Some(".bss".into()),
            addr: bss_address,
            size: bss_size,
            file_off: 0,
            file_size: 0,
            perms: Perms {
                read: Some(true),
                write: Some(true),
                exec: Some(false),
            },
        });
    }
    Ok(Image {
        len: d.len() as u64,
        format: Format::Dol(DolFacts {
            text,
            data,
            bss_address,
            bss_size,
            entry,
        }),
        segments,
        regions: Vec::new(),
        entry: Some(entry),
        symbol_count: 0,
    })
}

fn parse_nintendo_ds(d: &[u8]) -> Result<Image, FormatError> {
    if d.len() < 0x40 {
        return Err(FormatError::Truncated("Nintendo DS header"));
    }
    let en = Endian::Little;
    let arm9_offset = u64::from(
        en.u32(d, 0x20)
            .ok_or(FormatError::Truncated("ARM9 offset"))?,
    );
    let arm9_entry = u64::from(
        en.u32(d, 0x24)
            .ok_or(FormatError::Truncated("ARM9 entry"))?,
    );
    let arm9_ram = u64::from(en.u32(d, 0x28).ok_or(FormatError::Truncated("ARM9 RAM"))?);
    let arm9_size = u64::from(en.u32(d, 0x2c).ok_or(FormatError::Truncated("ARM9 size"))?);
    let arm7_offset = u64::from(
        en.u32(d, 0x30)
            .ok_or(FormatError::Truncated("ARM7 offset"))?,
    );
    let arm7_entry = u64::from(
        en.u32(d, 0x34)
            .ok_or(FormatError::Truncated("ARM7 entry"))?,
    );
    let arm7_ram = u64::from(en.u32(d, 0x38).ok_or(FormatError::Truncated("ARM7 RAM"))?);
    let arm7_size = u64::from(en.u32(d, 0x3c).ok_or(FormatError::Truncated("ARM7 size"))?);
    if arm9_size == 0 || arm7_size == 0 {
        return Err(FormatError::Malformed(
            "Nintendo DS image has an empty ARM image",
        ));
    }
    checked_range(d, arm9_offset, arm9_size, "ARM9 image")?;
    checked_range(d, arm7_offset, arm7_size, "ARM7 image")?;
    let segments = vec![
        Segment {
            name: Some("arm9".into()),
            addr: arm9_ram,
            size: arm9_size,
            file_off: arm9_offset,
            file_size: arm9_size,
            perms: Perms {
                read: Some(true),
                write: Some(false),
                exec: Some(true),
            },
        },
        Segment {
            name: Some("arm7".into()),
            addr: arm7_ram,
            size: arm7_size,
            file_off: arm7_offset,
            file_size: arm7_size,
            perms: Perms {
                read: Some(true),
                write: Some(false),
                exec: Some(true),
            },
        },
    ];
    Ok(Image {
        len: d.len() as u64,
        format: Format::NintendoDs(NintendoDsFacts {
            arm9_entry,
            arm9_ram,
            arm9_offset,
            arm9_size,
            arm7_entry,
            arm7_ram,
            arm7_offset,
            arm7_size,
        }),
        segments,
        regions: Vec::new(),
        entry: Some(arm9_entry),
        symbol_count: 0,
    })
}

fn parse_ncch(d: &[u8]) -> Result<Image, FormatError> {
    if d.len() < 0x200 {
        return Err(FormatError::Truncated("NCCH header"));
    }
    if d.get(0x100..0x104) != Some(b"NCCH") {
        return Err(FormatError::Malformed("NCCH signature"));
    }
    let en = Endian::Little;
    let flags = *d.get(0x18f).ok_or(FormatError::Truncated("NCCH flags"))?;
    let exefs_offset = u64::from(
        en.u32(d, 0x1a0)
            .ok_or(FormatError::Truncated("ExeFS offset"))?,
    );
    let exefs_size = u64::from(
        en.u32(d, 0x1a4)
            .ok_or(FormatError::Truncated("ExeFS size"))?,
    );
    let exefs_offset = exefs_offset
        .checked_mul(0x200)
        .ok_or(FormatError::Malformed("ExeFS offset"))?;
    let exefs_size = exefs_size
        .checked_mul(0x200)
        .ok_or(FormatError::Malformed("ExeFS size"))?;
    let exefs = checked_range(d, exefs_offset, exefs_size, "ExeFS")?;
    if exefs.len() < 0x200 {
        return Err(FormatError::Truncated("ExeFS header"));
    }
    let code_address = en
        .u32(d, 0x210)
        .map(u64::from)
        .ok_or(FormatError::Truncated("3DS code address"))?;
    let code_size = en
        .u32(d, 0x218)
        .map(u64::from)
        .ok_or(FormatError::Truncated("3DS code size"))?;
    // CompressExefsCode is bit 0 of the SCI flags byte at exheader+0xd.
    if d.get(0x20d).is_some_and(|byte| byte & 1 != 0) {
        return Err(FormatError::Malformed(
            "compressed 3DS ExeFS .code requires decompression",
        ));
    }
    let mut code_file_off = None;
    let mut code_file_size = 0u64;
    for index in 0..10usize {
        let header = index * 16;
        let name_bytes = &exefs[header..header + 8];
        let name_end = name_bytes.iter().position(|&byte| byte == 0).unwrap_or(8);
        let name = std::str::from_utf8(&name_bytes[..name_end]).unwrap_or_default();
        if name != ".code" {
            continue;
        }
        let relative = u64::from(
            en.u32(exefs, header + 8)
                .ok_or(FormatError::Truncated("ExeFS file offset"))?,
        );
        let size = u64::from(
            en.u32(exefs, header + 12)
                .ok_or(FormatError::Truncated("ExeFS file size"))?,
        );
        let relative = relative
            .checked_add(0x200)
            .ok_or(FormatError::Malformed("ExeFS code offset"))?;
        let absolute = exefs_offset
            .checked_add(relative)
            .ok_or(FormatError::Malformed("ExeFS code offset"))?;
        checked_range(d, absolute, size, "ExeFS .code")?;
        code_file_off = Some(absolute);
        code_file_size = size;
        break;
    }
    let code_file_off = code_file_off.ok_or(FormatError::Malformed("ExeFS has no .code"))?;
    let segment = Segment {
        name: Some(".code".into()),
        addr: code_address,
        size: code_size.max(code_file_size),
        file_off: code_file_off,
        file_size: code_file_size,
        perms: Perms {
            read: Some(true),
            write: Some(false),
            exec: Some(true),
        },
    };
    Ok(Image {
        len: d.len() as u64,
        format: Format::Ncch(NcchFacts {
            flags,
            exefs_offset,
            exefs_size,
            code_address,
            code_size,
            code_file_off,
        }),
        segments: vec![segment],
        regions: Vec::new(),
        entry: Some(code_address),
        symbol_count: 0,
    })
}

fn parse_psp_prx(d: &[u8]) -> Result<Image, FormatError> {
    let mut image = parse_elf(d)?;
    let elf = match image.format {
        Format::Elf(elf) => elf,
        _ => return Err(FormatError::Malformed("PSP PRX is not ELF")),
    };
    if elf.endian != Endian::Little || elf.machine != 8 {
        return Err(FormatError::Malformed("PSP PRX is not little-endian MIPS"));
    }
    image.format = Format::PspPrx(PspPrxFacts { elf });
    Ok(image)
}

fn self_header(d: &[u8]) -> Result<(u32, u16, u16, u64, u64, u64, u64), FormatError> {
    if d.len() < 0x80 {
        return Err(FormatError::Truncated("SCE SELF header"));
    }
    if d.get(0..4) != Some(b"SCE\0") {
        return Err(FormatError::Malformed("SCE SELF signature"));
    }
    let en = Endian::Big;
    let version = en.u32(d, 4).ok_or(FormatError::Truncated("SELF version"))?;
    let flags = en.u16(d, 8).ok_or(FormatError::Truncated("SELF flags"))?;
    let header_type = en
        .u16(d, 0xa)
        .ok_or(FormatError::Truncated("SELF header type"))?;
    let header_size = en
        .u64(d, 0x10)
        .ok_or(FormatError::Truncated("SELF header size"))?;
    let extracted_size = en
        .u64(d, 0x18)
        .ok_or(FormatError::Truncated("SELF extracted size"))?;
    let info_offset = en
        .u64(d, 0x28)
        .ok_or(FormatError::Truncated("SELF info offset"))?;
    let elf_offset = en
        .u64(d, 0x30)
        .ok_or(FormatError::Truncated("SELF ELF offset"))?;
    if header_size < 0x20 || header_size > d.len() as u64 {
        return Err(FormatError::Malformed("SELF header size"));
    }
    if extracted_size == 0 {
        return Err(FormatError::Malformed("SELF extracted size"));
    }
    Ok((
        version,
        flags,
        header_type,
        header_size,
        extracted_size,
        info_offset,
        elf_offset,
    ))
}

fn detect_sce_kind(d: &[u8]) -> Result<SceSelfKind, FormatError> {
    let (_, _, _, _, elf_filesize, _, elf_offset) = self_header(d)?;
    let elf = checked_range(d, elf_offset, elf_filesize, "SELF embedded ELF")?;
    let image = parse_elf(elf).map_err(|_| FormatError::Malformed("SELF embedded ELF"))?;
    let facts = match image.format {
        Format::Elf(facts) => facts,
        _ => return Err(FormatError::Malformed("SELF embedded ELF")),
    };
    match facts.machine {
        40 => Ok(SceSelfKind::Vita),
        21 | 23 => Ok(SceSelfKind::Ps3),
        _ => Err(FormatError::Malformed("unknown SELF processor")),
    }
}

fn parse_sce_self(d: &[u8], expected: Option<SceSelfKind>) -> Result<Image, FormatError> {
    let (version, flags, header_type, header_size, extracted_size, info_offset, elf_offset) =
        self_header(d)?;
    if info_offset != 0 && info_offset >= d.len() as u64 {
        return Err(FormatError::Malformed("SELF info offset"));
    }
    let kind = detect_sce_kind(d)?;
    if expected.is_some_and(|expected| expected != kind) {
        return Err(FormatError::Malformed(
            "SELF processor does not match loader",
        ));
    }
    let embedded = checked_range(d, elf_offset, extracted_size, "SELF embedded ELF")?;
    let mut image = parse_elf(embedded)?;
    let elf = match image.format {
        Format::Elf(elf) => elf,
        _ => return Err(FormatError::Malformed("SELF embedded ELF")),
    };
    for segment in &mut image.segments {
        segment.file_off = segment
            .file_off
            .checked_add(elf_offset)
            .ok_or(FormatError::Malformed("SELF segment offset"))?;
        let end = segment
            .file_off
            .checked_add(segment.file_size)
            .ok_or(FormatError::Malformed("SELF segment range"))?;
        if end > d.len() as u64 {
            return Err(FormatError::Truncated("SELF segment"));
        }
    }
    image.len = d.len() as u64;
    image.format = Format::SceSelf(SceSelfFacts {
        kind,
        version,
        flags,
        header_type,
        header_size,
        extracted_size,
        info_offset,
        elf_offset,
        elf_filesize: extracted_size,
        encrypted: false,
        elf,
    });
    Ok(image)
}

fn elf_section_table(d: &[u8], facts: ElfFacts) -> Result<(u64, u16, u16, u16), FormatError> {
    let en = facts.endian;
    if facts.class_bits == 64 {
        Ok((
            en.u64(d, 0x28).ok_or(FormatError::Truncated("e_shoff"))?,
            en.u16(d, 0x3a)
                .ok_or(FormatError::Truncated("e_shentsize"))?,
            en.u16(d, 0x3c).ok_or(FormatError::Truncated("e_shnum"))?,
            en.u16(d, 0x3e)
                .ok_or(FormatError::Truncated("e_shstrndx"))?,
        ))
    } else {
        Ok((
            u64::from(en.u32(d, 0x20).ok_or(FormatError::Truncated("e_shoff"))?),
            en.u16(d, 0x2e)
                .ok_or(FormatError::Truncated("e_shentsize"))?,
            en.u16(d, 0x30).ok_or(FormatError::Truncated("e_shnum"))?,
            en.u16(d, 0x32)
                .ok_or(FormatError::Truncated("e_shstrndx"))?,
        ))
    }
}

fn elf_section(
    d: &[u8],
    facts: ElfFacts,
    table: u64,
    entsize: u16,
    index: usize,
) -> Result<(u32, u32, u64, u64, u64, u64), FormatError> {
    let o = table
        .checked_add(
            u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_mul(u64::from(entsize)))
                .ok_or(FormatError::Malformed("section index"))?,
        )
        .ok_or(FormatError::Malformed("section offset"))?;
    let en = facts.endian;
    if facts.class_bits == 64 {
        Ok((
            en.u32(
                d,
                usize::try_from(o).map_err(|_| FormatError::Malformed("section offset"))?,
            )
            .ok_or(FormatError::Truncated("section name"))?,
            en.u32(
                d,
                usize::try_from(o + 4).map_err(|_| FormatError::Malformed("section offset"))?,
            )
            .ok_or(FormatError::Truncated("section type"))?,
            en.u64(
                d,
                usize::try_from(o + 8).map_err(|_| FormatError::Malformed("section offset"))?,
            )
            .ok_or(FormatError::Truncated("section flags"))?,
            en.u64(
                d,
                usize::try_from(o + 16).map_err(|_| FormatError::Malformed("section offset"))?,
            )
            .ok_or(FormatError::Truncated("section address"))?,
            en.u64(
                d,
                usize::try_from(o + 24).map_err(|_| FormatError::Malformed("section offset"))?,
            )
            .ok_or(FormatError::Truncated("section file offset"))?,
            en.u64(
                d,
                usize::try_from(o + 32).map_err(|_| FormatError::Malformed("section offset"))?,
            )
            .ok_or(FormatError::Truncated("section size"))?,
        ))
    } else {
        Ok((
            en.u32(
                d,
                usize::try_from(o).map_err(|_| FormatError::Malformed("section offset"))?,
            )
            .ok_or(FormatError::Truncated("section name"))?,
            en.u32(
                d,
                usize::try_from(o + 4).map_err(|_| FormatError::Malformed("section offset"))?,
            )
            .ok_or(FormatError::Truncated("section type"))?,
            u64::from(
                en.u32(
                    d,
                    usize::try_from(o + 8).map_err(|_| FormatError::Malformed("section offset"))?,
                )
                .ok_or(FormatError::Truncated("section flags"))?,
            ),
            u64::from(
                en.u32(
                    d,
                    usize::try_from(o + 12)
                        .map_err(|_| FormatError::Malformed("section offset"))?,
                )
                .ok_or(FormatError::Truncated("section address"))?,
            ),
            u64::from(
                en.u32(
                    d,
                    usize::try_from(o + 16)
                        .map_err(|_| FormatError::Malformed("section offset"))?,
                )
                .ok_or(FormatError::Truncated("section file offset"))?,
            ),
            u64::from(
                en.u32(
                    d,
                    usize::try_from(o + 20)
                        .map_err(|_| FormatError::Malformed("section offset"))?,
                )
                .ok_or(FormatError::Truncated("section size"))?,
            ),
        ))
    }
}

fn section_name(d: &[u8], string_offset: u64, string_size: u64, name: u32) -> String {
    let Some(table) = checked_range(d, string_offset, string_size, "section names").ok() else {
        return String::new();
    };
    let start = usize::try_from(name)
        .ok()
        .filter(|start| *start < table.len());
    let Some(start) = start else {
        return String::new();
    };
    let end = table[start..]
        .iter()
        .position(|&byte| byte == 0)
        .map(|end| start + end)
        .unwrap_or(table.len());
    String::from_utf8_lossy(&table[start..end]).into_owned()
}

fn looks_like_wiiu_rpl(d: &[u8]) -> bool {
    if d.len() < 0x34 || d.get(0..4) != Some(b"\x7fELF") || d[4] != 1 || d[5] != 2 {
        return false;
    }
    let machine = u16::from_be_bytes([d[18], d[19]]);
    let phnum = u16::from_be_bytes([d[44], d[45]]);
    machine == 20 && phnum == 0
}

fn parse_wiiu_rpl(d: &[u8]) -> Result<Image, FormatError> {
    let elf = parse_elf(d)?;
    let facts = match elf.format {
        Format::Elf(facts) => facts,
        _ => return Err(FormatError::Malformed("RPL is not ELF")),
    };
    if facts.machine != 20 || facts.endian != Endian::Big {
        return Err(FormatError::Malformed("RPL is not big-endian PowerPC"));
    }
    let (table, entsize, count, string_index) = elf_section_table(d, facts)?;
    if count == 0 || entsize == 0 || usize::from(string_index) >= usize::from(count) {
        return Err(FormatError::Malformed("RPL section table"));
    }
    let string_section = elf_section(d, facts, table, entsize, usize::from(string_index))?;
    let mut regions = Vec::new();
    let mut segments = Vec::new();
    let mut symbol_count = 0usize;
    let mut compressed_sections = 0usize;
    for index in 0..usize::from(count) {
        let (name_offset, kind, flags, address, file_offset, size) =
            elf_section(d, facts, table, entsize, index)?;
        let name = section_name(d, string_section.4, string_section.5, name_offset);
        let alloc = flags & 2 != 0;
        if kind == 2 || kind == 11 {
            let entry_size = if facts.class_bits == 64 { 24 } else { 16 };
            symbol_count =
                symbol_count.saturating_add(usize::try_from(size / entry_size).unwrap_or(0));
        }
        if flags & 0x8000_0000 != 0 {
            compressed_sections = compressed_sections.saturating_add(1);
        }
        if size != 0 {
            regions.push(Region {
                name: name.clone(),
                addr: address,
                size,
                alloc,
                placement: Placement::Mapped,
            });
        }
        if !alloc || size == 0 || kind == 8 {
            continue;
        }
        checked_range(d, file_offset, size, "RPL section data")?;
        segments.push(Segment {
            name: Some(name),
            addr: address,
            size,
            file_off: file_offset,
            file_size: size,
            perms: Perms {
                read: Some(true),
                write: Some(flags & 1 != 0),
                exec: Some(flags & 4 != 0),
            },
        });
    }
    Ok(Image {
        len: d.len() as u64,
        format: Format::WiiURpl(WiiURplFacts {
            elf: facts,
            compressed_sections,
        }),
        segments,
        regions,
        entry: elf.entry,
        symbol_count,
    })
}

fn parse_xex(d: &[u8]) -> Result<Image, FormatError> {
    if d.len() < 24 || d.get(0..4) != Some(b"XEX2") {
        return Err(FormatError::Malformed("XEX2 header"));
    }
    let en = Endian::Big;
    let module_flags = en
        .u32(d, 4)
        .ok_or(FormatError::Truncated("XEX module flags"))?;
    let code_offset = u64::from(
        en.u32(d, 8)
            .ok_or(FormatError::Truncated("XEX PE data offset"))?,
    );
    let certificate_offset = u64::from(
        en.u32(d, 16)
            .ok_or(FormatError::Truncated("XEX security info offset"))?,
    );
    let header_count = en
        .u32(d, 20)
        .ok_or(FormatError::Truncated("XEX header count"))?;
    let table_end = 24usize
        .checked_add(
            usize::try_from(header_count)
                .ok()
                .and_then(|count| count.checked_mul(8))
                .ok_or(FormatError::Malformed("XEX optional headers"))?,
        )
        .ok_or(FormatError::Malformed("XEX optional headers"))?;
    if table_end > d.len() {
        return Err(FormatError::Truncated("XEX optional headers"));
    }
    let mut entry = None;
    let mut image_base = None;
    for index in 0..usize::try_from(header_count).unwrap_or(0) {
        let offset = 24 + index * 8;
        let key = en
            .u32(d, offset)
            .ok_or(FormatError::Truncated("XEX header key"))?;
        let value = u64::from(
            en.u32(d, offset + 4)
                .ok_or(FormatError::Truncated("XEX header value"))?,
        );
        match key {
            0x0001_0100 => entry = Some(value),
            0x0001_0201 => image_base = Some(value),
            _ => {}
        }
    }
    let code_start =
        usize::try_from(code_offset).map_err(|_| FormatError::Malformed("XEX PE data offset"))?;
    let embedded = d
        .get(code_start..)
        .ok_or(FormatError::Truncated("XEX PE data"))?;
    let pe = parse_pe(embedded)
        .map_err(|_| FormatError::Malformed("XEX embedded PE is encrypted or malformed"))?;
    if pe.segments.is_empty() {
        return Err(FormatError::Malformed("XEX embedded PE has no sections"));
    }
    let pe_base = match &pe.format {
        Format::Pe(facts) => facts.image_base,
        _ => return Err(FormatError::Malformed("XEX embedded PE")),
    };
    let image_base = image_base.or(Some(pe_base));
    let address_delta = image_base.unwrap_or(pe_base).wrapping_sub(pe_base);
    let mut segments = pe.segments;
    for segment in &mut segments {
        segment.file_off = segment
            .file_off
            .checked_add(code_offset)
            .ok_or(FormatError::Malformed("XEX section offset"))?;
        checked_range(d, segment.file_off, segment.file_size, "XEX section data")?;
        segment.addr = segment.addr.wrapping_add(address_delta);
    }
    let entry = entry.or_else(|| pe.entry.map(|value| value.wrapping_add(address_delta)));
    Ok(Image {
        len: d.len() as u64,
        format: Format::Xex(XexFacts {
            version: 2,
            module_flags,
            code_offset,
            certificate_offset,
            header_count,
            image_base,
            entry,
        }),
        segments,
        regions: pe.regions,
        entry,
        symbol_count: pe.symbol_count,
    })
}

fn load_raw(d: &[u8], base: u64) -> Result<LoadedImage, FormatError> {
    if d.is_empty() {
        return Err(FormatError::TooSmall);
    }
    let image = Image {
        len: d.len() as u64,
        format: Format::Raw(RawFacts { base }),
        segments: vec![Segment {
            name: Some("raw".into()),
            addr: base,
            size: d.len() as u64,
            file_off: 0,
            file_size: d.len() as u64,
            perms: Perms::unknown(),
        }],
        regions: Vec::new(),
        entry: Some(base),
        symbol_count: 0,
    };
    Ok(LoadedImage {
        bytes: d.to_vec(),
        image,
        loader: Loader::Raw,
    })
}
fn looks_like_coff(d: &[u8]) -> bool {
    if d.len() < 20 {
        return false;
    }
    let machine = u16::from_le_bytes([d[0], d[1]]);
    let sections = u16::from_le_bytes([d[2], d[3]]) as usize;
    let optional_size = u16::from_le_bytes([d[16], d[17]]) as usize;
    matches!(machine, 0x014c | 0x01c0 | 0x8664 | 0xaa64 | 0x5032 | 0x5064)
        && sections != 0
        && sections <= 96
        && 20usize
            .checked_add(optional_size)
            .and_then(|o| o.checked_add(sections.checked_mul(40)?))
            .is_some_and(|end| end <= d.len())
}

fn parse_coff(d: &[u8]) -> Result<Image, FormatError> {
    if d.len() < 20 {
        return Err(FormatError::Truncated("coff header"));
    }
    let en = Endian::Little;
    let machine = en.u16(d, 0).ok_or(FormatError::Truncated("coff machine"))?;
    let section_count = en
        .u16(d, 2)
        .ok_or(FormatError::Truncated("coff section count"))?;
    let symbol_ptr = en
        .u32(d, 8)
        .ok_or(FormatError::Truncated("coff symbol table"))?;
    let symbol_count = en
        .u32(d, 12)
        .ok_or(FormatError::Truncated("coff symbol count"))?;
    let optional_size =
        en.u16(d, 16)
            .ok_or(FormatError::Truncated("coff optional header size"))? as usize;
    let characteristics = en
        .u16(d, 18)
        .ok_or(FormatError::Truncated("coff characteristics"))?;
    let section_table = 20usize
        .checked_add(optional_size)
        .ok_or(FormatError::Malformed("coff section table"))?;
    let section_count_usize = usize::from(section_count);
    let table_end = section_table
        .checked_add(
            section_count_usize
                .checked_mul(40)
                .ok_or(FormatError::Malformed("coff section count"))?,
        )
        .ok_or(FormatError::Malformed("coff section table"))?;
    if table_end > d.len() {
        return Err(FormatError::Truncated("coff section table"));
    }

    let mut segments = Vec::new();
    let mut regions = Vec::new();
    for index in 0..section_count_usize {
        let o = section_table + index * 40;
        let raw_name = &d[o..o + 8];
        let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
        let virtual_size = u64::from(
            en.u32(d, o + 8)
                .ok_or(FormatError::Truncated("coff virtual size"))?,
        );
        let address = u64::from(
            en.u32(d, o + 12)
                .ok_or(FormatError::Truncated("coff section address"))?,
        );
        let raw_size = u64::from(
            en.u32(d, o + 16)
                .ok_or(FormatError::Truncated("coff raw size"))?,
        );
        let raw_ptr = u64::from(
            en.u32(d, o + 20)
                .ok_or(FormatError::Truncated("coff raw pointer"))?,
        );
        let section_flags = en
            .u32(d, o + 36)
            .ok_or(FormatError::Truncated("coff section flags"))?;
        let size = virtual_size.max(raw_size);
        regions.push(Region {
            name: name.clone(),
            addr: address,
            size,
            alloc: size != 0,
            placement: Placement::Mapped,
        });
        if raw_size == 0 {
            continue;
        }
        let raw_end = raw_ptr
            .checked_add(raw_size)
            .ok_or(FormatError::Malformed("coff raw range"))?;
        if raw_end > d.len() as u64 {
            return Err(FormatError::Truncated("coff section data"));
        }
        let perms = Perms {
            read: Some(section_flags & 0x4000_0000 != 0),
            write: Some(section_flags & 0x8000_0000 != 0),
            exec: Some(section_flags & 0x2000_0000 != 0),
        };
        segments.push(Segment {
            name: Some(name),
            addr: address,
            size,
            file_off: raw_ptr,
            file_size: raw_size,
            perms,
        });
    }

    let symbol_bytes = u64::from(symbol_count)
        .checked_mul(18)
        .and_then(|size| u64::from(symbol_ptr).checked_add(size));
    if symbol_count != 0 && symbol_bytes.is_none_or(|end| end > d.len() as u64) {
        return Err(FormatError::Truncated("coff symbols"));
    }
    Ok(Image {
        len: d.len() as u64,
        format: Format::Coff(CoffFacts {
            machine,
            section_count,
            characteristics,
        }),
        segments,
        regions,
        entry: None,
        symbol_count: symbol_count as usize,
    })
}

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        out.push(((high << 4) | low) as u8);
    }
    Some(out)
}

fn packed_data(records: Vec<(u64, Vec<u8>)>) -> Result<(Vec<u8>, Vec<Segment>), FormatError> {
    let mut cells = Vec::new();
    for (base, data) in records {
        for (offset, byte) in data.into_iter().enumerate() {
            let address = base
                .checked_add(offset as u64)
                .ok_or(FormatError::Malformed("address overflow"))?;
            cells.push((address, byte));
        }
    }
    if cells.is_empty() {
        return Err(FormatError::Malformed("no data records"));
    }
    cells.sort_unstable_by_key(|(address, _)| *address);
    let mut bytes = Vec::with_capacity(cells.len());
    let mut segments = Vec::new();
    let mut run_addr = cells[0].0;
    let mut run_offset = 0usize;
    let mut previous = None;
    for (address, byte) in cells {
        if previous == Some(address) {
            if bytes.last().copied() != Some(byte) {
                return Err(FormatError::Malformed("overlapping data differs"));
            }
            continue;
        }
        if let Some(previous) = previous {
            if address != previous.saturating_add(1) {
                segments.push(Segment {
                    name: Some("data".into()),
                    addr: run_addr,
                    size: (bytes.len() - run_offset) as u64,
                    file_off: run_offset as u64,
                    file_size: (bytes.len() - run_offset) as u64,
                    perms: Perms::unknown(),
                });
                run_addr = address;
                run_offset = bytes.len();
            }
        }
        bytes.push(byte);
        previous = Some(address);
    }
    segments.push(Segment {
        name: Some("data".into()),
        addr: run_addr,
        size: (bytes.len() - run_offset) as u64,
        file_off: run_offset as u64,
        file_size: (bytes.len() - run_offset) as u64,
        perms: Perms::unknown(),
    });
    Ok((bytes, segments))
}

fn parse_intel_hex(d: &[u8]) -> Result<LoadedImage, FormatError> {
    let text = std::str::from_utf8(d).map_err(|_| FormatError::Malformed("intel hex text"))?;
    let mut records = Vec::new();
    let mut base = 0u64;
    let mut start = None;
    let mut address_bits = 16;
    let mut data_records = 0u32;
    let mut saw_eof = false;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if saw_eof {
            return Err(FormatError::Malformed("intel hex data after eof"));
        }
        let Some(body) = line.strip_prefix(':') else {
            return Err(FormatError::Malformed("intel hex record"));
        };
        let bytes = hex_bytes(body).ok_or(FormatError::Malformed("intel hex digits"))?;
        let count = usize::from(
            *bytes
                .first()
                .ok_or(FormatError::Malformed("intel hex record length"))?,
        );
        if bytes.len() != count + 5 {
            return Err(FormatError::Malformed("intel hex record length"));
        }
        if bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
            return Err(FormatError::Malformed("intel hex checksum"));
        }
        let address = u64::from(u16::from_be_bytes([bytes[1], bytes[2]]));
        let record_type = bytes[3];
        let data = &bytes[4..4 + count];
        match record_type {
            0x00 => {
                let absolute = base
                    .checked_add(address)
                    .ok_or(FormatError::Malformed("intel hex address"))?;
                records.push((absolute, data.to_vec()));
                data_records = data_records.saturating_add(1);
            }
            0x01 if count == 0 => saw_eof = true,
            0x02 if count == 2 => {
                base = u64::from(u16::from_be_bytes([data[0], data[1]])) << 4;
                address_bits = address_bits.max(20);
            }
            0x03 if count == 4 => {
                start = Some(
                    (u64::from(u16::from_be_bytes([data[0], data[1]])) << 4)
                        .saturating_add(u64::from(u16::from_be_bytes([data[2], data[3]]))),
                );
            }
            0x04 if count == 2 => {
                base = u64::from(u16::from_be_bytes([data[0], data[1]])) << 16;
                address_bits = 32;
            }
            0x05 if count == 4 => {
                start = Some(u64::from(u32::from_be_bytes([
                    data[0], data[1], data[2], data[3],
                ])));
            }
            _ => return Err(FormatError::Malformed("intel hex record type")),
        }
    }
    if !saw_eof {
        return Err(FormatError::Malformed("intel hex missing eof"));
    }
    let (bytes, segments) = packed_data(records)?;
    let image = Image {
        len: d.len() as u64,
        format: Format::IntelHex(IntelHexFacts {
            address_bits,
            data_records,
            start,
        }),
        segments,
        regions: Vec::new(),
        entry: start,
        symbol_count: 0,
    };
    Ok(LoadedImage {
        bytes,
        image,
        loader: Loader::IntelHex,
    })
}

fn parse_motorola_srec(d: &[u8]) -> Result<LoadedImage, FormatError> {
    let text = std::str::from_utf8(d).map_err(|_| FormatError::Malformed("s-record text"))?;
    let mut records = Vec::new();
    let mut start = None;
    let mut address_bits = 0u8;
    let mut data_records = 0u32;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let Some(body) = line.strip_prefix('S') else {
            return Err(FormatError::Malformed("s-record prefix"));
        };
        let kind = body
            .as_bytes()
            .first()
            .copied()
            .and_then(|byte| (byte as char).to_digit(10))
            .ok_or(FormatError::Malformed("s-record type"))? as u8;
        let bytes = hex_bytes(&body[1..]).ok_or(FormatError::Malformed("s-record digits"))?;
        let count = usize::from(
            *bytes
                .first()
                .ok_or(FormatError::Malformed("s-record length"))?,
        );
        if bytes.len() != count + 1 || count < 2 {
            return Err(FormatError::Malformed("s-record length"));
        }
        if bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0xff {
            return Err(FormatError::Malformed("s-record checksum"));
        }
        let (address_len, data_record, start_record) = match kind {
            0 => (2, false, false),
            1 => (2, true, false),
            2 => (3, true, false),
            3 => (4, true, false),
            5 => (2, false, false),
            6 => (3, false, false),
            7 => (4, false, true),
            8 => (3, false, true),
            9 => (2, false, true),
            _ => return Err(FormatError::Malformed("s-record type")),
        };
        if count < address_len + 1 {
            return Err(FormatError::Malformed("s-record address"));
        }
        let address = bytes[1..1 + address_len]
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        address_bits = address_bits.max((address_len * 8) as u8);
        let data_start = 1 + address_len;
        let data_end = bytes.len() - 1;
        if data_record {
            records.push((address, bytes[data_start..data_end].to_vec()));
            data_records = data_records.saturating_add(1);
        } else if start_record {
            start = Some(address);
        }
    }
    let (bytes, segments) = packed_data(records)?;
    let image = Image {
        len: d.len() as u64,
        format: Format::MotorolaSrec(MotorolaSrecFacts {
            address_bits,
            data_records,
            start,
        }),
        segments,
        regions: Vec::new(),
        entry: start,
        symbol_count: 0,
    };
    Ok(LoadedImage {
        bytes,
        image,
        loader: Loader::MotorolaSrec,
    })
}

fn parse_elf(d: &[u8]) -> Result<Image, FormatError> {
    let class_bits = match d.get(4) {
        Some(1) => 32,
        Some(2) => 64,
        _ => return Err(FormatError::Malformed("ei_class")),
    };
    let en = match d.get(5) {
        Some(1) => Endian::Little,
        Some(2) => Endian::Big,
        _ => return Err(FormatError::Malformed("ei_data")),
    };
    let w64 = class_bits == 64;

    let obj_type = en.u16(d, 16).ok_or(FormatError::Truncated("e_type"))?;
    let machine = en.u16(d, 18).ok_or(FormatError::Truncated("e_machine"))?;
    let (entry, phoff, shoff, flags_off) = if w64 {
        (
            en.u64(d, 24).ok_or(FormatError::Truncated("e_entry"))?,
            en.u64(d, 32).ok_or(FormatError::Truncated("e_phoff"))? as usize,
            en.u64(d, 40).ok_or(FormatError::Truncated("e_shoff"))? as usize,
            48,
        )
    } else {
        (
            u64::from(en.u32(d, 24).ok_or(FormatError::Truncated("e_entry"))?),
            en.u32(d, 28).ok_or(FormatError::Truncated("e_phoff"))? as usize,
            en.u32(d, 32).ok_or(FormatError::Truncated("e_shoff"))? as usize,
            36,
        )
    };
    let flags = en
        .u32(d, flags_off)
        .ok_or(FormatError::Truncated("e_flags"))?;
    let (phentsize, phnum, shentsize, shnum, shstrndx) = if w64 {
        (
            en.u16(d, 54),
            en.u16(d, 56),
            en.u16(d, 58),
            en.u16(d, 60),
            en.u16(d, 62),
        )
    } else {
        (
            en.u16(d, 42),
            en.u16(d, 44),
            en.u16(d, 46),
            en.u16(d, 48),
            en.u16(d, 50),
        )
    };
    let phentsize = phentsize.unwrap_or(0) as usize;
    let phnum = phnum.unwrap_or(0) as usize;
    let shentsize = shentsize.unwrap_or(0) as usize;
    let shnum = shnum.unwrap_or(0) as usize;
    let shstrndx = shstrndx.unwrap_or(0) as usize;

    // Program headers -> mapped segments.
    let mut segments = Vec::new();
    for i in 0..phnum {
        let o = match phoff.checked_add(
            i.checked_mul(phentsize)
                .ok_or(FormatError::Malformed("phnum*phentsize"))?,
        ) {
            Some(o) => o,
            None => break,
        };
        let header_end = if w64 { 48 } else { 28 };
        if o > d.len().saturating_sub(header_end) {
            break;
        }
        let Some(p_type) = en.u32(d, o) else { break };
        if p_type != 1 {
            continue;
        }
        let (off, va, fsz, msz, fl) = if w64 {
            (
                en.u64(d, o + 8),
                en.u64(d, o + 16),
                en.u64(d, o + 32),
                en.u64(d, o + 40),
                en.u32(d, o + 4),
            )
        } else {
            (
                en.u32(d, o + 4).map(u64::from),
                en.u32(d, o + 8).map(u64::from),
                en.u32(d, o + 16).map(u64::from),
                en.u32(d, o + 20).map(u64::from),
                en.u32(d, o + 24),
            )
        };
        let (Some(off), Some(va), Some(fsz), Some(msz)) = (off, va, fsz, msz) else {
            break;
        };
        let fl = fl.unwrap_or(0);
        segments.push(Segment {
            name: None,
            addr: va,
            size: msz,
            file_off: off,
            file_size: fsz,
            // p_flags == 0 says nothing, and must not be read as "no access".
            perms: if fl == 0 {
                Perms::unknown()
            } else {
                Perms {
                    read: Some(fl & 4 != 0),
                    write: Some(fl & 2 != 0),
                    exec: Some(fl & 1 != 0),
                }
            },
        });
    }

    // Section headers -> regions, plus the symbol count.
    let sh = |i: usize| -> Option<usize> { shoff.checked_add(i.checked_mul(shentsize)?) };
    let shstr_off = sh(shstrndx)
        .and_then(|o| {
            let name_offset = if w64 { 24 } else { 16 };
            if o > d.len().saturating_sub(name_offset + 8) {
                return None;
            }
            if w64 {
                en.u64(d, o + name_offset)
            } else {
                en.u32(d, o + name_offset).map(u64::from)
            }
        })
        .unwrap_or(0) as usize;

    let mut regions = Vec::new();
    let mut symbol_count = 0usize;
    for i in 0..shnum {
        let Some(o) = sh(i) else { break };
        let header_end = if w64 { 64 } else { 40 };
        if o > d.len().saturating_sub(header_end) {
            break;
        }
        let Some(name_off) = en.u32(d, o) else { break };
        let Some(sh_type) = en.u32(d, o + 4) else {
            break;
        };
        let (sh_flags, sh_addr, sh_size, sh_entsize) = if w64 {
            (
                en.u64(d, o + 8),
                en.u64(d, o + 16),
                en.u64(d, o + 32),
                en.u64(d, o + 56),
            )
        } else {
            (
                en.u32(d, o + 8).map(u64::from),
                en.u32(d, o + 12).map(u64::from),
                en.u32(d, o + 20).map(u64::from),
                en.u32(d, o + 36).map(u64::from),
            )
        };
        let (Some(sh_flags), Some(sh_addr), Some(sh_size)) = (sh_flags, sh_addr, sh_size) else {
            break;
        };
        if sh_type == 2 {
            if let Some(es) = sh_entsize.filter(|e| *e != 0) {
                symbol_count = symbol_count.saturating_add((sh_size / es) as usize);
            }
        }
        let name = read_cstr(d, shstr_off.saturating_add(name_off as usize));
        let placement = if sh_addr == 0 || sh_size == 0 {
            Placement::Unaddressed
        } else {
            match segments.iter().position(|s| s.overlaps(sh_addr, sh_size)) {
                Some(of) => Placement::Aliases { of },
                None => Placement::Mapped,
            }
        };
        regions.push(Region {
            name,
            addr: sh_addr,
            size: sh_size,
            alloc: sh_flags & 2 != 0,
            placement,
        });
    }

    Ok(Image {
        len: d.len() as u64,
        format: Format::Elf(ElfFacts {
            class_bits,
            endian: en,
            obj_type,
            machine,
            flags,
        }),
        segments,
        regions,
        entry: (entry != 0).then_some(entry),
        symbol_count,
    })
}

fn parse_pe(d: &[u8]) -> Result<Image, FormatError> {
    let en = Endian::Little;
    let lfanew = en.u32(d, 0x3c).ok_or(FormatError::Truncated("e_lfanew"))? as usize;
    if d.get(lfanew..lfanew + 4) != Some(b"PE\0\0") {
        return Err(FormatError::Malformed("pe signature"));
    }
    let coff = lfanew + 4;
    let machine = en.u16(d, coff).ok_or(FormatError::Truncated("machine"))?;
    let nsec = en.u16(d, coff + 2).ok_or(FormatError::Truncated("nsec"))? as usize;
    let opt_size = en
        .u16(d, coff + 16)
        .ok_or(FormatError::Truncated("opt size"))? as usize;
    let opt = coff + 20;
    let magic = en.u16(d, opt).ok_or(FormatError::Truncated("opt magic"))?;
    let plus = match magic {
        0x10b => false,
        0x20b => true,
        _ => return Err(FormatError::Malformed("optional header magic")),
    };
    let entry_rva = en.u32(d, opt + 16).ok_or(FormatError::Truncated("entry"))?;
    let image_base = if plus {
        en.u64(d, opt + 24)
            .ok_or(FormatError::Truncated("image base"))?
    } else {
        u64::from(
            en.u32(d, opt + 28)
                .ok_or(FormatError::Truncated("image base"))?,
        )
    };

    let sec_start = opt
        .checked_add(opt_size)
        .ok_or(FormatError::Malformed("optional header size"))?;
    let mut segments = Vec::new();
    for i in 0..nsec {
        let o = match sec_start
            .checked_add(i.checked_mul(40).ok_or(FormatError::Malformed("nsec*40"))?)
        {
            Some(o) => o,
            None => break,
        };
        if o > d.len().saturating_sub(40) {
            break;
        }
        let Some(raw_name) = d.get(o..o + 8) else {
            break;
        };
        let (Some(vsize), Some(vaddr), Some(rsize), Some(raddr)) = (
            en.u32(d, o + 8),
            en.u32(d, o + 12),
            en.u32(d, o + 16),
            en.u32(d, o + 20),
        ) else {
            break;
        };
        let Some(chars) = en.u32(d, o + 36) else {
            break;
        };
        let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        segments.push(Segment {
            name: Some(String::from_utf8_lossy(&raw_name[..end]).into_owned()),
            addr: image_base.saturating_add(u64::from(vaddr)),
            size: u64::from(vsize),
            file_off: u64::from(raddr),
            file_size: u64::from(rsize),
            perms: Perms {
                read: Some(chars & 0x4000_0000 != 0),
                write: Some(chars & 0x8000_0000 != 0),
                exec: Some(chars & 0x2000_0000 != 0),
            },
        });
    }

    Ok(Image {
        len: d.len() as u64,
        format: Format::Pe(PeFacts {
            machine,
            plus,
            image_base,
        }),
        segments,
        regions: Vec::new(),
        entry: (entry_rva != 0).then(|| image_base.saturating_add(u64::from(entry_rva))),
        symbol_count: 0,
    })
}

fn mach_o_endian_class(d: &[u8]) -> Option<(Endian, u8)> {
    match d.get(0..4)? {
        b"\xfe\xed\xfa\xce" => Some((Endian::Big, 32)),
        b"\xce\xfa\xed\xfe" => Some((Endian::Little, 32)),
        b"\xfe\xed\xfa\xcf" => Some((Endian::Big, 64)),
        b"\xcf\xfa\xed\xfe" => Some((Endian::Little, 64)),
        _ => None,
    }
}

fn is_mach_o_magic(d: &[u8]) -> bool {
    mach_o_endian_class(d).is_some()
}

fn is_fat_mach_o_magic(d: &[u8]) -> bool {
    matches!(
        d.get(0..4),
        Some(b"\xca\xfe\xba\xbe" | b"\xbe\xba\xfe\xca" | b"\xca\xfe\xba\xbf" | b"\xbf\xba\xfe\xca")
    )
}

fn fat_mach_o_slice(d: &[u8], index: usize) -> Result<&[u8], FormatError> {
    let (en, is_64) = match d.get(0..4) {
        Some(b"\xca\xfe\xba\xbe") => (Endian::Big, false),
        Some(b"\xbe\xba\xfe\xca") => (Endian::Little, false),
        Some(b"\xca\xfe\xba\xbf") => (Endian::Big, true),
        Some(b"\xbf\xba\xfe\xca") => (Endian::Little, true),
        _ => return Err(FormatError::Malformed("fat Mach-O magic")),
    };
    let count = en
        .u32(d, 4)
        .ok_or(FormatError::Truncated("fat architecture count"))?;
    let entry_size = if is_64 { 32usize } else { 20usize };
    let count = usize::try_from(count).map_err(|_| FormatError::Malformed("fat count"))?;
    let table_start = 8usize;
    let table_end = table_start
        .checked_add(
            count
                .checked_mul(entry_size)
                .ok_or(FormatError::Malformed("fat architecture table"))?,
        )
        .ok_or(FormatError::Malformed("fat architecture table"))?;
    if table_end > d.len() {
        return Err(FormatError::Truncated("fat architecture table"));
    }
    if index >= count {
        return Err(FormatError::Malformed(
            "fat Mach-O slice index out of range",
        ));
    }
    let entry = table_start + index * entry_size;
    let offset = if is_64 {
        en.u64(d, entry + 8)
            .ok_or(FormatError::Truncated("fat slice offset"))?
    } else {
        u64::from(
            en.u32(d, entry + 8)
                .ok_or(FormatError::Truncated("fat slice offset"))?,
        )
    };
    let size = if is_64 {
        en.u64(d, entry + 16)
            .ok_or(FormatError::Truncated("fat slice size"))?
    } else {
        u64::from(
            en.u32(d, entry + 12)
                .ok_or(FormatError::Truncated("fat slice size"))?,
        )
    };
    let start = usize::try_from(offset).map_err(|_| FormatError::Malformed("fat slice offset"))?;
    let end = offset
        .checked_add(size)
        .ok_or(FormatError::Malformed("fat slice range"))?;
    let end = usize::try_from(end).map_err(|_| FormatError::Malformed("fat slice range"))?;
    if start < table_end || end > d.len() || start > end {
        return Err(FormatError::Truncated("fat slice"));
    }
    Ok(&d[start..end])
}

fn mach_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn parse_mach_o(d: &[u8]) -> Result<Image, FormatError> {
    const LC_SEGMENT: u32 = 0x1;
    const LC_SYMTAB: u32 = 0x2;
    const LC_MAIN: u32 = 0x8000_0028;
    const LC_SEGMENT_64: u32 = 0x19;

    let (en, class_bits) = mach_o_endian_class(d).ok_or(FormatError::Malformed("mach-o magic"))?;
    let w64 = class_bits == 64;
    let header_size = if w64 { 32usize } else { 28usize };
    let cpu_type = en.u32(d, 4).ok_or(FormatError::Truncated("cpu type"))?;
    let cpu_subtype = en.u32(d, 8).ok_or(FormatError::Truncated("cpu subtype"))?;
    let file_type = en.u32(d, 12).ok_or(FormatError::Truncated("file type"))?;
    let ncmds = en.u32(d, 16).ok_or(FormatError::Truncated("ncmds"))?;
    let sizeofcmds = en.u32(d, 20).ok_or(FormatError::Truncated("sizeofcmds"))?;
    let flags = en.u32(d, 24).ok_or(FormatError::Truncated("flags"))?;
    let commands_end = header_size
        .checked_add(usize::try_from(sizeofcmds).map_err(|_| FormatError::Malformed("commands"))?)
        .ok_or(FormatError::Malformed("commands size"))?;
    if commands_end > d.len() {
        return Err(FormatError::Truncated("load commands"));
    }

    let mut segments = Vec::new();
    let mut regions = Vec::new();
    let mut symbol_count = 0usize;
    let mut entryoff = None;
    let mut cursor = header_size;

    for _ in 0..ncmds {
        let cmd = en
            .u32(d, cursor)
            .ok_or(FormatError::Truncated("load command header"))?;
        let cmdsize = en
            .u32(
                d,
                cursor
                    .checked_add(4)
                    .ok_or(FormatError::Malformed("command"))?,
            )
            .ok_or(FormatError::Truncated("load command size"))?;
        let cmdsize = usize::try_from(cmdsize).map_err(|_| FormatError::Malformed("command"))?;
        if cmdsize < 8 {
            return Err(FormatError::Malformed("load command size"));
        }
        let end = cursor
            .checked_add(cmdsize)
            .ok_or(FormatError::Malformed("load command range"))?;
        if end > commands_end || end > d.len() {
            return Err(FormatError::Truncated("load command"));
        }
        let command = &d[cursor..end];

        match cmd {
            LC_SEGMENT if !w64 => {
                if cmdsize < 56 {
                    return Err(FormatError::Malformed("segment command"));
                }
                let name = mach_name(&command[8..16]);
                let vmaddr = en.u32(command, 24).map(u64::from).unwrap();
                let vmsize = en.u32(command, 28).map(u64::from).unwrap();
                let file_off = en.u32(command, 32).map(u64::from).unwrap();
                let file_size = en.u32(command, 36).map(u64::from).unwrap();
                let initprot = en.u32(command, 44).unwrap();
                let nsects = usize::try_from(en.u32(command, 48).unwrap())
                    .map_err(|_| FormatError::Malformed("section count"))?;
                let section_end = 56usize
                    .checked_add(
                        nsects
                            .checked_mul(68)
                            .ok_or(FormatError::Malformed("section count"))?,
                    )
                    .ok_or(FormatError::Malformed("sections"))?;
                if section_end > cmdsize {
                    return Err(FormatError::Truncated("segment sections"));
                }
                segments.push(Segment {
                    name: Some(name),
                    addr: vmaddr,
                    size: vmsize,
                    file_off,
                    file_size,
                    perms: Perms {
                        read: Some(initprot & 1 != 0),
                        write: Some(initprot & 2 != 0),
                        exec: Some(initprot & 4 != 0),
                    },
                });
                for i in 0..nsects {
                    let at = 56 + i * 68;
                    let section_name = mach_name(&command[at..at + 16]);
                    let addr = en.u32(command, at + 32).map(u64::from).unwrap();
                    let size = en.u32(command, at + 36).map(u64::from).unwrap();
                    regions.push(Region {
                        name: section_name,
                        addr,
                        size,
                        alloc: addr != 0 && size != 0,
                        placement: Placement::Mapped,
                    });
                }
            }
            LC_SEGMENT_64 if w64 => {
                if cmdsize < 72 {
                    return Err(FormatError::Malformed("segment command"));
                }
                let name = mach_name(&command[8..16]);
                let vmaddr = en.u64(command, 24).unwrap();
                let vmsize = en.u64(command, 32).unwrap();
                let file_off = en.u64(command, 40).unwrap();
                let file_size = en.u64(command, 48).unwrap();
                let initprot = en.u32(command, 60).unwrap();
                let nsects = usize::try_from(en.u32(command, 64).unwrap())
                    .map_err(|_| FormatError::Malformed("section count"))?;
                let section_end = 72usize
                    .checked_add(
                        nsects
                            .checked_mul(80)
                            .ok_or(FormatError::Malformed("section count"))?,
                    )
                    .ok_or(FormatError::Malformed("sections"))?;
                if section_end > cmdsize {
                    return Err(FormatError::Truncated("segment sections"));
                }
                segments.push(Segment {
                    name: Some(name),
                    addr: vmaddr,
                    size: vmsize,
                    file_off,
                    file_size,
                    perms: Perms {
                        read: Some(initprot & 1 != 0),
                        write: Some(initprot & 2 != 0),
                        exec: Some(initprot & 4 != 0),
                    },
                });
                for i in 0..nsects {
                    let at = 72 + i * 80;
                    let section_name = mach_name(&command[at..at + 16]);
                    let addr = en.u64(command, at + 32).unwrap();
                    let size = en.u64(command, at + 40).unwrap();
                    regions.push(Region {
                        name: section_name,
                        addr,
                        size,
                        alloc: addr != 0 && size != 0,
                        placement: Placement::Mapped,
                    });
                }
            }
            LC_SYMTAB => {
                if cmdsize < 24 {
                    return Err(FormatError::Malformed("symbol table command"));
                }
                symbol_count = usize::try_from(en.u32(command, 12).unwrap())
                    .map_err(|_| FormatError::Malformed("symbol count"))?;
            }
            LC_MAIN => {
                if cmdsize < 24 {
                    return Err(FormatError::Malformed("main command"));
                }
                entryoff = Some(en.u64(command, 8).unwrap());
            }
            _ => {}
        }
        cursor = end;
    }

    let entry = entryoff.and_then(|offset| {
        segments.iter().find_map(|segment| {
            let delta = offset.checked_sub(segment.file_off)?;
            if delta >= segment.file_size {
                return None;
            }
            segment.addr.checked_add(delta)
        })
    });
    Ok(Image {
        len: d.len() as u64,
        format: Format::Mach(MachFacts {
            class_bits,
            endian: en,
            cpu_type,
            cpu_subtype,
            file_type,
            flags,
        }),
        segments,
        regions,
        entry,
        symbol_count,
    })
}

fn read_cstr(d: &[u8], at: usize) -> String {
    let tail = match d.get(at..) {
        Some(t) => t,
        None => return String::new(),
    };
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    // Cap: a corrupt name offset must not turn into a megabyte-long "name".
    String::from_utf8_lossy(&tail[..end.min(256)]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use ventris_addr::AddrError;

    const PS2_ELF: &str = match option_env!("VENTRIS_PS2_ELF") {
        Some(path) => path,
        None => "",
    };
    const WIN_PE: &str = match option_env!("VENTRIS_WIN_PE") {
        Some(path) => path,
        None => "",
    };

    fn corpus(p: &str) -> Option<Vec<u8>> {
        let path = PathBuf::from(p);
        path.is_file().then(|| std::fs::read(path).ok()).flatten()
    }

    // ---- synthetic ELF, for the sweeps: no external file, fully deterministic

    fn synth_elf() -> Vec<u8> {
        let mut d = vec![0u8; 0x200];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 1; // 32-bit
        d[5] = 1; // little endian
        d[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        d[18..20].copy_from_slice(&8u16.to_le_bytes()); // EM_MIPS
        d[24..28].copy_from_slice(&0x1008u32.to_le_bytes()); // entry
        d[28..32].copy_from_slice(&0x34u32.to_le_bytes()); // phoff
        d[32..36].copy_from_slice(&0x80u32.to_le_bytes()); // shoff
        d[42..44].copy_from_slice(&32u16.to_le_bytes()); // phentsize
        d[44..46].copy_from_slice(&1u16.to_le_bytes()); // phnum
        d[46..48].copy_from_slice(&40u16.to_le_bytes()); // shentsize
        d[48..50].copy_from_slice(&2u16.to_le_bytes()); // shnum
        d[50..52].copy_from_slice(&1u16.to_le_bytes()); // shstrndx
        let p = 0x34;
        d[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        d[p + 8..p + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // vaddr
        d[p + 20..p + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // memsz
        // section 0: the aliasing one, named "image"
        let s = 0x80;
        d[s + 12..s + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // addr
        d[s + 20..s + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // size
        // section 1: shstrtab at file offset 0x180
        let s1 = 0x80 + 40;
        d[s1 + 16..s1 + 20].copy_from_slice(&0x180u32.to_le_bytes());
        d[0x180..0x186].copy_from_slice(b"image\0");
        d
    }

    fn synth_n64() -> Vec<u8> {
        let mut d = vec![0u8; 0x800];
        d[0..4].copy_from_slice(&[0x80, 0x37, 0x12, 0x40]);
        d[0x08..0x0c].copy_from_slice(&0x8000_0400u32.to_be_bytes());
        d[0x400..0x404].copy_from_slice(&[0x3c, 0x08, 0x80, 0x00]);
        d
    }

    fn synth_dol() -> Vec<u8> {
        let mut d = vec![0u8; 0x300];
        d[0x00..0x04].copy_from_slice(&0x100u32.to_be_bytes());
        d[0x1c..0x20].copy_from_slice(&0x104u32.to_be_bytes());
        d[0x48..0x4c].copy_from_slice(&0x8000_3100u32.to_be_bytes());
        d[0x64..0x68].copy_from_slice(&0x8000_4100u32.to_be_bytes());
        d[0x90..0x94].copy_from_slice(&4u32.to_be_bytes());
        d[0xac..0xb0].copy_from_slice(&4u32.to_be_bytes());
        d[0xd8..0xdc].copy_from_slice(&0x8000_5000u32.to_be_bytes());
        d[0xdc..0xe0].copy_from_slice(&0x20u32.to_be_bytes());
        d[0xe0..0xe4].copy_from_slice(&0x8000_3100u32.to_be_bytes());
        d[0x100..0x104].copy_from_slice(&[0x38, 0x60, 0, 1]);
        d[0x104..0x108].copy_from_slice(&[0x90, 0x61, 0, 0]);
        d
    }

    fn synth_mach_o() -> Vec<u8> {
        let mut d = vec![0u8; 0x200];
        d[..4].copy_from_slice(b"\xcf\xfa\xed\xfe"); // 64-bit little endian
        d[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes()); // x86_64
        d[8..12].copy_from_slice(&3u32.to_le_bytes());
        d[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        d[16..20].copy_from_slice(&3u32.to_le_bytes()); // segment, main, symtab
        d[20..24].copy_from_slice(&200u32.to_le_bytes());

        let segment = 0x20;
        d[segment..segment + 4].copy_from_slice(&0x19u32.to_le_bytes());
        d[segment + 4..segment + 8].copy_from_slice(&152u32.to_le_bytes());
        d[segment + 8..segment + 14].copy_from_slice(b"__TEXT");
        d[segment + 24..segment + 32].copy_from_slice(&0x1000u64.to_le_bytes());
        d[segment + 32..segment + 40].copy_from_slice(&0x1000u64.to_le_bytes());
        d[segment + 40..segment + 48].copy_from_slice(&0u64.to_le_bytes());
        d[segment + 48..segment + 56].copy_from_slice(&0x200u64.to_le_bytes());
        d[segment + 56..segment + 60].copy_from_slice(&7u32.to_le_bytes());
        d[segment + 60..segment + 64].copy_from_slice(&5u32.to_le_bytes()); // r-x
        d[segment + 64..segment + 68].copy_from_slice(&1u32.to_le_bytes());
        let section = segment + 72;
        d[section..section + 6].copy_from_slice(b"__text");
        d[section + 16..section + 22].copy_from_slice(b"__TEXT");
        d[section + 32..section + 40].copy_from_slice(&0x1100u64.to_le_bytes());
        d[section + 40..section + 48].copy_from_slice(&4u64.to_le_bytes());
        d[section + 48..section + 52].copy_from_slice(&0x100u32.to_le_bytes());

        let main = segment + 152;
        d[main..main + 4].copy_from_slice(&0x8000_0028u32.to_le_bytes());
        d[main + 4..main + 8].copy_from_slice(&24u32.to_le_bytes());
        d[main + 8..main + 16].copy_from_slice(&0x100u64.to_le_bytes());

        let symtab = main + 24;
        d[symtab..symtab + 4].copy_from_slice(&2u32.to_le_bytes());
        d[symtab + 4..symtab + 8].copy_from_slice(&24u32.to_le_bytes());
        d[symtab + 12..symtab + 16].copy_from_slice(&3u32.to_le_bytes());
        d[0x100..0x104].copy_from_slice(&[0xc3, 0, 0, 0]);
        d
    }

    fn synth_fat_mach_o() -> Vec<u8> {
        let x86 = synth_mach_o();
        let mut arm = x86.clone();
        arm[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes()); // arm64
        let table_start = 8usize;
        let first_offset = 0x40usize;
        let second_offset = first_offset + x86.len();
        let mut d = vec![0u8; second_offset + arm.len()];
        d[..4].copy_from_slice(b"\xca\xfe\xba\xbe"); // FAT_MAGIC, big endian
        d[4..8].copy_from_slice(&2u32.to_be_bytes());
        for (entry, (cpu, offset, size)) in [
            (0usize, (0x0100_0007u32, first_offset, x86.len())),
            (1usize, (0x0100_000cu32, second_offset, arm.len())),
        ] {
            let at = table_start + entry * 20;
            d[at..at + 4].copy_from_slice(&cpu.to_be_bytes());
            d[at + 8..at + 12].copy_from_slice(&(offset as u32).to_be_bytes());
            d[at + 12..at + 16].copy_from_slice(&(size as u32).to_be_bytes());
        }
        d[first_offset..second_offset].copy_from_slice(&x86);
        d[second_offset..].copy_from_slice(&arm);
        d
    }

    fn synthetic_nds() -> Vec<u8> {
        let mut d = vec![0u8; 0x140];
        for (offset, value) in [
            (0x20, 0x200u32),
            (0x24, 0x0200_0000u32),
            (0x28, 0x0200_0000u32),
            (0x2c, 0x20u32),
            (0x30, 0x240u32),
            (0x34, 0x0380_0000u32),
            (0x38, 0x0380_0000u32),
            (0x3c, 0x10u32),
        ] {
            d[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        d.resize(0x250, 0);
        d
    }

    fn synthetic_ncch() -> Vec<u8> {
        let mut d = vec![0u8; 0x600];
        d[0x100..0x104].copy_from_slice(b"NCCH");
        d[0x18f] = 1;
        d[0x1a0..0x1a4].copy_from_slice(&1u32.to_le_bytes());
        d[0x1a4..0x1a8].copy_from_slice(&2u32.to_le_bytes());
        d[0x210..0x214].copy_from_slice(&0x0010_0000u32.to_le_bytes());
        d[0x218..0x21c].copy_from_slice(&4u32.to_le_bytes());
        d[0x200..0x208].copy_from_slice(b".code\0\0\0");
        d[0x208..0x20c].copy_from_slice(&0u32.to_le_bytes());
        d[0x20c..0x210].copy_from_slice(&4u32.to_le_bytes());
        d[0x400..0x404].copy_from_slice(&[0x00, 0xbf, 0, 0]);
        d
    }

    fn synthetic_self(machine: u16) -> Vec<u8> {
        let mut elf = synth_elf();
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        let elf_offset = 0x100usize;
        let mut d = vec![0u8; elf_offset + elf.len()];
        d[..4].copy_from_slice(b"SCE\0");
        d[4..8].copy_from_slice(&2u32.to_be_bytes());
        d[8..10].copy_from_slice(&1u16.to_be_bytes());
        d[10..12].copy_from_slice(&1u16.to_be_bytes());
        d[0x10..0x18].copy_from_slice(&(elf_offset as u64).to_be_bytes());
        d[0x18..0x20].copy_from_slice(&(elf.len() as u64).to_be_bytes());
        d[0x28..0x30].copy_from_slice(&0x80u64.to_be_bytes());
        d[0x30..0x38].copy_from_slice(&(elf_offset as u64).to_be_bytes());
        d[elf_offset..].copy_from_slice(&elf);
        d
    }

    fn synthetic_pe() -> Vec<u8> {
        let mut d = vec![0u8; 0x204];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        d[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        d[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
        d[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        d[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
        d[0xb4..0xb8].copy_from_slice(&0x1000u32.to_le_bytes());
        d[0x114..0x118].copy_from_slice(&0x1000u32.to_le_bytes());
        d[0x178..0x17e].copy_from_slice(b".text\0");
        d[0x180..0x184].copy_from_slice(&4u32.to_le_bytes());
        d[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes());
        d[0x188..0x18c].copy_from_slice(&4u32.to_le_bytes());
        d[0x18c..0x190].copy_from_slice(&0x200u32.to_le_bytes());
        d[0x19c..0x1a0].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        d[0x200..0x204].copy_from_slice(&[0xc3, 0, 0, 0]);
        d
    }

    fn synthetic_xex() -> Vec<u8> {
        let pe = synthetic_pe();
        let code_offset = 0x1000usize;
        let mut d = vec![0u8; code_offset + pe.len()];
        d[..4].copy_from_slice(b"XEX2");
        d[8..12].copy_from_slice(&(code_offset as u32).to_be_bytes());
        d[20..24].copy_from_slice(&2u32.to_be_bytes());
        d[24..28].copy_from_slice(&0x0001_0100u32.to_be_bytes());
        d[28..32].copy_from_slice(&0x2000u32.to_be_bytes());
        d[32..36].copy_from_slice(&0x0001_0201u32.to_be_bytes());
        d[36..40].copy_from_slice(&0x1000u32.to_be_bytes());
        d[code_offset..].copy_from_slice(&pe);
        d
    }

    fn synthetic_wiiu_rpl() -> Vec<u8> {
        let mut d = vec![0u8; 0x215];
        d[..4].copy_from_slice(b"\x7fELF");
        d[4] = 1; // 32-bit
        d[5] = 2; // big endian
        d[16..18].copy_from_slice(&2u16.to_be_bytes()); // ET_EXEC
        d[18..20].copy_from_slice(&20u16.to_be_bytes()); // EM_PPC
        d[24..28].copy_from_slice(&0x1000u32.to_be_bytes()); // entry
        d[32..36].copy_from_slice(&0x80u32.to_be_bytes()); // section table
        d[40..42].copy_from_slice(&32u16.to_be_bytes()); // phentsize
        d[42..44].copy_from_slice(&0u16.to_be_bytes()); // phnum: RPL
        d[46..48].copy_from_slice(&40u16.to_be_bytes()); // shentsize
        d[48..50].copy_from_slice(&3u16.to_be_bytes()); // shnum
        d[50..52].copy_from_slice(&2u16.to_be_bytes()); // shstrndx

        let text = 0x80 + 40;
        d[text..text + 4].copy_from_slice(&1u32.to_be_bytes()); // name
        d[text + 4..text + 8].copy_from_slice(&1u32.to_be_bytes()); // PROGBITS
        d[text + 8..text + 12].copy_from_slice(&6u32.to_be_bytes()); // ALLOC|EXEC
        d[text + 12..text + 16].copy_from_slice(&0x1000u32.to_be_bytes());
        d[text + 16..text + 20].copy_from_slice(&0x200u32.to_be_bytes());
        d[text + 20..text + 24].copy_from_slice(&4u32.to_be_bytes());

        let strings = 0x80 + 80;
        d[strings..strings + 4].copy_from_slice(&7u32.to_be_bytes()); // .shstrtab
        d[strings + 4..strings + 8].copy_from_slice(&3u32.to_be_bytes()); // STRTAB
        d[strings + 16..strings + 20].copy_from_slice(&0x204u32.to_be_bytes());
        d[strings + 20..strings + 24].copy_from_slice(&17u32.to_be_bytes());
        d[0x200..0x204].copy_from_slice(&[0x38, 0x60, 0, 1]);
        d[0x204..0x215].copy_from_slice(b"\0.text\0.shstrtab\0");
        d
    }

    #[test]
    fn synthetic_elf_round_trips() {
        let img = Image::parse(&synth_elf()).unwrap();
        assert_eq!(img.segments.len(), 1);
        assert_eq!(img.entry, Some(0x1008));
        assert_eq!(img.aliasing_regions().count(), 1);
    }

    #[test]
    fn n64_and_dol_containers_expose_console_segments() {
        let n64 = Image::load(&synth_n64(), Loader::Auto, None).unwrap();
        assert_eq!(n64.loader, Loader::N64Rom);
        let Format::N64Rom(n64_facts) = n64.image.format else {
            panic!("not Nintendo 64 ROM");
        };
        assert_eq!(n64_facts.entry, 0x8000_0400);
        assert_eq!(n64.image.segments[0].file_off, 0x400);
        assert_eq!(
            n64.image.bytes_at(&n64.bytes, 0x8000_0400, 4),
            Some(&n64.bytes[0x400..0x404])
        );

        let dol = Image::load(&synth_dol(), Loader::Dol, None).unwrap();
        let Format::Dol(dol_facts) = dol.image.format else {
            panic!("not DOL");
        };
        assert_eq!(dol_facts.text[0].size, 4);
        assert_eq!(dol_facts.data[0].address, 0x8000_4100);
        assert_eq!(dol_facts.bss_size, 0x20);
        assert_eq!(dol.image.entry, Some(0x8000_3100));
        assert_eq!(dol.image.segments.len(), 3);
    }

    #[test]
    fn handheld_and_console_containers_round_trip() {
        let nds = Image::load(&synthetic_nds(), Loader::NintendoDs, None).unwrap();
        assert!(matches!(nds.image.format, Format::NintendoDs(_)));
        assert_eq!(nds.image.segments.len(), 2);
        assert_eq!(nds.image.entry, Some(0x0200_0000));

        let ncch = Image::load(&synthetic_ncch(), Loader::Ncch, None).unwrap();
        let Format::Ncch(facts) = ncch.image.format else {
            panic!("not NCCH");
        };
        let wiiu = Image::load(&synthetic_wiiu_rpl(), Loader::Auto, None).unwrap();
        assert_eq!(wiiu.loader, Loader::WiiURpl);
        assert!(matches!(wiiu.image.format, Format::WiiURpl(_)));
        assert_eq!(wiiu.image.segments[0].addr, 0x1000);
        assert_eq!(facts.code_address, 0x0010_0000);
        assert_eq!(facts.code_file_off, 0x400);
        assert_eq!(ncch.image.segments[0].file_size, 4);

        let psp = Image::load(&synth_elf(), Loader::PspPrx, None).unwrap();
        assert!(matches!(psp.image.format, Format::PspPrx(_)));
    }

    #[test]
    fn self_and_xex_containers_expose_embedded_code() {
        let vita = Image::load(&synthetic_self(40), Loader::VitaSelf, None).unwrap();
        let Format::SceSelf(vita_facts) = vita.image.format else {
            panic!("not Vita SELF");
        };
        assert_eq!(vita_facts.kind, SceSelfKind::Vita);
        assert_eq!(vita_facts.elf_offset, 0x100);
        assert_eq!(vita.image.entry, Some(0x1008));

        let ps3 = Image::load(&synthetic_self(21), Loader::Ps3Self, None).unwrap();
        let Format::SceSelf(ps3_facts) = ps3.image.format else {
            panic!("not PS3 SELF");
        };
        assert_eq!(ps3_facts.kind, SceSelfKind::Ps3);

        let xex = Image::load(&synthetic_xex(), Loader::Xex, None).unwrap();
        let Format::Xex(xex_facts) = xex.image.format else {
            panic!("not XEX");
        };
        assert_eq!(xex_facts.code_offset, 0x1000);
        assert_eq!(xex.image.entry, Some(0x2000));
        assert_eq!(xex.image.segments[0].file_off, 0x1200);
    }

    #[test]
    fn custom_loader_detection_and_language_facts_are_explicit() {
        let ncch = Image::load(&synthetic_ncch(), Loader::Auto, None).unwrap();
        assert_eq!(ncch.loader, Loader::Ncch);

        let vita = Image::load(&synthetic_self(40), Loader::Auto, None).unwrap();
        assert_eq!(vita.loader, Loader::VitaSelf);

        let ps3 = Image::load(&synthetic_self(23), Loader::Auto, None).unwrap();
        assert_eq!(ps3.loader, Loader::Ps3Self);

        let xex = Image::load(&synthetic_xex(), Loader::Auto, None).unwrap();
        assert_eq!(xex.loader, Loader::Xex);

        let truncated_nds = Image::load(&[0u8; 0x3f], Loader::NintendoDs, None);
        assert_eq!(
            truncated_nds,
            Err(FormatError::Truncated("Nintendo DS header"))
        );

        let mips64_be = ElfFacts {
            class_bits: 64,
            endian: Endian::Big,
            obj_type: 2,
            machine: 8,
            flags: 0,
        };
        assert!(
            mips64_be
                .consistent_languages()
                .contains(&"MIPS:BE:64:default")
        );
        let spu = ElfFacts {
            machine: 23,
            ..mips64_be
        };
        assert_eq!(spu.consistent_languages(), ["SPU:BE:32:default"]);
    }

    #[test]
    fn synthetic_mach_o_round_trips() {
        let bytes = synth_mach_o();
        let img = Image::parse(&bytes).unwrap();
        let Format::Mach(facts) = img.format else {
            panic!("not Mach-O");
        };
        assert_eq!(
            (
                facts.class_bits,
                facts.endian,
                facts.cpu_type,
                facts.file_type
            ),
            (64, Endian::Little, 0x0100_0007, 2)
        );
        assert_eq!(facts.consistent_languages(), ["x86:LE:64:default"]);
        assert_eq!(img.entry, Some(0x1100));
        assert_eq!(img.symbol_count, 3);
        assert_eq!(img.segments.len(), 1);
        assert_eq!(img.segments[0].name.as_deref(), Some("__TEXT"));
        assert_eq!(img.segments[0].perms.exec, Some(true));
        assert_eq!(img.regions[0].name, "__text");
        assert_eq!(img.bytes_at(&bytes, 0x1100, 4), Some(&bytes[0x100..0x104]));
    }

    #[test]
    fn mach_o_entryoff_maps_from_segment_file_offset() {
        let mut bytes = synth_mach_o();
        bytes[0x48..0x50].copy_from_slice(&0x80u64.to_le_bytes());
        let image = Image::parse(&bytes).unwrap();
        assert_eq!(image.entry, Some(0x1080));
    }

    #[test]
    fn universal_mach_o_requires_and_honours_slice_selection() {
        let fat = synth_fat_mach_o();
        assert_eq!(
            Image::parse(&fat),
            Err(FormatError::Malformed(
                "fat Mach-O requires a selected slice"
            ))
        );
        let x86 = Image::load_with_slice(&fat, Loader::Auto, None, Some(0)).unwrap();
        assert_eq!(x86.loader, Loader::MachO);
        assert_eq!(x86.image.entry, Some(0x1100));
        let Format::Mach(x86_facts) = x86.image.format else {
            panic!("slice 0 is not Mach-O");
        };
        assert_eq!(x86_facts.cpu_type, 0x0100_0007);
        assert_eq!(x86_facts.consistent_languages(), ["x86:LE:64:default"]);

        let arm = Image::load_with_slice(&fat, Loader::Auto, None, Some(1)).unwrap();
        assert_eq!(arm.loader, Loader::MachO);
        assert_eq!(arm.image.entry, Some(0x1100));
        let Format::Mach(arm_facts) = arm.image.format else {
            panic!("slice 1 is not Mach-O");
        };
        assert_eq!(arm_facts.cpu_type, 0x0100_000c);
        assert_eq!(arm_facts.consistent_languages(), ["AARCH64:LE:64:v8A"]);
        assert_ne!(x86.bytes, arm.bytes);
        assert_eq!(x86.bytes.len(), arm.bytes.len());
        assert!(matches!(
            Image::load_with_slice(&fat, Loader::Auto, None, Some(2)),
            Err(FormatError::Malformed(
                "fat Mach-O slice index out of range"
            ))
        ));
    }

    #[test]
    fn mach_o_truncation_and_fat_inputs_are_bounded() {
        let full = synth_mach_o();
        for n in 0..full.len() {
            let _ = Image::parse(&full[..n]);
        }
        assert_eq!(
            Image::parse(b"\xca\xfe\xba\xbe"),
            Err(FormatError::Malformed(
                "fat Mach-O requires a selected slice"
            ))
        );
        let mut malformed = full;
        malformed[0x24..0x28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Image::parse(&malformed),
            Err(FormatError::Truncated(_))
        ));
    }

    /// Hostile input class 1: every truncation of a valid file.
    #[test]
    fn no_prefix_of_a_valid_image_panics() {
        let full = synth_elf();
        for n in 0..full.len() {
            let _ = Image::parse(&full[..n]);
        }
    }

    /// Hostile input class 2: single-byte corruption anywhere in the headers.
    #[test]
    fn no_single_byte_corruption_panics() {
        let full = synth_elf();
        for i in 0..full.len() {
            for v in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                let mut d = full.clone();
                d[i] = v;
                let _ = Image::parse(&d);
            }
        }
    }

    /// Hostile input class 3: structured garbage. Deterministic LCG so a
    /// failure is reproducible from the seed alone.
    #[test]
    fn no_pseudorandom_blob_panics() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let len = (next() % 512) as usize;
            let mut d: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            if d.len() >= 4 {
                // half the blobs claim to be something, to reach deeper code
                if next() & 1 == 0 {
                    d[..4].copy_from_slice(b"\x7fELF");
                } else {
                    d[..2].copy_from_slice(b"MZ");
                }
            }
            let _ = Image::parse(&d);
        }
    }

    #[test]
    fn tiny_and_unknown_inputs_are_errors_not_panics() {
        assert_eq!(Image::parse(&[]), Err(FormatError::TooSmall));
        assert_eq!(Image::parse(b"\x7fEL"), Err(FormatError::TooSmall));
        assert_eq!(
            Image::parse(b"not an executable"),
            Err(FormatError::UnknownFormat)
        );
        assert!(matches!(
            Image::parse(b"\x7fELF\x09"),
            Err(FormatError::Malformed(_))
        ));
    }

    /// L0 must not decide the processor. Same facts, several answers.
    #[test]
    fn machine_facts_underdetermine_the_language() {
        let f = ElfFacts {
            class_bits: 32,
            endian: Endian::Little,
            obj_type: 2,
            machine: 8,
            flags: 0x2092_4000,
        };
        let langs = f.consistent_languages();
        assert!(langs.len() >= 2, "{langs:?}");
        assert!(langs.contains(&"r5900:LE:32:default"));
        assert!(langs.contains(&"MIPS:LE:32:default"));
    }

    // ---- real corpus. Numbers below were computed by an independent parser.

    #[test]
    fn ps2_elf_geometry_matches_an_independent_parser() {
        let Some(d) = corpus(PS2_ELF) else {
            eprintln!("PS2 corpus absent; skipping");
            return;
        };
        let img = Image::parse(&d).unwrap();
        assert_eq!(img.len, 10_699_044);
        let Format::Elf(f) = img.format else {
            panic!("not ELF")
        };
        assert_eq!(
            (f.class_bits, f.endian, f.machine, f.flags),
            (32, Endian::Little, 8, 0x2092_4000)
        );
        assert_eq!(img.entry, Some(0x0010_0008));
        assert_eq!(img.symbol_count, 22_529);

        assert_eq!(img.segments.len(), 1, "one PT_LOAD");
        let s = &img.segments[0];
        assert_eq!(
            (s.addr, s.size, s.file_off),
            (0x0010_0000, 0x008a_cc80, 0x60)
        );
        assert!(
            s.perms.is_unknown(),
            "p_flags is 0 in this file: {:?}",
            s.perms
        );

        assert_eq!(img.regions.len(), 9);
    }

    /// The overlay condition, derived from the file: one non-ALLOC section named
    /// `image` claiming the same addresses as the only PT_LOAD.
    #[test]
    fn ps2_elf_overlay_condition_is_derived_not_inherited() {
        let Some(d) = corpus(PS2_ELF) else {
            eprintln!("PS2 corpus absent; skipping");
            return;
        };
        let img = Image::parse(&d).unwrap();
        let aliasing: Vec<_> = img.aliasing_regions().collect();
        assert_eq!(aliasing.len(), 1, "{aliasing:?}");
        let r = aliasing[0];
        assert_eq!(r.name, "image");
        assert!(!r.alloc, "a non-ALLOC section with an address is the tell");
        assert_eq!((r.addr, r.size), (0x0010_0000, 0x008a_cc80));
        assert_eq!(r.placement, Placement::Aliases { of: 0 });
    }

    /// End to end: L0 + the address policy reproduce the exact trap from the
    /// session -- `0x0019d3f0` is ambiguous, and both candidates are named.
    #[test]
    fn ps2_elf_makes_a_bare_offset_refuse_with_both_candidates() {
        let Some(d) = corpus(PS2_ELF) else {
            eprintln!("PS2 corpus absent; skipping");
            return;
        };

        let t = Image::parse(&d).unwrap().space_table();
        match t.resolve("0x0019d3f0") {
            Err(AddrError::Ambiguous { candidates, .. }) => {
                assert_eq!(candidates, vec!["ram".to_string(), "image".to_string()]);
            }
            other => panic!("expected refusal naming both spaces, got {other:?}"),
        }
        assert!(t.resolve("image::0x0019d3f0").is_ok());
        assert!(t.resolve("ram::0x0019d3f0").is_ok());
    }

    #[test]
    fn win_pe_geometry_matches_an_independent_parser() {
        let Some(d) = corpus(WIN_PE) else {
            eprintln!("PE corpus absent; skipping");
            return;
        };
        let img = Image::parse(&d).unwrap();
        assert_eq!(img.len, 2_553_856);
        let Format::Pe(f) = img.format else {
            panic!("not PE")
        };
        assert_eq!(
            (f.machine, f.plus, f.image_base),
            (0x8664, true, 0x1_4000_0000)
        );
        assert_eq!(img.entry, Some(0x1_4000_0000 + 0x1b_b0ac));
        assert_eq!(img.segments.len(), 5);
        let names: Vec<_> = img.segments.iter().filter_map(|s| s.name.clone()).collect();
        assert_eq!(names, [".text", ".rdata", ".data", ".pdata", ".reloc"]);
        let text = &img.segments[0];
        assert_eq!(text.addr, 0x1_4000_1000);
        assert_eq!(text.perms.exec, Some(true));
        assert_eq!(text.perms.write, Some(false));
    }
    #[test]
    fn bytes_at_is_file_backed_and_segment_bounded() {
        let Some(d) = corpus(WIN_PE) else {
            eprintln!("PE corpus absent; skipping");
            return;
        };
        let img = Image::parse(&d).unwrap();
        let text = &img.segments[0];
        let expected = &d[text.file_off as usize..text.file_off as usize + 4];
        assert_eq!(img.bytes_at(&d, text.addr, 4), Some(expected));
        assert_eq!(
            img.bytes_at(&d, text.addr + text.file_size - 1, 4)
                .unwrap()
                .len(),
            1
        );
        assert!(img.bytes_at(&d, 0, 1).is_none());
    }

    /// A PE has no aliasing regions, so bare offsets stay ergonomic. The policy
    /// only gets strict where the file forces it.
    #[test]
    fn pe_images_keep_bare_offsets_unambiguous() {
        let Some(d) = corpus(WIN_PE) else {
            eprintln!("PE corpus absent; skipping");
            return;
        };
        let img = Image::parse(&d).unwrap();
        assert_eq!(img.aliasing_regions().count(), 0);
        assert!(img.space_table().resolve("0x140001000").is_ok());
    }

    /// Truncation of a *real* 10 MB image, which exercises paths a synthetic
    /// header never reaches. Coarse steps so the sweep stays cheap.
    #[test]
    fn truncated_real_images_do_not_panic() {
        for p in [PS2_ELF, WIN_PE] {
            let Some(d) = corpus(p) else { continue };
            let mut n = 0usize;
            while n < d.len() {
                let _ = Image::parse(&d[..n]);
                n += 4093; // prime stride: hits unaligned boundaries
            }
        }
    }

    #[test]
    fn content_hash_is_stable_and_input_sensitive() {
        let a = synth_elf();
        let mut b = a.clone();
        b[0x100] ^= 1;
        assert_eq!(Image::content_hash(&a), Image::content_hash(&a));
        assert_ne!(Image::content_hash(&a), Image::content_hash(&b));
    }

    #[test]
    fn parsing_never_reads_a_language_from_the_file() {
        // Guard against regression by construction: `Image` exposes facts and a
        // *plural* candidate list, so there is no single-valued language to read.
        let img = Image::parse(&synth_elf()).unwrap();
        let Format::Elf(f) = img.format else { panic!() };
        assert!(f.consistent_languages().len() > 1);
    }

    #[test]
    fn segment_overlap_is_half_open_and_zero_size_safe() {
        let s = Segment {
            name: None,
            addr: 0x1000,
            size: 0x100,
            file_off: 0,
            file_size: 0,
            perms: Perms::unknown(),
        };
        assert!(s.overlaps(0x10ff, 1));
        assert!(!s.overlaps(0x1100, 1), "touching ranges do not overlap");
        assert!(!s.overlaps(0xfff, 1));
        assert!(!s.overlaps(0x1000, 0), "zero-size claims nothing");
    }

    #[test]
    fn corrupt_section_name_offset_cannot_produce_a_huge_name() {
        let mut d = synth_elf();
        // point section 0's name at a spot with no NUL before EOF
        d[0x80..0x84].copy_from_slice(&0xffffu32.to_le_bytes());
        let img = Image::parse(&d).unwrap();
        assert!(img.regions.iter().all(|r| r.name.len() <= 256));
    }

    #[test]
    fn absurd_header_counts_are_bounded_by_the_input() {
        let mut d = synth_elf();
        d[44..46].copy_from_slice(&u16::MAX.to_le_bytes()); // phnum
        d[48..50].copy_from_slice(&u16::MAX.to_le_bytes()); // shnum

        let img = Image::parse(&d).unwrap();
        assert!(img.segments.len() < 64, "stopped at the end of input");
        assert!(img.regions.len() < 64);
    }
    #[test]
    fn absurd_table_offsets_are_rejected_without_panicking() {
        let mut elf32 = synth_elf();
        elf32[28..32].copy_from_slice(&u32::MAX.to_le_bytes()); // e_phoff
        elf32[32..36].copy_from_slice(&u32::MAX.to_le_bytes()); // e_shoff
        assert!(Image::parse(&elf32).is_ok());

        let mut elf64 = vec![0u8; 0x80];
        elf64[..4].copy_from_slice(b"\x7fELF");
        elf64[4] = 2; // 64-bit
        elf64[5] = 1; // little endian
        elf64[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf64[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf64[32..40].copy_from_slice(&u64::MAX.to_le_bytes()); // e_phoff
        elf64[40..48].copy_from_slice(&u64::MAX.to_le_bytes()); // e_shoff
        elf64[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf64[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf64[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf64[60..62].copy_from_slice(&1u16.to_le_bytes());
        assert!(Image::parse(&elf64).is_ok());
    }

    #[test]
    fn a_directory_is_not_a_corpus() {
        assert!(corpus(".").is_none());
        assert!(corpus("Z:/nope").is_none());
    }

    #[test]
    fn independent_ground_truth_file_is_present_for_review() {
        // The numbers asserted above came from a separate parser; its dump is
        // kept next to the workspace so a reviewer can diff rather than trust.
        let gt = Path::new("../../ground_truth.json");
        if !gt.is_file() {
            eprintln!("ground_truth.json absent (regenerate before trusting the corpus numbers)");
        }
    }
}
