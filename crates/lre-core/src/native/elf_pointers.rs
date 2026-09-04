//! Untrusted pointers from allocated ELF data; relocation observations win.
use super::{err, ElfSection, NativeImport, NativeXref, Result};
use std::collections::HashMap;

pub(super) fn collect(data: &[u8], sections: &[ElfSection], import: &mut NativeImport, width: usize, be: bool) -> Result<()> {
    let relocated: HashMap<_, _> = import.xrefs.iter()
        .filter(|x| x.provenance == "native-import:elf-reloc")
        .map(|x| (x.from, x.to)).collect();
    for section in sections {
        let selected = matches!(section.typ, 14 | 15)
            || section.name == ".data" || section.name.starts_with(".data.")
            || section.name == ".rodata" || section.name.starts_with(".rodata.");
        if !selected || section.flags & 2 == 0 || section.flags & 4 != 0 || section.typ == 8 {
            continue;
        }
        let Some(end) = section.off.checked_add(section.size) else {
            return err("ELF pointer section file range overflow");
        };
        let Some(bytes) = usize::try_from(section.off).ok().zip(usize::try_from(end).ok())
            .and_then(|(start, end)| data.get(start..end)) else {
            return err("ELF pointer section outside file");
        };
        let skip = (section.addr.wrapping_neg() & (width as u64 - 1)) as usize;
        let Some(bytes) = bytes.get(skip..) else { continue; };
        for (index, chunk) in bytes.chunks_exact(width).enumerate() {
            let Some(source) = section.addr.checked_add((skip + index * width) as u64) else {
                return err("ELF pointer section address overflow");
            };
            let target = relocated.get(&source).copied().unwrap_or_else(|| match (width, be) {
                (4, false) => u32::from_le_bytes(chunk.try_into().unwrap()) as u64,
                (4, true) => u32::from_be_bytes(chunk.try_into().unwrap()) as u64,
                (8, false) => u64::from_le_bytes(chunk.try_into().unwrap()),
                (8, true) => u64::from_be_bytes(chunk.try_into().unwrap()),
                _ => unreachable!("ELF pointer width"),
            });
            if !import.mappings.iter().any(|m| m.flags & 4 != 0 && target >= m.vaddr && target - m.vaddr < m.size) {
                continue;
            }
            if matches!(section.typ, 14 | 15) {
                import.initializer_candidates.push(target);
            } else {
                import.pointer_candidates.push(target);
            }
            if !relocated.contains_key(&source) {
                import.xrefs.push(NativeXref::with_provenance(source, target, "DATA", "native-import:elf-pointer"));
            }
        }
    }
    import.pointer_candidates.sort_unstable();
    import.pointer_candidates.dedup();
    import.initializer_candidates.sort_unstable();
    import.initializer_candidates.dedup();
    Ok(())
}

pub(super) fn confirm_initializers(import: &mut NativeImport) {
    use crate::native_runtime::{ConsoleSession, FlowKind};
    let candidates: Vec<_> = import.initializer_candidates.iter().copied()
        .filter(|a| !import.functions.iter().any(|f| f.entry == *a)).collect();
    if candidates.is_empty() { return; }
    let Ok(mut session) = ConsoleSession::new(&import.cfg) else { return; };
    if session.load_mapped(import).is_err() { return; }
    let flows = session.try_flow_batch(&candidates);
    for (entry, flow) in candidates.into_iter().zip(flows) {
        if flow.address == entry && flow.length != 0 && !matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl) {
            import.functions.push(super::NativeFunction { entry, name: format!("FUN_{entry:08x}"), size: 1 });
        }
    }
}
