//! Loaded ELF addresses and relocation bytes must agree across native consumers.
use lre_core::{native::import_elf, session::ProgramImage};

fn fixture(width: usize, be: bool, relocation: u64, image_base: u64) -> Vec<u8> {
    let mut data = vec![0u8; 0x600];
    data[..6].copy_from_slice(b"\x7fELF\x01\x01");
    data[4] = if width == 8 { 2 } else { 1 };
    data[5] = if be { 2 } else { 1 };
    let mut put = |offset: usize, size: usize, value: u64| {
        for i in 0..size { data[offset + if be { size - 1 - i } else { i }] = (value >> (i * 8)) as u8; }
    };
    put(16, 2, 3); // ET_DYN; a nonzero prelinked base must remain unchanged.
    put(18, 2, if width == 8 { 62 } else if be { 20 } else { 3 });
    put(24, width, image_base + 0x1000);
    let stride = if width == 8 { 64 } else { 40 };
    if width == 8 {
        for (offset, size, value) in [(32, 8, 0x80), (40, 8, 0x100), (54, 2, 56), (56, 2, 1),
                                     (58, 2, stride), (60, 2, 5), (62, 2, 4)] { put(offset, size, value); }
        put(0x80, 4, 1);
        put(0x90, 8, image_base);
    } else {
        for (offset, size, value) in [(28, 4, 0x80), (32, 4, 0x100), (42, 2, 32), (44, 2, 1),
                                     (46, 2, stride), (48, 2, 5), (50, 2, 4)] { put(offset, size, value); }
        put(0x80, 4, 1);
        put(0x88, 4, image_base);
    }
    let names = b"\0.text\0.data\0.reloc\0.shstrtab\0";
    let record_words = if relocation == 4 { 3 } else if relocation == 9 { 2 } else { 1 };
    let reloc_size = if relocation == 19 { 2 * width } else { 3 * record_words * width };
    for (index, name, typ, flags, addr, offset, size) in [
        (1, 1, 1, 6, image_base + 0x1000, 0x400, 64),
        (2, 7, 1, 3, image_base + 0x2000, 0x440, 3 * width),
        (3, 13, relocation, 0, 0, 0x480, reloc_size),
        (4, 20, 3, 0, 0, 0x380, names.len()),
    ] {
        let start = 0x100 + index * stride as usize;
        put(start, 4, name);
        put(start + 4, 4, typ);
        for (i, value) in [flags, addr, offset, size as u64].into_iter().enumerate() {
            put(start + 8 + i * width, width, value);
        }
    }
    let relative_type = if be { 22 } else { 8 };
    for (i, addend) in [image_base + 0x1010, 0, u64::MAX - 15].into_iter().enumerate() {
        if relocation == 4 || relocation == 9 {
            let record = 0x480 + i * record_words * width;
            put(record, width, image_base + 0x2000 + (i * width) as u64);
            put(record + width, width, relative_type);
            if relocation == 4 { put(record + 2 * width, width, addend); }
        }
        if relocation != 4 { put(0x440 + i * width, width, addend); }
    }
    if relocation == 19 {
        put(0x480, width, image_base + 0x2000);
        put(0x480 + width, width, 7); // Relocate the following two words.
    }
    data[0x380..0x380 + names.len()].copy_from_slice(names);
    data[0x400..0x404].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
    data
}

#[test]
fn loaded_elf_addresses_and_relative_pointer_bytes_agree() {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("ventris-elf-image-{}-{stamp}", std::process::id()));
    for (width, be) in [(8, false), (4, false), (4, true)] {
        for relocation in [4, 9, 19] {
            for original_base in [0, 0x400000] {
                let data = fixture(width, be, relocation, original_base);
                let import = import_elf(&data).unwrap();
                let bias = if original_base != 0 { 0 } else if width == 8 { 0x100000 } else { 0x10000 };
                let loaded_base = original_base + bias;
                assert!(import.functions.iter().any(|f| f.entry == loaded_base + 0x1000),
                        "entry must use loaded addresses: width={width} be={be} relocation={relocation}");
                std::fs::write(&path, &data).unwrap();
                let mut image = ProgramImage::open(&path).unwrap();
                assert_eq!(image.read(loaded_base + 0x1000, 4).unwrap(), [0x90, 0x90, 0x90, 0xc3]);
                let mapping = import.mappings.iter().find(|m| m.vaddr == loaded_base + 0x2000).unwrap();
                for (i, value) in [loaded_base + 0x1010, bias, bias.wrapping_sub(16)].into_iter().enumerate() {
                    let expected: Vec<_> = (0..width).map(|j| (value >> (8 * if be { width - 1 - j } else { j })) as u8).collect();
                    let at = loaded_base + 0x2000 + (i * width) as u64;
                    assert_eq!(image.read(at, width as u64).unwrap(), expected, "relocated image word {i}");
                    assert_eq!(&mapping.bytes[i * width..(i + 1) * width], expected, "console mapping word {i}");
                    assert_eq!(image.read(at + 1, 2).unwrap(), expected[1..3], "partial pointer read");
                }
                image.patch(loaded_base + 0x2001, vec![0xaa]);
                assert_eq!(image.read(loaded_base + 0x2001, 1).unwrap(), [0xaa], "user patches override relocations");
                assert!(image.read(loaded_base + 0x3000, 1).is_none());
                drop(image);
            }
        }
    }
    // BSS relocations overlay zero-fill, never bytes at the section's file offset.
    let mut data = fixture(8, false, 4, 0);
    data[0x184..0x188].copy_from_slice(&8u32.to_le_bytes()); // SHT_NOBITS
    data[0x1a0..0x1a8].copy_from_slice(&32u64.to_le_bytes());
    data[0x440..0x460].fill(0xa5);
    std::fs::write(&path, data).unwrap();
    let image = ProgramImage::open(&path).unwrap();
    assert_eq!(image.read(0x102000, 8).unwrap(), 0x101010u64.to_le_bytes());
    assert_eq!(image.read(0x102018, 8).unwrap(), [0; 8]);
    drop(image);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn undefined_elf32_symbols_are_not_function_definitions() {
    for be in [false, true] {
        let mut data = fixture(4, be, 4, 0x400000);
        let mut put = |offset: usize, value: u32| {
            data[offset..offset + 4].copy_from_slice(&if be { value.to_be_bytes() } else { value.to_le_bytes() });
        };
        // Replace the relocation section with one dynamic function symbol.
        for (offset, value) in [(0x17c, 11), (0x18c, 16), (0x190, 4), (0x1b4, 0x60),
                                (0x480, 0x40), (0x484, 0x401010), (0x488, 4)] {
            put(offset, value);
        }
        data[0x48c..0x490].copy_from_slice(&[0x12, 0, 0, 0]); // STT_FUNC, SHN_UNDEF
        data[0x3c0..0x3c9].copy_from_slice(b"imported\0");
        let import = import_elf(&data).unwrap();
        assert!(!import.functions.iter().any(|f| f.entry == 0x401010),
                "a nonzero undefined-symbol value does not define code");
        assert!(import.externals.iter().any(|(address, name)| *address == 0 && name == "imported"));
        // The same address remains a real function when the symbol is defined.
        data[0x48e..0x490].copy_from_slice(&if be { 1u16.to_be_bytes() } else { 1u16.to_le_bytes() });
        let import = import_elf(&data).unwrap();
        assert!(import.functions.iter().any(|f| f.entry == 0x401010 && f.name == "imported"));
        assert!(!import.externals.iter().any(|(_, name)| name == "imported"));
    }
}
