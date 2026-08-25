//! Reads the pinned corpus ELF's DWARF, and records what it does and does not
//! cover.
//!
//! `dungeon_game.elf` carries both DWARF 2 and a 240 KB `.mdebug` section. The
//! DWARF describes only the linked-in runtime library; every prototype in it
//! comes from libgcc. The game's own translation units — `game_world.cpp` and
//! its siblings — are described in `.mdebug` alone, which is MIPS symbolic debug
//! and a different format entirely. This test asserts the reader recovers the
//! DWARF that is there, so a future change cannot silently lose it, and the
//! absence of the game's own functions is documented rather than asserted:
//! adding an `.mdebug` reader should make them appear without failing a test
//! that demanded they be missing.

use std::path::Path;

use ventris_format::dwarf::DebugType;

/// The pinned PS2 image, when the caller says where the corpus lives.
///
/// The corpus is not in the repository, so its location comes from the
/// environment exactly as the Python gates take `--image-dir`. Absent, the test
/// skips rather than hard-coding one machine's layout.
fn corpus() -> Option<Vec<u8>> {
    let directory = std::env::var_os("VENTRIS_CORPUS_DIR")?;
    let path = Path::new(&directory).join("dungeon_game.elf");
    path.is_file()
        .then(|| std::fs::read(&path).expect("the corpus image is readable"))
}

#[test]
fn recovers_the_runtime_prototypes_the_dwarf_describes() {
    let Some(bytes) = corpus() else {
        eprintln!("VENTRIS_CORPUS_DIR unset or image absent; skipping");
        return;
    };
    let image = ventris_format::Image::parse(&bytes).expect("the ELF is parsed");
    let info = image.debug_info(&bytes).expect("debug info parses");
    assert!(
        info.functions.len() >= 17,
        "expected the runtime's prototypes, got {}",
        info.functions.len()
    );

    // `_fpadd_parts` returns `struct _fpnum *`, which is the case that matters:
    // a pointer return recovered from a declaration rather than inferred from
    // arithmetic.
    let pointer_returning = info
        .functions
        .values()
        .find(|function| function.name == "_fpadd_parts")
        .expect("the soft-float helper is described");
    assert!(
        pointer_returning
            .return_type
            .as_ref()
            .is_some_and(DebugType::is_pointer),
        "expected a pointer return, got {:?}",
        pointer_returning.return_type
    );
    assert!(
        !pointer_returning.parameters.is_empty(),
        "the helper takes parameters and they should be recovered"
    );

    // A function returning nothing is an absent `DW_AT_type`, not a void type,
    // and must not be confused with a function whose type failed to resolve.
    assert!(
        info.functions
            .values()
            .any(|function| function.return_type.is_none()),
        "expected at least one void-returning prototype"
    );
}
