//! Ghidra's getBytes callback pads a valid short read, not an unmapped start.
use lre_worker::BinaryBacking;

#[test]
fn worker_pads_short_reads_but_rejects_unmapped_starts() {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("ventris-worker-bytes-{}-{stamp}", std::process::id()));
    std::fs::write(&path, [0x90, 0xc3]).unwrap();
    let result = {
        let backing = BinaryBacking::from_file(&path, 0x400000).unwrap();
        let short = backing.read(0x400001, 4);
        assert!(backing.read(0x400002, 1).is_none());
        assert!(backing.read(0x3fffff, 1).is_none());
        short
    };
    std::fs::remove_file(path).unwrap();
    assert_eq!(result, Some(vec![0xc3, 0, 0, 0]));
}
