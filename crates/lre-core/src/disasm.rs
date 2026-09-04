//! Minimal x86-64 instruction decoder for stripped-binary function
//! discovery: exact instruction length (full prefix/ModRM/SIB/disp/immed
//! coverage) plus control-flow classification of terminal opcodes
//! (direct call/jmp/jcc, indirect, ret/stop). SLEIGH pcode and
//! decompilation live in the worker; this only walks boundaries.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Next,
    /// Direct relative call: target = len_end + rel32.
    Call(u64),
    /// Direct relative unconditional jump.
    Jump(u64),
    /// Direct conditional near jump (Jcc rel8/rel32).
    JumpCond(u64),
    /// Indirect call (register or memory): stops the linear walk; the RDI
    /// setup immediately before it may seed the caller entry (ELF _start
    /// to __libc_start_main convention).
    IndirectCall,
    /// Indirect jump (switch table etc.): stops the linear walk.
    Indirect,
    /// Ret/iret/trap/int3: stops the walk.
    Stop,
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstrInfo {
    pub len: u8,
    pub flow: Flow,
    pub rip_data: Option<u64>,
}

/// Opcodes with an immediate following the memory/operand encoding.
#[derive(Clone, Copy, PartialEq)]
enum ImmKind {
    None,
    I8,
    I16,
    I32,
    I64,
    Imm8Rel,
    Imm32Rel,
}

struct OpInfo {
    modrm: bool,
    imm: ImmKind,
}

fn op_info(op: u8, op2: Option<u8>, op3: Option<u8>, rex_w: bool) -> OpInfo {
    use ImmKind::*;
    if op == 0x0f {
        let o2 = op2.unwrap_or(0);
        if o2 == 0x38 || o2 == 0x3a {
            return OpInfo {
                modrm: true,
                imm: if o2 == 0x3a { I8 } else { None },
            };
        }
        // 0F opcodes WITHOUT a ModRM byte: syscall (05), invd/wbinvd
        // (08/09), ud2 (0b), wrmsr/rdtsc/rdmsr (30/31/32), their siblings
        // (33/34/35/37), emms (77), cpuid (a2), bswap (c8..cf). The old
        // table assumed modrm for every 0F opcode, mis-lengthening
        // syscall/rdtsc/bswap and poisoning every walk through them.
        let no_modrm = matches!(o2, 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0b | 0x30 | 0x31
            | 0x32 | 0x33 | 0x34 | 0x35 | 0x37 | 0x77 | 0xa2 | 0xc8..=0xcf);
        return match o2 {
            0x70..=0x7f => OpInfo { modrm: true, imm: I8 },
            0x80..=0x8f => OpInfo { modrm: false, imm: Imm32Rel },
            0xc2 | 0xc0 | 0xc1 => OpInfo { modrm: true, imm: I8 },
            _ if no_modrm => OpInfo { modrm: false, imm: None },
            _ => OpInfo { modrm: true, imm: None },
        };
    }
    match op {
        0x80 | 0x82 => OpInfo { modrm: true, imm: I8 },
        0x81 => OpInfo { modrm: true, imm: I32 },
        0x83 => OpInfo { modrm: true, imm: I8 },
        0x84..=0x8f => OpInfo { modrm: true, imm: None },
        0xc0 | 0xc1 => OpInfo { modrm: true, imm: I8 },
        0xc6 => OpInfo { modrm: true, imm: I8 },
        0xc7 => OpInfo { modrm: true, imm: I32 },
        0xd0..=0xd3 => OpInfo { modrm: true, imm: None },
        0xf6 | 0xf7 => OpInfo { modrm: true, imm: None },
        0xfe | 0xff => OpInfo { modrm: true, imm: None },
        0x69 => OpInfo { modrm: true, imm: I32 },
        0x6b => OpInfo { modrm: true, imm: I8 },
        0xb0..=0xb7 => OpInfo { modrm: false, imm: I8 },
        0xb8..=0xbf => OpInfo {
            modrm: false,
            imm: if rex_w { I64 } else { I32 },
        },
        0x05 | 0x0d | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d => {
            OpInfo { modrm: false, imm: I32 }
        }
        0x68 => OpInfo { modrm: false, imm: I32 },
        0x6a => OpInfo { modrm: false, imm: I8 },
        0xa8 => OpInfo { modrm: false, imm: I8 },
        0xa9 => OpInfo { modrm: false, imm: I32 },
        0xa0..=0xa3 => OpInfo { modrm: false, imm: I32 },
        0xe4..=0xe7 => OpInfo { modrm: false, imm: I8 },
        0xcd => OpInfo { modrm: false, imm: I8 },
        0x50..=0x5f => OpInfo { modrm: false, imm: None }, // push/pop reg
        0x90..=0x97 => OpInfo { modrm: false, imm: None }, // nop; xchg reg
        0xa4..=0xa7 => OpInfo { modrm: false, imm: None }, // movs/cmps
        0x98..=0x9f => OpInfo { modrm: false, imm: None }, // cbw/cwde/cdq...
        0xc8 | 0xc9 => OpInfo { modrm: false, imm: None }, // enter/leave
        0xd4..=0xd7 => OpInfo { modrm: false, imm: None }, // aam/aad/salc
        0xe0..=0xe3 => OpInfo { modrm: false, imm: None }, // loop/jrcxz
        0xf1 => OpInfo { modrm: false, imm: None },        // int1
        0xf8..=0xfd => OpInfo { modrm: false, imm: None }, // clc/stc/cld/std
        // DEFAULT: one-byte opcodes overwhelmingly carry a ModRM byte
        // (all /r forms 00..3F, 63, 88..8F, x87 D8..DF, shifts). The old
        // no-modrm default mis-lengthened e.g. `add eax,ebx` (01 c3) as
        // one byte, misaligning every walk past the first arithmetic.
        _ => OpInfo { modrm: true, imm: None },
    }
}

/// ModRM + SIB + displacement length for memory operands (starting the
/// walk at `b[m]` = the ModRM byte, with the opcode consumed at `p`).
fn mem_modlen(b: &[u8], m: usize, force_memory: bool) -> u8 {
    let Some(&modrm) = b.get(m) else {
        return 0;
    };
    let modbits = modrm >> 6;
    if !force_memory && modbits == 3 {
        return 0; // register operand
    }
    let rm = modrm & 7;
    match modbits {
        0 => {
            if rm == 4 {
                let sib = b.get(m + 1).copied().unwrap_or(0);
                let base = sib & 7;
                if base == 5 && (sib >> 7) == 0 {
                    5 // SIB + disp32, no base
                } else {
                    1
                }
            } else if rm == 5 {
                4 // disp32, no base
            } else {
                0
            }
        }
        1 => 1,
        2 => 4,
        _ => 0, // register form (impossible here)
    }
}

/// Decodes one instruction at `b` (>= 15 bytes) and returns its length and
/// flow. `addr` is the instruction address (for rel-target computation).
pub fn decode(b: &[u8], addr: u64) -> InstrInfo {
    let mut p = 0usize;
    let mut rex_w = false;
    let mut rex_b = false;
    // Legacy prefixes + REX.
    loop {
        let c = b.get(p).copied().unwrap_or(0);
        match c {
            0x66 | 0x67 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 => p += 1,
            0x40..=0x4f => {
                rex_w = c & 8 != 0;
                rex_b = c & 1 != 0;
                p += 1;
            }
            _ => break,
        }
    }
    let op = b.get(p).copied().unwrap_or(0);
    let op2 = b.get(p + 1).copied();
    let op3 = b.get(p + 2).copied();

    // Immediate-length dependent on operand size prefix.
    let has_op66 = b[..p].contains(&0x66);
    let _ = (rex_b, has_op66);

    // Control-flow classification first (using raw op inspection).
    let flow_len: Option<(Flow, u8)> = match op {
        0xe8 => Some((Flow::Call(rel_target(b, p + 1, 5, addr)), 5)),
        0xe9 => Some((Flow::Jump(rel_target(b, p + 1, 5, addr)), 5)),
        0xeb => Some((Flow::Jump(rel8_target(b, p + 1, 2, addr)), 2)),
        0x70..=0x7f => Some((Flow::JumpCond(rel8_target(b, p + 1, 2, addr)), 2)),
        0x0f if op2.map(|o| (0x80..=0x8f).contains(&o)).unwrap_or(false) => {
            Some((Flow::JumpCond(rel_target(b, p + 2, 6, addr)), 6))
        }
        0x0f
            if op2
                .map(|o| matches!(o, 0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x95 | 0x96 | 0x97 | 0x98 | 0x99 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f))
                .unwrap_or(false) =>
        {
            Some((Flow::Next, 3)) // setcc/setb; flow Next (handled below by full len)
        }
        0xc3 | 0xc2 | 0xcb | 0xca | 0xcf => Some((Flow::Stop, if op == 0xc2 || op == 0xca { 3 } else { 1 })),
        0xcc => Some((Flow::Stop, 1)),
        0xf4 | 0xf5 | 0xfa | 0xfb | 0xfc | 0xfd | 0xfe => Some((Flow::Stop, 1)),
        0xcd => Some((Flow::Stop, 2)),
        _ => None,
    };
    if let Some((f, l)) = flow_len {
        return InstrInfo { len: l, flow: f, rip_data: None };
    }
    // 0F 90-9F setcc/setb: flow Next with full length.
    if op == 0x0f && op2.map(|o| (0x90..=0x9f).contains(&o)).unwrap_or(false) {
        let m = p + 2;
        let len = p + 3 + mem_modlen(b, m, false) as usize;
        return InstrInfo { len: len.min(15) as u8, flow: Flow::Next, rip_data: None };
    }

    let info = op_info(op, op2, op3, rex_w);
    let mut len = p + 1usize; // prefixes + opcode
    if op == 0x0f {
        len = p + 2; // 0f + op2
        if op2 == Some(0x38) || op2 == Some(0x3a) {
            len += 1;
        }
    }
    if info.modrm {
        // `len` already includes the prefixes (p), so the ModRM byte is at
        // index `len`, not `p + len` (a prefixed memory operand read the
        // wrong byte and misaligned every subsequent walk).
        let m = len;
        let modrm = b.get(m).copied().unwrap_or(0);
        let reg = (modrm >> 3) & 7;
        let modbits = modrm >> 6;
        let rm = modrm & 7;
        let is_rip_rel = modbits == 0 && rm == 5;
        let flow = if op == 0xff {
            match reg {
                2 => Flow::IndirectCall,
                4 => Flow::Indirect,
                _ => Flow::Next,
            }
        } else {
            Flow::Next
        };
        len += 1; // modrm
        len += mem_modlen(b, m, false) as usize;
        // F6/F7 group: the immediate exists only for the TEST forms
        // (modrm ext 0); NOT/NEG/MUL/DIV take none.
        let reg = (modrm >> 3) & 7;
        let f_test_imm = match (op, reg) {
            (0xf6, 0) => Some(1),
            (0xf7, 0) => Some(4),
            _ => None,
        };
        match f_test_imm.or(match info.imm {
            ImmKind::I8 => Some(1),
            ImmKind::I16 => Some(2),
            ImmKind::I32 => Some(4),
            ImmKind::I64 => Some(8),
            ImmKind::None | ImmKind::Imm8Rel | ImmKind::Imm32Rel => None,
        }) {
            Some(n) => len += n,
            None => {}
        }
        let final_len = len.min(15) as u8;
        let rip_data = if is_rip_rel && !matches!(flow, Flow::IndirectCall | Flow::Indirect) {
            let disp = i32::from_le_bytes([
                b.get(m + 1).copied().unwrap_or(0),
                b.get(m + 2).copied().unwrap_or(0),
                b.get(m + 3).copied().unwrap_or(0),
                b.get(m + 4).copied().unwrap_or(0),
            ]) as i64;
            Some(addr.wrapping_add(final_len as u64).wrapping_add(disp as u64))
        } else {
            None
        };
        return InstrInfo { len: final_len, flow, rip_data };
    }
    match info.imm {
        ImmKind::I8 => len += 1,
        ImmKind::I16 => len += 2,
        ImmKind::I32 => len += 4,
        ImmKind::I64 => len += 8,
        ImmKind::Imm8Rel => len += 1,
        ImmKind::Imm32Rel => len += 4,
        ImmKind::None => {}
    }
    InstrInfo { len: len.min(15) as u8, flow: Flow::Next, rip_data: None }
}

fn rel_target(b: &[u8], o: usize, total: usize, addr: u64) -> u64 {
    let rel = i32::from_le_bytes([
        b.get(o).copied().unwrap_or(0),
        b.get(o + 1).copied().unwrap_or(0),
        b.get(o + 2).copied().unwrap_or(0),
        b.get(o + 3).copied().unwrap_or(0),
    ]) as i64;
    addr.wrapping_add(total as u64).wrapping_add(rel as u64)
}
/// Short-relative branch target: the displacement is one sign-extended
/// byte (EB/70..7F). Reading 4 bytes would include the following
/// instruction in the displacement.
fn rel8_target(b: &[u8], o: usize, total: usize, addr: u64) -> u64 {
    let rel = b.get(o).copied().unwrap_or(0) as i8 as i64;
    addr.wrapping_add(total as u64).wrapping_add(rel as u64)
}

/// Linear-sweep + flow function discovery over a code range.
///
/// `seeds` are known entry points (ELF entry, PLT stubs, exported funcs).
/// Returns discovered function entries in address order: every seed and
/// every direct-call target reachable inside the sweep, with a conservative
/// size (distance to the next discovered function or the next stop).
#[derive(Debug, Default)]
pub struct Discovery {
    pub entries: Vec<u64>,
    pub sizes: Vec<u64>,
    pub calls: Vec<(u64, u64)>,
    pub data_refs: Vec<(u64, u64)>,
}

/// Flow-based discovery over `maps` (vaddr, size, file_off, bytes);
/// `seeds` are known entries. Every seed and every direct-call target
/// reachable becomes a function; sizes are distances to the next entry.
pub fn discover(maps: &[(u64, u64, u64, &[u8])], seeds: &[u64]) -> Discovery {
    let mut entries: Vec<u64> = seeds.to_vec();
    entries.sort_unstable();
    entries.dedup();
    let mut queue: Vec<u64> = entries.clone();
    let mut processed: Vec<u64> = Vec::new();
    let mut calls = Vec::new();
    let mut data_refs = Vec::new();
    let mut proven_bodies: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();

    while let Some(start) = queue.pop() {
        if processed.contains(&start) {
            continue;
        }
        processed.push(start);
        let Some((sv, ss, _sf, bytes)) = maps.iter().find(|(v, s, _, _)| {
            start >= *v && start < v + s
        }) else {
            continue;
        };
        // Two-path walk: conditional branches explore the target first and
        // keep the fall-through on an explicit stack (a single linear path
        // over the taken edge skips bodies behind the non-taken edge — the
        // dtors_aux `jne` ahead of its call to deregister_tm_clones).
        let mut paths: Vec<u64> = Vec::new();
        let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut addr = start;
        let mut span_end: u64 = start;
        let mut walked = 0u32;
        loop {
            let in_map = |a: u64| maps.iter().any(|(v, s, _, _)| a >= *v && a < v + s);
            if !visited.insert(addr) {
                // already covered (loop back-edge) — continue this path's
                // fall-through only if a conditional put one aside
                if paths.is_empty() {
                    break;
                }
                addr = paths.pop().unwrap();
                continue;
            }
            let off = (addr - sv) as usize;
            if off >= *ss as usize {
                if paths.is_empty() {
                    break;
                }
                addr = paths.pop().unwrap();
                continue;
            }
            let win = &bytes[off..];
            let info = decode(win, addr);
            span_end = span_end.max(addr + info.len as u64);
            if let Some(target) = info.rip_data {
                if in_map(target) {
                    data_refs.push((addr, target));
                }
            }
            match info.flow {
                Flow::Call(t) => {
                    calls.push((addr, t));
                    if in_map(t) && !entries.contains(&t) {
                        entries.push(t);
                        queue.push(t);
                    }
                    addr += info.len as u64;
                }
                Flow::Jump(t) => {
                    // Forward, in-map targets advance the walk within the function.
                    // If the jump is at the start of the function (a tail call /
                    // forwarder stub like `endbr64; jmp target`), the target is
                    // a function entry.
                    if in_map(t) {
                        let is_thunk = addr == start
                            || (addr == start + 4 && bytes.get((start - sv) as usize..(start - sv) as usize + 4) == Some(&[0xf3, 0x0f, 0x1e, 0xfa]));
                        if is_thunk && !entries.contains(&t) {
                            entries.push(t);
                            queue.push(t);
                        }
                        if t > addr {
                            addr = t;
                        } else {
                            if paths.is_empty() {
                                break;
                            }
                            addr = paths.pop().unwrap();
                            continue;
                        }
                    } else {
                        addr += info.len as u64;
                    }
                }
                Flow::JumpCond(t) => {
                    if in_map(t) && t > addr {
                        // target first, fall-through saved for later
                        paths.push(addr + info.len as u64);
                        addr = t;
                    } else {
                        addr += info.len as u64;
                    }
                }
                Flow::IndirectCall => {
                    maybe_seed_entry(bytes, *sv, off, &mut entries, &mut queue);
                    addr += info.len as u64;
                }
                Flow::Indirect | Flow::Stop | Flow::Bad => {
                    if paths.is_empty() {
                        break;
                    }
                    addr = paths.pop().unwrap();
                    continue;
                }
                Flow::Next => addr += info.len as u64,
            }
            walked += 1;
            if walked > 100_000 {
                break;
            }
        }
        // Conservative proven body: the walk's trailing extent when one
        // exists, capped by the distance to the next entry (a fall-through
        // path must never make a body overlap the following function).
        // The old size-always-distance-to-next fiction is gone.
        // Next-entry cap: the distance to the next discovered function,
        // or the end of the CURRENT map when there is none (a last function
        // in a section previously used start+16, capping its proven body at
        // 16 bytes).
        let next = entries
            .iter()
            .filter(|e| **e > start)
            .min()
            .copied()
            .unwrap_or(sv + ss);
        let proven = span_end.saturating_sub(start).max(1);
        proven_bodies.insert(start, proven.min(next - start).max(1));
    }
    entries.sort_unstable();
    entries.dedup();
    let sizes = entries
        .iter()
        .map(|e| proven_bodies.get(e).copied().unwrap_or(16))
        .collect();
    calls.dedup();
    data_refs.sort_unstable();
    data_refs.dedup();
    Discovery {
        entries,
        sizes,
        calls,
        data_refs,
    }
}

/// ELF/x86-64 startup convention: the arguments to the indirect
/// `__libc_start_main` call are set by the instructions just before it —
/// the first (RDI) is the user entry (`main`). Scanning the preceding
/// bytes for `mov rdi, imm64` (48 bf), `mov rdi, imm32` (48 c7 c7), or
/// `lea rdi, [rip+disp32]` (48 8d 3d) seeds that target when it lands
/// inside the code mapping. Byte-level heuristic scan (backwards,
/// closest match wins) — the same convention Ghidra's entry-point
/// recovery uses.
pub(crate) fn maybe_seed_entry(
    bytes: &[u8],
    map_vaddr: u64,
    off: usize,
    entries: &mut Vec<u64>,
    queue: &mut Vec<u64>,
) {
    let in_code = |a: u64| a >= map_vaddr && a < map_vaddr + bytes.len() as u64;
    let mut sp = off;
    let lo = off.saturating_sub(40);
    while sp > lo {
        sp -= 1;
        let b = bytes;
        if sp + 10 <= off && b.get(sp) == Some(&0x48) && b.get(sp + 1) == Some(&0xbf) {
            // mov rdi, imm64
            if let Some(imm_bytes) = b.get(sp + 2..sp + 10) {
                let imm = u64::from_le_bytes(imm_bytes.try_into().unwrap());
                if in_code(imm) && !entries.contains(&imm) {
                    entries.push(imm);
                    queue.push(imm);
                    return;
                }
            }
        }
        if sp + 7 <= off && b.get(sp..sp + 3) == Some(&[0x48, 0xc7, 0xc7]) {
            // mov rdi, imm32 (zero-extended)
            if let Some(imm_bytes) = b.get(sp + 3..sp + 7) {
                let imm = u32::from_le_bytes(imm_bytes.try_into().unwrap()) as u64;
                if in_code(imm) && !entries.contains(&imm) {
                    entries.push(imm);
                    queue.push(imm);
                    return;
                }
            }
        }
        if sp + 7 <= off && b.get(sp..sp + 3) == Some(&[0x48, 0x8d, 0x3d]) {
            // lea rdi, [rip+disp32]
            if let Some(disp_bytes) = b.get(sp + 3..sp + 7) {
                let disp = i32::from_le_bytes(disp_bytes.try_into().unwrap());
                let t = (map_vaddr + sp as u64).wrapping_add(7).wrapping_add(disp as u64);
                if in_code(t) && !entries.contains(&t) {
                    entries.push(t);
                    queue.push(t);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_and_flows() {
        // push rbp; mov rbp,rsp; call +5; add eax, 0x28; ret
        let bytes = [
            0x55, 0x48, 0x89, 0xe5, 0xe8, 0x05, 0x00, 0x00, 0x00, 0x83, 0xc0, 0x28, 0xc3,
        ];
        let mut addr = 0x1000u64;
        let mut flows = Vec::new();
        let mut p = 0usize;
        while p < bytes.len() {
            let info = decode(&bytes[p..], addr);
            flows.push((info.len, info.flow));
            addr += info.len as u64;
            p += info.len as usize;
        }
        // len(3) check: 55=1, 48 89 e5=3, e8+5=5, 83 c0 28=3, c3=1
        let lens: Vec<u8> = flows.iter().map(|(l, _)| *l).collect();
        assert_eq!(lens, vec![1, 3, 5, 3, 1]);
        assert_eq!(flows[2].1, Flow::Call(0x1000 + 1 + 3 + 5 + 5));
        assert!(matches!(flows[3].1, Flow::Next));
        assert_eq!(flows[4].1, Flow::Stop);
    }

    #[test]
    fn discover_finds_call_targets() {
        let code: Vec<u8> = vec![
            0x55, 0x48, 0x89, 0xe5, 0x83, 0xc0, 0x28, 0x5d, 0xc3, // funcA: add eax,0x28; pop; ret
            0x90, 0x90, // pad
            0x55, 0x48, 0x89, 0xe5, 0xe8, 0xec, 0xff, 0xff, 0xff, // funcB: call funcA (rel -20)
            0x31, 0xc0, 0xc3, // xor eax,eax; ret
        ];
        let maps = vec![(0x400000u64, code.len() as u64, 0u64, code.as_slice())];
        let d = discover(&maps, &[0x400000, 0x40000b]);
        assert_eq!(d.entries, vec![0x400000, 0x40000b]);
        assert_eq!(d.calls, vec![(0x40000f, 0x400000)]);
    }

    #[test]
    fn main_prologue_lengths() {
        // gcc -O1 prologue from the QA-003 many-function fixture:
        // push rbx | mov edi,imm32 | call | mov ebx,eax | mov edi,imm32 |
        // call | add eax,ebx | ...
        let bytes = [
            0x53, // push rbx (1)
            0xbf, 0x00, 0x00, 0x00, 0x00, // mov edi, 0 (5)
            0xe8, 0x83, 0xf5, 0xff, 0xff, // call (5)
            0x89, 0xc3, // mov ebx, eax (2)
            0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1 (5)
            0xe8, 0x7b, 0xf5, 0xff, 0xff, // call (5)
            0x01, 0xc3, // add eax, ebx (2)
        ];
        let mut addr = 0x400ed8u64;
        let mut p = 0usize;
        let mut lens = Vec::new();
        while p < bytes.len() {
            let info = decode(&bytes[p..], addr);
            lens.push(info.len);
            addr += info.len as u64;
            p += info.len as usize;
        }
        assert_eq!(lens, vec![1, 5, 5, 2, 5, 5, 2]);
    }

    #[test]
    fn short_branch_and_no_modrm_0f_lengths() {
        // 73 02 (jbe +2 over two nops): target = addr + 4, NOT addr + 5+<garbage>.
        let d = decode(&[0x73, 0x02, 0x90, 0x90], 0x1000);
        assert_eq!(d.len, 2);
        assert_eq!(d.flow, Flow::JumpCond(0x1004));
        // EB 0 (jmps over nothing): target = addr + 2 (the old 4-byte read
        // produced addr + 2 + rel, where rel included two following bytes).
        let d = decode(&[0xeb, 0x00, 0x55, 0x55], 0x2000);
        assert_eq!(d.len, 2);
        assert_eq!(d.flow, Flow::Jump(0x2002));
        // syscall (0f 05), rdtsc (0f 31), cpuid (0f a2), bswap eax (0f c8):
        // no ModRM byte — old table said 3+ bytes.
        for enc in [[0x0f, 0x05], [0x0f, 0x31], [0x0f, 0xa2], [0x0f, 0xc8]] {
            assert_eq!(decode(&enc, 0x3000).len, 2, "enc {enc:x?}");
        }
        // F6 test al, imm8 (f6 c0 55 = 3) vs NOT al (f6 d0 = 2, no imm).
        assert_eq!(decode(&[0xf6, 0xc0, 0x55], 0x4000).len, 3);
        assert_eq!(decode(&[0xf6, 0xd0], 0x4000).len, 2);
        // F7 test rax, imm32 (f7 c0 78 56 34 12 = 6) vs NOT rax (f7 d0 = 2).
        assert_eq!(
            decode(&[0xf7, 0xc0, 0x78, 0x56, 0x34, 0x12], 0x4000).len,
            6
        );
        assert_eq!(decode(&[0xf7, 0xd0], 0x4000).len, 2);
    }

    #[test]
    fn prefixed_memory_lengths() {
        // ENDBR64 (f3 0f 1e fa) = 4; mov rax,[rip+0x12345678] (48 8b 05
        // 78 56 34 12) = 7; lea rdi,[rip+disp32] (48 8d 3d ...) = 7. The
        // ModRM index bug decoded the prefixed memory form as 9+ bytes.
        let bytes = [
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0x48, 0x8b, 0x05, 0x78, 0x56, 0x34, 0x12, // mov rax,[rip+..]
            0x48, 0x8d, 0x3d, 0x7a, 0x04, 0x40, 0x00, // lea rdi,[rip+..]
        ];
        let info = decode(&bytes, 0x400380);
        assert_eq!(info.len, 4);
        let info = decode(&bytes[4..], 0x400384);
        assert_eq!(info.len, 7);
        let info = decode(&bytes[11..], 0x40038b);
        assert_eq!(info.len, 7);
    }

    #[test]
    fn conditional_fallthrough_discovers_call_target() {
        // jne +8 over the call; the call body is reachable only on the
        // non-taken edge (the dtors_aux shape).
        let mut code = vec![0x90u8; 0x100];
        // 0x00: jne +8 (skips 0x02..0x0a) -> target 0x0a
        code[0x00] = 0x75;
        code[0x01] = 0x08;
        // 0x02: call 0x20 (fall-through only)
        code[0x02] = 0xe8;
        code[0x03..0x07].copy_from_slice(&((0x20 - 0x07) as i32).to_le_bytes());
        // 0x0a: ret
        code[0x0a] = 0xc3;
        // 0x20: ret (the called function)
        code[0x20] = 0xc3;
        let maps = vec![(0x400000u64, code.len() as u64, 0u64, code.as_slice())];
        let d = discover(&maps, &[0x400000]);
        assert!(d.entries.contains(&0x400020), "fall-through call target discovered");
        assert!(d.calls.iter().any(|(f, t)| *f == 0x400002 && *t == 0x400020));
    }

    #[test]
    fn indirect_call_seeds_rdi_entry() {
        // _start convention: mov rdi, 0x4000a0; call [rip+0]
        let mut code = vec![0x90u8; 0x100];
        code[0x20] = 0x48;
        code[0x21] = 0xbf;
        code[0x22..0x2a].copy_from_slice(&0x4000a0u64.to_le_bytes());
        code[0x2a] = 0xff;
        code[0x2b] = 0x15;
        code[0x2c..0x30].copy_from_slice(&0i32.to_le_bytes());
        let maps = vec![(0x400000u64, code.len() as u64, 0u64, code.as_slice())];
        let d = discover(&maps, &[0x400020]);
        // The walk's seed is the start; the RDI imm64 before the indirect
        // call seeds the caller entry even though no direct call reaches it.
        assert_eq!(d.entries, vec![0x400020, 0x4000a0]);
    }
}
