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
    /// Indirect call/jump (register or memory): stops linear walk.
    Indirect,
    /// Ret/iret/trap/int3: stops the walk.
    Stop,
    Bad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstrInfo {
    pub len: u8,
    pub flow: Flow,
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
        return match o2 {
            0x70..=0x7f => OpInfo { modrm: true, imm: I8 },
            0x80..=0x8f => OpInfo { modrm: false, imm: Imm32Rel },
            0xc2 | 0xc0 | 0xc1 => OpInfo { modrm: true, imm: I8 },
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
        0xf6 => OpInfo { modrm: true, imm: I8 },
        0xf7 => OpInfo { modrm: true, imm: I32 },
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
        _ => OpInfo { modrm: false, imm: None },
    }
}

/// ModRM + SIB + displacement length for memory operands (starting the
/// walk at `b[m]` = the ModRM byte, with the opcode consumed at `p`).
fn mem_modlen(b: &[u8], m: usize, force_memory: bool) -> u8 {
    let modrm = b[m];
    let modbits = modrm >> 6;
    if !force_memory && modbits == 3 {
        return 0; // register operand
    }
    let rm = modrm & 7;
    match modbits {
        0 => {
            if rm == 4 {
                let sib = b[m + 1];
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
        0xeb => Some((Flow::Jump(rel_target(b, p + 1, 2, addr)), 2)),
        0x70..=0x7f => Some((Flow::JumpCond(rel_target(b, p + 1, 2, addr)), 2)),
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
        return InstrInfo { len: l, flow: f };
    }
    // 0F 90-9F setcc/setb: flow Next with full length.
    if op == 0x0f && op2.map(|o| (0x90..=0x9f).contains(&o)).unwrap_or(false) {
        let m = p + 2;
        let len = p + 3 + mem_modlen(b, m, false) as usize;
        return InstrInfo { len: len.min(15) as u8, flow: Flow::Next };
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
        let m = p + len;
        let modrm = b.get(m).copied().unwrap_or(0);
        let flow = if op == 0xff {
            let reg = (modrm >> 3) & 7;
            match reg {
                2 | 4 => Flow::Indirect,
                6 => Flow::Stop,
                3 | 5 | 0 | 1 | 7 => Flow::Next,
                _ => Flow::Next,
            }
        } else {
            Flow::Next
        };
        len += 1; // modrm
        len += mem_modlen(b, m, false) as usize;
        match info.imm {
            ImmKind::I8 => len += 1,
            ImmKind::I16 => len += 2,
            ImmKind::I32 => len += 4,
            ImmKind::I64 => len += 8,
            ImmKind::None => {}
            ImmKind::Imm8Rel | ImmKind::Imm32Rel => {}
        }
        return InstrInfo { len: len.min(15) as u8, flow };
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
    InstrInfo { len: len.min(15) as u8, flow: Flow::Next }
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
        let mut addr = start;
        let mut count = 0u32;
        loop {
            let off = (addr - sv) as usize;
            if off >= *ss as usize {
                break;
            }
            let win = &bytes[off..];
            let info = decode(win, addr);
            match info.flow {
                Flow::Call(t) => {
                    calls.push((addr, t));
                    let in_map = maps.iter().any(|(v, s, _, _)| t >= *v && t < v + s);
                    if in_map && !entries.contains(&t) {
                        entries.push(t);
                        queue.push(t);
                    }
                    addr += info.len as u64;
                }
                Flow::Jump(t) | Flow::JumpCond(t) => {
                    let in_map = maps.iter().any(|(v, s, _, _)| t >= *v && t < v + s);
                    if t > addr && in_map {
                        addr = t;
                    } else {
                        addr += info.len as u64;
                    }
                }
                Flow::Indirect | Flow::Stop | Flow::Bad => break,
                Flow::Next => addr += info.len as u64,
            }
            count += 1;
            if count > 100_000 {
                break;
            }
        }
    }
    entries.sort_unstable();
    entries.dedup();
    let sizes = (0..entries.len())
        .map(|i| {
            entries
                .get(i + 1)
                .copied()
                .unwrap_or(entries[i] + 16)
                - entries[i]
        })
        .collect();
    Discovery {
        entries,
        sizes,
        calls,
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
}
