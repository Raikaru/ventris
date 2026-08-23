use crate::{AccessKind, AddressFact, Evidence, EvidenceSource, MemoryAccess};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RuntimeEventKind {
    Memory {
        access: AccessKind,
        address: u64,
        width: u32,
        value: Option<u64>,
    },
    Call {
        target: u64,
    },
    Register {
        register: String,
        value: u64,
    },
    Marker {
        text: String,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuntimeEvent {
    pub sequence: u64,
    pub instruction: u64,
    pub kind: RuntimeEventKind,
}

impl RuntimeEvent {
    pub fn memory(
        sequence: u64,
        instruction: u64,
        access: AccessKind,
        address: u64,
        width: u32,
        value: Option<u64>,
    ) -> Self {
        Self {
            sequence,
            instruction,
            kind: RuntimeEventKind::Memory {
                access,
                address,
                width,
                value,
            },
        }
    }

    pub fn call(sequence: u64, instruction: u64, target: u64) -> Self {
        Self {
            sequence,
            instruction,
            kind: RuntimeEventKind::Call { target },
        }
    }

    pub fn register(
        sequence: u64,
        instruction: u64,
        register: impl Into<String>,
        value: u64,
    ) -> Self {
        Self {
            sequence,
            instruction,
            kind: RuntimeEventKind::Register {
                register: register.into(),
                value,
            },
        }
    }

    pub fn marker(sequence: u64, instruction: u64, text: impl Into<String>) -> Self {
        Self {
            sequence,
            instruction,
            kind: RuntimeEventKind::Marker { text: text.into() },
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuntimeCall {
    pub sequence: u64,
    pub instruction: u64,
    pub target: u64,
    pub evidence: Evidence,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuntimeRegisterWrite {
    pub sequence: u64,
    pub instruction: u64,
    pub register: String,
    pub value: u64,
    pub evidence: Evidence,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RuntimeMarker {
    pub sequence: u64,
    pub instruction: u64,
    pub text: String,
    pub evidence: Evidence,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RuntimeEvidence {
    pub memory: Vec<MemoryAccess>,
    pub calls: Vec<RuntimeCall>,
    pub registers: Vec<RuntimeRegisterWrite>,
    pub markers: Vec<RuntimeMarker>,
    pub evidence: Vec<Evidence>,
}

/// Normalize emulator callbacks into evidence-bearing observations without
/// treating a runtime value as a static type assertion. Repeated events stay
/// repeated: frequency and ordering are useful to later analyses.
pub fn ingest(events: &[RuntimeEvent]) -> RuntimeEvidence {
    let mut ordered = events.to_vec();
    ordered.sort_by_key(|event| event.sequence);
    let mut report = RuntimeEvidence::default();
    for event in ordered {
        match event.kind {
            RuntimeEventKind::Memory {
                access,
                address,
                width,
                value,
            } => {
                let evidence = Evidence {
                    source: EvidenceSource::EmulatorMemory {
                        sequence: event.sequence,
                        instruction: event.instruction,
                        access,
                        address,
                        width,
                        value,
                    },
                    confidence: crate::Confidence::new(95).unwrap(),
                };
                report.memory.push(MemoryAccess {
                    instruction: event.instruction,
                    kind: access,
                    width,
                    address: AddressFact::Absolute { address },
                    evidence: vec![evidence.clone()],
                });
                report.evidence.push(evidence);
            }
            RuntimeEventKind::Call { target } => {
                let evidence = Evidence {
                    source: EvidenceSource::EmulatorCall {
                        sequence: event.sequence,
                        instruction: event.instruction,
                        target,
                    },
                    confidence: crate::Confidence::new(90).unwrap(),
                };
                report.calls.push(RuntimeCall {
                    sequence: event.sequence,
                    instruction: event.instruction,
                    target,
                    evidence: evidence.clone(),
                });
                report.evidence.push(evidence);
            }
            RuntimeEventKind::Register { register, value } => {
                let evidence = Evidence {
                    source: EvidenceSource::EmulatorRegister {
                        sequence: event.sequence,
                        instruction: event.instruction,
                        register: register.clone(),
                        value,
                    },
                    confidence: crate::Confidence::new(85).unwrap(),
                };
                report.registers.push(RuntimeRegisterWrite {
                    sequence: event.sequence,
                    instruction: event.instruction,
                    register,
                    value,
                    evidence: evidence.clone(),
                });
                report.evidence.push(evidence);
            }
            RuntimeEventKind::Marker { text } => {
                let evidence = Evidence {
                    source: EvidenceSource::EmulatorMarker {
                        sequence: event.sequence,
                        instruction: event.instruction,
                        text: text.clone(),
                    },
                    confidence: crate::Confidence::new(80).unwrap(),
                };
                report.markers.push(RuntimeMarker {
                    sequence: event.sequence,
                    instruction: event.instruction,
                    text,
                    evidence: evidence.clone(),
                });
                report.evidence.push(evidence);
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingests_events_in_sequence_order_and_preserves_runtime_values() {
        let events = [
            RuntimeEvent::call(3, 0x100c, 0x2000),
            RuntimeEvent::memory(2, 0x1008, AccessKind::Write, 0x3000, 4, Some(0xfeed)),
            RuntimeEvent::memory(1, 0x1004, AccessKind::Read, 0x3000, 4, Some(0xbeef)),
            RuntimeEvent::register(4, 0x1010, "$v0", 7),
            RuntimeEvent::marker(5, 0x1014, "damage-applied"),
        ];
        let report = ingest(&events);
        assert_eq!(report.evidence.len(), 5);
        assert_eq!(report.memory[0].instruction, 0x1004);
        assert_eq!(report.memory[1].instruction, 0x1008);
        assert_eq!(report.calls[0].target, 0x2000);
        assert_eq!(report.registers[0].register, "$v0");
        assert_eq!(report.markers[0].text, "damage-applied");
        assert!(matches!(
            report.memory[0].evidence[0].source,
            EvidenceSource::EmulatorMemory {
                sequence: 1,
                value: Some(0xbeef),
                ..
            }
        ));
    }

    #[test]
    fn empty_trace_is_a_valid_empty_report() {
        assert_eq!(ingest(&[]), RuntimeEvidence::default());
    }
}
