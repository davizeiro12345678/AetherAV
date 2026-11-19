//! ELF parser - Linux/Unix executables and shared objects.
//!
//! Feature extraction mirrors the PE parser so the heuristic/ML layers stay
//! format-agnostic: per-section entropy, RWX segments (the ELF analogue of a
//! W^X violation), and the dynamic dependency list.

use crate::section::SectionInfo;
use aether_common::{ElfHeaderStatus, Error, Result};
use goblin::elf::Elf;

/// Classify the ELF header without reading tables or trusting file extensions.
pub fn inspect_header(data: &[u8]) -> Option<ElfHeaderStatus> {
    if !data.starts_with(b"\x7fELF") {
        return None;
    }
    if data.len() < 16 {
        return Some(ElfHeaderStatus::Truncated);
    }

    let (minimum_size, size_offset) = match data[4] {
        1 => (52, 40), // ELF32
        2 => (64, 52), // ELF64
        _ => return Some(ElfHeaderStatus::Invalid),
    };
    let little_endian = match data[5] {
        1 => true,
        2 => false,
        _ => return Some(ElfHeaderStatus::Invalid),
    };
    if data[6] != 1 {
        return Some(ElfHeaderStatus::Invalid);
    }
    if data.len() < minimum_size {
        return Some(ElfHeaderStatus::Truncated);
    }

    let size_bytes = [data[size_offset], data[size_offset + 1]];
    let version_bytes = [data[20], data[21], data[22], data[23]];
    let (declared_size, version) = if little_endian {
        (
            u16::from_le_bytes(size_bytes),
            u32::from_le_bytes(version_bytes),
        )
    } else {
        (
            u16::from_be_bytes(size_bytes),
            u32::from_be_bytes(version_bytes),
        )
    };
    let declared_size = usize::from(declared_size);
    Some(if version != 1 || declared_size < minimum_size {
        ElfHeaderStatus::Invalid
    } else if data.len() < declared_size {
        ElfHeaderStatus::Truncated
    } else {
        ElfHeaderStatus::Valid
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfArch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Riscv,
    Other(u16),
}

impl ElfArch {
    fn from_machine(m: u16) -> ElfArch {
        // values from elf.h EM_*
        match m {
            3 => ElfArch::X86,
            62 => ElfArch::X86_64,
            40 => ElfArch::Arm,
            183 => ElfArch::Aarch64,
            243 => ElfArch::Riscv,
            other => ElfArch::Other(other),
        }
    }
}

/// Scanner-relevant view of an ELF object.
#[derive(Debug, Clone)]
pub struct ElfInfo {
    pub arch: ElfArch,
    pub is_lib: bool,
    pub entry: u64,
    pub sections: Vec<SectionInfo>,
    pub libraries: Vec<String>,
    /// True if any PT_LOAD segment is simultaneously writable and executable.
    pub has_rwx_segment: bool,
    /// True if the binary is statically linked (no interpreter / dynamic libs).
    pub is_static: bool,
}

impl ElfInfo {
    pub fn parse(data: &[u8]) -> Result<ElfInfo> {
        let elf = Elf::parse(data).map_err(|e| Error::Parser(format!("ELF parse failed: {e}")))?;

        // Program-header flags: PF_X=1, PF_W=2, PF_R=4. PT_LOAD=1.
        const PT_LOAD: u32 = 1;
        const PF_X: u32 = 1;
        const PF_W: u32 = 2;
        let has_rwx_segment = elf
            .program_headers
            .iter()
            .any(|ph| ph.p_type == PT_LOAD && (ph.p_flags & PF_W != 0) && (ph.p_flags & PF_X != 0));

        // Section header flags: SHF_WRITE=0x1, SHF_EXECINSTR=0x4.
        const SHF_WRITE: u64 = 0x1;
        const SHF_EXEC: u64 = 0x4;
        let sections = elf
            .section_headers
            .iter()
            .map(|sh| {
                let name = elf
                    .shdr_strtab
                    .get_at(sh.sh_name)
                    .unwrap_or("<invalid>")
                    .to_string();
                SectionInfo::from_range(
                    name,
                    data,
                    sh.sh_offset as usize,
                    sh.sh_size as usize,
                    sh.sh_size,
                    sh.sh_flags & SHF_WRITE != 0,
                    sh.sh_flags & SHF_EXEC != 0,
                )
            })
            .collect();

        let libraries = elf.libraries.iter().map(|s| s.to_string()).collect();
        let is_static = elf.interpreter.is_none() && elf.libraries.is_empty();

        Ok(ElfInfo {
            arch: ElfArch::from_machine(elf.header.e_machine),
            is_lib: elf.is_lib,
            entry: elf.entry,
            sections,
            libraries,
            has_rwx_segment,
            is_static,
        })
    }

    pub fn max_section_entropy(&self) -> f64 {
        self.sections
            .iter()
            .map(|s| s.entropy)
            .fold(0.0_f64, f64::max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_elf32_and_elf64_in_both_byte_orders() {
        for (class, size, size_offset) in [(1, 52, 40), (2, 64, 52)] {
            for encoding in [1, 2] {
                let mut bytes = [0; 64];
                bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', class, encoding, 1]);
                if encoding == 1 {
                    bytes[20] = 1;
                    bytes[size_offset] = size as u8;
                } else {
                    bytes[23] = 1;
                    bytes[size_offset + 1] = size as u8;
                }
                assert_eq!(inspect_header(&bytes[..size]), Some(ElfHeaderStatus::Valid));
                assert_eq!(
                    inspect_header(&bytes[..size - 1]),
                    Some(ElfHeaderStatus::Truncated)
                );
                bytes[5] = 0;
                assert_eq!(
                    inspect_header(&bytes[..size]),
                    Some(ElfHeaderStatus::Invalid)
                );
            }
        }
    }

    #[test]
    fn distinguishes_non_elf_from_truncated_and_invalid_headers() {
        assert_eq!(inspect_header(b"text"), None);
        assert_eq!(inspect_header(b"\x7fELF"), Some(ElfHeaderStatus::Truncated));
        let mut bytes = [0; 64];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[20] = 1;
        bytes[52] = 63;
        assert_eq!(inspect_header(&bytes), Some(ElfHeaderStatus::Invalid));
        bytes[52] = 65;
        assert_eq!(inspect_header(&bytes), Some(ElfHeaderStatus::Truncated));
        bytes[52] = 64;
        bytes[20] = 0;
        assert_eq!(inspect_header(&bytes), Some(ElfHeaderStatus::Invalid));
    }

    #[test]
    fn rejects_non_elf() {
        assert!(matches!(
            ElfInfo::parse(b"MZ not elf"),
            Err(Error::Parser(_))
        ));
    }

    #[test]
    fn arch_mapping() {
        assert_eq!(ElfArch::from_machine(62), ElfArch::X86_64);
        assert_eq!(ElfArch::from_machine(183), ElfArch::Aarch64);
        assert!(matches!(ElfArch::from_machine(999), ElfArch::Other(999)));
    }
}
