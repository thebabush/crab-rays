use std::ffi::{c_int, c_void, CStr, CString};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};

use ida_sdk::loader::{
    LinputRef, LoaderT, QStrRef,
    ldr_set_proc, ldr_add_seg,
    ldr_add_entry, ldr_set_name, ldr_filename_cmt, ldr_patch_qword,
};

// ---------------------------------------------------------------------------
// SBF ELF e_machine values
// ---------------------------------------------------------------------------
const EM_SBF_V1: u16 = 0x00F7;
const EM_SBF_V2: u16 = 0x0107;

const FORMAT_NAME: &CStr = c"Solana SBF ELF";
const PROC_NAME:   &CStr = c"SBF";

// ---------------------------------------------------------------------------
// Exported loader descriptor
// ---------------------------------------------------------------------------
#[unsafe(no_mangle)]
pub static LDSC: LoaderT = LoaderT {
    version:         900,
    flags:           0,
    accept_file:     accept_file_cb,
    load_file:       load_file_cb,
    save_file:       std::ptr::null(),
    move_segm:       std::ptr::null(),
    process_archive: std::ptr::null(),
};

// ---------------------------------------------------------------------------
// accept_file callback
// ---------------------------------------------------------------------------

/// Pure ELF header check - no IDA dependency; used by tests.
///
/// Returns `true` if `header` (at least 20 bytes) looks like a 64-bit SBF ELF.
fn is_sbf_elf(header: &[u8]) -> bool {
    header.len() >= 20
        && header[0..4] == *b"\x7fELF"
        && header[4] == 2  // EI_CLASS = ELFCLASS64
        && {
            let e_machine = u16::from_le_bytes([header[18], header[19]]);
            e_machine == EM_SBF_V1 || e_machine == EM_SBF_V2
        }
}

unsafe extern "C" fn accept_file_cb(
    fileformatname: *mut c_void,
    processor:      *mut c_void,
    li:             *mut c_void,
    _filename:      *const std::ffi::c_char,
) -> c_int {
    let li = unsafe { LinputRef::from_raw(li) };
    let mut hdr = [0u8; 64];
    li.seek(0);
    if li.read(&mut hdr) < 64 { return 0; }
    if !is_sbf_elf(&hdr) { return 0; }

    unsafe { QStrRef::from_raw(fileformatname) }.set(FORMAT_NAME);
    unsafe { QStrRef::from_raw(processor) }.set(PROC_NAME);
    1
}

// ---------------------------------------------------------------------------
// load_file callback
// ---------------------------------------------------------------------------
unsafe extern "C" fn load_file_cb(
    li:        *mut c_void,
    _neflags:  u16,
    _fmt_name: *const std::ffi::c_char,
) {
    let li = unsafe { LinputRef::from_raw(li) };
    let file_size = li.size() as usize;
    let mut buf = vec![0u8; file_size];
    li.seek(0);
    li.read(&mut buf);

    let Ok(obj) = object::File::parse(buf.as_slice()) else { return };

    ldr_set_proc();

    // Create one IDA segment per allocated ELF section.
    // BSS-like sections have no file content (file_sz == 0) but still need a
    // covering segment so that symbols pointing into them are not orphaned.
    for section in obj.sections() {
        let addr = section.address();
        let size = section.size();
        if size == 0 || addr == 0 { continue; }

        let raw_name = section.name().unwrap_or("");
        let (sclass, fallback) = seg_class(section.kind());
        let seg_name = if raw_name.is_empty() { fallback } else { raw_name.trim_start_matches('.') };

        let Ok(cname)   = CString::new(seg_name) else { continue };
        let Ok(csclass) = CString::new(sclass)   else { continue };

        // Best-effort: skip sections IDA refuses to create (e.g. overlaps).
        let _ = ldr_add_seg(addr, addr + size, &cname, &csclass);

        // Only map file bytes for sections that actually have them.
        if let Some((file_off, file_sz)) = section.file_range() {
            if file_sz > 0 {
                li.file_to_base(file_off as i64, addr, addr + file_sz);
            }
        }
    }

    // Name symbols - chain both tables but skip exact duplicates (same address +
    // name can appear in both .symtab and .dynsym).
    let mut seen = std::collections::HashSet::new();
    for sym in obj.symbols().chain(obj.dynamic_symbols()) {
        let addr = sym.address();
        if addr == 0 { continue; }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() { continue; }
        if !seen.insert((addr, name)) { continue; }
        let Ok(cname) = CString::new(name) else { continue };

        // Best-effort: duplicate or invalid names are silently skipped.
        if sym.kind() == SymbolKind::Text {
            let _ = ldr_add_entry(addr, &cname);
        } else {
            let _ = ldr_set_name(addr, &cname);
        }
    }

    // Mark ELF entry point
    let entry = obj.entry();
    if entry != 0 {
        let _ = ldr_add_entry(entry, c"entry");
    }

    // Apply dynamic relocations
    apply_relocations(&obj, &buf);

    ldr_filename_cmt();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn seg_class(kind: SectionKind) -> (&'static str, &'static str) {
    match kind {
        SectionKind::Text                        => ("CODE",  "text"),
        SectionKind::Data | SectionKind::Tls     => ("DATA",  "data"),
        SectionKind::UninitializedData
        | SectionKind::UninitializedTls          => ("BSS",   "bss"),
        _                                        => ("CONST", "rodata"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- seg_class ---

    #[test]
    fn seg_class_text() {
        assert_eq!(seg_class(SectionKind::Text), ("CODE", "text"));
    }

    #[test]
    fn seg_class_data() {
        assert_eq!(seg_class(SectionKind::Data), ("DATA", "data"));
        assert_eq!(seg_class(SectionKind::Tls),  ("DATA", "data"));
    }

    #[test]
    fn seg_class_bss() {
        assert_eq!(seg_class(SectionKind::UninitializedData), ("BSS", "bss"));
        assert_eq!(seg_class(SectionKind::UninitializedTls),  ("BSS", "bss"));
    }

    #[test]
    fn seg_class_rodata_fallback() {
        // ReadOnlyData and other unrecognised kinds fall back to CONST/rodata.
        assert_eq!(seg_class(SectionKind::ReadOnlyData), ("CONST", "rodata"));
        assert_eq!(seg_class(SectionKind::Other),        ("CONST", "rodata"));
    }

    // --- parse_rel_entry ---

    #[test]
    fn parse_rel_entry_basic() {
        // r_offset = 0x1234_5678_9ABC_DEF0
        // r_sym    = 0x0000_0002  (bits 63:32 of r_info)
        // r_type   = 0x0000_0001  (bits 31:0  of r_info)
        let r_offset: u64 = 0x1234_5678_9ABC_DEF0;
        let r_info:   u64 = (2u64 << 32) | 1;
        let mut entry = [0u8; 16];
        entry[..8].copy_from_slice(&r_offset.to_le_bytes());
        entry[8..].copy_from_slice(&r_info.to_le_bytes());

        let (off, sym, ty) = parse_rel_entry(&entry);
        assert_eq!(off, 0x1234_5678_9ABC_DEF0);
        assert_eq!(sym, 2);
        assert_eq!(ty,  1);
    }

    #[test]
    fn parse_rel_entry_type8() {
        // r_type = 8 (R_BPF_64_RELATIVE), sym = 0
        let r_info: u64 = 8;
        let mut entry = [0u8; 16];
        entry[8..].copy_from_slice(&r_info.to_le_bytes());
        let (_, sym, ty) = parse_rel_entry(&entry);
        assert_eq!(sym, 0);
        assert_eq!(ty,  8);
    }

    #[test]
    fn parse_rel_entry_max_sym() {
        // sym index spanning the full high 32 bits
        let r_info: u64 = (0xFFFF_FFFFu64 << 32) | 1;
        let mut entry = [0u8; 16];
        entry[8..].copy_from_slice(&r_info.to_le_bytes());
        let (_, sym, ty) = parse_rel_entry(&entry);
        assert_eq!(sym, 0xFFFF_FFFF);
        assert_eq!(ty, 1);
    }

    // --- is_sbf_elf ---

    /// Build a 20-byte ELF-like header for testing is_sbf_elf.
    fn elf_header(class: u8, e_machine: u16) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0..4].copy_from_slice(b"\x7fELF");
        h[4] = class;       // EI_CLASS
        h[5] = 1;           // EI_DATA = ELFDATA2LSB
        h[6] = 1;           // EI_VERSION
        h[18..20].copy_from_slice(&e_machine.to_le_bytes());
        h
    }

    #[test]
    fn is_sbf_elf_v1_accepted() {
        let h = elf_header(2, EM_SBF_V1);
        assert!(is_sbf_elf(&h));
    }

    #[test]
    fn is_sbf_elf_v2_accepted() {
        let h = elf_header(2, EM_SBF_V2);
        assert!(is_sbf_elf(&h));
    }

    #[test]
    fn is_sbf_elf_32bit_rejected() {
        let h = elf_header(1, EM_SBF_V1); // ELFCLASS32
        assert!(!is_sbf_elf(&h));
    }

    #[test]
    fn is_sbf_elf_wrong_machine_rejected() {
        let h = elf_header(2, 0x0003); // EM_386
        assert!(!is_sbf_elf(&h));
    }

    #[test]
    fn is_sbf_elf_bad_magic_rejected() {
        let mut h = elf_header(2, EM_SBF_V1);
        h[0] = 0x00; // corrupt magic
        assert!(!is_sbf_elf(&h));
    }

    #[test]
    fn is_sbf_elf_short_header_rejected() {
        let h = elf_header(2, EM_SBF_V1);
        assert!(!is_sbf_elf(&h[..10])); // truncated
    }

    // --- va_to_file_offset ---

    /// Build a minimal ELF64 LE binary with one .text section at VA 0x1000,
    /// file offset 0x040, size 0x10.
    ///
    /// Layout:
    ///   [0x000..0x040]  ELF header
    ///   [0x040..0x050]  .text content (16 zero bytes)
    ///   [0x050..0x061]  .shstrtab: b"\0.text\0.shstrtab\0" (17 bytes)
    ///   [0x061..0x080]  padding
    ///   [0x080..0x0C0]  section header 0: null
    ///   [0x0C0..0x100]  section header 1: .text
    ///   [0x100..0x140]  section header 2: .shstrtab
    fn minimal_elf64() -> Vec<u8> {
        let mut buf = vec![0u8; 0x140];

        // ELF header
        buf[0x00..0x04].copy_from_slice(b"\x7fELF");
        buf[0x04] = 2;              // ELFCLASS64
        buf[0x05] = 1;              // ELFDATA2LSB
        buf[0x06] = 1;              // EV_CURRENT
        buf[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());        // e_type = ET_EXEC
        buf[0x12..0x14].copy_from_slice(&EM_SBF_V1.to_le_bytes());  // e_machine
        buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());        // e_version
        buf[0x18..0x20].copy_from_slice(&0x1000u64.to_le_bytes());   // e_entry
        // e_phoff = 0 (no program headers)
        buf[0x28..0x30].copy_from_slice(&0x080u64.to_le_bytes());    // e_shoff
        buf[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());       // e_ehsize
        buf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());       // e_phentsize
        // e_phnum = 0
        buf[0x3A..0x3C].copy_from_slice(&64u16.to_le_bytes());       // e_shentsize
        buf[0x3C..0x3E].copy_from_slice(&3u16.to_le_bytes());        // e_shnum
        buf[0x3E..0x40].copy_from_slice(&2u16.to_le_bytes());        // e_shstrndx = 2

        // .shstrtab at 0x050: "\0.text\0.shstrtab\0" (17 bytes)
        // Offsets: NUL=0, .text=1, .shstrtab=7
        let shstrtab = b"\0.text\0.shstrtab\0";
        buf[0x050..0x050 + shstrtab.len()].copy_from_slice(shstrtab);

        // Section header 1: .text  (at 0x0C0)
        let sh1 = 0x0C0;
        buf[sh1     ..sh1+4 ].copy_from_slice(&1u32.to_le_bytes());       // sh_name = 1
        buf[sh1+0x04..sh1+8 ].copy_from_slice(&1u32.to_le_bytes());       // sh_type = SHT_PROGBITS
        buf[sh1+0x08..sh1+16].copy_from_slice(&6u64.to_le_bytes());       // sh_flags = ALLOC|EXEC
        buf[sh1+0x10..sh1+24].copy_from_slice(&0x1000u64.to_le_bytes());  // sh_addr
        buf[sh1+0x18..sh1+32].copy_from_slice(&0x040u64.to_le_bytes());   // sh_offset
        buf[sh1+0x20..sh1+40].copy_from_slice(&0x10u64.to_le_bytes());    // sh_size
        buf[sh1+0x30..sh1+56].copy_from_slice(&1u64.to_le_bytes());       // sh_addralign

        // Section header 2: .shstrtab (at 0x100)
        let sh2 = 0x100;
        buf[sh2     ..sh2+4 ].copy_from_slice(&7u32.to_le_bytes());       // sh_name = 7
        buf[sh2+0x04..sh2+8 ].copy_from_slice(&3u32.to_le_bytes());       // sh_type = SHT_STRTAB
        buf[sh2+0x18..sh2+32].copy_from_slice(&0x050u64.to_le_bytes());   // sh_offset
        buf[sh2+0x20..sh2+40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes()); // sh_size
        buf[sh2+0x30..sh2+56].copy_from_slice(&1u64.to_le_bytes());       // sh_addralign

        buf
    }

    #[test]
    fn va_to_file_offset_hit() {
        let elf = minimal_elf64();
        let obj = object::File::parse(elf.as_slice()).unwrap();
        // VA 0x1000 is the start of .text; file offset should be 0x040.
        assert_eq!(va_to_file_offset(&obj, 0x1000), Some(0x040));
    }

    #[test]
    fn va_to_file_offset_mid_section() {
        let elf = minimal_elf64();
        let obj = object::File::parse(elf.as_slice()).unwrap();
        // VA 0x1005 is 5 bytes into .text; file offset = 0x040 + 5 = 0x045.
        assert_eq!(va_to_file_offset(&obj, 0x1005), Some(0x045));
    }

    #[test]
    fn va_to_file_offset_past_end() {
        let elf = minimal_elf64();
        let obj = object::File::parse(elf.as_slice()).unwrap();
        // VA 0x1010 is just past the end of .text (size 0x10); should be None.
        assert_eq!(va_to_file_offset(&obj, 0x1010), None);
    }

    #[test]
    fn va_to_file_offset_unmapped() {
        let elf = minimal_elf64();
        let obj = object::File::parse(elf.as_slice()).unwrap();
        // VA 0x2000 is nowhere in the file.
        assert_eq!(va_to_file_offset(&obj, 0x2000), None);
    }
}

// ---------------------------------------------------------------------------
// Relocation helpers
// ---------------------------------------------------------------------------

/// Map a virtual address to its file offset via section ranges.
pub(crate) fn va_to_file_offset(obj: &object::File<'_>, va: u64) -> Option<usize> {
    for section in obj.sections() {
        let start = section.address();
        let size  = section.size();
        if va >= start && va < start + size {
            let (file_off, _) = section.file_range()?;
            return Some((file_off + (va - start)) as usize);
        }
    }
    None
}

/// Decode a 16-byte SBF REL entry into `(r_offset, r_sym_idx, r_type)`.
///
/// The SBF relocation format stores:
/// - bytes  0..8: `r_offset` (little-endian u64)
/// - bytes  8..16: `r_info` (little-endian u64): high 32 bits = sym index,
///   low 32 bits = relocation type
fn parse_rel_entry(entry: &[u8]) -> (u64, usize, u32) {
    let r_offset = u64::from_le_bytes(entry[0..8].try_into().expect("chunks_exact(16) guarantees 16-byte entries"));
    let r_info   = u64::from_le_bytes(entry[8..16].try_into().expect("chunks_exact(16) guarantees 16-byte entries"));
    (r_offset, (r_info >> 32) as usize, r_info as u32)
}

/// Parse `.rel.dyn` and apply SBF relocations into the IDA database.
///
/// R_BPF_64_64  (type 1): patch_qword(r_offset, sym_value + implicit_addend)
/// R_BPF_64_RELATIVE (type 8): base = 0 in SBF, nothing to do
fn apply_relocations(obj: &object::File<'_>, buf: &[u8]) {
    // Build an indexed list of dynamic symbol addresses.
    let dynsyms: Vec<u64> = obj.dynamic_symbols().map(|s| s.address()).collect();

    let Some(rel_sec) = obj.section_by_name(".rel.dyn") else { return };
    let Some((file_off, file_sz)) = rel_sec.file_range() else { return };
    let rel_data = &buf[file_off as usize..(file_off + file_sz) as usize];

    // Each SBF REL entry: r_offset (8 bytes LE) + r_info (8 bytes LE)
    for entry in rel_data.chunks_exact(16) {
        let (r_offset, r_sym, r_type) = parse_rel_entry(entry);

        match r_type {
            1 => {
                // R_BPF_64_64: final = sym_value + implicit_addend_at_r_offset
                // object::dynamic_symbols() skips the ELF null symbol (index 0),
                // so ELF dynsym index N maps to dynsyms[N-1].
                let sym_value = r_sym.checked_sub(1)
                    .and_then(|i| dynsyms.get(i))
                    .copied()
                    .unwrap_or(0);
                let addend = va_to_file_offset(obj, r_offset)
                    .and_then(|off| buf.get(off..off + 8))
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                ldr_patch_qword(r_offset, sym_value.wrapping_add(addend));
            }
            8 => {} // R_BPF_64_RELATIVE: base = 0, no patch needed
            _ => {
                #[cfg(debug_assertions)]
                eprintln!("sbf loader: unhandled relocation type {r_type} at {r_offset:#x}");
            }
        }
    }
}
