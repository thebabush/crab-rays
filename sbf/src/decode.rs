//! Pure SBF instruction decoder - no IDA SDK dependency.
//!
//! [`decode`] takes raw 8-byte instruction words and returns a [`DecodedInsn`]
//! describing the instruction type and operands.  All IDA writeback lives in
//! `ana.rs`; this module contains only plain Rust.

// ---------------------------------------------------------------------------
// Itype - instruction type enum
// ---------------------------------------------------------------------------

/// SBF instruction itypes - one per mnemonic.
///
/// Must stay in sync with the `SBF_INSTRUC` table in `lph.rs`.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
pub enum Itype {
    // Legacy 64-bit load immediate (two words)
    LDDW = 0,
    // Load from memory
    LDXB, LDXH, LDXW, LDXDW,
    // Store immediate to memory
    STB, STH, STW, STDW,
    // Store register to memory
    STXB, STXH, STXW, STXDW,
    // 32-bit ALU
    ADD32, SUB32, MUL32, DIV32,
    OR32, AND32, LSH32, RSH32,
    NEG32, MOD32, XOR32, MOV32, ARSH32,
    LE, BE,
    // 64-bit ALU (MUL64/DIV64/NEG64/MOD64 removed: SBFv2 repurposed those opcodes)
    ADD64, SUB64,
    OR64, AND64, LSH64, RSH64,
    XOR64, MOV64, ARSH64,
    // Jumps (64-bit)
    JA,
    JEQ, JGT, JGE, JSET, JNE, JSGT, JSGE, JLT, JLE, JSLT, JSLE,
    // Jumps (32-bit)
    JA32,
    JEQ32, JGT32, JGE32, JSET32, JNE32, JSGT32, JSGE32, JLT32, JLE32, JSLT32, JSLE32,
    // Control
    CALL, CALLX, SYSCALL, EXIT,
    LAST,
}

impl TryFrom<u16> for Itype {
    type Error = ();
    /// Convert a raw IDA itype to `Itype`.
    ///
    /// Returns `Err(())` for any value ≥ `LAST` (unknown/foreign itype).
    ///
    /// # Safety
    /// Uses `transmute` which is sound because `Itype` is `#[repr(u16)]` with
    /// contiguous discriminants 0..LAST assigned by the compiler.
    fn try_from(v: u16) -> Result<Self, ()> {
        if v < Itype::LAST as u16 {
            // SAFETY: all values in 0..LAST are valid Itype discriminants.
            Ok(unsafe { std::mem::transmute::<u16, Itype>(v) })
        } else {
            Err(())
        }
    }
}

// ---------------------------------------------------------------------------
// Decoded operand representation
// ---------------------------------------------------------------------------

/// Operand data size.
///
/// Maps to IDA `dt_byte`/`dt_word`/`dt_dword`/`dt_qword` in `ana.rs`;
/// expressed here without any IDA SDK types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataSize {
    Byte,
    Word,
    Dword,
    Qword,
}

/// A fully described instruction operand without IDA SDK types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedOp {
    None,
    Reg   { reg: u8,             size: DataSize },
    Imm   { val: u64,            size: DataSize },
    Displ { base: u8, off: i16,  size: DataSize },
    Near  { target: u64 },
}

/// A fully decoded SBF instruction with no IDA SDK dependency.
#[derive(Clone, Copy, Debug)]
pub struct DecodedInsn {
    pub itype: Itype,
    pub ops:   [DecodedOp; 3],
}

// ---------------------------------------------------------------------------
// Opcode constants
// Taken verbatim from the Solana sbpf crate (anza-xyz/sbpf/src/ebpf.rs).
// We match on full 8-bit opcodes rather than decomposing class/op bits.
// ---------------------------------------------------------------------------

// Classes
const BPF_LD:          u8 = 0x00;
const BPF_LDX:         u8 = 0x01;
const BPF_ST:          u8 = 0x02;
const BPF_STX:         u8 = 0x03;
const BPF_ALU32_LOAD:  u8 = 0x04;
const BPF_JMP64:       u8 = 0x05;
const BPF_JMP32:       u8 = 0x06;
const BPF_ALU64_STORE: u8 = 0x07;

// Source modifier bits
const BPF_K: u8 = 0x00; // immediate
const BPF_X: u8 = 0x08; // register

// Legacy size modifiers (BPF_LD/LDX/ST/STX classes)
const BPF_W:  u8 = 0x00;
const BPF_H:  u8 = 0x08;
const BPF_B:  u8 = 0x10;
const BPF_DW: u8 = 0x18;

// New size modifiers (BPF_ALU32_LOAD / BPF_ALU64_STORE classes)
const BPF_1B: u8 = 0x20;
const BPF_2B: u8 = 0x30;
const BPF_4B: u8 = 0x80;
const BPF_8B: u8 = 0x90;

// Memory modes
const BPF_IMM: u8 = 0x00;
const BPF_MEM: u8 = 0x60;

// ALU operation codes (high 4 bits)
const BPF_ADD:  u8 = 0x00;
const BPF_SUB:  u8 = 0x10;
const BPF_MUL:  u8 = 0x20;
const BPF_DIV:  u8 = 0x30;
const BPF_OR:   u8 = 0x40;
const BPF_AND:  u8 = 0x50;
const BPF_LSH:  u8 = 0x60;
const BPF_RSH:  u8 = 0x70;
const BPF_NEG:  u8 = 0x80;
const BPF_MOD:  u8 = 0x90;
const BPF_XOR:  u8 = 0xa0;
const BPF_MOV:  u8 = 0xb0;
const BPF_ARSH: u8 = 0xc0;
const BPF_END:  u8 = 0xd0;

// JMP operation codes (high 4 bits)
const BPF_JA:   u8 = 0x00;
const BPF_JEQ:  u8 = 0x10;
const BPF_JGT:  u8 = 0x20;
const BPF_JGE:  u8 = 0x30;
const BPF_JSET: u8 = 0x40;
const BPF_JNE:  u8 = 0x50;
const BPF_JSGT: u8 = 0x60;
const BPF_JSGE: u8 = 0x70;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;
const BPF_JLT:  u8 = 0xa0;
const BPF_JLE:  u8 = 0xb0;
const BPF_JSLT: u8 = 0xc0;
const BPF_JSLE: u8 = 0xd0;

// Full opcodes - legacy LD/LDX/ST/STX
const LD_DW_IMM:  u8 = BPF_LD  | BPF_IMM | BPF_DW;  // 0x18  lddw dst, imm64 (2 words)
const LD_B_REG:   u8 = BPF_LDX | BPF_MEM | BPF_B;   // 0x71  ldxb
const LD_H_REG:   u8 = BPF_LDX | BPF_MEM | BPF_H;   // 0x69  ldxh
const LD_W_REG:   u8 = BPF_LDX | BPF_MEM | BPF_W;   // 0x61  ldxw
const LD_DW_REG:  u8 = BPF_LDX | BPF_MEM | BPF_DW;  // 0x79  ldxdw
const ST_B_IMM:   u8 = BPF_ST  | BPF_MEM | BPF_B;   // 0x72  stb  imm
const ST_H_IMM:   u8 = BPF_ST  | BPF_MEM | BPF_H;   // 0x6a  sth  imm
const ST_W_IMM:   u8 = BPF_ST  | BPF_MEM | BPF_W;   // 0x62  stw  imm
const ST_DW_IMM:  u8 = BPF_ST  | BPF_MEM | BPF_DW;  // 0x7a  stdw imm
const ST_B_REG:   u8 = BPF_STX | BPF_MEM | BPF_B;   // 0x73  stxb
const ST_H_REG:   u8 = BPF_STX | BPF_MEM | BPF_H;   // 0x6b  stxh
const ST_W_REG:   u8 = BPF_STX | BPF_MEM | BPF_W;   // 0x63  stxw
const ST_DW_REG:  u8 = BPF_STX | BPF_MEM | BPF_DW;  // 0x7b  stxdw

// Full opcodes - new memory (moved classes)
const LD_1B_REG:  u8 = BPF_ALU32_LOAD  | BPF_X | BPF_1B;  // 0x2c  ldxb
const LD_2B_REG:  u8 = BPF_ALU32_LOAD  | BPF_X | BPF_2B;  // 0x3c  ldxh
const LD_4B_REG:  u8 = BPF_ALU32_LOAD  | BPF_X | BPF_4B;  // 0x8c  ldxw
const LD_8B_REG:  u8 = BPF_ALU32_LOAD  | BPF_X | BPF_8B;  // 0x9c  ldxdw
const ST_1B_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_1B;  // 0x27  stb  imm
const ST_2B_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_2B;  // 0x37  sth  imm
const ST_4B_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_4B;  // 0x87  stw  imm
const ST_8B_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_8B;  // 0x97  stdw imm
const ST_1B_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_1B;  // 0x2f  stxb
const ST_2B_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_2B;  // 0x3f  stxh
const ST_4B_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_4B;  // 0x8f  stxw
const ST_8B_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_8B;  // 0x9f  stxdw

// Full opcodes - ALU32 (BPF_ALU32_LOAD class)
const ADD32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_ADD;
const ADD32_REG:  u8 = BPF_ALU32_LOAD | BPF_X | BPF_ADD;
const SUB32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_SUB;
const SUB32_REG:  u8 = BPF_ALU32_LOAD | BPF_X | BPF_SUB;
const MUL32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_MUL;
// MUL32_REG/DIV32_REG/MOD32_REG omitted: same opcode as LD_1B/2B/8B_REG in SBFv2
const DIV32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_DIV;
const OR32_IMM:   u8 = BPF_ALU32_LOAD | BPF_K | BPF_OR;
const OR32_REG:   u8 = BPF_ALU32_LOAD | BPF_X | BPF_OR;
const AND32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_AND;
const AND32_REG:  u8 = BPF_ALU32_LOAD | BPF_X | BPF_AND;
const LSH32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_LSH;
const LSH32_REG:  u8 = BPF_ALU32_LOAD | BPF_X | BPF_LSH;
const RSH32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_RSH;
const RSH32_REG:  u8 = BPF_ALU32_LOAD | BPF_X | BPF_RSH;
const NEG32:      u8 = BPF_ALU32_LOAD | BPF_K | BPF_NEG;
const MOD32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_MOD;
const XOR32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_XOR;
const XOR32_REG:  u8 = BPF_ALU32_LOAD | BPF_X | BPF_XOR;
const MOV32_IMM:  u8 = BPF_ALU32_LOAD | BPF_K | BPF_MOV;
const MOV32_REG:  u8 = BPF_ALU32_LOAD | BPF_X | BPF_MOV;
const ARSH32_IMM: u8 = BPF_ALU32_LOAD | BPF_K | BPF_ARSH;
const ARSH32_REG: u8 = BPF_ALU32_LOAD | BPF_X | BPF_ARSH;
const LE:         u8 = BPF_ALU32_LOAD | BPF_K | BPF_END;
const BE:         u8 = BPF_ALU32_LOAD | BPF_X | BPF_END;

// Full opcodes - ALU64 (BPF_ALU64_STORE class)
const ADD64_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_ADD;
const ADD64_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_ADD;
const SUB64_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_SUB;
const SUB64_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_SUB;
// MUL64/DIV64/NEG64/MOD64 opcodes are omitted: in SBFv2 their opcode slots
// (0x27/0x2f/0x37/0x3f/0x87/0x97/0x9f) are repurposed for the new memory
// encoding (ST_*B_IMM/REG above).  Those arms are unreachable dead code.
const OR64_IMM:   u8 = BPF_ALU64_STORE | BPF_K | BPF_OR;
const OR64_REG:   u8 = BPF_ALU64_STORE | BPF_X | BPF_OR;
const AND64_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_AND;
const AND64_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_AND;
const LSH64_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_LSH;
const LSH64_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_LSH;
const RSH64_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_RSH;
const RSH64_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_RSH;
const XOR64_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_XOR;
const XOR64_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_XOR;
const MOV64_IMM:  u8 = BPF_ALU64_STORE | BPF_K | BPF_MOV;
const MOV64_REG:  u8 = BPF_ALU64_STORE | BPF_X | BPF_MOV;
const ARSH64_IMM: u8 = BPF_ALU64_STORE | BPF_K | BPF_ARSH;
const ARSH64_REG: u8 = BPF_ALU64_STORE | BPF_X | BPF_ARSH;

// Full opcodes - JMP64
const JA64:       u8 = BPF_JMP64 | BPF_K | BPF_JA;
const JEQ64_IMM:  u8 = BPF_JMP64 | BPF_K | BPF_JEQ;
const JEQ64_REG:  u8 = BPF_JMP64 | BPF_X | BPF_JEQ;
const JGT64_IMM:  u8 = BPF_JMP64 | BPF_K | BPF_JGT;
const JGT64_REG:  u8 = BPF_JMP64 | BPF_X | BPF_JGT;
const JGE64_IMM:  u8 = BPF_JMP64 | BPF_K | BPF_JGE;
const JGE64_REG:  u8 = BPF_JMP64 | BPF_X | BPF_JGE;
const JSET64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSET;
const JSET64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSET;
const JNE64_IMM:  u8 = BPF_JMP64 | BPF_K | BPF_JNE;
const JNE64_REG:  u8 = BPF_JMP64 | BPF_X | BPF_JNE;
const JSGT64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSGT;
const JSGT64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSGT;
const JSGE64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSGE;
const JSGE64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSGE;
const CALL_IMM:   u8 = BPF_JMP64 | BPF_K | BPF_CALL;
const CALL_REG:   u8 = BPF_JMP64 | BPF_X | BPF_CALL;
const EXIT:       u8 = BPF_JMP64 | BPF_K | BPF_EXIT;
const JLT64_IMM:  u8 = BPF_JMP64 | BPF_K | BPF_JLT;
const JLT64_REG:  u8 = BPF_JMP64 | BPF_X | BPF_JLT;
const JLE64_IMM:  u8 = BPF_JMP64 | BPF_K | BPF_JLE;
const JLE64_REG:  u8 = BPF_JMP64 | BPF_X | BPF_JLE;
const JSLT64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSLT;
const JSLT64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSLT;
const JSLE64_IMM: u8 = BPF_JMP64 | BPF_K | BPF_JSLE;
const JSLE64_REG: u8 = BPF_JMP64 | BPF_X | BPF_JSLE;

// Full opcodes - JMP32
const JA32:       u8 = BPF_JMP32 | BPF_K | BPF_JA;
const JEQ32_IMM:  u8 = BPF_JMP32 | BPF_K | BPF_JEQ;
const JEQ32_REG:  u8 = BPF_JMP32 | BPF_X | BPF_JEQ;
const JGT32_IMM:  u8 = BPF_JMP32 | BPF_K | BPF_JGT;
const JGT32_REG:  u8 = BPF_JMP32 | BPF_X | BPF_JGT;
const JGE32_IMM:  u8 = BPF_JMP32 | BPF_K | BPF_JGE;
const JGE32_REG:  u8 = BPF_JMP32 | BPF_X | BPF_JGE;
const JSET32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSET;
const JSET32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSET;
const JNE32_IMM:  u8 = BPF_JMP32 | BPF_K | BPF_JNE;
const JNE32_REG:  u8 = BPF_JMP32 | BPF_X | BPF_JNE;
const JSGT32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSGT;
const JSGT32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSGT;
const JSGE32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSGE;
const JSGE32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSGE;
const JLT32_IMM:  u8 = BPF_JMP32 | BPF_K | BPF_JLT;
const JLT32_REG:  u8 = BPF_JMP32 | BPF_X | BPF_JLT;
const JLE32_IMM:  u8 = BPF_JMP32 | BPF_K | BPF_JLE;
const JLE32_REG:  u8 = BPF_JMP32 | BPF_X | BPF_JLE;
const JSLT32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSLT;
const JSLT32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSLT;
const JSLE32_IMM: u8 = BPF_JMP32 | BPF_K | BPF_JSLE;
const JSLE32_REG: u8 = BPF_JMP32 | BPF_X | BPF_JSLE;

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/// True for the lddw opcode, which consumes two consecutive 8-byte words.
pub fn is_two_word(opc: u8) -> bool {
    opc == LD_DW_IMM
}

/// Branch target address: next instruction address + `off` * 8 bytes.
///
/// Matches sbpf: `target_pc = ptr + off + 1` (in instruction units)
/// → `ea + 8 + off * 8`.
pub fn branch_target(ea: u64, off: i16) -> u64 {
    ea.wrapping_add(8).wrapping_add((off as i64 * 8) as u64)
}

impl Itype {
    pub fn is_cond_jump(self) -> bool {
        match self {
            Itype::JEQ   | Itype::JGT   | Itype::JGE   | Itype::JSET  | Itype::JNE  |
            Itype::JSGT  | Itype::JSGE  | Itype::JLT   | Itype::JLE   | Itype::JSLT | Itype::JSLE |
            Itype::JEQ32 | Itype::JGT32 | Itype::JGE32 | Itype::JSET32| Itype::JNE32 |
            Itype::JSGT32| Itype::JSGE32| Itype::JLT32 | Itype::JLE32 | Itype::JSLT32| Itype::JSLE32
                => true,
            Itype::LDDW |
            Itype::LDXB  | Itype::LDXH  | Itype::LDXW  | Itype::LDXDW |
            Itype::STB   | Itype::STH   | Itype::STW   | Itype::STDW  |
            Itype::STXB  | Itype::STXH  | Itype::STXW  | Itype::STXDW |
            Itype::ADD32 | Itype::SUB32 | Itype::MUL32 | Itype::DIV32 |
            Itype::OR32  | Itype::AND32 | Itype::LSH32 | Itype::RSH32 |
            Itype::NEG32 | Itype::MOD32 | Itype::XOR32 | Itype::MOV32 | Itype::ARSH32 |
            Itype::LE    | Itype::BE    |
            Itype::ADD64 | Itype::SUB64 |
            Itype::OR64  | Itype::AND64 | Itype::LSH64 | Itype::RSH64 |
            Itype::XOR64 | Itype::MOV64 | Itype::ARSH64 |
            Itype::JA    | Itype::JA32  |
            Itype::CALL  | Itype::CALLX | Itype::SYSCALL | Itype::EXIT |
            Itype::LAST
                => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Main decoder
// ---------------------------------------------------------------------------

/// Decode a raw SBF instruction.
///
/// * `raw1` - first (and usually only) 8-byte instruction word.
/// * `raw2` - second word; only meaningful when [`is_two_word`] returns true
///   for the opcode; pass `0` otherwise.
/// * `ea`   - instruction address, used for branch-target calculation.
///
/// Returns `None` for unrecognised opcodes.
pub fn decode(raw1: u64, raw2: u64, ea: u64) -> Option<DecodedInsn> {
    use DataSize::{Byte, Word, Dword, Qword};

    let opc = (raw1        & 0xFF) as u8;
    let dst = ((raw1 >> 8) & 0x0F) as u8;
    let src = ((raw1 >> 12)& 0x0F) as u8;
    let off = (raw1 >> 16) as i16;
    // imm is a signed 32-bit field, sign-extended to i64 per sbpf convention
    let imm = (raw1 >> 32) as i32 as i64;

    // Local builder helpers - keep match arms compact.
    let r  = |reg:  u8,            size: DataSize| DecodedOp::Reg   { reg, size };
    let im = |val:  u64,           size: DataSize| DecodedOp::Imm   { val, size };
    let dp = |base: u8, off: i16,  size: DataSize| DecodedOp::Displ { base, off, size };
    let nr = |target: u64|                         DecodedOp::Near  { target };
    const NO: DecodedOp = DecodedOp::None;

    macro_rules! ins {
        ($it:expr, $op0:expr, $op1:expr, $op2:expr) => {
            Some(DecodedInsn { itype: $it, ops: [$op0, $op1, $op2] })
        };
    }

    match opc {
        // ── legacy 64-bit load immediate (two 8-byte words) ─────────────────
        LD_DW_IMM => {
            let imm2 = (raw2 >> 32) as u32;
            let full = ((imm2 as u64) << 32) | (imm as u32 as u64);
            ins!(Itype::LDDW, r(dst, Qword), im(full, Qword), NO)
        }

        // ── legacy LDX (class 0x01) ──────────────────────────────────────────
        LD_B_REG  => ins!(Itype::LDXB,  r(dst, Byte),  dp(src, off, Byte),  NO),
        LD_H_REG  => ins!(Itype::LDXH,  r(dst, Word),  dp(src, off, Word),  NO),
        LD_W_REG  => ins!(Itype::LDXW,  r(dst, Dword), dp(src, off, Dword), NO),
        LD_DW_REG => ins!(Itype::LDXDW, r(dst, Qword), dp(src, off, Qword), NO),

        // ── legacy ST imm (class 0x02) ───────────────────────────────────────
        ST_B_IMM  => ins!(Itype::STB,  dp(dst, off, Byte),  im(imm as u64, Byte),  NO),
        ST_H_IMM  => ins!(Itype::STH,  dp(dst, off, Word),  im(imm as u64, Word),  NO),
        ST_W_IMM  => ins!(Itype::STW,  dp(dst, off, Dword), im(imm as u64, Dword), NO),
        ST_DW_IMM => ins!(Itype::STDW, dp(dst, off, Qword), im(imm as u64, Qword), NO),

        // ── legacy STX reg (class 0x03) ──────────────────────────────────────
        ST_B_REG  => ins!(Itype::STXB,  dp(dst, off, Byte),  r(src, Byte),  NO),
        ST_H_REG  => ins!(Itype::STXH,  dp(dst, off, Word),  r(src, Word),  NO),
        ST_W_REG  => ins!(Itype::STXW,  dp(dst, off, Dword), r(src, Dword), NO),
        ST_DW_REG => ins!(Itype::STXDW, dp(dst, off, Qword), r(src, Qword), NO),

        // ── new LDX (class 0x04 with new size bits) ──────────────────────────
        LD_1B_REG => ins!(Itype::LDXB,  r(dst, Byte),  dp(src, off, Byte),  NO),
        LD_2B_REG => ins!(Itype::LDXH,  r(dst, Word),  dp(src, off, Word),  NO),
        LD_4B_REG => ins!(Itype::LDXW,  r(dst, Dword), dp(src, off, Dword), NO),
        LD_8B_REG => ins!(Itype::LDXDW, r(dst, Qword), dp(src, off, Qword), NO),

        // ── new ST imm (class 0x07 with new size bits) ───────────────────────
        ST_1B_IMM => ins!(Itype::STB,  dp(dst, off, Byte),  im(imm as u64, Byte),  NO),
        ST_2B_IMM => ins!(Itype::STH,  dp(dst, off, Word),  im(imm as u64, Word),  NO),
        ST_4B_IMM => ins!(Itype::STW,  dp(dst, off, Dword), im(imm as u64, Dword), NO),
        ST_8B_IMM => ins!(Itype::STDW, dp(dst, off, Qword), im(imm as u64, Qword), NO),

        // ── new STX reg (class 0x07 with new size bits) ──────────────────────
        ST_1B_REG => ins!(Itype::STXB,  dp(dst, off, Byte),  r(src, Byte),  NO),
        ST_2B_REG => ins!(Itype::STXH,  dp(dst, off, Word),  r(src, Word),  NO),
        ST_4B_REG => ins!(Itype::STXW,  dp(dst, off, Dword), r(src, Dword), NO),
        ST_8B_REG => ins!(Itype::STXDW, dp(dst, off, Qword), r(src, Qword), NO),

        // ── ALU32 ─────────────────────────────────────────────────────────────
        ADD32_IMM  => ins!(Itype::ADD32,  r(dst, Dword), im(imm as u64, Dword), NO),
        ADD32_REG  => ins!(Itype::ADD32,  r(dst, Dword), r(src, Dword),         NO),
        SUB32_IMM  => ins!(Itype::SUB32,  r(dst, Dword), im(imm as u64, Dword), NO),
        SUB32_REG  => ins!(Itype::SUB32,  r(dst, Dword), r(src, Dword),         NO),
        MUL32_IMM  => ins!(Itype::MUL32,  r(dst, Dword), im(imm as u64, Dword), NO),
        DIV32_IMM  => ins!(Itype::DIV32,  r(dst, Dword), im(imm as u64, Dword), NO),
        OR32_IMM   => ins!(Itype::OR32,   r(dst, Dword), im(imm as u64, Dword), NO),
        OR32_REG   => ins!(Itype::OR32,   r(dst, Dword), r(src, Dword),         NO),
        AND32_IMM  => ins!(Itype::AND32,  r(dst, Dword), im(imm as u64, Dword), NO),
        AND32_REG  => ins!(Itype::AND32,  r(dst, Dword), r(src, Dword),         NO),
        LSH32_IMM  => ins!(Itype::LSH32,  r(dst, Dword), im(imm as u64, Dword), NO),
        LSH32_REG  => ins!(Itype::LSH32,  r(dst, Dword), r(src, Dword),         NO),
        RSH32_IMM  => ins!(Itype::RSH32,  r(dst, Dword), im(imm as u64, Dword), NO),
        RSH32_REG  => ins!(Itype::RSH32,  r(dst, Dword), r(src, Dword),         NO),
        NEG32      => ins!(Itype::NEG32,  r(dst, Dword), NO,                    NO),
        MOD32_IMM  => ins!(Itype::MOD32,  r(dst, Dword), im(imm as u64, Dword), NO),
        XOR32_IMM  => ins!(Itype::XOR32,  r(dst, Dword), im(imm as u64, Dword), NO),
        XOR32_REG  => ins!(Itype::XOR32,  r(dst, Dword), r(src, Dword),         NO),
        MOV32_IMM  => ins!(Itype::MOV32,  r(dst, Dword), im(imm as u64, Dword), NO),
        MOV32_REG  => ins!(Itype::MOV32,  r(dst, Dword), r(src, Dword),         NO),
        ARSH32_IMM => ins!(Itype::ARSH32, r(dst, Dword), im(imm as u64, Dword), NO),
        ARSH32_REG => ins!(Itype::ARSH32, r(dst, Dword), r(src, Dword),         NO),
        LE         => ins!(Itype::LE,     r(dst, Dword), im(imm as u64, Dword), NO),
        BE         => ins!(Itype::BE,     r(dst, Dword), im(imm as u64, Dword), NO),

        // ── ALU64 ─────────────────────────────────────────────────────────────
        ADD64_IMM  => ins!(Itype::ADD64,  r(dst, Qword), im(imm as u64, Qword), NO),
        ADD64_REG  => ins!(Itype::ADD64,  r(dst, Qword), r(src, Qword),         NO),
        SUB64_IMM  => ins!(Itype::SUB64,  r(dst, Qword), im(imm as u64, Qword), NO),
        SUB64_REG  => ins!(Itype::SUB64,  r(dst, Qword), r(src, Qword),         NO),
        // MUL64/DIV64/NEG64/MOD64 removed: opcode slots repurposed for new memory
        // encoding in SBFv2 (matched above as ST_*B_IMM/REG).
        OR64_IMM   => ins!(Itype::OR64,   r(dst, Qword), im(imm as u64, Qword), NO),
        OR64_REG   => ins!(Itype::OR64,   r(dst, Qword), r(src, Qword),         NO),
        AND64_IMM  => ins!(Itype::AND64,  r(dst, Qword), im(imm as u64, Qword), NO),
        AND64_REG  => ins!(Itype::AND64,  r(dst, Qword), r(src, Qword),         NO),
        LSH64_IMM  => ins!(Itype::LSH64,  r(dst, Qword), im(imm as u64, Qword), NO),
        LSH64_REG  => ins!(Itype::LSH64,  r(dst, Qword), r(src, Qword),         NO),
        RSH64_IMM  => ins!(Itype::RSH64,  r(dst, Qword), im(imm as u64, Qword), NO),
        RSH64_REG  => ins!(Itype::RSH64,  r(dst, Qword), r(src, Qword),         NO),
        XOR64_IMM  => ins!(Itype::XOR64,  r(dst, Qword), im(imm as u64, Qword), NO),
        XOR64_REG  => ins!(Itype::XOR64,  r(dst, Qword), r(src, Qword),         NO),
        MOV64_IMM  => ins!(Itype::MOV64,  r(dst, Qword), im(imm as u64, Qword), NO),
        MOV64_REG  => ins!(Itype::MOV64,  r(dst, Qword), r(src, Qword),         NO),
        ARSH64_IMM => ins!(Itype::ARSH64, r(dst, Qword), im(imm as u64, Qword), NO),
        ARSH64_REG => ins!(Itype::ARSH64, r(dst, Qword), r(src, Qword),         NO),

        // ── JMP64 ─────────────────────────────────────────────────────────────
        JA64 => ins!(Itype::JA, nr(branch_target(ea, off)), NO, NO),

        JEQ64_IMM  => ins!(Itype::JEQ,  r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JEQ64_REG  => ins!(Itype::JEQ,  r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JGT64_IMM  => ins!(Itype::JGT,  r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JGT64_REG  => ins!(Itype::JGT,  r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JGE64_IMM  => ins!(Itype::JGE,  r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JGE64_REG  => ins!(Itype::JGE,  r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JSET64_IMM => ins!(Itype::JSET, r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSET64_REG => ins!(Itype::JSET, r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JNE64_IMM  => ins!(Itype::JNE,  r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JNE64_REG  => ins!(Itype::JNE,  r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JSGT64_IMM => ins!(Itype::JSGT, r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSGT64_REG => ins!(Itype::JSGT, r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JSGE64_IMM => ins!(Itype::JSGE, r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSGE64_REG => ins!(Itype::JSGE, r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JLT64_IMM  => ins!(Itype::JLT,  r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JLT64_REG  => ins!(Itype::JLT,  r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JLE64_IMM  => ins!(Itype::JLE,  r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JLE64_REG  => ins!(Itype::JLE,  r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JSLT64_IMM => ins!(Itype::JSLT, r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSLT64_REG => ins!(Itype::JSLT, r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),
        JSLE64_IMM => ins!(Itype::JSLE, r(dst, Qword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSLE64_REG => ins!(Itype::JSLE, r(dst, Qword), r(src, Qword),         nr(branch_target(ea, off))),

        // CALL_IMM: src==0 → syscall (builtin); src!=0 → PC-relative local call
        CALL_IMM => {
            if src == 0 {
                // Syscall: the hash is a u32 bit pattern; store zero-extended so
                // that op.value() yields the same bit pattern without sign extension.
                ins!(Itype::SYSCALL, im(imm as u32 as u64, Dword), NO, NO)
            } else {
                // Local call: target = (ea + 8) + imm * 8
                let target = ea.wrapping_add(8).wrapping_add((imm * 8) as u64);
                ins!(Itype::CALL, nr(target), NO, NO)
            }
        }

        // CALL_REG: indirect call through register
        CALL_REG => ins!(Itype::CALLX, r(src, Qword), NO, NO),

        EXIT => ins!(Itype::EXIT, NO, NO, NO),

        // ── JMP32 ─────────────────────────────────────────────────────────────
        JA32 => ins!(Itype::JA32, nr(branch_target(ea, off)), NO, NO),

        JEQ32_IMM  => ins!(Itype::JEQ32,  r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JEQ32_REG  => ins!(Itype::JEQ32,  r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JGT32_IMM  => ins!(Itype::JGT32,  r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JGT32_REG  => ins!(Itype::JGT32,  r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JGE32_IMM  => ins!(Itype::JGE32,  r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JGE32_REG  => ins!(Itype::JGE32,  r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JSET32_IMM => ins!(Itype::JSET32, r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSET32_REG => ins!(Itype::JSET32, r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JNE32_IMM  => ins!(Itype::JNE32,  r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JNE32_REG  => ins!(Itype::JNE32,  r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JSGT32_IMM => ins!(Itype::JSGT32, r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSGT32_REG => ins!(Itype::JSGT32, r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JSGE32_IMM => ins!(Itype::JSGE32, r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSGE32_REG => ins!(Itype::JSGE32, r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JLT32_IMM  => ins!(Itype::JLT32,  r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JLT32_REG  => ins!(Itype::JLT32,  r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JLE32_IMM  => ins!(Itype::JLE32,  r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JLE32_REG  => ins!(Itype::JLE32,  r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JSLT32_IMM => ins!(Itype::JSLT32, r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSLT32_REG => ins!(Itype::JSLT32, r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),
        JSLE32_IMM => ins!(Itype::JSLE32, r(dst, Dword), im(imm as u64, Dword), nr(branch_target(ea, off))),
        JSLE32_REG => ins!(Itype::JSLE32, r(dst, Dword), r(src, Dword),         nr(branch_target(ea, off))),

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use DataSize::{Byte, Dword, Qword, Word};

    fn raw(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
        (opc as u64)
            | ((dst as u64 & 0xF) << 8)
            | ((src as u64 & 0xF) << 12)
            | ((off as u16 as u64) << 16)
            | ((imm as u32 as u64) << 32)
    }

    #[test]
    fn branch_target_fwd() {
        // ea=0x1000, off=3 → 0x1000 + 8 + 3*8 = 0x1030
        assert_eq!(branch_target(0x1000, 3), 0x1030);
    }

    #[test]
    fn branch_target_back() {
        // ea=0x1000, off=-2 → 0x1000 + 8 - 16 = 0xFF8
        assert_eq!(branch_target(0x1000, -2), 0xFF8);
    }

    #[test]
    fn decode_add64_imm() {
        let r = raw(ADD64_IMM, 1, 0, 0, 42);
        let d = decode(r, 0, 0x1000).unwrap();
        assert_eq!(d.itype, Itype::ADD64);
        assert_eq!(d.ops[0], DecodedOp::Reg { reg: 1, size: Qword });
        assert_eq!(d.ops[1], DecodedOp::Imm { val: 42, size: Qword });
        assert_eq!(d.ops[2], DecodedOp::None);
    }

    #[test]
    fn decode_add32_reg() {
        let r = raw(ADD32_REG, 2, 3, 0, 0);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::ADD32);
        assert_eq!(d.ops[0], DecodedOp::Reg { reg: 2, size: Dword });
        assert_eq!(d.ops[1], DecodedOp::Reg { reg: 3, size: Dword });
    }

    #[test]
    fn decode_ldxb() {
        // ldxb dst=r1, [r2 + 4]
        let r = raw(LD_B_REG, 1, 2, 4, 0);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::LDXB);
        assert_eq!(d.ops[0], DecodedOp::Reg   { reg: 1, size: Byte });
        assert_eq!(d.ops[1], DecodedOp::Displ { base: 2, off: 4, size: Byte });
    }

    #[test]
    fn decode_stw_imm() {
        // stw [r3 + 8], 99
        let r = raw(ST_W_IMM, 3, 0, 8, 99);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::STW);
        assert_eq!(d.ops[0], DecodedOp::Displ { base: 3, off: 8, size: Dword });
        assert_eq!(d.ops[1], DecodedOp::Imm   { val: 99, size: Dword });
    }

    #[test]
    fn decode_stxh_reg() {
        // stxh [r4 - 2], r5
        let r = raw(ST_H_REG, 4, 5, -2, 0);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::STXH);
        assert_eq!(d.ops[0], DecodedOp::Displ { base: 4, off: -2, size: Word });
        assert_eq!(d.ops[1], DecodedOp::Reg   { reg: 5, size: Word });
    }

    #[test]
    fn decode_ja64() {
        let r = raw(JA64, 0, 0, 5, 0);
        let d = decode(r, 0, 0x2000).unwrap();
        assert_eq!(d.itype, Itype::JA);
        assert_eq!(d.ops[0], DecodedOp::Near { target: branch_target(0x2000, 5) });
    }

    #[test]
    fn decode_jeq64_imm() {
        let r = raw(JEQ64_IMM, 1, 0, 3, 7);
        let d = decode(r, 0, 0x1000).unwrap();
        assert_eq!(d.itype, Itype::JEQ);
        assert_eq!(d.ops[0], DecodedOp::Reg  { reg: 1, size: Qword });
        assert_eq!(d.ops[1], DecodedOp::Imm  { val: 7, size: Dword });
        assert_eq!(d.ops[2], DecodedOp::Near { target: branch_target(0x1000, 3) });
    }

    #[test]
    fn decode_syscall() {
        // CALL_IMM with src=0 → syscall
        let r = raw(CALL_IMM, 0, 0, 0, 0xDEAD);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::SYSCALL);
        assert_eq!(d.ops[0], DecodedOp::Imm { val: 0xDEAD, size: Dword });
    }

    #[test]
    fn decode_call_local() {
        // CALL_IMM with src=1 → local call; ea=0x1000, imm=2 → target=0x1000+8+16=0x1018
        let r = raw(CALL_IMM, 0, 1, 0, 2);
        let d = decode(r, 0, 0x1000).unwrap();
        assert_eq!(d.itype, Itype::CALL);
        assert_eq!(d.ops[0], DecodedOp::Near { target: 0x1018 });
    }

    #[test]
    fn decode_callx() {
        let r = raw(CALL_REG, 0, 3, 0, 0);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::CALLX);
        assert_eq!(d.ops[0], DecodedOp::Reg { reg: 3, size: Qword });
    }

    #[test]
    fn decode_exit() {
        let r = raw(EXIT, 0, 0, 0, 0);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::EXIT);
        assert_eq!(d.ops, [DecodedOp::None; 3]);
    }

    #[test]
    fn decode_lddw() {
        // lddw r1, 0xDEADBEEF_CAFEBABE
        let raw1 = raw(LD_DW_IMM, 1, 0, 0, 0xCAFEBABEu32 as i32);
        let raw2 = (0xDEADBEEFu64) << 32;
        let d = decode(raw1, raw2, 0).unwrap();
        assert_eq!(d.itype, Itype::LDDW);
        assert_eq!(d.ops[0], DecodedOp::Reg { reg: 1, size: Qword });
        assert_eq!(d.ops[1], DecodedOp::Imm { val: 0xDEADBEEF_CAFEBABE, size: Qword });
    }

    #[test]
    fn decode_unknown_opcode() {
        // 0xFF is not a valid SBF opcode
        assert!(decode(0xFF, 0, 0).is_none());
    }

    #[test]
    fn is_two_word_only_lddw() {
        assert!(is_two_word(LD_DW_IMM));
        assert!(!is_two_word(ADD64_IMM));
        assert!(!is_two_word(EXIT));
    }

    #[test]
    fn is_cond_jump_coverage() {
        assert!(Itype::JEQ.is_cond_jump());
        assert!(Itype::JSLE32.is_cond_jump());
        assert!(!Itype::JA.is_cond_jump());
        assert!(!Itype::CALL.is_cond_jump());
        assert!(!Itype::EXIT.is_cond_jump());
    }

    // All eleven 64-bit and eleven 32-bit conditional jump itypes must be
    // recognised by is_cond_jump; none of the non-conditional types should be.
    #[test]
    fn all_cond_jumps_recognized() {
        let conds = [
            Itype::JEQ,  Itype::JGT,  Itype::JGE,  Itype::JSET, Itype::JNE,
            Itype::JSGT, Itype::JSGE, Itype::JLT,  Itype::JLE,  Itype::JSLT, Itype::JSLE,
            Itype::JEQ32,  Itype::JGT32,  Itype::JGE32,  Itype::JSET32, Itype::JNE32,
            Itype::JSGT32, Itype::JSGE32, Itype::JLT32,  Itype::JLE32,  Itype::JSLT32, Itype::JSLE32,
        ];
        for it in conds { assert!(it.is_cond_jump(), "{it:?} should be cond jump"); }

        let non_conds = [Itype::JA, Itype::JA32, Itype::CALL, Itype::CALLX, Itype::SYSCALL, Itype::EXIT];
        for it in non_conds { assert!(!it.is_cond_jump(), "{it:?} should not be cond jump"); }
    }

    #[test]
    fn decode_neg32() {
        // neg32 r2 - unary: only op0, no op1
        let r = raw(NEG32, 2, 0, 0, 0);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::NEG32);
        assert_eq!(d.ops[0], DecodedOp::Reg { reg: 2, size: Dword });
        assert_eq!(d.ops[1], DecodedOp::None);
        assert_eq!(d.ops[2], DecodedOp::None);
    }

    #[test]
    fn decode_new_style_ldxb() {
        // LD_1B_REG: same semantics as LD_B_REG but different opcode
        let r = raw(LD_1B_REG, 1, 2, 4, 0);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::LDXB);
        assert_eq!(d.ops[0], DecodedOp::Reg   { reg: 1, size: Byte });
        assert_eq!(d.ops[1], DecodedOp::Displ { base: 2, off: 4, size: Byte });
    }

    #[test]
    fn decode_new_style_stxdw() {
        // ST_8B_REG: new-style stxdw [r4 + 0], r6
        let r = raw(ST_8B_REG, 4, 6, 0, 0);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::STXDW);
        assert_eq!(d.ops[0], DecodedOp::Displ { base: 4, off: 0, size: Qword });
        assert_eq!(d.ops[1], DecodedOp::Reg   { reg: 6, size: Qword });
    }

    #[test]
    fn decode_mov64_reg() {
        let r = raw(MOV64_REG, 0, 1, 0, 0);
        let d = decode(r, 0, 0).unwrap();
        assert_eq!(d.itype, Itype::MOV64);
        assert_eq!(d.ops[0], DecodedOp::Reg { reg: 0, size: Qword });
        assert_eq!(d.ops[1], DecodedOp::Reg { reg: 1, size: Qword });
    }

    #[test]
    fn decode_ja32() {
        let r = raw(JA32, 0, 0, 2, 0);
        let d = decode(r, 0, 0x3000).unwrap();
        assert_eq!(d.itype, Itype::JA32);
        assert_eq!(d.ops[0], DecodedOp::Near { target: branch_target(0x3000, 2) });
    }

    #[test]
    fn decode_jeq32_reg() {
        let r = raw(JEQ32_REG, 3, 4, 1, 0);
        let d = decode(r, 0, 0x2000).unwrap();
        assert_eq!(d.itype, Itype::JEQ32);
        assert_eq!(d.ops[0], DecodedOp::Reg  { reg: 3, size: Qword });
        assert_eq!(d.ops[1], DecodedOp::Reg  { reg: 4, size: Qword });
        assert_eq!(d.ops[2], DecodedOp::Near { target: branch_target(0x2000, 1) });
    }

    // Table-driven: one representative case per opcode group to confirm
    // itype assignment without exhaustively testing every encoding variant.
    #[test]
    fn decode_itype_table() {
        struct Case { raw1: u64, expected: Itype }
        let cases = [
            Case { raw1: raw(LD_DW_REG,  1, 2,  0, 0), expected: Itype::LDXDW  },
            Case { raw1: raw(ST_DW_IMM,  3, 0,  4, 7), expected: Itype::STDW   },
            Case { raw1: raw(ST_DW_REG,  3, 5,  0, 0), expected: Itype::STXDW  },
            Case { raw1: raw(SUB32_REG,  1, 2,  0, 0), expected: Itype::SUB32  },
            Case { raw1: raw(MUL32_IMM,  1, 0,  0, 4), expected: Itype::MUL32  },
            Case { raw1: raw(DIV32_IMM,  1, 0,  0, 2), expected: Itype::DIV32  },
            Case { raw1: raw(OR32_REG,   1, 2,  0, 0), expected: Itype::OR32   },
            Case { raw1: raw(XOR32_IMM,  1, 0,  0, 1), expected: Itype::XOR32  },
            Case { raw1: raw(LE,         1, 0,  0, 32), expected: Itype::LE    },
            Case { raw1: raw(BE,         1, 0,  0, 64), expected: Itype::BE    },
            Case { raw1: raw(SUB64_IMM,  1, 0,  0, 1), expected: Itype::SUB64  },
            Case { raw1: raw(AND64_REG,  1, 2,  0, 0), expected: Itype::AND64  },
            Case { raw1: raw(ARSH64_IMM, 1, 0,  0, 3), expected: Itype::ARSH64 },
        ];
        for c in &cases {
            let d = decode(c.raw1, 0, 0)
                .unwrap_or_else(|| panic!("decode failed for itype {:?}", c.expected));
            assert_eq!(d.itype, c.expected, "opcode byte 0x{:02x}", c.raw1 as u8);
        }
    }

    // Itype discriminants must be contiguous starting at 0 and LAST must equal
    // the number of real instructions - this is already enforced at compile time
    // by the SBF_INSTRUC array size, but an explicit assertion makes the intent
    // visible and catches any future enum reordering.
    #[test]
    fn itype_last_is_instruction_count() {
        // The 63 real instructions (LDDW..EXIT) sit at indices 0..LAST.
        // If LAST ever drifts, the SBF_INSTRUC static will fail to compile first,
        // but this test gives a clearer error message.
        assert!(Itype::LAST as usize > 0, "Itype::LAST must be positive");
        assert_eq!(Itype::EXIT as usize + 1, Itype::LAST as usize,
            "EXIT must be the last real instruction before LAST");
    }
}
