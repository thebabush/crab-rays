use ida_sdk::procmod::{
    CF_USE1, CF_USE2, CF_USE3, CF_CHG1, CF_STOP, CF_CALL,
    AsmT, InstrucT, ProcessorT,
};
use crate::decode::Itype;

macro_rules! insn {
    ($name:literal, $feat:expr) => {
        InstrucT { name: concat!($name, "\0").as_ptr() as _, feature: $feat }
    };
}

const USE12_CHG1: u32 = CF_USE1 | CF_USE2 | CF_CHG1;
const USE1_CHG1:  u32 = CF_USE1 | CF_CHG1;
const USE12:      u32 = CF_USE1 | CF_USE2;
const USE123:     u32 = CF_USE1 | CF_USE2 | CF_USE3;

#[unsafe(no_mangle)]
pub static SBF_INSTRUC: [InstrucT; Itype::LAST as usize] = [
    // LDDW
    insn!("lddw",   CF_CHG1),
    // LDX - dst is write-only (CHG1), src mem operand is read (USE2)
    insn!("ldxb",   CF_CHG1 | CF_USE2),
    insn!("ldxh",   CF_CHG1 | CF_USE2),
    insn!("ldxw",   CF_CHG1 | CF_USE2),
    insn!("ldxdw",  CF_CHG1 | CF_USE2),
    // ST imm
    insn!("stb",    USE12),
    insn!("sth",    USE12),
    insn!("stw",    USE12),
    insn!("stdw",   USE12),
    // STX reg
    insn!("stxb",   USE12),
    insn!("stxh",   USE12),
    insn!("stxw",   USE12),
    insn!("stxdw",  USE12),
    // ALU32
    insn!("add32",  USE12_CHG1),
    insn!("sub32",  USE12_CHG1),
    insn!("mul32",  USE12_CHG1),
    insn!("div32",  USE12_CHG1),
    insn!("or32",   USE12_CHG1),
    insn!("and32",  USE12_CHG1),
    insn!("lsh32",  USE12_CHG1),
    insn!("rsh32",  USE12_CHG1),
    insn!("neg32",  USE1_CHG1),
    insn!("mod32",  USE12_CHG1),
    insn!("xor32",  USE12_CHG1),
    insn!("mov32",  CF_CHG1 | CF_USE2),
    insn!("arsh32", USE12_CHG1),
    insn!("le",     USE1_CHG1),
    insn!("be",     USE1_CHG1),
    // ALU64 (mul64/div64/neg64/mod64 removed: SBFv2 repurposed those opcodes)
    insn!("add64",  USE12_CHG1),
    insn!("sub64",  USE12_CHG1),
    insn!("or64",   USE12_CHG1),
    insn!("and64",  USE12_CHG1),
    insn!("lsh64",  USE12_CHG1),
    insn!("rsh64",  USE12_CHG1),
    insn!("xor64",  USE12_CHG1),
    insn!("mov64",  CF_CHG1 | CF_USE2),
    insn!("arsh64", USE12_CHG1),
    // JMP64
    insn!("ja",     CF_STOP),
    insn!("jeq",    USE123),
    insn!("jgt",    USE123),
    insn!("jge",    USE123),
    insn!("jset",   USE123),
    insn!("jne",    USE123),
    insn!("jsgt",   USE123),
    insn!("jsge",   USE123),
    insn!("jlt",    USE123),
    insn!("jle",    USE123),
    insn!("jslt",   USE123),
    insn!("jsle",   USE123),
    // JMP32
    insn!("ja32",   CF_STOP),
    insn!("jeq32",  USE123),
    insn!("jgt32",  USE123),
    insn!("jge32",  USE123),
    insn!("jset32", USE123),
    insn!("jne32",  USE123),
    insn!("jsgt32", USE123),
    insn!("jsge32", USE123),
    insn!("jlt32",  USE123),
    insn!("jle32",  USE123),
    insn!("jslt32", USE123),
    insn!("jsle32", USE123),
    // Control
    insn!("call",    CF_CALL),
    insn!("callx",   CF_CALL | CF_USE1),
    insn!("syscall", CF_CALL),
    insn!("exit",    CF_STOP),
];

// Registers: r0..r10 + virtual CS/DS
pub const REG_CS:   i32 = 11;
pub const REG_DS:   i32 = 12;
pub const REGS_NUM: i32 = 13;

struct StrPtrArray<const N: usize>([*const std::ffi::c_char; N]);
unsafe impl<const N: usize> Sync for StrPtrArray<N> {}

static REG_NAMES: StrPtrArray<{ REGS_NUM as usize }> = StrPtrArray([
    c"r0".as_ptr(),
    c"r1".as_ptr(),
    c"r2".as_ptr(),
    c"r3".as_ptr(),
    c"r4".as_ptr(),
    c"r5".as_ptr(),
    c"r6".as_ptr(),
    c"r7".as_ptr(),
    c"r8".as_ptr(),
    c"r9".as_ptr(),
    c"r10".as_ptr(),
    c"cs".as_ptr(),
    c"ds".as_ptr(),
]);

// Minimal assembler definition - only the fields IDA really uses for a
// simple procmod; the rest are null.
static SBF_ASM: AsmT = AsmT {
    flag:           0,
    uflag:          0,
    _pad0:          0,
    name:           c"SBF assembler".as_ptr(),
    help:           0,
    _pad1:          0,
    header:         std::ptr::null(),
    origin:         c".org".as_ptr(),
    end:            c".end".as_ptr(),
    cmnt:           c";".as_ptr(),
    ascsep:         b'"',
    accsep:         b'\'',
    _pad2:          [0; 6],
    esccodes:       c"\\\"\\'".as_ptr(),
    a_ascii:        c".ascii".as_ptr(),
    a_byte:         c".byte".as_ptr(),
    a_word:         c".short".as_ptr(),
    a_dword:        c".long".as_ptr(),
    a_qword:        c".quad".as_ptr(),
    a_oword:        std::ptr::null(),
    a_float:        std::ptr::null(),
    a_double:       std::ptr::null(),
    a_tbyte:        std::ptr::null(),
    a_packreal:     std::ptr::null(),
    a_dups:         std::ptr::null(),
    a_bss:          c".space %s".as_ptr(),
    a_equ:          std::ptr::null(),
    a_seg:          std::ptr::null(),
    a_curip:        std::ptr::null(),
    out_func_header: std::ptr::null(),
    out_func_footer: std::ptr::null(),
    a_public:        std::ptr::null(),
    a_weak:          std::ptr::null(),
    a_extrn:         std::ptr::null(),
    a_comdef:        std::ptr::null(),
    get_type_name:   std::ptr::null(),
    a_align:         std::ptr::null(),
    lbrace:          0,
    rbrace:          0,
    _pad3:           [0; 6],
    a_mod:           std::ptr::null(),
    a_band:          std::ptr::null(),
    a_bor:           std::ptr::null(),
    a_xor:           std::ptr::null(),
    a_bnot:          std::ptr::null(),
    a_shl:           std::ptr::null(),
    a_shr:           std::ptr::null(),
    a_sizeof_fmt:    std::ptr::null(),
    flag2:           0,
    _pad4:           0,
    cmnt2:           std::ptr::null(),
    low8:            std::ptr::null(),
    high8:           std::ptr::null(),
    low16:           std::ptr::null(),
    high16:          std::ptr::null(),
    a_include_fmt:   std::ptr::null(),
    a_vstruc_fmt:    std::ptr::null(),
    a_rva:           std::ptr::null(),
    a_yword:         std::ptr::null(),
    a_zword:         std::ptr::null(),
};

struct AsmPtrArray([*const AsmT; 2]);
unsafe impl Sync for AsmPtrArray {}

static SBF_ASMS: AsmPtrArray = AsmPtrArray([
    &SBF_ASM as *const AsmT,
    std::ptr::null(),
]);

static SBF_SHORT_NAMES: StrPtrArray<2> = StrPtrArray([
    c"SBF".as_ptr(),
    std::ptr::null(),
]);
static SBF_LONG_NAMES: StrPtrArray<2> = StrPtrArray([
    c"Solana BPF".as_ptr(),
    std::ptr::null(),
]);

unsafe extern "C" {
    fn rust_procmod_notify(ud: *mut std::ffi::c_void, code: i32, ...) -> isize;
}

#[unsafe(no_mangle)]
pub static LPH: ProcessorT = ProcessorT {
    version:        900,       // IDP_INTERFACE_VERSION
    id:             0x8BF0,    // third-party IDs start at 0x8000
    flag:           0x002000 | 0x10000000, // PR_USE64 | PR_DEFSEG64
    flag2:          0,
    cnbits:         8,
    dnbits:         8,
    psnames:        SBF_SHORT_NAMES.0.as_ptr(),
    plnames:        SBF_LONG_NAMES.0.as_ptr(),
    assemblers:     SBF_ASMS.0.as_ptr() as _,
    _notify:        rust_procmod_notify,
    reg_names:      REG_NAMES.0.as_ptr(),
    regs_num:       REGS_NUM,
    reg_first_sreg: REG_CS,
    reg_last_sreg:  REG_DS,
    segreg_size:    0,
    reg_code_sreg:  REG_CS,
    reg_data_sreg:  REG_DS,
    codestart:      std::ptr::null(),
    retcodes:       std::ptr::null(),
    instruc_start:  0,
    instruc_end:    Itype::LAST as i32,
    instruc:        SBF_INSTRUC.as_ptr(),
    tbyte_size:     0,
    real_width:     [0; 4],
    icode_return:   Itype::EXIT as i32,
    unused_slot:    std::ptr::null(),
};
