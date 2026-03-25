use std::ffi::c_void;

// CF_ instruction feature-flag constants, sourced from the autocxx-generated
// ffi::cf_feat enum so they can never drift from the IDA SDK.
use ida_sdk_sys::ffi::cf_feat as CF;
pub const CF_STOP: u32 = CF::cf_stop as u32; ///< Instruction doesn't pass execution to the next one
pub const CF_CALL: u32 = CF::cf_call as u32; ///< CALL instruction (should make a procedure here)
pub const CF_CHG1: u32 = CF::cf_chg1 as u32; ///< The instruction modifies the first operand
pub const CF_USE1: u32 = CF::cf_use1 as u32; ///< The instruction uses value of the first operand
pub const CF_USE2: u32 = CF::cf_use2 as u32; ///< The instruction uses value of the second operand
pub const CF_USE3: u32 = CF::cf_use3 as u32; ///< The instruction uses value of the third operand

/// Instruction descriptor table entry - mirrors `instruc_t` from idp.hpp.
#[repr(C)]
pub struct InstrucT {
    pub name:    *const std::ffi::c_char,
    pub feature: u32,
}
unsafe impl Sync for InstrucT {}
const _: () = assert!(std::mem::size_of::<InstrucT>() == 16);

/// Assembler definition - mirrors `asm_t` from idp.hpp (416 bytes on 64-bit).
#[repr(C)]
pub struct AsmT {
    pub flag:            u32,
    pub uflag:           u16,   // uint16 in SDK; 2 bytes padding follow before name
    pub _pad0:           u16,
    pub name:            *const std::ffi::c_char,
    pub help:            u32,   // help_t = int
    pub _pad1:           u32,
    pub header:          *const *const std::ffi::c_char,
    pub origin:          *const std::ffi::c_char,
    pub end:             *const std::ffi::c_char,
    pub cmnt:            *const std::ffi::c_char,
    pub ascsep:          u8,
    pub accsep:          u8,
    pub _pad2:           [u8; 6],
    pub esccodes:        *const std::ffi::c_char,
    pub a_ascii:         *const std::ffi::c_char,
    pub a_byte:          *const std::ffi::c_char,
    pub a_word:          *const std::ffi::c_char,
    pub a_dword:         *const std::ffi::c_char,
    pub a_qword:         *const std::ffi::c_char,
    pub a_oword:         *const std::ffi::c_char,
    pub a_float:         *const std::ffi::c_char,
    pub a_double:        *const std::ffi::c_char,
    pub a_tbyte:         *const std::ffi::c_char,
    pub a_packreal:      *const std::ffi::c_char,
    pub a_dups:          *const std::ffi::c_char,
    pub a_bss:           *const std::ffi::c_char,
    pub a_equ:           *const std::ffi::c_char,
    pub a_seg:           *const std::ffi::c_char,
    pub a_curip:         *const std::ffi::c_char,
    // --- fields below are at offsets 192..416 ---
    pub out_func_header: *const c_void, // fn ptr - nullptr = use default
    pub out_func_footer: *const c_void, // fn ptr - nullptr = comment line
    pub a_public:        *const std::ffi::c_char,
    pub a_weak:          *const std::ffi::c_char,
    pub a_extrn:         *const std::ffi::c_char,
    pub a_comdef:        *const std::ffi::c_char,
    pub get_type_name:   *const c_void, // fn ptr - nullptr = not provided
    pub a_align:         *const std::ffi::c_char,
    pub lbrace:          u8,
    pub rbrace:          u8,
    pub _pad3:           [u8; 6],
    pub a_mod:           *const std::ffi::c_char,
    pub a_band:          *const std::ffi::c_char,
    pub a_bor:           *const std::ffi::c_char,
    pub a_xor:           *const std::ffi::c_char,
    pub a_bnot:          *const std::ffi::c_char,
    pub a_shl:           *const std::ffi::c_char,
    pub a_shr:           *const std::ffi::c_char,
    pub a_sizeof_fmt:    *const std::ffi::c_char,
    pub flag2:           u32,
    pub _pad4:           u32,
    pub cmnt2:           *const std::ffi::c_char,
    pub low8:            *const std::ffi::c_char,
    pub high8:           *const std::ffi::c_char,
    pub low16:           *const std::ffi::c_char,
    pub high16:          *const std::ffi::c_char,
    pub a_include_fmt:   *const std::ffi::c_char,
    pub a_vstruc_fmt:    *const std::ffi::c_char,
    pub a_rva:           *const std::ffi::c_char,
    pub a_yword:         *const std::ffi::c_char,
    pub a_zword:         *const std::ffi::c_char,
}
unsafe impl Sync for AsmT {}
const _: () = assert!(std::mem::size_of::<AsmT>() == 416);

/// Processor module descriptor - mirrors `processor_t` from idp.hpp (144 bytes on 64-bit).
#[repr(C)]
pub struct ProcessorT {
    pub version:        i32,
    pub id:             i32,
    pub flag:           u32,
    pub flag2:          u32,
    pub cnbits:         i32,
    pub dnbits:         i32,
    pub psnames:        *const *const std::ffi::c_char,
    pub plnames:        *const *const std::ffi::c_char,
    pub assemblers:     *const *const AsmT,
    pub _notify:        unsafe extern "C" fn(*mut c_void, i32, ...) -> isize,
    pub reg_names:      *const *const std::ffi::c_char,
    pub regs_num:       i32,
    pub reg_first_sreg: i32,
    pub reg_last_sreg:  i32,
    pub segreg_size:    i32,
    pub reg_code_sreg:  i32,
    pub reg_data_sreg:  i32,
    pub codestart:      *const c_void,
    pub retcodes:       *const c_void,
    pub instruc_start:  i32,
    pub instruc_end:    i32,
    pub instruc:        *const InstrucT,
    pub tbyte_size:     usize,
    pub real_width:     [u8; 4],
    pub icode_return:   i32,
    pub unused_slot:    *const c_void,
}
unsafe impl Sync for ProcessorT {}
const _: () = assert!(std::mem::size_of::<ProcessorT>() == 144);
