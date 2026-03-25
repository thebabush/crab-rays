// Lints triggered by autocxx-generated code - suppress crate-wide.
#![allow(unsafe_op_in_unsafe_fn, clippy::empty_line_after_doc_comments, clippy::too_many_arguments)]

// include_cpp! generates a pub(crate) mod named `ffi` at the call site.
// Nesting it in a private module avoids the E0255/E0365 collision that occurs
// when `pub use ffi` is placed at the same level as the generated `mod ffi`.
#[allow(unused_imports, unused_unsafe)]
mod _inner {
    use autocxx::prelude::*;
    include_cpp! {
        #include "idp.hpp"
        #include "ua.hpp"
        #include "insn_helpers.hpp"
        #include "ldr_helpers.hpp"
        safety!(unsafe_ffi)

        // ----- Core processor-module types ------------------------------------
        generate!("processor_t")
        generate!("insn_t")
        generate!("op_t")
        generate!("outctx_t")
        generate!("instruc_t")
        generate!("asm_t")
        generate!("optype")
        generate!("op_dtype")
        generate!("cf_feat")

        // ----- insn / op helpers (insn_helpers.hpp) --------------------------
        generate!("sbf_next_qword")
        generate!("insn_get_ea")
        generate!("insn_get_size")
        generate!("insn_set_itype")
        generate!("insn_op")
        generate!("op_set_shown")
        generate!("op_set_type")
        generate!("op_set_dtype")
        generate!("op_set_reg")
        generate!("op_set_value")
        generate!("op_set_phrase")
        generate!("op_set_addr")
        generate!("op_set_near")

        // ----- emu helpers ---------------------------------------------------
        generate!("insn_get_itype")
        generate!("op_get_type")
        generate!("op_get_reg")
        generate!("op_get_phrase")
        generate!("op_get_addr")
        generate!("op_get_value")
        generate!("insn_op0_addr")
        generate!("insn_op2_addr")
        generate!("sbf_add_flow")
        generate!("sbf_add_jump")

        // ----- out helpers ---------------------------------------------------
        generate!("ctx_out_mnemonic")
        generate!("ctx_out_one_operand")
        generate!("ctx_insn_op_type")
        generate!("ctx_out_reg")
        generate!("ctx_out_hex")
        generate!("ctx_out_name_expr")
        generate!("ctx_out_open_bracket")
        generate!("ctx_out_close_bracket")
        generate!("ctx_out_comma")
        generate!("ctx_out_plus_sign")
        generate!("ctx_out_minus_sign")
        generate!("ctx_out_space")
        generate!("ctx_flush")
        generate!("ctx_insn_itype")
        generate!("ctx_out_keyword")
        generate!("sbf_add_call_near")

        // ----- loader helpers (ldr_helpers.hpp) ------------------------------
        generate!("ldr_read")
        generate!("ldr_seek")
        generate!("ldr_size")
        generate!("ldr_qstr_set")
        generate!("ldr_set_proc")
        generate!("ldr_add_seg")
        generate!("ldr_file_to_base")
        generate!("ldr_add_entry")
        generate!("ldr_set_name")
        generate!("ldr_filename_cmt")
        generate!("ldr_patch_qword")
    }
    // include_cpp! generates a private `mod ffi` - re-export its public items
    // while we can still see it (same module scope).
    pub use ffi::*;
}

// Re-export the generated bindings under a public `ffi` module.
pub mod ffi {
    pub use super::_inner::*;
}
