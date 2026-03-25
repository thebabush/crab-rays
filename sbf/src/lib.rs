// Lints triggered by autocxx-generated code used via procmod_rs/loader_rs.
#![allow(unsafe_op_in_unsafe_fn, unused_unsafe, clippy::empty_line_after_doc_comments, clippy::too_many_arguments, private_interfaces)]

mod ana;
mod decode;
mod emu;
mod lph;
mod ldsc;
mod out;

use ida_sdk::{Insn, InsnMut, OutCtx, OpRef};

// ---------------------------------------------------------------------------
// Callbacks invoked by shim.cpp after va_list unpacking.
// Unsafe is confined here; inner functions receive safe wrappers.
// ---------------------------------------------------------------------------

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_ana_insn(insn: *mut procmod_rs::ffi::insn_t) -> isize {
    debug_assert!(!insn.is_null(), "IDA passed null insn_t to rust_ana_insn");
    ana::ana_insn(InsnMut::from_raw(unsafe { &mut *insn }))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_emu_insn(insn: *const procmod_rs::ffi::insn_t) -> isize {
    debug_assert!(!insn.is_null(), "IDA passed null insn_t to rust_emu_insn");
    emu::emu_insn(&Insn::from_raw(unsafe { &*insn }))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_out_insn(ctx: *mut procmod_rs::ffi::outctx_t) -> isize {
    debug_assert!(!ctx.is_null(), "IDA passed null outctx_t to rust_out_insn");
    out::out_insn(&mut OutCtx::from_raw(unsafe { &mut *ctx }))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "C" fn rust_out_operand(ctx: *mut procmod_rs::ffi::outctx_t, op: *const procmod_rs::ffi::op_t) -> isize {
    debug_assert!(!ctx.is_null(), "IDA passed null outctx_t to rust_out_operand");
    debug_assert!(!op.is_null(),  "IDA passed null op_t to rust_out_operand");
    out::out_operand(
        &mut OutCtx::from_raw(unsafe { &mut *ctx }),
        &OpRef::from_raw(unsafe { &*op }),
    )
}
