use ida_sdk_sys::ffi;
use crate::op::{OpKind, OpRef};

/// Mutable wrapper around an IDA `outctx_t`.
pub struct OutCtx<'a>(pub(crate) &'a mut ffi::outctx_t);

impl<'a> OutCtx<'a> {
    pub fn from_raw(ctx: &'a mut ffi::outctx_t) -> Self { Self(ctx) }

    pub fn out_mnemonic(&mut self)  { unsafe { ffi::ctx_out_mnemonic(self.0) } }
    pub fn out_comma(&mut self)     { unsafe { ffi::ctx_out_comma(self.0) } }
    pub fn out_space(&mut self)     { unsafe { ffi::ctx_out_space(self.0) } }
    pub fn flush(&mut self)         { unsafe { ffi::ctx_flush(self.0) } }
    pub fn out_open_bracket(&mut self)  { unsafe { ffi::ctx_out_open_bracket(self.0) } }
    pub fn out_close_bracket(&mut self) { unsafe { ffi::ctx_out_close_bracket(self.0) } }
    pub fn out_plus_sign(&mut self)     { unsafe { ffi::ctx_out_plus_sign(self.0) } }
    pub fn out_minus_sign(&mut self)    { unsafe { ffi::ctx_out_minus_sign(self.0) } }

    pub fn insn_itype(&mut self) -> u16 {
        unsafe { ffi::ctx_insn_itype(self.0) }
    }

    pub fn insn_op_type(&mut self, n: i32) -> OpKind {
        OpKind::from(unsafe { ffi::ctx_insn_op_type(self.0, autocxx::c_int(n)) })
    }

    pub fn out_one_operand(&mut self, n: i32) -> bool {
        unsafe { ffi::ctx_out_one_operand(self.0, autocxx::c_int(n)) }
    }

    pub fn out_reg(&mut self, reg: u16) {
        unsafe { ffi::ctx_out_reg(self.0, reg) }
    }

    pub fn out_hex(&mut self, v: u64) {
        unsafe { ffi::ctx_out_hex(self.0, v) }
    }

    pub fn out_keyword(&mut self, s: &std::ffi::CStr) {
        unsafe { ffi::ctx_out_keyword(self.0, s.as_ptr()) }
    }

    pub fn out_name_expr(&mut self, op: &OpRef<'_>, ea: u64) -> bool {
        unsafe { ffi::ctx_out_name_expr(self.0, op.0 as *const ffi::op_t, ea) }
    }
}
