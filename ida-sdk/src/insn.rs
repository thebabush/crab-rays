use ida_sdk_sys::ffi;
use crate::op::OpMut;

/// Read-only view of an IDA `insn_t`.
pub struct Insn<'a>(pub(crate) &'a ffi::insn_t);

/// Mutable view of an IDA `insn_t`.
pub struct InsnMut<'a>(pub(crate) &'a mut ffi::insn_t);

// ---- shared read methods (implemented on both via a macro to avoid duplication) ----

macro_rules! insn_readers {
    ($self:ident, $inner:expr) => {
        pub fn ea(&$self)       -> u64  { unsafe { ffi::insn_get_ea($inner) } }
        pub fn size(&$self)     -> u16  { unsafe { ffi::insn_get_size($inner) } }
        pub fn itype(&$self)    -> u16  { unsafe { ffi::insn_get_itype($inner) } }
        pub fn op0_addr(&$self) -> u64  { unsafe { ffi::insn_op0_addr($inner) } }
        pub fn op2_addr(&$self) -> u64  { unsafe { ffi::insn_op2_addr($inner) } }

        pub fn add_flow(&$self)                    { unsafe { ffi::sbf_add_flow($inner) } }
        pub fn add_jump(&$self, target: u64)       { unsafe { ffi::sbf_add_jump($inner, target) } }
        pub fn add_call_near(&$self, target: u64)  { unsafe { ffi::sbf_add_call_near($inner, target) } }
    };
}

impl<'a> Insn<'a> {
    pub fn from_raw(insn: &'a ffi::insn_t) -> Self { Self(insn) }
    insn_readers!(self, self.0);
}

impl<'a> InsnMut<'a> {
    pub fn from_raw(insn: &'a mut ffi::insn_t) -> Self { Self(insn) }
    insn_readers!(self, self.0);

    pub fn next_qword(&mut self) -> u64 {
        unsafe { ffi::sbf_next_qword(self.0) }
    }

    pub fn set_itype(&mut self, itype: u16) {
        unsafe { ffi::insn_set_itype(self.0, itype) }
    }

    /// Return a mutable wrapper around operand slot `n` (0–7).
    /// Panics in debug builds if the SDK returns a null pointer.
    pub fn op_mut(&mut self, n: i32) -> OpMut<'_> {
        let ptr = unsafe { ffi::insn_op(self.0, autocxx::c_int(n)) };
        debug_assert!(!ptr.is_null(), "insn_op returned null for slot {n}");
        OpMut::from_raw(unsafe { &mut *ptr })
    }
}
