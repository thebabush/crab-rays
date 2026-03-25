use ida_sdk_sys::ffi;

// IDA optype_t values (ua.hpp o_*)
/// Operand kind - mirrors IDA's `optype_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Void,
    Reg,
    Displ,
    Imm,
    Near,
    /// IDA returned a raw value not covered by SBF operand kinds.
    Other(u8),
}

impl From<u8> for OpKind {
    fn from(v: u8) -> Self {
        use ida_sdk_sys::ffi::optype_t as OT;
        match v {
            x if x == OT::o_void  as u8 => Self::Void,
            x if x == OT::o_reg   as u8 => Self::Reg,
            x if x == OT::o_displ as u8 => Self::Displ,
            x if x == OT::o_imm   as u8 => Self::Imm,
            x if x == OT::o_near  as u8 => Self::Near,
            other => Self::Other(other),
        }
    }
}

impl From<OpKind> for u8 {
    fn from(k: OpKind) -> u8 {
        use ida_sdk_sys::ffi::optype_t as OT;
        match k {
            OpKind::Void     => OT::o_void  as u8,
            OpKind::Reg      => OT::o_reg   as u8,
            OpKind::Displ    => OT::o_displ as u8,
            OpKind::Imm      => OT::o_imm   as u8,
            OpKind::Near     => OT::o_near  as u8,
            OpKind::Other(v) => v,
        }
    }
}


/// Read-only view of an IDA `op_t`.
pub struct OpRef<'a>(pub(crate) &'a ffi::op_t);

/// Mutable view of an IDA `op_t`.
pub struct OpMut<'a>(pub(crate) &'a mut ffi::op_t);

impl<'a> OpRef<'a> {
    pub fn from_raw(op: &'a ffi::op_t) -> Self { Self(op) }

    pub fn kind(&self)   -> OpKind { OpKind::from(unsafe { ffi::op_get_type(self.0) }) }
    pub fn reg(&self)    -> u16 { unsafe { ffi::op_get_reg(self.0) } }
    pub fn phrase(&self) -> u16 { unsafe { ffi::op_get_phrase(self.0) } }
    pub fn addr(&self)   -> u64 { unsafe { ffi::op_get_addr(self.0) } }
    pub fn value(&self)  -> u64 { unsafe { ffi::op_get_value(self.0) } }
}

impl<'a> OpMut<'a> {
    pub fn from_raw(op: &'a mut ffi::op_t) -> Self { Self(op) }

    // ----- low-level setters -------------------------------------------------

    pub fn set_type(&mut self, t: u8)   { unsafe { ffi::op_set_type(self.0, t as _) } }
    pub fn set_dtype(&mut self, d: u8)  { unsafe { ffi::op_set_dtype(self.0, d as _) } }
    pub fn set_reg(&mut self, r: u16)   { unsafe { ffi::op_set_reg(self.0, r as _) } }
    pub fn set_phrase(&mut self, r: u16) { unsafe { ffi::op_set_phrase(self.0, r as _) } }
    pub fn set_shown(&mut self)          { unsafe { ffi::op_set_shown(self.0) } }

    pub fn set_value(&mut self, v: u64) {
        unsafe { ffi::op_set_value(self.0, autocxx::c_ulonglong(v)) }
    }
    pub fn set_addr(&mut self, a: u64) {
        unsafe { ffi::op_set_addr(self.0, autocxx::c_ulonglong(a)) }
    }

    // ----- composite operand builders ----------------------------------------

    /// Register operand: `o_reg`, dtype, reg, shown.
    pub fn set_reg_op(&mut self, reg: u8, dtype: u8) {
        self.set_type(OpKind::Reg.into());
        self.set_dtype(dtype);
        self.set_reg(reg as u16);
        self.set_shown();
    }

    /// Immediate operand: `o_imm`, dtype, value, shown.
    pub fn set_imm_op(&mut self, val: u64, dtype: u8) {
        self.set_type(OpKind::Imm.into());
        self.set_dtype(dtype);
        self.set_value(val);
        self.set_shown();
    }

    /// Displacement operand: `o_displ`, dtype, phrase (base reg), addr (offset), shown.
    pub fn set_displ_op(&mut self, base: u8, off: i16, dtype: u8) {
        self.set_type(OpKind::Displ.into());
        self.set_dtype(dtype);
        self.set_phrase(base as u16);
        self.set_addr(off as i64 as u64);
        self.set_shown();
    }

    /// Near-code target: delegates to the `op_set_near` shim (sets type, dtype, addr, shown).
    pub fn set_near_op(&mut self, target: u64) {
        unsafe { ffi::op_set_near(self.0, autocxx::c_ulonglong(target)) }
    }
}
