/// IDA writeback adapter for the SBF decoder.
///
/// Reads raw instruction bytes via `InsnMut`, delegates the actual decode to
/// the pure [`crate::decode`] module, then projects the result into IDA's
/// `insn_t` / `op_t` representation.

use ida_sdk::InsnMut;
use crate::decode::{DataSize, DecodedInsn, DecodedOp, decode, is_two_word};

pub fn ana_insn(mut insn: InsnMut<'_>) -> isize {
    let ea   = insn.ea();
    let raw1 = insn.next_qword();                                      // advances size by 8
    let opc  = (raw1 & 0xFF) as u8;
    let raw2 = if is_two_word(opc) { insn.next_qword() } else { 0 }; // advances size by 8 more if lddw

    let Some(decoded) = decode(raw1, raw2, ea) else { return 0 };
    apply_to_ida(&decoded, &mut insn);
    insn.size() as isize
}

// ---------------------------------------------------------------------------
// IDA projection
// ---------------------------------------------------------------------------

fn apply_to_ida(d: &DecodedInsn, insn: &mut InsnMut<'_>) {
    insn.set_itype(d.itype as u16);
    for (i, op) in d.ops.iter().enumerate() {
        match *op {
            DecodedOp::None => {}
            DecodedOp::Reg   { reg,       size } => insn.op_mut(i as i32).set_reg_op(reg, dt(size)),
            DecodedOp::Imm   { val,       size } => insn.op_mut(i as i32).set_imm_op(val, dt(size)),
            DecodedOp::Displ { base, off, size } => insn.op_mut(i as i32).set_displ_op(base, off, dt(size)),
            DecodedOp::Near  { target          } => insn.op_mut(i as i32).set_near_op(target),
        }
    }
}

fn dt(size: DataSize) -> u8 {
    use ida_sdk_sys::ffi::op_dtype_t as DT;
    match size {
        DataSize::Byte  => DT::dt_byte  as u8,
        DataSize::Word  => DT::dt_word  as u8,
        DataSize::Dword => DT::dt_dword as u8,
        DataSize::Qword => DT::dt_qword as u8,
    }
}
