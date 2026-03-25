use ida_sdk::Insn;
use crate::decode::Itype;

/// Emulate the instruction: mark code cross-references so IDA can follow flow.
/// Returns 1 on success.
pub fn emu_insn(insn: &Insn<'_>) -> isize {
    let Ok(itype) = Itype::try_from(insn.itype()) else {
        // Unknown itype - assume sequential flow to avoid orphaning bytes.
        insn.add_flow();
        return 1;
    };

    match itype {
        // Unconditional jumps - only the branch target, no fall-through
        Itype::JA | Itype::JA32 => {
            insn.add_jump(insn.op0_addr());
        }

        // Conditional jumps - branch target + sequential fall-through
        t if t.is_cond_jump() => {
            insn.add_jump(insn.op2_addr());
            insn.add_flow();
        }

        // CALL (resolved local call) - call xref + fall-through after return
        Itype::CALL => {
            insn.add_call_near(insn.op0_addr());
            insn.add_flow();
        }

        // CALLX (indirect call via register) - target unknown statically;
        // CF_CALL in instruc table tells IDA it's a call; just fall through.
        Itype::CALLX => {
            insn.add_flow();
        }

        // EXIT - CF_STOP, no flow out
        Itype::EXIT => {}

        // Everything else (ALU, mem ops, SYSCALL) - sequential flow
        _ => {
            insn.add_flow();
        }
    }

    1
}

