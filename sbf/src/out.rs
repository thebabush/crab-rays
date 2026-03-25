use ida_sdk::{OutCtx, OpRef, OpKind};
use crate::decode::Itype;

/// Output the full instruction line: mnemonic followed by operands.
pub fn out_insn(ctx: &mut OutCtx<'_>) -> isize {
    ctx.out_mnemonic();

    let mut first = true;
    for n in 0i32..3 {
        if ctx.insn_op_type(n) == OpKind::Void { break; }
        if !first {
            ctx.out_comma();
            ctx.out_space();
        }
        ctx.out_one_operand(n);
        first = false;
    }

    ctx.flush();
    1
}

/// Output a single operand according to its type.
pub fn out_operand(ctx: &mut OutCtx<'_>, op: &OpRef<'_>) -> isize {
    match op.kind() {
        OpKind::Reg => {
            ctx.out_reg(op.reg());
            1
        }
        OpKind::Imm => {
            let val = op.value();
            if ctx.insn_itype() == Itype::SYSCALL as u16 {
                if let Some(name) = syscall_name(val as u32) {
                    let cname = std::ffi::CString::new(name)
                        .expect("syscall names must not contain interior nulls");
                    ctx.out_keyword(cname.as_c_str());
                } else {
                    ctx.out_hex(val);
                }
            } else {
                ctx.out_hex(val);
            }
            1
        }
        OpKind::Displ => {
            // Format: [base_reg+offset] / [base_reg-offset] / [base_reg]
            let base   = op.phrase();
            let offset = op.addr() as i64;
            ctx.out_open_bracket();
            ctx.out_reg(base);
            if offset > 0 {
                ctx.out_plus_sign();
                ctx.out_hex(offset as u64);
            } else if offset < 0 {
                ctx.out_minus_sign();
                ctx.out_hex((-offset) as u64);
            }
            ctx.out_close_bracket();
            1
        }
        OpKind::Near => {
            let addr = op.addr();
            if !ctx.out_name_expr(op, addr) {
                ctx.out_hex(addr);
            }
            1
        }
        OpKind::Void | OpKind::Other(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Syscall hash → name table
// ---------------------------------------------------------------------------

const fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        h = h.wrapping_mul(33).wrapping_add(s[i] as u32);
        i += 1;
    }
    h
}

struct SyscallEntry {
    hash: u32,
    name: &'static str,
}

macro_rules! sc {
    ($name:literal) => {
        SyscallEntry { hash: djb2($name.as_bytes()), name: $name }
    };
}

static SYSCALLS: &[SyscallEntry] = &[
    sc!("sol_log_"),
    sc!("sol_log_64_"),
    sc!("sol_log_compute_units_"),
    sc!("sol_log_pubkey"),
    sc!("sol_memcpy_"),
    sc!("sol_memmove_"),
    sc!("sol_memcmp_"),
    sc!("sol_memset_"),
    sc!("sol_panic_"),
    sc!("sol_alloc_free_"),
    sc!("sol_invoke_signed_c"),
    sc!("sol_invoke_signed_rust"),
    sc!("sol_create_program_address"),
    sc!("sol_try_find_program_address"),
    sc!("sol_sha256"),
    sc!("sol_keccak256"),
    sc!("sol_secp256k1_recover"),
    sc!("sol_blake3"),
    sc!("sol_curve_validate_point"),
    sc!("sol_curve_group_op"),
    sc!("sol_curve_multiscalar_mul"),
    sc!("sol_curve_pairing_map"),
    sc!("sol_get_clock_sysvar"),
    sc!("sol_get_epoch_schedule_sysvar"),
    sc!("sol_get_fees_sysvar"),
    sc!("sol_get_rent_sysvar"),
    sc!("sol_get_return_data"),
    sc!("sol_set_return_data"),
    sc!("sol_log_data"),
    sc!("sol_get_processed_sibling_instruction"),
    sc!("sol_get_stack_height"),
    sc!("sol_poseidon"),
    sc!("sol_remaining_compute_units"),
    sc!("sol_alt_bn128_group_op"),
    sc!("sol_alt_bn128_compression"),
    sc!("sol_big_mod_exp"),
];

fn syscall_name(hash: u32) -> Option<&'static str> {
    SYSCALLS.iter().find(|e| e.hash == hash).map(|e| e.name)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_name_lookup() {
        // Known syscalls must resolve by their own hash.
        for entry in SYSCALLS {
            let got = syscall_name(entry.hash);
            assert_eq!(got, Some(entry.name), "hash 0x{:08x} did not resolve to \"{}\"", entry.hash, entry.name);
        }
    }

    #[test]
    fn syscall_no_hash_collision() {
        let mut seen = std::collections::HashMap::new();
        for entry in SYSCALLS {
            if let Some(prev) = seen.insert(entry.hash, entry.name) {
                panic!("hash collision: 0x{:08x} shared by \"{}\" and \"{}\"", entry.hash, prev, entry.name);
            }
        }
    }

    #[test]
    fn syscall_unknown_hash_returns_none() {
        // 0x00000000 and 0xFFFFFFFF are very unlikely to match any real entry.
        assert!(syscall_name(0x00000000).is_none());
        assert!(syscall_name(0xFFFFFFFF).is_none());
    }

    #[test]
    fn djb2_empty_string() {
        // djb2("") = initial seed 5381
        assert_eq!(djb2(b""), 5381);
    }

    #[test]
    fn djb2_single_char() {
        // djb2("A") = 5381 * 33 + 65 = 177638 + 65 = 177703
        assert_eq!(djb2(b"A"), 5381u32.wrapping_mul(33).wrapping_add(b'A' as u32));
    }

    #[test]
    fn djb2_is_deterministic() {
        // Same input must always produce the same output.
        assert_eq!(djb2(b"sol_log_"), djb2(b"sol_log_"));
    }
}
