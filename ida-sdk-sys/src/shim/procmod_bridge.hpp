#pragma once
#include <idp.hpp>
#include <ua.hpp>

// Rust callbacks - implemented by the target procmod crate and exported as extern "C".
extern "C" ssize_t rust_ana_insn(insn_t *insn);
extern "C" ssize_t rust_emu_insn(const insn_t *insn);
extern "C" ssize_t rust_out_insn(outctx_t *ctx);
extern "C" ssize_t rust_out_operand(outctx_t *ctx, const op_t *op);

// Generic procmod notify hook for Rust procmods.
// Install this in processor_t._notify.  It unpacks va_list events and
// dispatches to the four Rust callbacks declared above.
extern "C" ssize_t idaapi rust_procmod_notify(void *ud, int code, va_list va);
