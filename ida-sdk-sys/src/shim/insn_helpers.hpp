#pragma once
#include <idp.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <cstdint>

// ---------------------------------------------------------------------------
// Typed wrappers for insn_t / op_t field access.
// autocxx cannot reach into anonymous unions, so we expose each field
// explicitly here.  All functions are trivial inlines - zero overhead.
// ---------------------------------------------------------------------------

// Read next 8 bytes from the instruction stream and advance insn->size.
inline uint64_t sbf_next_qword(insn_t *insn)
{
    return insn_get_next_qword(insn);
}

// ----- insn_t field accessors -----------------------------------------------
inline uint64_t insn_get_ea(const insn_t *insn)            { return insn->ea; }
inline uint16_t insn_get_size(const insn_t *insn)          { return insn->size; }
inline void     insn_set_itype(insn_t *insn, uint16_t itype) { insn->itype = itype; }

// ----- op_t operand builders ------------------------------------------------
inline op_t *insn_op(insn_t *insn, int n) { return &insn->ops[n]; }

inline void op_set_shown(op_t *op)                  { op->set_shown(); }
inline void op_set_type(op_t *op, optype_t t)        { op->type  = t; }
inline void op_set_dtype(op_t *op, op_dtype_t d)     { op->dtype = d; }

// Register operand
inline void op_set_reg(op_t *op, uint16_t r)         { op->reg   = r; }

// Immediate operand (value)
inline void op_set_value(op_t *op, uval_t v)         { op->value = v; }

// Memory / displacement operand: base register in phrase, byte offset in addr
inline void op_set_phrase(op_t *op, uint16_t r)      { op->phrase = r; }
inline void op_set_addr(op_t *op, ea_t a)            { op->addr   = a; }

// Near-code target (call / branch)
inline void op_set_near(op_t *op, ea_t target)
{
    op->type  = o_near;
    op->dtype = dt_code;
    op->addr  = target;
    op->set_shown();
}

// ----- Cross-reference helpers (used in emu) --------------------------------
inline void sbf_add_cref(const insn_t *insn, ea_t to, int opoff, cref_t type)
{
    insn_add_cref(*insn, to, opoff, type);
}

inline void sbf_add_dref(const insn_t *insn, ea_t to, int opoff, dref_t type)
{
    insn_add_dref(*insn, to, opoff, type);
}

// ----- insn_t additional readers -------------------------------------------
inline uint16_t insn_get_itype(const insn_t *insn) { return insn->itype; }

// ----- op_t field readers (used in emu / out) ------------------------------
inline uint8_t  op_get_type(const op_t *op)   { return op->type; }
inline uint16_t op_get_reg(const op_t *op)    { return op->reg; }
inline uint16_t op_get_phrase(const op_t *op) { return op->phrase; }
inline uint64_t op_get_addr(const op_t *op)   { return (uint64_t)op->addr; }
inline uint64_t op_get_value(const op_t *op)  { return (uint64_t)op->value; }

// Direct per-slot address readers (avoid const op_t* return type issues)
inline uint64_t insn_op0_addr(const insn_t *insn) { return (uint64_t)insn->ops[0].addr; }
inline uint64_t insn_op2_addr(const insn_t *insn) { return (uint64_t)insn->ops[2].addr; }

// Typed flow helpers - embed the cref_t constant so Rust doesn't need it
inline void sbf_add_flow(const insn_t *insn)
{
    insn_add_cref(*insn, insn->ea + insn->size, 0, fl_F);
}
inline void sbf_add_jump(const insn_t *insn, uint64_t target)
{
    insn_add_cref(*insn, (ea_t)target, 0, fl_JN);
}

// ----- outctx_t wrappers (used in out) -------------------------------------
inline void   ctx_out_mnemonic(outctx_t *ctx)      { ctx->out_mnemonic(); }
inline bool   ctx_out_one_operand(outctx_t *ctx, int n) { return ctx->out_one_operand(n); }

// Peek at operand type inside the ctx's insn without exposing const op_t*
inline uint8_t ctx_insn_op_type(outctx_t *ctx, int n) { return ctx->insn.ops[n].type; }

// Output register by index using the processor's register name table
inline void ctx_out_reg(outctx_t *ctx, uint16_t reg)
{
    ctx->out_register(get_ph()->reg_names[reg]);
}

// Output a value as hex (COLOR_NUMBER)
inline void ctx_out_hex(outctx_t *ctx, uint64_t v) { ctx->out_long((sval_t)v, 16); }

// Output a value as signed decimal (for displacement offsets)
inline void ctx_out_sdec(outctx_t *ctx, uint64_t v)
{
    ctx->out_long((sval_t)(int64_t)v, 10);
}

// Output a name expression for an o_near / o_mem operand
inline bool ctx_out_name_expr(outctx_t *ctx, const op_t *op, uint64_t ea)
{
    return ctx->out_name_expr(*op, (ea_t)ea, BADADDR);
}

// Single-character output helpers (avoid passing char from Rust)
inline void ctx_out_open_bracket(outctx_t *ctx)  { ctx->out_symbol('['); }
inline void ctx_out_close_bracket(outctx_t *ctx) { ctx->out_symbol(']'); }
inline void ctx_out_comma(outctx_t *ctx)         { ctx->out_symbol(','); }
inline void ctx_out_plus_sign(outctx_t *ctx)     { ctx->out_symbol('+'); }
inline void ctx_out_minus_sign(outctx_t *ctx)    { ctx->out_symbol('-'); }
inline void ctx_out_space(outctx_t *ctx)         { ctx->out_char(' '); }
inline void ctx_flush(outctx_t *ctx)             { ctx->flush_outbuf(); }

// Get the itype of the instruction being output
inline uint16_t ctx_insn_itype(const outctx_t *ctx) { return ctx->insn.itype; }

// Output a keyword string (colored)
inline void ctx_out_keyword(outctx_t *ctx, const char *s) { ctx->out_keyword(s); }

// Call xref: emit fl_CN toward target
inline void sbf_add_call_near(const insn_t *insn, uint64_t target)
{
    insn_add_cref(*insn, (ea_t)target, 0, fl_CN);
}
