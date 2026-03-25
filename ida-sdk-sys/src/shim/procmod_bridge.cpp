#include "procmod_bridge.hpp"

// Minimal concrete procmod_t that routes IDA 9.x on_event calls back through
// the notify function so the va_list dispatch handles both paths uniformly.
struct RustProcmodT : public procmod_t
{
    virtual ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
        return rust_procmod_notify(nullptr, (int)code, va);
    }
};

ssize_t idaapi rust_procmod_notify(void * /*ud*/, int code, va_list va)
{
    switch ( code )
    {
        case processor_t::ev_get_procmod:
            return (ssize_t)(size_t) new RustProcmodT();

        case processor_t::ev_ana_insn:
        {
            insn_t *insn = va_arg(va, insn_t *);
            return rust_ana_insn(insn);
        }

        case processor_t::ev_emu_insn:
        {
            const insn_t *insn = va_arg(va, const insn_t *);
            return rust_emu_insn(insn);
        }

        case processor_t::ev_out_insn:
        {
            outctx_t *ctx = va_arg(va, outctx_t *);
            return rust_out_insn(ctx);
        }

        case processor_t::ev_out_operand:
        {
            outctx_t *ctx = va_arg(va, outctx_t *);
            const op_t *op  = va_arg(va, const op_t *);
            return rust_out_operand(ctx, op);
        }

        default:
            return 0;
    }
}
