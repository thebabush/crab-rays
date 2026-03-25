// constants_check.cpp - compile-time verification that hand-copied Rust
// constants in ida-sdk match the authoritative IDA SDK definitions.
//
// If any assertion fires, update the corresponding constant in:
//   ida-sdk/src/procmod.rs  - CF_* flags
//
// Note: optype_t (o_*) and op_dtype_t (dt_*) values are NOT checked here;
// they are consumed directly from the autocxx-generated ffi enums and can
// never be out of sync.

#include <idp.hpp>   // CF_* instruction feature bits

// ---------------------------------------------------------------------------
// CF_ instruction feature bits (idp.hpp)
// ---------------------------------------------------------------------------
static_assert(CF_STOP == 0x00001, "CF_STOP mismatch - update ida-sdk/src/procmod.rs");
static_assert(CF_CALL == 0x00002, "CF_CALL mismatch - update ida-sdk/src/procmod.rs");
static_assert(CF_CHG1 == 0x00004, "CF_CHG1 mismatch - update ida-sdk/src/procmod.rs");
static_assert(CF_USE1 == 0x00100, "CF_USE1 mismatch - update ida-sdk/src/procmod.rs");
static_assert(CF_USE2 == 0x00200, "CF_USE2 mismatch - update ida-sdk/src/procmod.rs");
static_assert(CF_USE3 == 0x00400, "CF_USE3 mismatch - update ida-sdk/src/procmod.rs");

