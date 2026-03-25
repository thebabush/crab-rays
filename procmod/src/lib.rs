// Re-export SDK bindings from the shared ida-sdk-sys crate.
// All autocxx build logic and raw FFI generation live there.

pub mod ffi {
    pub use ida_sdk_sys::ffi::*;
}
