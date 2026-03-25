use std::ffi::{c_int, c_void, CStr};
use ida_sdk_sys::ffi;
use crate::{IdaError, IdaResult};

/// Loader descriptor - mirrors `loader_t` from loader.hpp (48 bytes on 64-bit).
#[repr(C)]
pub struct LoaderT {
    pub version:         u32,
    pub flags:           u32,
    pub accept_file:     unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *const std::ffi::c_char) -> c_int,
    pub load_file:       unsafe extern "C" fn(*mut c_void, u16, *const std::ffi::c_char),
    pub save_file:       *const c_void,
    pub move_segm:       *const c_void,
    pub process_archive: *const c_void,
}
unsafe impl Sync for LoaderT {}
const _: () = assert!(std::mem::size_of::<LoaderT>() == 48);

// autocxx generates functions that take `*mut autocxx::c_void`, not `*mut std::ffi::c_void`.
// We store the pointer in the autocxx type internally and cast on construction.
type AcVoid = autocxx::c_void;

// ---------------------------------------------------------------------------
// Typed handles for opaque IDA pointers
// ---------------------------------------------------------------------------

/// Wrapper around a `linput_t *` received from IDA loader callbacks.
pub struct LinputRef(*mut AcVoid);

impl LinputRef {
    /// # Safety
    /// `li` must be a valid, non-null `linput_t *` for the lifetime of this handle.
    pub unsafe fn from_raw(li: *mut c_void) -> Self { Self(li as *mut AcVoid) }

    pub fn seek(&self, pos: i64) {
        unsafe { ffi::ldr_seek(self.0, pos) }
    }

    pub fn read(&self, buf: &mut [u8]) -> i64 {
        unsafe { ffi::ldr_read(self.0, buf.as_mut_ptr(), buf.len() as u64) }
    }

    pub fn size(&self) -> i64 {
        unsafe { ffi::ldr_size(self.0) }
    }

    pub fn file_to_base(&self, foff: i64, ea1: u64, ea2: u64) -> bool {
        unsafe { ffi::ldr_file_to_base(self.0, foff, ea1, ea2) }
    }
}

/// Wrapper around a `qstring *` received from IDA loader callbacks.
pub struct QStrRef(*mut AcVoid);

impl QStrRef {
    /// # Safety
    /// `s` must be a valid, non-null `qstring *` for the lifetime of this handle.
    pub unsafe fn from_raw(s: *mut c_void) -> Self { Self(s as *mut AcVoid) }

    pub fn set(&self, v: &CStr) {
        unsafe { ffi::ldr_qstr_set(self.0, v.as_ptr()) }
    }
}

// ---------------------------------------------------------------------------
// Global IDA database helpers
// ---------------------------------------------------------------------------

pub fn ldr_set_proc() {
    ffi::ldr_set_proc();
}

pub fn ldr_add_seg(start: u64, end: u64, name: &CStr, sclass: &CStr) -> IdaResult {
    let ok = unsafe { ffi::ldr_add_seg(start, end, name.as_ptr(), sclass.as_ptr()) };
    if ok { Ok(()) } else { Err(IdaError) }
}

pub fn ldr_add_entry(ea: u64, name: &CStr) -> IdaResult {
    let ok = unsafe { ffi::ldr_add_entry(ea, name.as_ptr()) };
    if ok { Ok(()) } else { Err(IdaError) }
}

pub fn ldr_set_name(ea: u64, name: &CStr) -> IdaResult {
    let ok = unsafe { ffi::ldr_set_name(ea, name.as_ptr()) };
    if ok { Ok(()) } else { Err(IdaError) }
}

pub fn ldr_filename_cmt() {
    ffi::ldr_filename_cmt();
}

pub fn ldr_patch_qword(ea: u64, val: u64) {
    ffi::ldr_patch_qword(ea, val);
}
