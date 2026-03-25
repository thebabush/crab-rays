#![allow(unsafe_op_in_unsafe_fn, clippy::empty_line_after_doc_comments, clippy::too_many_arguments)]

pub mod insn;
pub mod loader;
pub mod op;
pub mod outctx;
pub mod procmod;

/// Opaque failure returned by IDA API calls that do not provide error details.
#[derive(Debug)]
pub struct IdaError;

/// Result type for IDA API calls that can fail without providing error details.
pub type IdaResult<T = ()> = Result<T, IdaError>;

pub use insn::{Insn, InsnMut};
pub use op::{OpKind, OpMut, OpRef};
pub use outctx::OutCtx;
