# 🦀 crab-rays 🦀

> **Unsupported.** This is personal experimental code. It has only been tested on macOS (ARM64) with IDA 9.3. No other platforms, IDA versions, or configurations are known to work or are planned.

Experiments in writing IDA Pro processor modules and loaders in Rust.

The concrete subject is Solana SBF (sBPF v2) - a useful target because it's small enough to be tractable but real enough to be interesting. The actual goal is to figure out how far you can get with Rust + `autocxx` before the IDA SDK fights back.

## Building

Requires the IDA SDK. Set `IDASDK` to its `src/` subdirectory:

```sh
IDASDK=~/idasdk93/src cargo build           # debug
IDASDK=~/idasdk93/src cargo build --release  # release
```

## Installation

The processor module and loader are compiled into a single dylib. Symlink it into the appropriate IDA directories:

**Debug:**
```sh
ln -sf "$(pwd)/target/debug/libsbf.dylib"   ~/.idapro/procs/sbf.dylib
ln -sf "$(pwd)/target/debug/libsbf.dylib"   ~/.idapro/loaders/sbf.dylib
```

**Release:**
```sh
ln -sf "$(pwd)/target/release/libsbf.dylib" ~/.idapro/procs/sbf.dylib
ln -sf "$(pwd)/target/release/libsbf.dylib" ~/.idapro/loaders/sbf.dylib
```

Symlinks mean `cargo build` is all you need to reload - no copying.
