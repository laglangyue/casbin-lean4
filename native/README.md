# Native regular-expression primitive

Authorization, model parsing, policy management and expression evaluation are implemented in Lean. `regex.cpp` is a narrow FFI binding to Google's RE2, configured for UTF-8, leftmost-first matching, named captures and nonthrowing compile errors. The extra RE2 `\C` byte escape is rejected because Go regexp does not accept it.

`scripts/build-re2.py` downloads RE2 **2023-03-01** from Google, verifies SHA-256 **7a9a4824958586980926a300b4717202485c4b4115ac031822e29aa4ef207e48**, and builds a position-independent static library. Sources, objects and the upstream BSD license are kept under `.lake/native/`; the resulting library is linked into the executables. No Go authorization process or shell evaluation is used at runtime.

RE2 copyright belongs to The RE2 Authors. License: https://github.com/google/re2/blob/2023-03-01/LICENSE

Lean's interpreter requires the primitive's native module to be loaded. `scripts/run-lean.py` builds and loads only this primitive module before running a Lean example. Normal Lake executables link it automatically.

## Linux runtime dependencies

On Ubuntu/Debian install `g++ libc++-dev libc++abi-dev libuv1-dev libgmp-dev sqlite3`. Other Linux distributions need equivalent development libraries. RE2 uses the system C++ compiler; Lean 4.35.0 also links against libc++, libc++abi, libuv and GMP. The libc++ development packages include the required LLVM unwind dependencies. macOS supplies the C++ runtime with the system tools, and Lean's macOS toolchain includes its other native libraries.

On Linux, set `LEAN_CC=cc` before running Lake. Lake queries the system C++ compiler for the libstdc++ library path, and the system C compiler links against the host's glibc. This keeps the native code's headers and linked runtimes consistent even when Lean's bundled sysroot uses an older glibc. Linux binaries therefore depend on the build host's native runtime versions.
