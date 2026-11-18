# Integrator Code Quality & Architectural Documentation Standards

## Universal Documentation Standard
Every source file in the Integrator codebase—across Rust (`app/src/`), Swift (`ui-macos/`, `app/src/*.swift`), C++ (`app/src/*.cpp`), Objective-C (`app/src/*.m`), and C# (`ui-windows/`)—must adhere to these documentation requirements. This applies unconditionally to all existing code and all newly generated or modified code.

### 1. Exhaustive Architectural Header
Every file must open with a comprehensive top-of-file documentation block detailing:
- **Module Purpose & Scope**: What system responsibility this file owns, including its state lifecycle and core abstractions.
- **Architectural Linkages & Dependencies**:
  - **Upstream Callers**: Who instantiates, invokes, or monitors this module (e.g., `core.rs`, UI view models, native platform event loops).
  - **Downstream Callees**: What underlying OS APIs, hardware bridges, crypto primitives, or network layers this file depends on.
  - **Cross-Platform / Cross-Device Flow**: How data or commands passing through this file relate to the counterpart machine (Mac ↔ Windows 11) over TCP/UDP transport or shared memory.
- **Threading & Concurrency Model**: Which threads, dispatch queues, or async runtimes execute this code (e.g., Tokio multi-thread runtime, Windows STA UI thread, macOS main GCD thread, low-level OS hook threads).
- **Security & Safety Invariants**: Cryptographic guarantees, memory safety boundaries (`unsafe` blocks), rate-limiting/clamping rules, and failure containment strategies.

### 2. Comprehensive Function & Struct Documentation
- **Structs & Enums**: Explain the semantic purpose of every type and every individual field, including units of measurement (e.g., bytes, milliseconds, DIPs, fixed-point ratios), expected ranges, and serialization formats (Bincode, JSON, raw bytes).
- **Functions & Methods**:
  - Provide doc comments explaining the function's algorithm, preconditions, postconditions, and return values.
  - Explain *why* specific parameters and options are chosen.
  - Document all error cases and retry semantics.

### 3. Line-by-Line & Block-by-Block Inline Comments
- Complex algorithmic steps (e.g., coordinate normalization across asymmetric displays, SPAKE2 key derivation, frame packet framing, ring-buffer slot swapping, virtual camera activation) must have line-by-line or tight block comments.
- Explain non-obvious constants, OS-specific magic numbers (e.g., Windows COM GUIDs, Media Foundation attributes, macOS IOKit properties), and performance optimizations.
- State explicitly why alternative approaches were rejected (e.g., why FrameServer cannot have `MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES`).

### 4. Zero Code Regressions
- Adding comments must never alter existing logic, modify API contracts, or break build/test pipelines.
- All code must continue to pass `cargo test --lib`, `cargo build --release`, and platform compilation scripts (`build-universal-app.sh`, `dotnet build`).
