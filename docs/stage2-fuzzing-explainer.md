# Stage 2 Fuzzing Explainer

This note clarifies what is being fuzzed in Stage 2 and how it differs from Stage 1.

## Short Answer

Stage 2 fuzzes **raw testcase bytes**. Those bytes are parsed into a `Candidate`, then run through the RLBox boundary path, validator, sink, and oracle.

So yes: AFL++ is a smarter input generator, but with feedback that helps it explore new behavior faster than random generation.

## What Is Being Fuzzed

In Stage 2, AFL++ mutates file input bytes. Each testcase drives this pipeline:

`bytes -> parser -> candidate -> RLBox boundary -> validator -> sink -> oracle`

Concretely:

- `bytes -> parser`
  - `src/core/byte_parser.hpp` maps bytes to `Candidate { offset, length }`.
- `candidate -> RLBox boundary`
  - `src/core/rlbox_adapter.hpp` passes fields through RLBox calls and unwraps with `copy_and_verify(...)`.
- `validator`
  - `src/core/validators.hpp` decides whether the value is accepted.
- `sink + oracle`
  - `src/core/sink_oracle.hpp` simulates trusted use and reports unsafe accepted values.
  - Oracle failure uses `abort()` so AFL++ records failures as crashes.

## Stage 1 vs Stage 2

- **Stage 1 (random generation)**
  - Inputs come from host-side random sampling.
  - Search is unguided and may waste effort on repetitive safe cases.

- **Stage 2 (coverage-guided fuzzing)**
  - Inputs come from AFL++ mutations of testcase bytes.
  - AFL++ keeps inputs that increase coverage and prioritizes promising mutations.
  - Expected outcome: faster discovery of validator-bypass cases under the same budget.

## Why This Still Tests Validators

Although AFL++ mutates bytes, the security question remains the same:

Does any value that **passes validation** still cause unsafe behavior at the sink?

If yes, Stage 2 found a validator insufficiency for that use-site.

## Improvements Layered on Top

The Stage 2 harness adds three pieces on top of the basic file-input loop.

### 1. AFL++ persistent mode

The AFL targets compile in two modes based on the toolchain:

- With `afl-clang-fast++`: `__AFL_HAVE_MANUAL_CONTROL` is defined, so the entrypoint calls `__AFL_INIT()` and reuses the process across test cases via `__AFL_LOOP(10000)`. This keeps RLBox setup amortized and typically yields 10-100x exec speed vs. fork-per-testcase mode.
- With MSVC / regular clang: the same source falls back to reading `argv[1]` as a file, so local smoke-testing and reproduction work unchanged.

### 2. Sink-dependent validator sufficiency

A validator is only **sufficient relative to a sink**. The repo pairs weak vs strong behavior under comparable budgets:

| Pair | Weak side (expect crashes) | Control (expect clean) |
| --- | --- | --- |
| Range write | `bad_validator` + `sink_use` | `good_validator` + `sink_use` |
| 16-elem index | `length_only_validator` + `sink_indexed_read` | (same sink would be safe under `good_validator`) |
| 4-elem index | `unchecked_validator` + `sink_indexed_read_small` | `clamp_small_index` + `unchecked_validator` + same sink |
| Division | `unchecked_validator` + `sink_divide` | `nonzero_validator` + `sink_divide` |

Full target names: `stage2_afl_bad_validator` / `good`, `length_only_indexed`, `unchecked_indexed` / `clamped_indexed`, `div_by_zero` / `div_by_zero_guarded`.

### 3. Boundary-focused seed corpus

`scripts/gen_seeds.py` enumerates offset/length pairs near validator and sink boundaries, then **filters** so every seed is safe under **all** shipped AFL `(validator, sink)` pairs (otherwise AFL aborts on a crashing seed). The corpus size changes when new targets tighten that universal-safe set.
