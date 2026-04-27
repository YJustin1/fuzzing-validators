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

The Stage 2 harness now adds three ingredients on top of the basic file-input loop.

### 1. AFL++ persistent mode

The AFL targets compile in two modes based on the toolchain:

- With `afl-clang-fast++`: `__AFL_HAVE_MANUAL_CONTROL` is defined, so the entrypoint calls `__AFL_INIT()` and reuses the process across test cases via `__AFL_LOOP(10000)`. This keeps RLBox setup amortized and typically yields 10-100x exec speed vs. fork-per-testcase mode.
- With MSVC / regular clang: the same source falls back to reading `argv[1]` as a file, so local smoke-testing and reproduction work unchanged.

### 2. Sink-dependent validator sufficiency

A single validator is not categorically "good" or "bad" — sufficiency depends on the sink. To exercise this, the harness ships a second sink and a second deliberately-weak validator:

- `sink_use` (range sink): uses both `offset` and `length` to `memset` into a buffer. Safe under `good_validator`; unsafe under `bad_validator`.
- `sink_indexed_read` (index sink): uses `offset` as an index into a 16-entry table. Safe under `good_validator`; unsafe under `length_only_validator`, which only constrains `length` and leaves `offset` unbounded.

This gives three paired AFL targets:

| Target | Validator | Sink | Expected |
| --- | --- | --- | --- |
| `stage2_afl_bad_validator` | `bad_validator` | `sink_use` | crashes found |
| `stage2_afl_good_validator` | `good_validator` | `sink_use` | no crashes |
| `stage2_afl_length_only_indexed` | `length_only_validator` | `sink_indexed_read` | crashes found |

The length-only + indexed pair is the clearest demonstration of the core proposal claim: validation must be evaluated against the concrete use-site.

### 3. Boundary-focused seed corpus

`scripts/gen_seeds.py` writes 21 seeds that cluster around validator/sink decision boundaries (0, 1, `BUFFER_SIZE-1`, `BUFFER_SIZE`, `INDEX_TABLE_SIZE-1`, `INDEX_TABLE_SIZE`, and negatives). Every seed is required to be crash-safe across all three AFL targets so the same `seeds/` directory can bootstrap any campaign without triggering AFL's "crashing seed" abort.
