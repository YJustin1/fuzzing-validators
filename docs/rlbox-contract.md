# RLBox Validator Fuzzing Contract

## Problem Definition

This project tests whether RLBox-style host validators are sufficient for the way values are used after untainting.

A finding exists when:

1. A candidate value is treated as sandbox output.
2. The host validator accepts it.
3. The trusted use-site performs an unsafe action or violates an invariant.

## Canonical Pipeline

`sandbox_output -> validator -> sink -> oracle`

- **sandbox_output**: candidate untrusted value (synthetic, fuzzed, or library-derived).
- **validator**: host check used before untainting.
- **sink**: trusted code path that consumes the accepted value.
- **oracle**: detector for crash, sanitizer signal, or explicit invariant failure.

## Stage Definitions

- **Stage 1**: Random generator against isolated validator harness.
- **Stage 2**: Coverage-guided fuzzing of validator harness (no library model).
- **Stage 3**: Library-aware replay using captured sandbox outputs.
- **Stage 4**: Integrated end-to-end fuzzing across library + validator + sink.

## Non-Goals

- Generic parser fuzzing that ignores the validator/sink relationship.
- Measuring throughput without security relevance.

## Required Artifacts Per Target

- Target implementation (`validator + sink + oracle`)
- Run command with execution budget
- Repro input for any discovered failure
- Classification of finding (bounds, integer overflow, stale state, etc.)
