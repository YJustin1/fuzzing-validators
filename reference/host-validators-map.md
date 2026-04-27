# Host.cpp / tests.rs mapping

`docs/host.cpp` and `docs/tests.rs` come from an upstream Haybale-based
test suite. Haybale is a symbolic-execution tool, so it can exercise
every function with symbolic inputs and symbolic sandbox memory. Our
tool is a dynamic fuzzer, which means we can only *observe* concrete
runs. That changes what each case looks like on our side.

This doc tracks every function in `docs/host.cpp`, its `tests.rs`
expectation, and exactly how we reproduce (or deliberately skip) it.

## Category summary

`docs/host.cpp` has three kinds of functions, and each kind lives in
a different place in this repo:

| Category | Shape | Where we handle it |
| --- | --- | --- |
| **(A) Constant-behavior** | No inputs; outcome is fixed | Smoke runner (`smoke_host_examples` + `scripts/smoke_test.py`) |
| **(B) Arg-driven** | One scalar argument controls outcome | Smoke runner with a pinned argument |
| **(C) RLBox-specific** | Sandbox memory is the attacker-controlled input | Dedicated AFL harnesses (`stage2_afl_unchecked_indexed`, `stage2_afl_clamped_indexed`) |

Only category (C) actually exercises the RLBox boundary, so that's
where the fuzzer delivers real value. Categories (A) and (B) are here
as a parity check against `tests.rs`.

## Full mapping

| `host.cpp` function | `tests.rs` expects | Category | Our target | Expected outcome |
| --- | --- | --- | --- | --- |
| `trivial_array_read` | `Ok` | A | `smoke_host_examples trivial_array_read` | exit 0 |
| `repeated_array_read` | `Ok` | A | `smoke_host_examples repeated_array_read` | exit 0 |
| `trivial_array_read_2d` | `Ok` | A | `smoke_host_examples trivial_array_read_2d` | exit 0 |
| `trivial_struct_read` | `Ok` | A | `smoke_host_examples trivial_struct_read` | exit 0 |
| `trivial_struct_read_nested` | `Ok` | A | `smoke_host_examples trivial_struct_read_nested` | exit 0 |
| `basic_null_read` | `Err` | A | `smoke_host_examples basic_null_read` | SIGSEGV / AV |
| `basic_null_write` | `Err` | A | `smoke_host_examples basic_null_write` | SIGSEGV / AV |
| `basic_div_by_zero` | `Err` | A | `smoke_host_examples basic_div_by_zero` | SIGFPE / STATUS_INTEGER_DIVIDE_BY_ZERO |
| `basic_oob_read` | `Err` | A | `smoke_host_examples basic_oob_read` | **ASan-only**: reads neighboring stack without sanitizers |
| `basic_oob_write` | `Err` | A | `smoke_host_examples basic_oob_write` | **ASan-only**: writes neighboring stack without sanitizers |
| `basic_oob_read_from_arg` | `Err` | B | `smoke_host_examples basic_oob_read_from_arg 99` | **ASan-only** (same caveat) |
| `basic_null_write2` | `Err` | B | `smoke_host_examples basic_null_write2` (pinned to `nullptr`) | SIGSEGV / AV |
| `basic_div_by_zero2` | `Err` | B | `smoke_host_examples basic_div_by_zero2 0` | SIGFPE / divide-by-zero |
| `basic_div_by_zero_guarded` | `Ok` | B | `smoke_host_examples basic_div_by_zero_guarded 0` and `... 7` | exit 0 |
| `sandbox_array_index_unchecked_unsafe` | `Err` | C | `stage2_afl_unchecked_indexed` | AFL finds crash via oracle `small_index_out_of_bounds` |
| `sandbox_primitive_array_index_unchecked_unsafe` | `Err` | C | `stage2_afl_unchecked_indexed` (same model - primitive vs `std::array` doesn't change our fuzz pipeline) | AFL finds crash |
| `sandbox_array_index_unchecked_safe` | `Err` | C | `stage2_afl_unchecked_indexed` (see note below) | AFL finds crash |
| `sandbox_array_index_checked` | `Ok` | C | `stage2_afl_clamped_indexed` | AFL should report 0 crashes |

## Why `sandbox_array_index_unchecked_safe` still crashes for us

In `host.cpp` this function writes a known-safe value (`2`) into the
sandbox array before reading it back and using it as a host-array
index. On first glance that looks safe - we just wrote `2`, indexing
a 4-element array with `2` is fine. Haybale still flags it (`Err`)
because its attacker model allows the sandbox memory to be modified
concurrently between the write and the read (TOCTOU race). That's an
intentionally paranoid, multithreaded model.

Our fuzzer models the same thing by construction: every sandbox read
in our pipeline returns fuzzer-controlled bytes, *regardless* of what
the sandboxed code just wrote. So the `_safe` variant and the plain
`_unchecked_unsafe` variant collapse into the same fuzz target
(`stage2_afl_unchecked_indexed`) with the same expected outcome
(crash). This matches the `tests.rs` verdict.

## Division-by-zero family (bonus)

The `basic_div_by_zero2` / `basic_div_by_zero_guarded` pair is also
available as a matched pair of AFL targets, useful for stress-testing
the oracle and report pipeline with a non-bounds bug class:

| Target | Validator | Sink | Expected |
| --- | --- | --- | --- |
| `stage2_afl_div_by_zero` | `unchecked_validator` | `sink_divide` | crash (`divide_by_zero`) |
| `stage2_afl_div_by_zero_guarded` | `nonzero_validator` | `sink_divide` | no crashes |

Unlike the array-index family these don't exercise an RLBox boundary
in the traditional sense - the "attacker value" here is a denominator,
not an index. They're here to demonstrate that the same
validator / sink / oracle framing covers non-bounds bug classes too.

## Running

### Smoke test (categories A + B)

Build with MSVC Debug (Windows) or any local toolchain, then:

```powershell
python scripts/smoke_test.py
```

The runner prints a per-case table and a category legend. For a fair
result on the ASan-only rows, build with `-DENABLE_SANITIZERS=ON` on
Linux and pass `--binary` to the instrumented executable.

### AFL campaigns (category C + division bonus)

```powershell
scripts/fuzz.ps1 stage2_afl_unchecked_indexed out_unchecked 600
scripts/fuzz.ps1 stage2_afl_clamped_indexed   out_clamped   600
scripts/fuzz.ps1 stage2_afl_div_by_zero       out_div       300
scripts/fuzz.ps1 stage2_afl_div_by_zero_guarded out_div_g   300
```

Then aggregate:

```powershell
scripts/report.ps1 out_unchecked out_clamped out_div out_div_g
```

Calibration expectation:

- `stage2_afl_unchecked_indexed`: non-zero crashes, all bucketed as `small_index_out_of_bounds`.
- `stage2_afl_clamped_indexed`: zero crashes.
- `stage2_afl_div_by_zero`: non-zero crashes, all bucketed as `divide_by_zero`.
- `stage2_afl_div_by_zero_guarded`: zero crashes.
