#!/usr/bin/env python3
"""Generate a boundary-focused seed corpus for Stage 2 AFL campaigns.

Each seed is an 8-byte little-endian (offset: int32, length: int32) pair
that the Stage 2 byte parser maps directly into a Candidate.

We deliberately pick values at/near the validator boundaries so AFL
starts with good coverage of the decision branches:

  - buffer size = 128
  - index table size = 16
  - 0, 1, size-1, size, size+1 for both offset and length
  - plus a few non-boundary "interior" values

Writes one file per seed to ``seeds/``. Safe to run repeatedly; existing
files with the same name will be overwritten.
"""
from __future__ import annotations

import os
import struct

BUFFER_SIZE = 128
INDEX_TABLE_SIZE = 16
SMALL_INDEX_SIZE = 4  # sink_indexed_read_small; same span as host_examples small tables

SEED_DIR = os.path.join(os.path.dirname(__file__), "..", "seeds")
SEED_DIR = os.path.normpath(SEED_DIR)


def encode(offset: int, length: int) -> bytes:
    return struct.pack("<ii", offset, length)


def build_corpus() -> list[tuple[str, bytes]]:
    interesting_offsets = {
        0,
        1,
        2,
        3,
        INDEX_TABLE_SIZE - 1,
        INDEX_TABLE_SIZE,
        INDEX_TABLE_SIZE + 1,
        BUFFER_SIZE - 1,
        BUFFER_SIZE,
        BUFFER_SIZE + 1,
        -1,
        64,
    }
    interesting_lengths = {
        0,
        1,
        BUFFER_SIZE - 1,
        BUFFER_SIZE,
        BUFFER_SIZE + 1,
        -1,
        32,
    }

    corpus: list[tuple[str, bytes]] = []
    idx = 0
    for off in sorted(interesting_offsets):
        for ln in sorted(interesting_lengths):
            # AFL refuses to start on crashing seeds. The shared corpus is
            # used by every Stage 2 AFL target, so we require each seed to
            # be safe under all (validator, sink) pairings we ship.
            #
            #   bad_validator + sink_use:
            #     safe if bad_validator rejects OR sink_use is in-bounds.
            #   length_only_validator + sink_indexed_read:
            #     safe if length_only rejects OR offset is a valid index
            #     (0..INDEX_TABLE_SIZE).
            #   good_validator + sink_use:
            #     good_validator only accepts sink-safe inputs, always ok.
            #   unchecked_validator + sink_indexed_read_small:
            #     no validator, so we need offset in [0, SMALL_INDEX_SIZE).
            #   unchecked_validator + sink_divide:
            #     no validator, so we need offset != 0.
            #   clamped / div_by_zero_guarded: always safe.
            bad_accepts = 0 <= off < BUFFER_SIZE
            sink_use_safe = off >= 0 and ln >= 0 and (off + ln) <= BUFFER_SIZE
            bad_pair_safe = (not bad_accepts) or sink_use_safe

            length_only_accepts = 0 <= ln < BUFFER_SIZE
            indexed_safe = 0 <= off < INDEX_TABLE_SIZE
            length_only_pair_safe = (not length_only_accepts) or indexed_safe

            unchecked_indexed_safe = 0 <= off < SMALL_INDEX_SIZE
            div_unchecked_safe = off != 0

            if not (bad_pair_safe
                    and length_only_pair_safe
                    and unchecked_indexed_safe
                    and div_unchecked_safe):
                continue
            name = f"seed_{idx:03d}_o{off}_l{ln}.bin"
            corpus.append((name, encode(off, ln)))
            idx += 1
    return corpus


def main() -> None:
    os.makedirs(SEED_DIR, exist_ok=True)
    corpus = build_corpus()
    for name, data in corpus:
        path = os.path.join(SEED_DIR, name)
        with open(path, "wb") as fh:
            fh.write(data)
    print(f"Wrote {len(corpus)} seeds to {SEED_DIR}")


if __name__ == "__main__":
    main()
