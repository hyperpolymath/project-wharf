#!/bin/bash -eu
# SPDX-License-Identifier: PMPL-1.0
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# ClusterFuzzLite build script for Rust fuzzing

cd "$SRC"/project-wharf

# Install nightly for fuzzing
rustup install nightly
rustup default nightly

# Build fuzz targets
cargo +nightly fuzz build

# Copy fuzz targets to output
for target in fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_*; do
    if [ -f "$target" ] && [ -x "$target" ]; then
        cp "$target" $OUT/
    fi
done
