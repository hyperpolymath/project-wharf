# SPDX-License-Identifier: PMPL-1.0
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# ClusterFuzzLite Dockerfile for Rust fuzzing

FROM gcr.io/oss-fuzz-base/base-builder-rust

COPY . $SRC/project-wharf
WORKDIR $SRC/project-wharf

COPY .clusterfuzzlite/build.sh $SRC/
