#!/usr/bin/env bash

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Runs the unit tests of every Envoy dynamic module under
# cmd/dataplane/envoy/dynamic-modules. They are Rust, so `go test ./...` never
# reaches them. Needs cargo, plus clang and libclang-dev for the SDK's bindgen
# step; cmd/dataplane/envoy/Dockerfile builds with the same. A module that ran
# no tests fails, so a broken wiring cannot pass as green.

set -o errexit -o nounset -o pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "${ROOT}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found: install a Rust toolchain (https://rustup.rs) with clang and libclang-dev" >&2
  exit 1
fi

status=0
for manifest in cmd/dataplane/envoy/dynamic-modules/*/Cargo.toml; do
  module="$(dirname "${manifest}")"
  echo "==> cargo test in ${module}"
  log="$(mktemp)"
  if ! cargo test --locked --manifest-path "${manifest}" 2>&1 | tee "${log}"; then
    status=1
  fi
  if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed' "${log}"; then
    echo "${module}: no tests ran" >&2
    status=1
  fi
  rm -f "${log}"
done
exit "${status}"
