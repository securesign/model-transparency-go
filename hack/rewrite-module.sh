#!/usr/bin/env bash
# Copyright 2025 The Sigstore Authors
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

set -euo pipefail

UPSTREAM_MODULE="github.com/sigstore/model-signing"
FORK_MODULE="github.com/securesign/model-transparency-go"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
    cat <<EOF
Usage: $(basename "$0") <to-fork|to-upstream> [--dry-run]

Rewrites the Go module path and all internal imports between upstream and fork.

Commands:
  to-fork       Rewrite from ${UPSTREAM_MODULE} -> ${FORK_MODULE}
  to-upstream    Rewrite from ${FORK_MODULE} -> ${UPSTREAM_MODULE}

Options:
  --dry-run     Show what would change without modifying files

Examples:
  $(basename "$0") to-fork              # Before publishing as securesign package
  $(basename "$0") to-upstream          # Before syncing from upstream sigstore
  $(basename "$0") to-fork --dry-run    # Preview changes
EOF
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

DIRECTION="$1"
DRY_RUN=false
if [[ "${2:-}" == "--dry-run" ]]; then
    DRY_RUN=true
fi

case "$DIRECTION" in
    to-fork)
        OLD="$UPSTREAM_MODULE"
        NEW="$FORK_MODULE"
        ;;
    to-upstream)
        OLD="$FORK_MODULE"
        NEW="$UPSTREAM_MODULE"
        ;;
    *)
        usage
        ;;
esac

current_module=$(head -1 "${REPO_ROOT}/go.mod" | awk '{print $2}')
if [[ "$current_module" == "$NEW" ]]; then
    echo "Module is already set to ${NEW}, nothing to do."
    exit 0
fi

if [[ "$current_module" != "$OLD" ]]; then
    echo "ERROR: go.mod declares module '${current_module}', expected '${OLD}'."
    echo "The module path doesn't match either upstream or fork. Aborting."
    exit 1
fi

files=()
while IFS= read -r -d '' f; do
    files+=("$f")
done < <(find "$REPO_ROOT" \
    -type f \( -name '*.go' -o -name 'go.mod' \) \
    -not -path '*/vendor/*' \
    -not -path '*/.git/*' \
    -print0)

affected=()
for f in "${files[@]}"; do
    if grep -qF "$OLD" "$f"; then
        affected+=("$f")
    fi
done

if [[ ${#affected[@]} -eq 0 ]]; then
    echo "No files contain '${OLD}'. Nothing to rewrite."
    exit 0
fi

echo "Rewriting: ${OLD} -> ${NEW}"
echo "Files affected: ${#affected[@]}"
echo ""

if $DRY_RUN; then
    for f in "${affected[@]}"; do
        echo "  ${f#"$REPO_ROOT"/}"
    done
    echo ""
    echo "(dry run — no files modified)"
    exit 0
fi

for f in "${affected[@]}"; do
    sed -i "s|${OLD}|${NEW}|g" "$f"
    echo "  rewritten: ${f#"$REPO_ROOT"/}"
done

echo ""
echo "Running go mod tidy..."
cd "$REPO_ROOT"
go mod tidy
echo ""
echo "Done. Module is now: ${NEW}"
echo "Run 'go vet ./...' to verify."
