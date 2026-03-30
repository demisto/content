#!/usr/bin/env bash
# generate-docs-commands.sh
#
# Generate README documentation for SPECIFIC commands and append them
# to the existing README of an integration.
#
# Usage:
#   ./tools/generate-docs-commands.sh <yml_path> <command1> [command2] [command3] ...
#
# Example:
#   ./tools/generate-docs-commands.sh \
#     Packs/CheckpointFirewall/Integrations/CheckPointFirewallV2/CheckPointFirewallV2.yml \
#     checkpoint-network-get checkpoint-network-list checkpoint-network-add
#
# What it does:
#   1. Backs up the existing README.md
#   2. Runs `demisto-sdk generate-docs` to produce a full README (overwrites)
#   3. Extracts ONLY the sections for the specified commands from the generated README
#   4. Restores the original README from backup
#   5. Appends the extracted command sections to the end of the original README
#   6. Cleans up all temporary files

set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    echo "Usage: $0 <yml_path> <command1> [command2] [command3] ..."
    echo ""
    echo "Arguments:"
    echo "  yml_path    Path to the integration .yml file"
    echo "  command*    One or more command names to extract docs for"
    echo ""
    echo "Example:"
    echo "  $0 Packs/MyPack/Integrations/MyInt/MyInt.yml my-command-get my-command-list"
    exit 1
}

# ── Validate arguments ──────────────────────────────────────────────
if [[ $# -lt 2 ]]; then
    err "At least 2 arguments required: <yml_path> and at least one <command_name>"
    usage
fi

YML_PATH="$1"
shift
COMMANDS=("$@")

if [[ ! -f "$YML_PATH" ]]; then
    err "YML file not found: $YML_PATH"
    exit 1
fi

# Derive the integration directory and README path
INT_DIR="$(dirname "$YML_PATH")"
README_PATH="${INT_DIR}/README.md"

if [[ ! -f "$README_PATH" ]]; then
    err "README.md not found at: $README_PATH"
    exit 1
fi

# ── Temporary files ─────────────────────────────────────────────────
BACKUP_FILE="$(mktemp /tmp/readme_backup_XXXXXX.md)"
GENERATED_FILE="$(mktemp /tmp/readme_generated_XXXXXX.md)"
EXTRACTED_FILE="$(mktemp /tmp/readme_extracted_XXXXXX.md)"

cleanup() {
    rm -f "$BACKUP_FILE" "$GENERATED_FILE" "$EXTRACTED_FILE"
}
trap cleanup EXIT

# ── Step 1: Back up existing README ─────────────────────────────────
info "Backing up existing README..."
cp "$README_PATH" "$BACKUP_FILE"
ok "Backup saved to $BACKUP_FILE"

# ── Step 2: Run generate-docs ───────────────────────────────────────
info "Running demisto-sdk generate-docs..."
echo "" | poetry run demisto-sdk generate-docs \
    -i "$YML_PATH" \
    -o "$INT_DIR" \
    --force 2>&1 | grep -v "^$" || true

# Save the generated README before restoring
cp "$README_PATH" "$GENERATED_FILE"
ok "Generated docs saved to temp file"

# ── Step 3: Restore original README ─────────────────────────────────
info "Restoring original README..."
cp "$BACKUP_FILE" "$README_PATH"
ok "Original README restored"

# ── Step 4: Extract specified command sections ──────────────────────
info "Extracting documentation for ${#COMMANDS[@]} command(s)..."

# Use Python for reliable markdown section extraction
python3 - "$GENERATED_FILE" "$EXTRACTED_FILE" "${COMMANDS[@]}" << 'PYTHON_SCRIPT'
import sys
import re

generated_file = sys.argv[1]
output_file = sys.argv[2]
target_commands = set(sys.argv[3:])

with open(generated_file, 'r') as f:
    content = f.read()

# Split into sections by ### headings
# Each section starts with "### <command-name>\n"
sections = re.split(r'(?=^### )', content, flags=re.MULTILINE)

extracted = []
found_commands = set()

for section in sections:
    # Match the heading
    match = re.match(r'^### (.+?)$', section, re.MULTILINE)
    if not match:
        continue

    command_name = match.group(1).strip()
    if command_name in target_commands:
        found_commands.add(command_name)
        # Strip trailing whitespace but keep the section content
        extracted.append(section.rstrip())

# Report missing commands
missing = target_commands - found_commands
if missing:
    print(f"WARNING: The following commands were NOT found in generated docs:", file=sys.stderr)
    for cmd in sorted(missing):
        print(f"  - {cmd}", file=sys.stderr)

if not extracted:
    print("ERROR: No command sections were extracted!", file=sys.stderr)
    sys.exit(1)

# Write extracted sections
with open(output_file, 'w') as f:
    f.write('\n'.join(extracted))
    f.write('\n')

print(f"Extracted {len(extracted)} command section(s): {', '.join(sorted(found_commands))}")
PYTHON_SCRIPT

ok "Extraction complete"

# ── Step 5: Append to original README ───────────────────────────────
info "Appending new command sections to README..."

# Ensure there's a newline at the end of the existing README before appending
# Then add a blank line separator and the new content
echo "" >> "$README_PATH"
cat "$EXTRACTED_FILE" >> "$README_PATH"

FINAL_LINES="$(wc -l < "$README_PATH" | tr -d ' ')"
ok "Done! README now has $FINAL_LINES lines"

# ── Summary ─────────────────────────────────────────────────────────
echo ""
info "Summary:"
echo "  File:     $README_PATH"
echo "  Commands: ${COMMANDS[*]}"
echo "  Lines:    $FINAL_LINES"
echo ""
ok "All done! Review the appended sections in your README."
