"""
Verifies that PRs which add a new XSOAR-supported integration, or modify the
`configuration:` block of an existing one, carry the `connectus-approved` label
before they can be merged. The check:

  1. Detects integration YML files touched by the PR whose owning pack is
     XSOAR-supported (``"support": "xsoar"`` in ``pack_metadata.json``).
  2. Flags the PR when such a file is newly added, or when the `configuration:`
     block of an existing one differs between the PR base and head.
  3. If the PR is flagged, ensures the `connectus-approved` label is set (added
     once the Connectus approval flow has signed off on the change).

Exit codes:
    0 - No triggering change OR the `connectus-approved` label is set.
    1 - Triggering change exists but the `connectus-approved` label is missing.
"""

import argparse
import json
import sys
from pathlib import PurePosixPath
from typing import Any

import urllib3
import yaml
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository

from utils import timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print  # noqa: A001 - intentional, matches existing scripts

CONNECTUS_APPROVED_LABEL = "connectus-approved"

PACKS_DIR = "Packs"
INTEGRATIONS_DIR = "Integrations"
PACK_METADATA_FILE = "pack_metadata.json"
XSOAR_SUPPORT = "xsoar"
CONFIGURATION_KEY = "configuration"
YML_SUFFIXES = (".yml", ".yaml")


def arguments_handler() -> argparse.Namespace:
    """Validates and parses script arguments.

    Returns:
       Namespace: Parsed arguments object.
    """
    parser = argparse.ArgumentParser(description=f"Check if {CONNECTUS_APPROVED_LABEL} label exists.")
    parser.add_argument("-p", "--pr_number", required=True, help="The PR number to check if the label exists.")
    parser.add_argument("-g", "--github_token", required=True, help="The GitHub token to authenticate the GitHub client.")
    return parser.parse_args()


def is_integration_yml(file_path: str) -> bool:
    """
    Return True if `file_path` is an integration's entity YML file, i.e. it matches
    ``Packs/<Pack>/Integrations/<IntegrationName>/<IntegrationName>.yml``.

    Matching on the full path shape (rather than "any YML under Integrations/")
    deliberately excludes companion files that live in the same folder but are
    not the integration definition - README.md, *_test.py, CHANGELOG.md, and
    test-data YAMLs - none of which can contain a `configuration:` block.

    ``PurePosixPath`` is used because filenames come from GitHub's PR API and are
    always forward-slash separated, regardless of the runner's OS.
    """
    path = PurePosixPath(file_path)
    parts = path.parts

    if len(parts) != 5:
        return False
    if parts[0] != PACKS_DIR or parts[2] != INTEGRATIONS_DIR:
        return False
    if path.suffix.lower() not in YML_SUFFIXES:
        return False
    # The YML must be named after its containing integration directory.
    return path.stem == parts[3]


def get_pack_name(file_path: str) -> str:
    """Return the pack name for a ``Packs/<Pack>/...`` path (empty string if not under Packs)."""
    parts = PurePosixPath(file_path).parts
    if len(parts) < 2 or parts[0] != PACKS_DIR:
        return ""
    return parts[1]


def get_file_content_at_ref(pr: PullRequest, file_path: str, ref: str) -> str | None:
    """
    Fetch the raw text content of `file_path` at the given git `ref`.

    Returns None when the file does not exist at that ref (e.g. a newly added
    file has no base version) or cannot be read.
    """
    try:
        contents = pr.base.repo.get_contents(file_path, ref=ref)
    except Exception as e:
        print(f"Warning: Could not fetch '{file_path}' at ref {ref}: {e}")
        return None

    if isinstance(contents, list):  # path is a directory - not something we can parse
        print(f"Warning: '{file_path}' at ref {ref} is a directory, skipping.")
        return None

    try:
        return contents.decoded_content.decode("utf-8")
    except Exception as e:
        print(f"Warning: Could not decode '{file_path}' at ref {ref}: {e}")
        return None


def parse_yml(content: str, file_path: str) -> dict[str, Any] | None:
    """Parse YAML `content` into a dict, returning None if it is malformed or not a mapping."""
    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as e:
        print(f"Warning: Failed to parse YAML file {file_path}: {e}")
        return None
    return parsed if isinstance(parsed, dict) else None


def is_xsoar_supported_pack(pr: PullRequest, pack_name: str, support_cache: dict[str, bool]) -> bool:
    """
    Return True if `pack_name`'s metadata declares ``"support": "xsoar"``.

    The metadata is read at the PR head SHA so that a pack newly added (or
    re-leveled) by this very PR is evaluated against its proposed state.
    Results are cached per pack so a PR touching several integrations in one
    pack costs a single API call.
    """
    if pack_name in support_cache:
        return support_cache[pack_name]

    supported = False
    metadata_path = f"{PACKS_DIR}/{pack_name}/{PACK_METADATA_FILE}"
    content = get_file_content_at_ref(pr, metadata_path, pr.head.sha)

    if content is None:
        print(f"Warning: Could not read {metadata_path}; treating pack '{pack_name}' as not XSOAR-supported.")
    else:
        try:
            metadata = json.loads(content)
            supported = metadata.get("support") == XSOAR_SUPPORT
        except json.JSONDecodeError as e:
            print(f"Warning: Failed to parse {metadata_path}: {e}; treating pack '{pack_name}' as not XSOAR-supported.")

    support_cache[pack_name] = supported
    return supported


def get_configuration(parsed_yml: dict[str, Any] | None) -> Any:
    """Return the `configuration` block of a parsed integration YML (empty list when absent)."""
    if not parsed_yml:
        return []
    return parsed_yml.get(CONFIGURATION_KEY, [])


def is_configuration_modified(pr: PullRequest, file_path: str) -> bool:
    """
    Return True if the `configuration:` block of `file_path` differs between the
    PR base and head.

    Comparing the parsed blocks (rather than the raw diff) means cosmetic YAML
    changes elsewhere in the file - a `dockerimage` bump, a reworded
    `description` - correctly do NOT trigger the gate, while any real change to
    a configuration param does.
    """
    base_content = get_file_content_at_ref(pr, file_path, pr.base.sha)
    head_content = get_file_content_at_ref(pr, file_path, pr.head.sha)

    if base_content is None or head_content is None:
        print(f"Warning: Could not compare '{file_path}' between base and head; skipping configuration comparison.")
        return False

    base_configuration = get_configuration(parse_yml(base_content, file_path))
    head_configuration = get_configuration(parse_yml(head_content, file_path))

    return base_configuration != head_configuration


def check_pr_contains_connectus_changes(pr: PullRequest) -> list[str]:
    """
    Return a list of human-readable reasons why this PR requires Connectus approval
    (empty when it does not).

    A reason is recorded when an integration YML in an XSOAR-supported pack is
    either newly added, or has had its `configuration:` block modified.
    """
    reasons: list[str] = []
    support_cache: dict[str, bool] = {}

    try:
        files = list(pr.get_files())
    except Exception as e:
        # Fail safe: if we cannot inspect the PR we require the label rather than
        # silently letting a potentially-gated change through.
        print(f"Error listing PR files: {e}. Requiring the label to be safe.")
        return [f"- Could not inspect the PR's files ({e}); requiring '{CONNECTUS_APPROVED_LABEL}' to be safe."]

    for file in files:
        if not is_integration_yml(file.filename):
            continue

        pack_name = get_pack_name(file.filename)
        if not is_xsoar_supported_pack(pr, pack_name, support_cache):
            print(f"Skipping '{file.filename}': pack '{pack_name}' is not {XSOAR_SUPPORT}-supported.")
            continue

        try:
            if file.status == "added":
                reasons.append(f"- New XSOAR-supported integration added: {file.filename}")
            elif file.status == "modified" and is_configuration_modified(pr, file.filename):
                reasons.append(f"- Modified 'configuration' of XSOAR-supported integration: {file.filename}")
        except Exception as e:
            print(f"Warning: Error processing {file.filename}: {e}")
            continue

    return reasons


def main() -> None:
    """
    Checks that the "connectus-approved" label exists on a PR when required. If the
    label exists the workflow passes; if it is missing (and required) the workflow fails.
    """
    options = arguments_handler()
    pr_number = int(options.pr_number)

    github_client: Github = Github(options.github_token, verify=False)
    content_repo: Repository = github_client.get_repo("demisto/content")
    pr: PullRequest = content_repo.get_pull(pr_number)

    pr_label_names = {label.name for label in pr.labels}

    print(f"Checking if {CONNECTUS_APPROVED_LABEL} label exist in PR {pr_number}")
    if CONNECTUS_APPROVED_LABEL in pr_label_names:
        print(f"SUCCESS: PR #{pr_number} has the required label: {CONNECTUS_APPROVED_LABEL}")
        sys.exit(0)

    reasons = check_pr_contains_connectus_changes(pr)
    if not reasons:
        print(
            "INFO: PR does not add a new XSOAR-supported integration or modify integration configuration params.\n"
            f"   The '{CONNECTUS_APPROVED_LABEL}' label is not required for this PR."
        )
        sys.exit(0)

    reasons_text = "\n".join(reasons)
    print(
        f"ERROR: Required label '{CONNECTUS_APPROVED_LABEL}' is missing from PR #{pr_number}.\n"
        "   The following changes require Connectus approval:\n"
        f"{reasons_text}\n"
        "   Please ask the Connectus team to review the changes and add the "
        f"'{CONNECTUS_APPROVED_LABEL}' label once approved."
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
