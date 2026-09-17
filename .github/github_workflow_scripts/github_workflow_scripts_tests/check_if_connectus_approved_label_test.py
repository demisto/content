"""
Unit tests for ``github_workflow_scripts/check_if_connectus_approved_label_exists.py``.

The script talks to the GitHub API via the ``PyGithub`` library; for unit
testing we never hit the network - we hand-build lightweight mock objects that
expose only the attributes the script actually reads.
"""

import json

import pytest

MODULE = "github_workflow_scripts.check_if_connectus_approved_label_exists"

XSOAR_METADATA = json.dumps({"name": "MyPack", "support": "xsoar"})
PARTNER_METADATA = json.dumps({"name": "MyPack", "support": "partner"})

INTEGRATION_YML = "Packs/MyPack/Integrations/MyIntegration/MyIntegration.yml"
PACK_METADATA = "Packs/MyPack/pack_metadata.json"


def integration_yml(configuration: str, dockerimage: str = "demisto/python3:3.10.1") -> str:
    """Build a minimal integration YML with the supplied ``configuration`` block."""
    return (
        "commonfields:\n"
        "  id: MyIntegration\n"
        "name: MyIntegration\n"
        f"configuration:\n{configuration}"
        "script:\n"
        "  type: python\n"
        f"  dockerimage: {dockerimage}\n"
    )


ONE_PARAM = "- display: Server URL\n  name: url\n  type: 0\n  required: true\n"
TWO_PARAMS = ONE_PARAM + "- display: API Key\n  name: apikey\n  type: 4\n  required: true\n"


# ---------------------------------------------------------------------------
# Tiny stand-in objects (no PyGithub dependency at test-collection time).
# ---------------------------------------------------------------------------


class _MockFile:
    def __init__(self, filename: str, status: str = "modified"):
        self.filename = filename
        self.status = status


class _MockLabel:
    def __init__(self, name: str):
        self.name = name


class _MockContentFile:
    def __init__(self, content: str):
        self.decoded_content = content.encode("utf-8")


class _MockRepo:
    """Serves file contents keyed by ``(path, ref)``; raises when the pair is unknown."""

    def __init__(self, contents: dict[tuple[str, str], str] | None = None):
        self._contents = contents or {}

    def get_contents(self, path: str, ref: str):
        try:
            return _MockContentFile(self._contents[(path, ref)])
        except KeyError:
            raise Exception(f"404: {path}@{ref} not found")


class _MockRef:
    def __init__(self, sha: str, repo: _MockRepo | None = None):
        self.sha = sha
        self.repo = repo


class _MockPullRequest:
    """Minimal stand-in matching the surface area used by the script under test."""

    BASE_SHA = "base-sha"
    HEAD_SHA = "head-sha"

    def __init__(self, number: int = 42, files=None, labels=None, contents=None, files_raise: bool = False):
        self.number = number
        self._files = files or []
        self._files_raise = files_raise
        self.labels = labels or []
        self.base = _MockRef(self.BASE_SHA, _MockRepo(contents))
        self.head = _MockRef(self.HEAD_SHA)

    def get_files(self):
        if self._files_raise:
            raise Exception("GitHub API is down")
        return iter(self._files)


def _contents(base_yml: str | None = None, head_yml: str | None = None, metadata: str = XSOAR_METADATA) -> dict:
    """Build the ``(path, ref) -> content`` map for a single-integration PR."""
    contents: dict[tuple[str, str], str] = {(PACK_METADATA, _MockPullRequest.HEAD_SHA): metadata}
    if base_yml is not None:
        contents[(INTEGRATION_YML, _MockPullRequest.BASE_SHA)] = base_yml
    if head_yml is not None:
        contents[(INTEGRATION_YML, _MockPullRequest.HEAD_SHA)] = head_yml
    return contents


def _run_main(mocker, pr: _MockPullRequest) -> int:
    """Run the script's ``main()`` against ``pr`` and return its exit code."""
    from github_workflow_scripts import check_if_connectus_approved_label_exists as script

    mock_repo = mocker.MagicMock()
    mock_repo.get_pull.return_value = pr
    mocker.patch.object(script, "Github", return_value=mocker.MagicMock(get_repo=lambda _: mock_repo))
    mocker.patch.object(
        script,
        "arguments_handler",
        return_value=mocker.MagicMock(pr_number=str(pr.number), github_token="token"),
    )

    with pytest.raises(SystemExit) as exit_info:
        script.main()
    return exit_info.value.code


# ---------------------------------------------------------------------------
# is_integration_yml
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "file_path, expected",
    [
        # The integration entity YML - the only shape we gate on.
        (INTEGRATION_YML, True),
        ("Packs/MyPack/Integrations/MyIntegration/MyIntegration.yaml", True),
        # Companion files in the same folder are not the integration definition.
        ("Packs/MyPack/Integrations/MyIntegration/MyIntegration.py", False),
        ("Packs/MyPack/Integrations/MyIntegration/README.md", False),
        ("Packs/MyPack/Integrations/MyIntegration/MyIntegration_test.py", False),
        # A YML in the integration folder not named after it (e.g. test data).
        ("Packs/MyPack/Integrations/MyIntegration/test_data/response.yml", False),
        ("Packs/MyPack/Integrations/MyIntegration/command_examples.yml", False),
        # Other content entities must not trigger the gate.
        ("Packs/MyPack/Scripts/MyScript/MyScript.yml", False),
        ("Packs/MyPack/Playbooks/MyPlaybook.yml", False),
        ("Packs/MyPack/ModelingRules/MyRule/MyRule.yml", False),
        ("Packs/MyPack/pack_metadata.json", False),
        # Paths outside Packs/.
        (".github/workflows/connectus-approved.yml", False),
        ("Tests/conf.json", False),
    ],
)
def test_is_integration_yml(file_path, expected):
    """
    Given:
        - A file path from a PR's changed-files list.

    When:
        - Running is_integration_yml.

    Then:
        - Only ``Packs/<Pack>/Integrations/<Name>/<Name>.yml`` is recognised as
          an integration definition.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import is_integration_yml

    assert is_integration_yml(file_path) is expected


@pytest.mark.parametrize(
    "file_path, expected",
    [
        (INTEGRATION_YML, "MyPack"),
        ("Packs/OtherPack/pack_metadata.json", "OtherPack"),
        ("Tests/conf.json", ""),
        ("README.md", ""),
    ],
)
def test_get_pack_name(file_path, expected):
    """
    Given:
        - A file path.

    When:
        - Running get_pack_name.

    Then:
        - The owning pack name is returned, or an empty string outside Packs/.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import get_pack_name

    assert get_pack_name(file_path) == expected


# ---------------------------------------------------------------------------
# The four mandated end-to-end scenarios
# ---------------------------------------------------------------------------


def test_new_xsoar_integration_without_label_fails(mocker, capsys):
    """
    Given:
        - A PR that adds a new integration YML in an XSOAR-supported pack.
        - The 'connectus-approved' label is missing.

    When:
        - Running the script's main function.

    Then:
        - The check fails (exit code 1) and the log names the offending file.
    """
    pr = _MockPullRequest(
        files=[_MockFile(INTEGRATION_YML, status="added")],
        contents=_contents(head_yml=integration_yml(ONE_PARAM)),
    )

    assert _run_main(mocker, pr) == 1

    output = capsys.readouterr().out
    assert "ERROR" in output
    assert "connectus-approved" in output
    assert "New XSOAR-supported integration added" in output
    assert INTEGRATION_YML in output


def test_modified_configuration_without_label_fails(mocker, capsys):
    """
    Given:
        - A PR that modifies the 'configuration' block of an existing integration
          in an XSOAR-supported pack.
        - The 'connectus-approved' label is missing.

    When:
        - Running the script's main function.

    Then:
        - The check fails (exit code 1) and the log names the offending file.
    """
    pr = _MockPullRequest(
        files=[_MockFile(INTEGRATION_YML, status="modified")],
        contents=_contents(
            base_yml=integration_yml(ONE_PARAM),
            head_yml=integration_yml(TWO_PARAMS),
        ),
    )

    assert _run_main(mocker, pr) == 1

    output = capsys.readouterr().out
    assert "ERROR" in output
    assert "connectus-approved" in output
    assert "Modified 'configuration' of XSOAR-supported integration" in output
    assert INTEGRATION_YML in output


def test_label_present_passes_despite_changes(mocker, capsys):
    """
    Given:
        - A PR that both adds a new integration and changes configuration params.
        - The 'connectus-approved' label IS present.

    When:
        - Running the script's main function.

    Then:
        - The check passes (exit code 0) regardless of the detected changes.
    """
    pr = _MockPullRequest(
        files=[_MockFile(INTEGRATION_YML, status="added")],
        labels=[_MockLabel("connectus-approved")],
        contents=_contents(head_yml=integration_yml(TWO_PARAMS)),
    )

    assert _run_main(mocker, pr) == 0

    output = capsys.readouterr().out
    assert "SUCCESS" in output
    assert "ERROR" not in output


def test_no_triggering_changes_passes(mocker, capsys):
    """
    Given:
        - A PR that touches no integration YMLs (only a script and release notes).
        - The 'connectus-approved' label is missing.

    When:
        - Running the script's main function.

    Then:
        - The check passes (exit code 0) because the label is not required.
    """
    pr = _MockPullRequest(
        files=[
            _MockFile("Packs/MyPack/Scripts/MyScript/MyScript.py", status="modified"),
            _MockFile("Packs/MyPack/ReleaseNotes/1_0_1.md", status="added"),
        ],
        contents=_contents(),
    )

    assert _run_main(mocker, pr) == 0

    output = capsys.readouterr().out
    assert "INFO" in output
    assert "not required" in output
    assert "ERROR" not in output


# ---------------------------------------------------------------------------
# check_pr_contains_connectus_changes - supporting cases
# ---------------------------------------------------------------------------


def test_non_xsoar_pack_is_ignored():
    """
    Given:
        - A PR adding a new integration to a partner-supported pack.

    When:
        - Running check_pr_contains_connectus_changes.

    Then:
        - No reasons are returned: the gate only covers XSOAR-supported packs.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import check_pr_contains_connectus_changes

    pr = _MockPullRequest(
        files=[_MockFile(INTEGRATION_YML, status="added")],
        contents=_contents(head_yml=integration_yml(ONE_PARAM), metadata=PARTNER_METADATA),
    )

    assert check_pr_contains_connectus_changes(pr) == []


def test_unchanged_configuration_is_ignored():
    """
    Given:
        - A PR modifying an integration YML where only the dockerimage changed
          and the 'configuration' block is identical.

    When:
        - Running check_pr_contains_connectus_changes.

    Then:
        - No reasons are returned: non-configuration edits don't require approval.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import check_pr_contains_connectus_changes

    pr = _MockPullRequest(
        files=[_MockFile(INTEGRATION_YML, status="modified")],
        contents=_contents(
            base_yml=integration_yml(ONE_PARAM, dockerimage="demisto/python3:3.10.1"),
            head_yml=integration_yml(ONE_PARAM, dockerimage="demisto/python3:3.10.2"),
        ),
    )

    assert check_pr_contains_connectus_changes(pr) == []


def test_missing_base_version_is_handled_gracefully():
    """
    Given:
        - A PR whose modified integration YML cannot be fetched at the base ref.

    When:
        - Running check_pr_contains_connectus_changes.

    Then:
        - The file is skipped without raising, and no reason is recorded.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import check_pr_contains_connectus_changes

    pr = _MockPullRequest(
        files=[_MockFile(INTEGRATION_YML, status="modified")],
        contents=_contents(head_yml=integration_yml(TWO_PARAMS)),  # no base entry
    )

    assert check_pr_contains_connectus_changes(pr) == []


def test_unparsable_yml_is_handled_gracefully():
    """
    Given:
        - A PR whose modified integration YML is malformed at the head ref.

    When:
        - Running check_pr_contains_connectus_changes.

    Then:
        - Parsing fails softly; the malformed head yields an empty configuration,
          which differs from the base, so the change is still flagged for review.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import check_pr_contains_connectus_changes

    pr = _MockPullRequest(
        files=[_MockFile(INTEGRATION_YML, status="modified")],
        contents=_contents(
            base_yml=integration_yml(ONE_PARAM),
            head_yml="configuration: [unclosed",
        ),
    )

    reasons = check_pr_contains_connectus_changes(pr)
    assert len(reasons) == 1
    assert "Modified 'configuration'" in reasons[0]


def test_unreadable_pack_metadata_is_treated_as_not_xsoar():
    """
    Given:
        - A PR adding an integration whose pack_metadata.json cannot be read.

    When:
        - Running check_pr_contains_connectus_changes.

    Then:
        - The pack is treated as not XSOAR-supported and no reason is recorded.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import check_pr_contains_connectus_changes

    pr = _MockPullRequest(
        files=[_MockFile(INTEGRATION_YML, status="added")],
        contents={},  # no metadata available at any ref
    )

    assert check_pr_contains_connectus_changes(pr) == []


def test_pack_support_lookup_is_cached():
    """
    Given:
        - A PR adding two integrations that live in the same pack.

    When:
        - Running check_pr_contains_connectus_changes.

    Then:
        - Both are flagged, and the pack metadata is fetched only once.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import check_pr_contains_connectus_changes

    second_yml = "Packs/MyPack/Integrations/OtherIntegration/OtherIntegration.yml"
    pr = _MockPullRequest(
        files=[_MockFile(INTEGRATION_YML, status="added"), _MockFile(second_yml, status="added")],
        contents=_contents(head_yml=integration_yml(ONE_PARAM)),
    )

    metadata_fetches = []
    original_get_contents = pr.base.repo.get_contents

    def counting_get_contents(path, ref):
        if path == PACK_METADATA:
            metadata_fetches.append(ref)
        return original_get_contents(path, ref)

    pr.base.repo.get_contents = counting_get_contents

    reasons = check_pr_contains_connectus_changes(pr)
    assert len(reasons) == 2
    assert len(metadata_fetches) == 1


def test_api_failure_requires_the_label():
    """
    Given:
        - Listing the PR's files raises (e.g. a GitHub API outage).

    When:
        - Running check_pr_contains_connectus_changes.

    Then:
        - A reason is returned so the gate fails safe rather than letting a
          potentially-gated change through unreviewed.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import check_pr_contains_connectus_changes

    pr = _MockPullRequest(files_raise=True)

    reasons = check_pr_contains_connectus_changes(pr)
    assert len(reasons) == 1
    assert "Could not inspect" in reasons[0]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "parsed_yml, expected",
    [
        ({"configuration": [{"name": "url"}]}, [{"name": "url"}]),
        ({"name": "NoConfig"}, []),
        (None, []),
    ],
)
def test_get_configuration(parsed_yml, expected):
    """
    Given:
        - A parsed integration YML (or None when parsing failed).

    When:
        - Running get_configuration.

    Then:
        - The configuration block is returned, defaulting to an empty list.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import get_configuration

    assert get_configuration(parsed_yml) == expected


def test_label_name_is_stable():
    """
    Given:
        - The workflow and the branch-protection rule both reference the label by name.

    When:
        - Reading CONNECTUS_APPROVED_LABEL.

    Then:
        - It is exactly 'connectus-approved'; any rename is a breaking change.
    """
    from github_workflow_scripts.check_if_connectus_approved_label_exists import CONNECTUS_APPROVED_LABEL

    assert CONNECTUS_APPROVED_LABEL == "connectus-approved"
