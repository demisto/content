"""
Unit tests for ``github_workflow_scripts/check_commonserverpython_nightly_label.py``.

The script talks to the GitHub API via the ``PyGithub`` library; for unit
testing we never hit the network — we hand-build lightweight mock objects
that expose only the attributes the script actually reads.
"""

import pytest


# ---------------------------------------------------------------------------
# Tiny stand-in objects (no PyGithub dependency at test-collection time).
# ---------------------------------------------------------------------------


class _MockFile:
    def __init__(self, filename: str):
        self.filename = filename


class _MockLabel:
    def __init__(self, name: str):
        self.name = name


class _MockComment:
    def __init__(self, body: str):
        self.body = body


class _MockPullRequest:
    """Minimal stand-in matching the surface area used by the script under test."""

    def __init__(self, number: int = 42, files=None, labels=None, comments=None):
        self.number = number
        self._files = files or []
        self.labels = labels or []
        self._comments = list(comments or [])
        self.created_comments: list[str] = []  # captured by ``create_issue_comment``

    # PyGithub-compatible methods --------------------------------------------------
    def get_files(self):
        return iter(self._files)

    def get_issue_comments(self):
        return iter(self._comments)

    def create_issue_comment(self, body: str):
        self.created_comments.append(body)
        self._comments.append(_MockComment(body))
        return _MockComment(body)


# ---------------------------------------------------------------------------
# pr_changes_protected_files
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "changed_files, expected",
    [
        # No protected file touched - nothing returned.
        (["Packs/SomePack/Integrations/Foo/Foo.py", "README.md"], []),
        # CommonServerPython touched - returned.
        (
            ["Packs/Base/Scripts/CommonServerPython/CommonServerPython.py"],
            ["Packs/Base/Scripts/CommonServerPython/CommonServerPython.py"],
        ),
        # CommonServerPowerShell touched - returned.
        (
            ["Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1"],
            ["Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1"],
        ),
        # Multiple protected helpers touched - all returned.
        (
            [
                "Packs/Base/Scripts/CommonServerPython/CommonServerPython.py",
                "Packs/Base/Scripts/CommonServer/CommonServer.js",
                "Packs/Other/file.py",
            ],
            [
                "Packs/Base/Scripts/CommonServerPython/CommonServerPython.py",
                "Packs/Base/Scripts/CommonServer/CommonServer.js",
            ],
        ),
    ],
)
def test_pr_changes_protected_files(changed_files, expected):
    """
    Given:
        - A pull request whose changed files vary between unrelated paths
          and the protected CommonServer* helpers.
    When:
        - ``pr_changes_protected_files`` is called.
    Then:
        - Only the protected files (in declaration order) are returned.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        pr_changes_protected_files,
    )

    pr = _MockPullRequest(files=[_MockFile(p) for p in changed_files])
    assert pr_changes_protected_files(pr) == expected


# ---------------------------------------------------------------------------
# reminder_comment_already_posted / post_reminder_comment_once
# ---------------------------------------------------------------------------


def test_reminder_comment_already_posted_returns_false_when_absent():
    """
    Given:
        - A PR with several unrelated comments (none containing the marker).
    When:
        - ``reminder_comment_already_posted`` is called.
    Then:
        - It returns False.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        reminder_comment_already_posted,
    )

    pr = _MockPullRequest(
        comments=[
            _MockComment("LGTM"),
            _MockComment("please rebase"),
            _MockComment(None),  # PyGithub may return None bodies; must be tolerated
        ]
    )
    assert reminder_comment_already_posted(pr) is False


def test_reminder_comment_already_posted_returns_true_when_marker_present():
    """
    Given:
        - A PR that already has an issue comment whose body contains the
          hidden marker used by this workflow.
    When:
        - ``reminder_comment_already_posted`` is called.
    Then:
        - It returns True.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        COMMENT_MARKER,
        reminder_comment_already_posted,
    )

    pr = _MockPullRequest(
        comments=[
            _MockComment("unrelated"),
            _MockComment(f"{COMMENT_MARKER}\nplease run nightly"),
        ]
    )
    assert reminder_comment_already_posted(pr) is True


def test_post_reminder_comment_once_posts_on_first_invocation():
    """
    Given:
        - A PR that has never received the reminder before.
    When:
        - ``post_reminder_comment_once`` is invoked.
    Then:
        - Exactly one comment is created and it carries the hidden marker.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        COMMENT_MARKER,
        post_reminder_comment_once,
    )

    pr = _MockPullRequest()
    post_reminder_comment_once(pr)

    assert len(pr.created_comments) == 1
    assert COMMENT_MARKER in pr.created_comments[0]


def test_post_reminder_comment_once_is_idempotent_across_runs():
    """
    Given:
        - A PR where the reminder was already posted in a previous workflow run.
    When:
        - ``post_reminder_comment_once`` is invoked again (simulating a
          ``synchronize`` / ``labeled`` / ``unlabeled`` re-run).
    Then:
        - No additional comment is created.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        post_reminder_comment_once,
    )

    pr = _MockPullRequest()

    post_reminder_comment_once(pr)  # first run -> posts
    post_reminder_comment_once(pr)  # second run -> must skip
    post_reminder_comment_once(pr)  # third run -> must skip

    assert len(pr.created_comments) == 1, (
        "Reminder comment must be posted exactly once per PR regardless of how " "many times the workflow re-runs."
    )


# ---------------------------------------------------------------------------
# Sanity checks on module-level constants
# ---------------------------------------------------------------------------


def test_protected_paths_includes_commonserverpython():
    """``CommonServerPython.py`` is the primary trigger and must be protected."""
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        PROTECTED_PATHS,
    )

    assert "Packs/Base/Scripts/CommonServerPython/CommonServerPython.py" in PROTECTED_PATHS


def test_nightly_run_passed_label_constant():
    """The label name should be stable: any rename is a breaking workflow change."""
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        NIGHTLY_RUN_PASSED_LABEL,
    )

    assert NIGHTLY_RUN_PASSED_LABEL == "nightly-run-passed"
