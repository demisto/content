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
    def __init__(self, body: str, on_delete=None):
        self.body = body
        self.deleted = False
        self._on_delete = on_delete  # optional callback so the PR can drop us from its list

    def delete(self):
        self.deleted = True
        if self._on_delete is not None:
            self._on_delete(self)


class _MockPullRequest:
    """Minimal stand-in matching the surface area used by the script under test."""

    def __init__(self, number: int = 42, files=None, labels=None, comments=None):
        self.number = number
        self._files = files or []
        self.labels = labels or []
        # Rebind each supplied comment's delete callback so calling
        # ``comment.delete()`` also removes it from this PR's comment list.
        self._comments: list[_MockComment] = []
        for c in comments or []:
            self._attach(c)
        self.created_comments: list[str] = []  # captured by ``create_issue_comment``

    # Internal helper --------------------------------------------------------------
    def _attach(self, comment: "_MockComment") -> "_MockComment":
        comment._on_delete = self._comments.remove
        self._comments.append(comment)
        return comment

    # PyGithub-compatible methods --------------------------------------------------
    def get_files(self):
        return iter(self._files)

    def get_issue_comments(self):
        # Return a snapshot so callers can safely mutate the underlying list
        # (e.g. via ``comment.delete()``) while iterating.
        return iter(list(self._comments))

    def create_issue_comment(self, body: str):
        self.created_comments.append(body)
        return self._attach(_MockComment(body))


# ---------------------------------------------------------------------------
# pr_changes_critical_files
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "changed_files, expected",
    [
        # No critical folder touched - nothing returned.
        (["Packs/SomePack/Integrations/Foo/Foo.py", "README.md"], []),
        # CommonServerPython source touched - returned.
        (
            ["Packs/Base/Scripts/CommonServerPython/CommonServerPython.py"],
            ["Packs/Base/Scripts/CommonServerPython/CommonServerPython.py"],
        ),
        # CommonServerPowerShell source touched - returned.
        (
            ["Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1"],
            ["Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1"],
        ),
        # Companion files inside critical folders (tests, YAMLs, fixtures,
        # READMEs) must also be treated as critical changes.
        (
            [
                "Packs/Base/Scripts/CommonServerPython/CommonServerPython_test.py",
                "Packs/Base/Scripts/CommonServerPython/CommonServerPython.yml",
                "Packs/Base/Scripts/CommonServerPython/test_data/some_fixture.json",
                "Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.Tests.ps1",
                "Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.yml",
                "Packs/Base/Scripts/CommonServer/CommonServer.yml",
                "Packs/Base/Scripts/CommonServer/README.md",
            ],
            [
                "Packs/Base/Scripts/CommonServerPython/CommonServerPython_test.py",
                "Packs/Base/Scripts/CommonServerPython/CommonServerPython.yml",
                "Packs/Base/Scripts/CommonServerPython/test_data/some_fixture.json",
                "Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.Tests.ps1",
                "Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.yml",
                "Packs/Base/Scripts/CommonServer/CommonServer.yml",
                "Packs/Base/Scripts/CommonServer/README.md",
            ],
        ),
        # Multiple critical helpers touched alongside unrelated files -
        # only files under critical folders are returned, in PR order.
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
        # A file that merely *shares a prefix* with a critical folder name
        # (e.g. a sibling folder like ``CommonServerPythonExtras``) must NOT
        # match, because the folder prefix ends with a trailing slash.
        (
            [
                "Packs/Base/Scripts/CommonServerPythonExtras/foo.py",
                "Packs/Base/Scripts/CommonServerHelper/CommonServer.js.bak",
            ],
            [],
        ),
    ],
)
def test_pr_changes_critical_files(changed_files, expected):
    """
    Given:
        - A pull request whose changed files vary between unrelated paths,
          critical source files, companion files (tests / YAMLs / fixtures /
          READMEs) inside the critical folders, and lookalike sibling
          folders that only *share a prefix* with a critical folder.
    When:
        - ``pr_changes_critical_files`` is called.
    Then:
        - Every file that lives under a critical folder is returned in PR
          order; unrelated files and prefix-lookalikes are excluded.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        pr_changes_critical_files,
    )

    pr = _MockPullRequest(files=[_MockFile(p) for p in changed_files])
    assert pr_changes_critical_files(pr) == expected


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
# delete_reminder_comment_if_present
# ---------------------------------------------------------------------------


def test_delete_reminder_comment_if_present_noop_when_no_reminder():
    """
    Given:
        - A PR with several unrelated comments but no reminder comment.
    When:
        - ``delete_reminder_comment_if_present`` is called.
    Then:
        - It returns 0 and leaves every existing comment intact.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        delete_reminder_comment_if_present,
    )

    unrelated = [_MockComment("LGTM"), _MockComment("please rebase")]
    pr = _MockPullRequest(comments=unrelated)

    assert delete_reminder_comment_if_present(pr) == 0
    assert not any(c.deleted for c in unrelated), "unrelated comments must never be deleted"
    assert len(pr._comments) == 2


def test_delete_reminder_comment_if_present_removes_stale_reminder():
    """
    Given:
        - A PR that has both unrelated comments and a stale reminder comment
          (identified by the hidden marker).
    When:
        - ``delete_reminder_comment_if_present`` is called.
    Then:
        - Exactly the reminder comment is deleted (and dropped from the PR),
          the unrelated comments are untouched, and the return value is 1.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        COMMENT_MARKER,
        delete_reminder_comment_if_present,
    )

    unrelated_a = _MockComment("LGTM")
    reminder = _MockComment(f"{COMMENT_MARKER}\nrun nightly please")
    unrelated_b = _MockComment("bumping")
    pr = _MockPullRequest(comments=[unrelated_a, reminder, unrelated_b])

    assert delete_reminder_comment_if_present(pr) == 1
    assert reminder.deleted is True
    assert reminder not in pr._comments
    assert unrelated_a.deleted is False
    assert unrelated_b.deleted is False
    assert unrelated_a in pr._comments
    assert unrelated_b in pr._comments


def test_delete_reminder_comment_if_present_removes_all_duplicates():
    """
    Given:
        - A PR that (due to a race / manual edit) contains multiple comments
          carrying the reminder marker.
    When:
        - ``delete_reminder_comment_if_present`` is called.
    Then:
        - Every marker-bearing comment is deleted, the count reflects that,
          and non-marker comments are preserved.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        COMMENT_MARKER,
        delete_reminder_comment_if_present,
    )

    r1 = _MockComment(f"{COMMENT_MARKER}\nfirst")
    keep = _MockComment("keep me")
    r2 = _MockComment(f"{COMMENT_MARKER}\nsecond")
    pr = _MockPullRequest(comments=[r1, keep, r2])

    assert delete_reminder_comment_if_present(pr) == 2
    assert r1.deleted is True
    assert r2.deleted is True
    assert keep.deleted is False
    assert pr._comments == [keep]


def test_post_then_delete_full_lifecycle():
    """
    Given:
        - A PR where the reminder was posted (critical file was modified),
          and then the developer reverted the change so the PR no longer
          touches any critical folder.
    When:
        - ``post_reminder_comment_once`` runs (posts), followed later by
          ``delete_reminder_comment_if_present`` (cleanup after revert).
    Then:
        - The comment is first posted, then removed cleanly, and a subsequent
          delete call is a no-op.
    """
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        COMMENT_MARKER,
        delete_reminder_comment_if_present,
        post_reminder_comment_once,
    )

    pr = _MockPullRequest()

    post_reminder_comment_once(pr)
    assert any(COMMENT_MARKER in (c.body or "") for c in pr._comments)

    assert delete_reminder_comment_if_present(pr) == 1
    assert not any(COMMENT_MARKER in (c.body or "") for c in pr._comments)

    # Idempotent: nothing to delete on the second call.
    assert delete_reminder_comment_if_present(pr) == 0


# ---------------------------------------------------------------------------
# Sanity checks on module-level constants
# ---------------------------------------------------------------------------


def test_critical_folders_includes_commonserverpython():
    """``CommonServerPython/`` is the primary trigger folder and must be marked critical."""
    from pathlib import PurePosixPath

    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        CRITICAL_FOLDERS,
    )

    assert PurePosixPath("Packs/Base/Scripts/CommonServerPython") in CRITICAL_FOLDERS


def test_critical_folders_are_pureposixpath():
    """
    Every entry in ``CRITICAL_FOLDERS`` must be a :class:`PurePosixPath`.

    This is the invariant that lets :func:`pr_changes_critical_files` use
    :meth:`PurePosixPath.is_relative_to` semantics rather than raw string
    matching. In particular, using :class:`PurePosixPath` (and NOT the plain
    strings we previously stored) is what makes prefix-lookalike sibling
    folders (e.g. ``CommonServerHelper/`` vs ``CommonServer/``) correctly
    NOT match, without us having to rely on a trailing-slash convention.
    """
    from pathlib import PurePosixPath

    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        CRITICAL_FOLDERS,
    )

    for folder in CRITICAL_FOLDERS:
        assert isinstance(
            folder, PurePosixPath
        ), f"critical folder {folder!r} must be a PurePosixPath, got {type(folder).__name__}"


def test_nightly_run_passed_label_constant():
    """The label name should be stable: any rename is a breaking workflow change."""
    from github_workflow_scripts.check_commonserverpython_nightly_label import (
        NIGHTLY_RUN_PASSED_LABEL,
    )

    assert NIGHTLY_RUN_PASSED_LABEL == "nightly-run-passed"
