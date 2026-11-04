import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from github_workflow_scripts import add_ready_for_ai_review_label as mod
from github_workflow_scripts.add_ready_for_ai_review_label import (
    CONTRIBUTION_FORM_FILLED_LABEL,
    READY_FOR_AI_REVIEW_LABEL,
    add_label_if_eligible,
    has_label,
    was_label_ever_added,
)

WORKFLOW_PATH = Path(__file__).resolve().parents[2] / "workflows" / "add-ready-for-ai-review-label.yml"


def _label(name: str):
    label = MagicMock()
    label.name = name
    return label


def _issue_event(event_name: str, label_name: str | None = None):
    event = MagicMock()
    event.event = event_name
    event.label = _label(label_name) if label_name else None
    return event


def _make_pr(*, number: int = 46356, labels: tuple[str, ...] = (CONTRIBUTION_FORM_FILLED_LABEL,), issue_events=None):
    pr = MagicMock()
    pr.number = number
    pr.labels = [_label(name) for name in labels]
    pr.get_issue_events.return_value = issue_events or []
    return pr


def _labeled_event_payload(number: int = 46356, label: str = CONTRIBUTION_FORM_FILLED_LABEL) -> str:
    """The relevant part of a real pull_request_target 'labeled' payload (see PR #46356)."""
    return json.dumps(
        {
            "action": "labeled",
            "label": {"name": label},
            "pull_request": {
                "number": number,
                "head": {"ref": "secureworks_5.1.0", "repo": {"fork": True}},
                "base": {"ref": "contrib/mpegman-scwx_secureworks_5.1.0"},
            },
        }
    )


class TestHasLabel:
    def test_present(self):
        assert has_label(_make_pr(labels=(CONTRIBUTION_FORM_FILLED_LABEL, "Contribution")), CONTRIBUTION_FORM_FILLED_LABEL)

    def test_absent(self):
        assert not has_label(_make_pr(labels=("Contribution",)), CONTRIBUTION_FORM_FILLED_LABEL)


class TestWasLabelEverAdded:
    def test_labeled_event_present(self):
        pr = _make_pr(issue_events=[_issue_event("labeled", READY_FOR_AI_REVIEW_LABEL)])
        assert was_label_ever_added(pr, READY_FOR_AI_REVIEW_LABEL) is True

    def test_labeled_then_removed_by_reviewer(self):
        """
        Given:
            - The AI reviewer already ran and removed the label (labeled + unlabeled in the history).
        When:
            - was_label_ever_added() is called.
        Then:
            - Returns True, so the label is not added a second time.
        """
        pr = _make_pr(
            issue_events=[
                _issue_event("labeled", READY_FOR_AI_REVIEW_LABEL),
                _issue_event("unlabeled", READY_FOR_AI_REVIEW_LABEL),
            ]
        )
        assert was_label_ever_added(pr, READY_FOR_AI_REVIEW_LABEL) is True

    def test_only_other_labels_and_events(self):
        pr = _make_pr(issue_events=[_issue_event("labeled", "Contribution"), _issue_event("assigned")])
        assert was_label_ever_added(pr, READY_FOR_AI_REVIEW_LABEL) is False

    def test_fails_safe_on_api_error(self):
        """
        Given:
            - The GitHub API fails while reading the issue events.
        When:
            - was_label_ever_added() is called.
        Then:
            - Returns True: never risk starting the AI reviewer twice.
        """
        pr = _make_pr()
        pr.get_issue_events.side_effect = Exception("API down")
        assert was_label_ever_added(pr, READY_FOR_AI_REVIEW_LABEL) is True


class TestAddLabelIfEligible:
    def test_adds_label(self):
        pr = _make_pr(labels=(CONTRIBUTION_FORM_FILLED_LABEL, "Contribution"))
        assert add_label_if_eligible(pr) is True
        pr.add_to_labels.assert_called_once_with(READY_FOR_AI_REVIEW_LABEL)

    def test_skips_when_form_label_was_removed(self):
        pr = _make_pr(labels=("Contribution",))
        assert add_label_if_eligible(pr) is False
        pr.add_to_labels.assert_not_called()

    def test_skips_when_label_was_added_before(self):
        pr = _make_pr(
            issue_events=[
                _issue_event("labeled", READY_FOR_AI_REVIEW_LABEL),
                _issue_event("unlabeled", READY_FOR_AI_REVIEW_LABEL),
            ]
        )
        assert add_label_if_eligible(pr) is False
        pr.add_to_labels.assert_not_called()


class TestMainEndToEnd:
    """Runs main() the way the workflow does: EVENT_PAYLOAD + token in the environment, GitHub mocked."""

    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch):
        monkeypatch.setenv("CONTENTBOT_GH_ADMIN_TOKEN", "token")

    def _run(self, monkeypatch, payload: str, pr):
        monkeypatch.setenv("EVENT_PAYLOAD", payload)
        with patch.object(mod, "Github") as gh_cls:
            repo = gh_cls.return_value.get_repo.return_value
            repo.get_pull.return_value = pr
            mod.main()
        return gh_cls, repo

    def test_labeled_event_adds_the_ai_review_label(self, monkeypatch):
        """
        Given:
            - A 'Contribution Form Filled' labeled event for PR 46356, which was never labeled before.
        When:
            - main() runs.
        Then:
            - The PR is fetched fresh from demisto/content by number and gets 'ready-for-ai-review'.
        """
        pr = _make_pr(number=46356)
        gh_cls, repo = self._run(monkeypatch, _labeled_event_payload(46356), pr)

        gh_cls.return_value.get_repo.assert_called_once_with("demisto/content")
        repo.get_pull.assert_called_once_with(46356)
        pr.add_to_labels.assert_called_once_with(READY_FOR_AI_REVIEW_LABEL)

    def test_second_event_after_reviewer_removed_the_label_does_nothing(self, monkeypatch):
        """
        Given:
            - The same PR gets another 'Contribution Form Filled' event after the reviewer removed its label.
        When:
            - main() runs.
        Then:
            - The label is not added again (one-shot).
        """
        pr = _make_pr(
            issue_events=[
                _issue_event("labeled", READY_FOR_AI_REVIEW_LABEL),
                _issue_event("unlabeled", READY_FOR_AI_REVIEW_LABEL),
            ]
        )
        self._run(monkeypatch, _labeled_event_payload(), pr)
        pr.add_to_labels.assert_not_called()

    def test_payload_without_pull_request_does_not_call_github(self, monkeypatch):
        monkeypatch.setenv("EVENT_PAYLOAD", json.dumps({"action": "labeled"}))
        with patch.object(mod, "Github") as gh_cls:
            mod.main()
        gh_cls.assert_not_called()

    def test_missing_event_payload_raises(self, monkeypatch):
        monkeypatch.delenv("EVENT_PAYLOAD", raising=False)
        with pytest.raises(Exception, match="EVENT_PAYLOAD"):
            mod.main()


class TestWorkflowDefinition:
    """Static checks of the workflow file. This reads the YAML; it does not evaluate GitHub expressions."""

    @pytest.fixture(scope="class")
    def workflow(self):
        return yaml.safe_load(WORKFLOW_PATH.read_text())

    @pytest.fixture(scope="class")
    def job(self, workflow):
        return workflow["jobs"]["add_ready_for_ai_review_label"]

    def test_triggers_only_on_labeled_pull_request_target(self, workflow):
        triggers = workflow.get(True) or workflow["on"]  # PyYAML parses a bare `on` key as True
        assert triggers == {"pull_request_target": {"types": ["labeled"]}}

    def test_job_filter_covers_fork_label_and_test_branch(self, job):
        condition = " ".join(job["if"].split())
        assert "github.repository == 'demisto/content'" in condition
        assert "github.event.pull_request.head.repo.fork == true" in condition
        assert f"github.event.label.name == '{CONTRIBUTION_FORM_FILLED_LABEL}'" in condition
        assert "contains(github.head_ref, 'xsoar-bot-contrib-ContributionTestPack') == false" in condition

    def test_marketplace_contribution_prs_are_not_excluded(self, job):
        assert "[Marketplace Contribution]" not in job["if"]

    def test_concurrency_is_per_pr(self, job):
        assert "github.event.pull_request.number" in job["concurrency"]["group"]
        assert job["concurrency"]["cancel-in-progress"] is False

    def test_script_gets_payload_and_token(self, job):
        step = next(s for s in job["steps"] if s.get("name") == "Add ready-for-ai-review label")
        assert set(step["env"]) == {"CONTENTBOT_GH_ADMIN_TOKEN", "EVENT_PAYLOAD"}
        assert "add_ready_for_ai_review_label.py" in step["run"]
