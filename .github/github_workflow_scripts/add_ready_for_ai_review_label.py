#!/usr/bin/env python3
"""Add the ``ready-for-ai-review`` label to an external contribution PR, once.

Adding the label starts the Marketplace AI Reviewer, which removes it when done.

Trigger: a ``pull_request_target`` ``labeled`` event for the ``Contribution Form Filled`` label
(the workflow filters on the label name).

Guards:
1. The PR must still have the ``Contribution Form Filled`` label (fetched fresh from the API).
2. The label is added at most once per PR lifetime. The AI reviewer removes the label when it finishes,
   so we look at the label history rather than the current labels.

Environment:
- ``CONTENTBOT_GH_ADMIN_TOKEN``: token allowed to add labels.
- ``EVENT_PAYLOAD``: JSON of the triggering GitHub event.
"""

from __future__ import annotations

import json

import urllib3
from github import Github
from github.PullRequest import PullRequest
from urllib3.exceptions import InsecureRequestWarning

from utils import get_env_var, timestamped_print

urllib3.disable_warnings(InsecureRequestWarning)
print = timestamped_print

CONTRIBUTION_FORM_FILLED_LABEL = "Contribution Form Filled"
READY_FOR_AI_REVIEW_LABEL = "ready-for-ai-review"
ORG_NAME = "demisto"
REPO_NAME = "content"


def has_label(pr: PullRequest, label_name: str) -> bool:
    return any(label.name == label_name for label in pr.labels)


def was_label_ever_added(pr: PullRequest, label_name: str) -> bool:
    """Return True if the label was added to the PR at any point, even if removed since.

    Fails safe: if the history can't be read, assume it was added, so the AI reviewer
    is never triggered twice.
    """
    try:
        return any(event.event == "labeled" and event.label and event.label.name == label_name for event in pr.get_issue_events())
    except Exception as e:
        print(f"Failed to fetch issue events for PR #{pr.number}: {e}, assuming label was added before.")
        return True


def add_label_if_eligible(pr: PullRequest) -> bool:
    """Add the label when the PR was never labeled with the AI reviewer label before."""

    if not has_label(pr, CONTRIBUTION_FORM_FILLED_LABEL):
        print(f"PR #{pr.number} no longer has '{CONTRIBUTION_FORM_FILLED_LABEL}' - skipping.")
        return False

    if was_label_ever_added(pr, READY_FOR_AI_REVIEW_LABEL):
        print(f"PR #{pr.number} already received '{READY_FOR_AI_REVIEW_LABEL}' before - not adding again.")
        return False

    pr.add_to_labels(READY_FOR_AI_REVIEW_LABEL)
    print(f"Added '{READY_FOR_AI_REVIEW_LABEL}' to PR #{pr.number}.")
    return True


def main() -> None:
    payload_str = get_env_var("EVENT_PAYLOAD")
    if not payload_str:
        raise ValueError("EVENT_PAYLOAD env variable not set or empty")
    payload: dict = json.loads(payload_str)
    pr_number = payload.get("pull_request", {}).get("number")
    if not pr_number:
        print("Event payload contains no pull_request.number, exiting.")
        return

    gh = Github(get_env_var("CONTENTBOT_GH_ADMIN_TOKEN"), verify=False)
    # Fetch the PR fresh: the event payload's labels may be stale.
    pr = gh.get_repo(f"{ORG_NAME}/{REPO_NAME}").get_pull(int(pr_number))
    add_label_if_eligible(pr)


if __name__ == "__main__":
    main()
