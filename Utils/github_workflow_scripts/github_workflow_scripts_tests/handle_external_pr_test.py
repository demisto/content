import os
import pytest
from typing import Final
from Utils.github_workflow_scripts.handle_external_pr import is_requires_security_reviewer


INTEGRATION_PATH: Final[str] = 'Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py'
PLAYBOOK_PATH: Final[str] = 'Packs/HelloWorld/Playbooks/playbook-HelloWorld.yml'
INCIDENT_TYPES_PATH: Final[str] = "Packs/HelloWorld/IncidentTypes/incidenttype-Hello_World.json"
INCIDENT_FIELDS_PATH: Final[str] = "Packs/HelloWorld/IncidentFields/incidentfield-Hello_World.json"
INDICATOR_TYPES_PATH: Final[str] = "Packs/CrisisManagement/IncidentTypes/Employee_Health_Check.json"
INDICATOR_FIELDS_PATH: Final[str] = "Packs/CrisisManagement/IndicatorFields/Job_Title.json"
LAYOUTS_PATH: Final[str] = "Packs/HelloWorld/Layouts/layout-details-Hello_World.json"
CLASSIFIERS_PATH: Final[str] = "Packs/HelloWorld/Classifiers/classifier-HelloWorld.json"
WIZARDS_PATH: Final[str] = "Packs/Phishing/Wizards/wizard-Phishing.json"
DASHBOARDS_PATH: Final[str] = "Packs/Base/Dashboards/dashboard-SystemHealth.json"
TRIGGERS_PATH: Final[str] = "Packs/Phishing/Triggers/Trigger_-_Phishing.json"

REQUIRES_SECURITY_REVIEW: Final[tuple] = (
    pytest.param(PLAYBOOK_PATH, id="Playbook requires security review"),
    pytest.param(INCIDENT_TYPES_PATH, id="Incident type requires security review"),
    pytest.param(INCIDENT_FIELDS_PATH, id="Incident field requires security review"),
    pytest.param(INCIDENT_TYPES_PATH, id="Incident type requires security review"),
    pytest.param(INCIDENT_FIELDS_PATH, id="Incident field requires security review"),
    pytest.param(LAYOUTS_PATH, id="Layout requires security review"),
    pytest.param(CLASSIFIERS_PATH, id="Classifier requires security review"),
    pytest.param(WIZARDS_PATH, id="Wizard requires security review"),
    pytest.param(DASHBOARDS_PATH, id="Dashboard requires security review"),
    pytest.param(TRIGGERS_PATH, id="Trigger requires security review"),
)
NOT_REQUIRE_SECURITY_REVIEW: Final[tuple] = (
    pytest.param(INTEGRATION_PATH, id="Integration does not require security review"),
)


@pytest.mark.parametrize(
    'support_levels, expected_support_level', [
        (
            {'xsoar'},
            'Xsoar Support Level'
        ),
        (
            {'xsoar', 'partner'},
            'Xsoar Support Level'
        ),
        (
            {'community', 'partner'},
            'Partner Support Level'
        ),
        (
            {'partner'},
            'Partner Support Level'
        ),
        (
            {'community'},
            'Community Support Level'
        ),
    ]
)
def test_get_highest_support_label(support_levels, expected_support_level):
    """
    Given:
        - a list of support levels for packs that were changed

    When:
        - running get_highest_support_label function

    Then:
        - make sure the highest support level is always returned
    """
    from Utils.github_workflow_scripts.handle_external_pr import get_highest_support_label
    assert get_highest_support_label(support_levels) == expected_support_level


@pytest.mark.parametrize(
    'fork_owner, expected_fork_owner', [
        ('test', 'test'),
        ('xsoar-bot', 'xsoar-contrib')
    ]
)
def test_get_packs_support_level_label(mocker, fork_owner, expected_fork_owner):
    """
    Given:
        - a pack and a fork owner

    When:
        - running get_packs_support_level_label function

    Then:
        - make sure correct support label is returned.
        - fork owner that is being delivered to the Checkout branch is correct.
    """
    from Utils.github_workflow_scripts.handle_external_pr import get_packs_support_level_label, Checkout
    from Utils.github_workflow_scripts.utils import ChangeCWD

    checkout_mocker = mocker.patch.object(Checkout, '__init__', return_value=None)
    mocker.patch.object(Checkout, '__enter__', return_value=None)
    mocker.patch.object(Checkout, '__exit__', return_value=None)
    mocker.patch.object(os, 'getenv', return_value=fork_owner)

    with ChangeCWD('Utils/github_workflow_scripts/github_workflow_scripts_tests/test_files'):
        assert get_packs_support_level_label(
            file_paths=['Packs/Pack1/pack_metadata.json'], external_pr_branch='test'
        ) == 'Xsoar Support Level'

    assert checkout_mocker.call_args.kwargs['fork_owner'] == expected_fork_owner


def test_get_packs_support_level_label_checkout_failed(mocker):
    """
    Given:
        - a pack

    When:
        - running get_packs_support_level_label function when Checkout fails.

    Then:
        - make sure correct support label is still returned.
    """
    from Utils.github_workflow_scripts.handle_external_pr import get_packs_support_level_label, Checkout
    from Utils.github_workflow_scripts.utils import ChangeCWD

    mocker.patch.object(Checkout, '__init__', return_value=Exception('Error'))

    with ChangeCWD('Utils/github_workflow_scripts/github_workflow_scripts_tests/test_files'):
        assert get_packs_support_level_label(
            file_paths=['Packs/Pack1/pack_metadata.json'], external_pr_branch='test'
        ) == 'Xsoar Support Level'


@pytest.mark.parametrize('pr_files', REQUIRES_SECURITY_REVIEW)
def test_is_requires_security_reviewer_return_true(pr_files: str):
    """
    Test to check whether a security reviewer is needed depending on the PR changed files.

    Given:
        - a list of file paths
    When:
        - The file includes a keyword that indicates it requires security review
    Then:
        - make sure the function correctly identifies that a security review is required
    """

    assert is_requires_security_reviewer([pr_files]) is True


@pytest.mark.parametrize('pr_files', NOT_REQUIRE_SECURITY_REVIEW)
def test_is_requires_security_reviewer_return_false(pr_files: str):
    """
    Given:
        - a list of files in a PR that do not require a security review
    When:
        - running is_requires_security_reviewer function
    Then:
        - make sure the function correctly identifies that a security review is not required
    """
    assert is_requires_security_reviewer([pr_files]) is False
