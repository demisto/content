import os
import pytest
from handle_external_pr import (
    is_requires_security_reviewer,
    SECURITY_CONTENT_ITEMS
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


@pytest.mark.parametrize('pr_files,expected', [
    ([f"Packs/HelloWorld/{SECURITY_CONTENT_ITEMS[0]}/{SECURITY_CONTENT_ITEMS[0].lower()}-Hello_World_Alert-V2.yml"], True),
    (['Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py'], False),
    (['Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py',
      f"Packs/HelloWorld/{SECURITY_CONTENT_ITEMS[1]}/{SECURITY_CONTENT_ITEMS[1].lower()}-Hello_World_Alert-V2.json"], True),
    (['Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py',
      f"Packs/HelloWorld/{SECURITY_CONTENT_ITEMS[2]}/{SECURITY_CONTENT_ITEMS[2].lower()}-Hello_World_Alert-V2.json"], True),
    (['Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py',
      f"Packs/HelloWorld/{SECURITY_CONTENT_ITEMS[3]}/{SECURITY_CONTENT_ITEMS[3].lower()}-Hello_World_Alert-V2.json"], True),
    (['Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py',
      f"Packs/HelloWorld/{SECURITY_CONTENT_ITEMS[4]}/{SECURITY_CONTENT_ITEMS[4].lower()}-Hello_World_Alert-V2.json"], True),
    (['Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py',
      f"Packs/HelloWorld/{SECURITY_CONTENT_ITEMS[5]}/{SECURITY_CONTENT_ITEMS[5].lower()}-Hello_World_Alert-V2.json"], True),
    (['Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py',
      f"Packs/HelloWorld/{SECURITY_CONTENT_ITEMS[6]}/{SECURITY_CONTENT_ITEMS[6].lower()}-Hello_World_Alert-V2.json"], True),
    (['Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py',
      f"Packs/HelloWorld/{SECURITY_CONTENT_ITEMS[7]}/{SECURITY_CONTENT_ITEMS[7].lower()}-Hello_World_Alert-V2.json"], True)
])
def test_is_requires_security_reviewer(pr_files: list[str], expected: bool):
    """
    Test to check whether a security reviewer is needed depending on the PR changed files.

    Given: a list of file paths

    When:
        - Case A: The provided file is a Playbook.
        - Case B: The provided file is an integration.
        - Case C: The provided files are an integration and an incident type.
        - Case D: The provided files are an integration and an incident field.
        - Case E: The provided files are an integration and an indicator type.
        - Case F: The provided files are an integration and an indicator field.
        - Case G: The provided files are an integration and a layout.
        - Case H: The provided files are an integration and a classifier.
        - Case I: The provided files are an integration and a wizard.

    Then:
        - Case A: Requires a security engineer review.
        - Case B: Doesn't require a security engineer review.
        - Cases C-I: Requires a security engineer review.
    """

    assert is_requires_security_reviewer(pr_files) == expected
