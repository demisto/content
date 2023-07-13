import os
import pytest


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
