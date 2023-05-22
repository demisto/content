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
        a list of support levels for packs that were changed

    When:
        running get_highest_support_label function

    Then:
        make sure the highest support level is always returned
    """
    from Utils.github_workflow_scripts.handle_external_pr import get_highest_support_label
    assert get_highest_support_label(support_levels) == expected_support_level
