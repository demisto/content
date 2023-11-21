import pytest


@pytest.mark.parametrize(
    'support_levels, expected_support_level', [
        (
            ['Utils/github_workflow_scripts/github_workflow_scripts_tests/test_files/Packs/Pack1/pack_metadata.json'],
            {'xsoar'}
        ),
        (
            ['Utils/github_workflow_scripts/github_workflow_scripts_tests/test_files/Packs/Pack2/pack_metadata.json'],
            {'partner'}
        ),
    ]
)
def test_get_support_level(support_levels, expected_support_level):
    """
        Given:
            - a list of support levels for packs that were changed

        When:
            - running get_highest_support_label function

        Then:
            - make sure the highest support level is always returned
    """
    from Utils.github_workflow_scripts.check_if_partner_approved_label_exists import get_support_level
    assert get_support_level(support_levels) == expected_support_level
