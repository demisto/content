from Utils.trigger_private_build import is_infrastructure_change


def test_is_infrastructure_change():
    """
    Given
    - A path to a file in content repo.

    When
    - Running is_infrastructure_change on it.

    Then
    - function returns True if the file is infrastructure
    """
    not_infra_file = is_infrastructure_change(['Utils/comment_on_pr.py'])
    infra_file = is_infrastructure_change(['Tests/scripts/validate_premium_packs.sh'])
    infra_folder = is_infrastructure_change(['Tests/private_build/run_content_tests_private.py'])
    assert not not_infra_file
    assert infra_file
    assert infra_folder
