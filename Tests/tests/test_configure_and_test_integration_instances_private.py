import pytest

from Tests.private_build.configure_and_test_integration_instances_private import find_needed_test_playbook_paths
from Tests.tests.constants_testing import SAMPLE_TESTPLAYBOOK_CONF


def test_find_needed_test_playbook_paths():
    """
    Scenario: Matching a test which is needed with available playbooks found in the ID set.
    Given: Test filter with HelloWorld_Scan-Test in it and a sample test playbook conf
    When: Finding the file path of the test
    Then: Return a set with one item in it where the item is the file_path for the test.
    :return:
    """
    sample_test_filter_path = './Utils/tests/test_data_old_content/sample_test_filter.txt'
    file_paths = find_needed_test_playbook_paths(test_playbooks=SAMPLE_TESTPLAYBOOK_CONF, filter_file_path=sample_test_filter_path)
    assert len(file_paths) == 1
    assert file_paths == {'/home/runner/work/content-private/content-private/content/Packs/HelloWorld/'
                          'TestPlaybooks/playbook-HelloWorld_Scan-Test.yml'}

