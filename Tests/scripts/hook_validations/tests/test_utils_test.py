import pytest

from Tests import test_utils
from Tests.scripts.constants import PACKS_PLAYBOOK_YML_REGEX, PACKS_TEST_PLAYBOOKS_REGEX
from Tests.test_utils import get_matching_regex, server_version_compare


class TestGetFile:
    PATH_TO_HERE = './Tests/scripts/hook_validations/tests/tests_data/'
    FILE_PATHS = [
        ('{}fake_integration.yml'.format(PATH_TO_HERE), test_utils.get_yaml),
        ('{}fake_json.json'.format(PATH_TO_HERE), test_utils.get_json)
    ]

    @pytest.mark.parametrize('file_path, func', FILE_PATHS)
    def test_get_yaml(self, file_path, func):
        assert func(file_path)


class TestGetRemoteFile:
    def test_get_remote_file_sanity(self):
        gmail_yml = test_utils.get_remote_file('Integrations/Gmail/Gmail.yml')
        assert gmail_yml
        assert gmail_yml['commonfields']['id'] == 'Gmail'

    def test_get_remote_file_origin(self):
        gmail_yml = test_utils.get_remote_file('Integrations/Gmail/Gmail.yml', 'master')
        assert gmail_yml
        assert gmail_yml['commonfields']['id'] == 'Gmail'

    def test_get_remote_file_tag(self):
        gmail_yml = test_utils.get_remote_file('Integrations/Gmail/Gmail.yml', '19.10.0')
        assert gmail_yml
        assert gmail_yml['commonfields']['id'] == 'Gmail'

    def test_get_remote_file_origin_tag(self):
        gmail_yml = test_utils.get_remote_file('Integrations/Gmail/Gmail.yml', 'origin/19.10.0')
        assert gmail_yml
        assert gmail_yml['commonfields']['id'] == 'Gmail'

    def test_get_remote_file_invalid(self):
        invalid_yml = test_utils.get_remote_file('Integrations/File/File.yml', '19.10.0')
        assert not invalid_yml

    def test_get_remote_file_invalid_branch(self):
        invalid_yml = test_utils.get_remote_file('Integrations/Gmail/Gmail.yml', 'NoSuchBranch')
        assert not invalid_yml

    def test_get_remote_file_invalid_origin_branch(self):
        invalid_yml = test_utils.get_remote_file('Integrations/Gmail/Gmail.yml', 'origin/NoSuchBranch')
        assert not invalid_yml


class TestGetMatchingRegex:
    INPUTS = [
        ('Packs/XDR/Playbooks/XDR.yml', [PACKS_PLAYBOOK_YML_REGEX, PACKS_TEST_PLAYBOOKS_REGEX],
         PACKS_PLAYBOOK_YML_REGEX),
        ('Packs/XDR/NoMatch/XDR.yml', [PACKS_PLAYBOOK_YML_REGEX, PACKS_TEST_PLAYBOOKS_REGEX], None)
    ]

    @pytest.mark.parametrize("string_to_match, regexes, answer", INPUTS)
    def test_get_matching_regex(self, string_to_match, regexes, answer):
        assert get_matching_regex(string_to_match, regexes) == answer


class TestServerVersionCompare:
    V5 = "5.0.0"
    V0 = "0.0.0"
    EQUAL = 0
    LEFT_IS_LATER = 1
    RIGHT_IS_LATER = -1
    INPUTS = [
        (V0, V5, RIGHT_IS_LATER),
        (V5, V0, LEFT_IS_LATER),
        (V5, V5, EQUAL)
    ]

    @pytest.mark.parametrize("left, right, answer", INPUTS)
    def test_server_version_compare(self, left, right, answer):
        assert server_version_compare(left, right) == answer
