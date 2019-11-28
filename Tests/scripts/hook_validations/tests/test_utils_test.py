import pytest
import yaml
from Tests import test_utils


class TestGetFile:
    PATH_TO_HERE = './Tests/scripts/hook_validations/tests/tests_data/'
    with open('{}fake_integration.yml'.format(PATH_TO_HERE), 'r') as f:
        data = yaml.safe_load(f)
    FILE_PATHS = [
        ('{}fake_json.json'.format(PATH_TO_HERE), test_utils.get_json, {"im a fake json": ["really!"]}),
        ('{}default_image.png'.format(PATH_TO_HERE), test_utils.get_yaml, {}),
        ('{}default_image.png'.format(PATH_TO_HERE), test_utils.get_json, {}),
        ('{}fake_integration.yml'.format(PATH_TO_HERE), test_utils.get_yaml, data)
    ]

    @pytest.mark.parametrize('file_path, func, expected', FILE_PATHS)
    def test_get_file(self, file_path, func, expected):
        assert func(file_path) == expected


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
