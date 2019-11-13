from Tests import test_utils


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
