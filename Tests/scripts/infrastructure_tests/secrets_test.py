from Tests.scripts.hook_validations.secrets import get_secrets, get_diff_text_files, is_text_file, \
    search_potential_secrets, remove_white_list_regex, create_temp_white_list, get_file_contents


class TestSecrets:
    TEST_YML_FILE = './Tests/scripts/hook_validations/tests/tests_data/fake_integration.yml'

    def test_get_secrets(self):
        secrets = get_secrets('master', True)
        assert not secrets

    def test_get_diff_text_files(self):
        changed_files = '''
        A       Integrations/Recorded_Future/Recorded_Future.yml
        D       Integrations/integration-Recorded_Future.yml'''
        get_diff = get_diff_text_files(changed_files)
        assert 'Integrations/Recorded_Future/Recorded_Future.yml' in get_diff

    def test_is_text_file(self):
        changed_files = 'Integrations/Recorded_Future/Recorded_Future.yml'
        is_txt = is_text_file(changed_files)
        assert is_txt is True

    def test_search_potential_secrets(self):
        secrets_found = search_potential_secrets([self.TEST_YML_FILE])
        assert not secrets_found

    def test_remove_white_list_regex(self):
        white_list = '155.165.45.232'
        file_contents = '''
        boop
        shmoop
        155.165.45.232
        '''
        file_contents = remove_white_list_regex(white_list, file_contents)
        assert white_list not in file_contents

    def test_temp_white_list(self):
        file_contents = get_file_contents(self.TEST_YML_FILE, '.yml')
        temp_white_list = create_temp_white_list(file_contents)
        assert 'sha256' in temp_white_list
