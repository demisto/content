import os
from Tests.scripts.hook_validations.secrets import get_secrets, get_diff_text_files, is_text_file, \
    search_potential_secrets, remove_white_list_regex, create_temp_white_list, get_file_contents, \
    retrieve_related_yml, regex_for_secrets, calculate_shannon_entropy, get_packs_white_list, get_generic_white_list, \
    remove_false_positives, is_secrets_disabled, ignore_base64


class TestSecrets:
    TEST_BASE_PATH = './Tests/scripts/hook_validations/tests/tests_data/fake_integration/'
    TEST_YML_FILE = TEST_BASE_PATH + 'fake_integration.yml'
    TEST_PY_FILE = TEST_BASE_PATH + 'fake_integration.py'
    TEST_WHITELIST_FILE_PACKS = TEST_BASE_PATH + 'fake.secrets-ignore'
    TEST_WHITELIST_FILE = TEST_BASE_PATH + 'fake_secrets_white_list.json'
    TEST_BASE_64_STRING = 'OCSn7JGqKehoyIyMCm7gPFjKXpawXvh2M32' * 20 + ' sade'

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

    def test_get_related_yml_contents(self):
        yml_file_contents = retrieve_related_yml(os.path.dirname(self.TEST_PY_FILE))
        assert 'Use the Zoom integration manage your Zoom users and meetings' in yml_file_contents

    def test_regex_for_secrets(self):
        line = 'dockerimage: demisto/duoadmin:1.0.0.147 199.199.178.199 123e4567-e89b-12d3-a456-426655440000'
        secrets, false_positives = regex_for_secrets(line)
        assert '1.0.0.147' in false_positives
        assert '123e4567-e89b-12d3-a456-426655440000' in false_positives
        assert '199.199.178.199' in secrets

    def test_calculate_shannon_entropy(self):
        test_string = 'SADE'
        entropy = calculate_shannon_entropy(test_string)
        assert entropy == 2.0

    def test_get_packs_white_list(self):
        final_white_list, ioc_white_list, files_while_list = get_packs_white_list(self.TEST_WHITELIST_FILE_PACKS)
        assert ioc_white_list == []
        assert files_while_list == []
        assert final_white_list == ['boop', 'sade', 'sade.txt', 'sade@sade.sade']

    def test_get_generic_white_list(self):
        final_white_list, ioc_white_list, files_while_list = get_generic_white_list(self.TEST_WHITELIST_FILE)
        assert ioc_white_list == ['sade@sade.sade']
        assert files_while_list == ['sade.txt']
        assert final_white_list == ['sade@sade.sade', 'aboop', 'asade']

    def test_remove_false_positives(self):
        line = '[I AM MISTER MEESEEKS LOOK AT ME] sade'
        line = remove_false_positives(line)
        assert line == ' sade'

    def test_is_secrets_disabled(self):
        line1 = 'disable-secrets-detection'
        skip_secrets = {'skip_once': False, 'skip_multi': False}
        skip_secrets = is_secrets_disabled(line1, skip_secrets)
        assert skip_secrets['skip_once'] and not skip_secrets['skip_multi']
        skip_secrets['skip_once'] = False
        line2 = 'disable-secrets-detection-start'
        skip_secrets = is_secrets_disabled(line2, skip_secrets)
        assert not skip_secrets['skip_once'] and skip_secrets['skip_multi']
        line3 = 'disable-secrets-detection-end'
        skip_secrets = is_secrets_disabled(line3, skip_secrets)
        assert not skip_secrets['skip_once'] and not skip_secrets['skip_multi']

    def test_ignore_base64(self):
        file_contents = self.TEST_BASE_64_STRING
        file_contents = ignore_base64(file_contents)
        assert file_contents.lstrip() == 'sade'
