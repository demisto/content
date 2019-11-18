from Tests.scripts.hook_validations.secrets import get_secrets, get_diff_text_files, is_text_file


class TestSecrets:
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
