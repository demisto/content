import unittest

from Tests.scripts.hook_validations.secrets import get_secrets, get_diff_text_files


class TestSecrets(unittest.TestCase):
    def test_get_secrets(self):
        secrets = get_secrets('master', True)
        assert not secrets

    def test_get_diff_text_files(self):
        changed_files = '''
        A       Integrations/Recorded_Future/Recorded_Future.yml
        D       Integrations/integration-Recorded_Future.yml'''
        get_diff = get_diff_text_files(changed_files)
        self.assertIn('Integrations/Recorded_Future/Recorded_Future.yml', get_diff)


if __name__ == '__main__':
    unittest.main()
