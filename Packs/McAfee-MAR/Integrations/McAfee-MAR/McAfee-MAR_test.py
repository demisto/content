import unittest

import demistomock as demisto
import importlib
import pytest

valid_private_key = """-----BEGIN PRIVATE KEY-----
This is a vaild Private Key
-----END PRIVATE KEY-----"""

valid_certificate = """-----BEGIN CERTIFICATE-----
This is a valid Certificate
-----END CERTIFICATE-----"""

invalid_private_key = r"\private\key\path.key"

invalid_certificate = """""-----BEGIN CERTIFICATE REQUEST-----
This is a valid Certificate
-----END CERTIFICATE REQUEST-----"""

spaces_in_certificate = """    -----BEGIN CERTIFICATE-----
This is a valid Certificate
-----END CERTIFICATE-----   """


def test_get_client_config(mocker):
    """
    Given
    - Configuration params - certificate, private_key, invalid_private_key
    When
    - Run validate_certificates_format
    Then
    - Validate the command and validation works as expected.
    """
    mcafee_mar = importlib.import_module("McAfee-MAR")

    # Invalid private Key
    valid_params = {'private_key': invalid_private_key,
                    'cert_file': valid_certificate,
                    'broker_ca_bundle': valid_certificate}
    mocker.patch.object(demisto, "params", return_value=valid_params)
    with pytest.raises(SystemExit):
        mcafee_mar.validate_certificates_format()

    # Invalid cert file
    valid_params = {'private_key': valid_private_key,
                    'cert_file': invalid_certificate,
                    'broker_ca_bundle': valid_certificate}
    mocker.patch.object(demisto, "params", return_value=valid_params)
    with pytest.raises(SystemExit):
        mcafee_mar.validate_certificates_format()

    # Invalid broker_ca_bundle
    valid_params = {'private_key': valid_private_key,
                    'cert_file': valid_certificate,
                    'broker_ca_bundle': invalid_certificate}
    mocker.patch.object(demisto, "params", return_value=valid_params)
    with pytest.raises(SystemExit):
        mcafee_mar.validate_certificates_format()

    # Everything is valid + spaces
    valid_params = {'private_key': valid_private_key,
                    'cert_file': valid_certificate,
                    'broker_ca_bundle': spaces_in_certificate}
    mocker.patch.object(demisto, "params", return_value=valid_params)
    mcafee_mar.validate_certificates_format()


class TestTranslateDict(unittest.TestCase):
    """
    Test cases for the translate_dict function.
    """

    def test_translate_dict_no_translation_needed(self):
        """
        Test the scenario where no translation is needed.
        """
        mcafee_mar = importlib.import_module("McAfee-MAR")
        d = {'key1': 'value1', 'key2': 'value2'}
        translator = {'key1': 'key1', 'key2': 'key2'}
        expected = {'key1': 'value1', 'key2': 'value2'}
        self.assertEqual(mcafee_mar.translate_dict(d, translator), expected)

    def test_translate_dict_translation_needed(self):
        """
        Test the scenario where every key in the dictionary needs to be translated.
        """
        mcafee_mar = importlib.import_module("McAfee-MAR")
        d = {'key1': 'value1', 'key2': 'value2'}
        translator = {'key1': 'new_key1', 'key2': 'new_key2'}
        expected = {'new_key1': 'value1', 'new_key2': 'value2'}
        self.assertEqual(mcafee_mar.translate_dict(d, translator), expected)

    def test_translate_dict_partial_translation(self):
        """
        Test the scenario where only some keys in the dictionary need to be translated.
        """
        mcafee_mar = importlib.import_module("McAfee-MAR")
        d = {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}
        translator = {'key1': 'new_key1'}
        expected = {'new_key1': 'value1', 'key2': 'value2', 'key3': 'value3'}
        self.assertEqual(mcafee_mar.translate_dict(d, translator), expected)

    def test_translate_dict_empty_dict(self):
        """
        Test the scenario where the input dictionary is empty.
        """
        mcafee_mar = importlib.import_module("McAfee-MAR")
        d = {}
        translator = {'key1': 'new_key1', 'key2': 'new_key2'}
        expected = {}
        self.assertEqual(mcafee_mar.translate_dict(d, translator), expected)


class TestExtractItemOutput(unittest.TestCase):
    """
    Test cases for the extract_item_output function.
    """

    def test_extract_item_output_no_capitalize(self):
        """
        Test the scenario where 'capitalize' is False.
        """
        mcafee_mar = importlib.import_module("McAfee-MAR")
        item = {'output': {'Collector1|Key1': 'value1', 'Collector2|Key2': 'value2'}, 'created_at': '2023-06-20'}
        capitalize = False
        expected = {'created_at': '2023-06-20', 'Key1': 'value1', 'Key2': 'value2'}
        self.assertEqual(mcafee_mar.extract_item_output(item, capitalize), expected)

    def test_extract_item_output_with_capitalize(self):
        """
        Test the scenario where 'capitalize' is True.
        """
        mcafee_mar = importlib.import_module("McAfee-MAR")
        item = {'output': {'Collector1|Key1': 'value1', 'Collector2|Key2': 'value2'}, 'created_at': '2023-06-20'}
        capitalize = True
        expected = {'created_at': '2023-06-20', 'Key1': 'value1', 'Key2': 'value2'}
        self.assertEqual(mcafee_mar.extract_item_output(item, capitalize), expected)

    def test_extract_item_output_no_pipe_in_key(self):
        """
        Test the scenario where there is no pipe ('|') in the output keys.
        """
        mcafee_mar = importlib.import_module("McAfee-MAR")
        item = {'output': {'Key1': 'value1', 'Key2': 'value2'}, 'created_at': '2023-06-20'}
        capitalize = False
        expected = {'created_at': '2023-06-20', 'Key1': 'value1', 'Key2': 'value2'}
        self.assertEqual(mcafee_mar.extract_item_output(item, capitalize), expected)

    def test_extract_item_output_empty_output(self):
        """
        Test the scenario where the output in the item is empty.
        """
        mcafee_mar = importlib.import_module("McAfee-MAR")
        item = {'output': {}, 'created_at': '2023-06-20'}
        capitalize = False
        expected = {'created_at': '2023-06-20'}
        self.assertEqual(mcafee_mar.extract_item_output(item, capitalize), expected)
