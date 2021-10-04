import unittest
from Base64EncodeV2 import encode


class Base64EncodeV2(unittest.TestCase):
    def test_encode_japanese(self):
        """
        Given: Japanese characters.
        When: Encoding the characters using Base64.
        Then: Validate that the human readable and context outputs are properly formatted and that the input was encoded
        correctly.
        """
        input = '日本語'
        expected_result = '5pel5pys6Kqe'
        actual_result, output = encode(input)
        assert actual_result == expected_result
        assert output == {
            'Base64':
                {
                    'encoded': expected_result
                }
        }

    def test_encode_english(self):
        """
        Given: English characters.
        When: Encoding the characters using Base64.
        Then: Validate that the human readable and context outputs are properly formatted and that the input was encoded
        correctly.
        """
        input = 'test'
        expected_result = 'dGVzdA=='
        actual_result, output = encode(input)
        assert actual_result == expected_result
        assert output == {
            'Base64':
                {
                    'encoded': expected_result
                }
        }

    def test_encode_german(self):
        """
        Given: German characters.
        When: Encoding the characters using Base64.
        Then: Validate that the human readable and context outputs are properly formatted and that the input was encoded
        correctly.
        """
        input = 'äpfel'
        expected_result = 'w6RwZmVs'
        actual_result, output = encode(input)
        assert actual_result == expected_result
        assert output == {
            'Base64':
                {
                    'encoded': expected_result
                }
        }

    def test_encode_hebrew(self):
        """
        Given: Hebrew characters.
        When: Encoding the characters using Base64.
        Then: Validate that the human readable and context outputs are properly formatted and that the input was encoded
        correctly.
        """
        input = 'בדיקה'
        expected_result = '15HXk9eZ16fXlA=='
        actual_result, output = encode(input)
        assert actual_result == expected_result
        assert output == {
            'Base64':
                {
                    'encoded': expected_result
                }
        }

    def test_encode_arabic(self):
        """
        Given: Arabic characters.
        When: Encoding the characters using Base64.
        Then: Validate that the human readable and context outputs are properly formatted and that the input was encoded
        correctly.
        """
        input = 'امتحان'
        expected_result = '2KfZhdiq2K3Yp9mG'
        actual_result, output = encode(input)
        assert actual_result == expected_result
        assert output == {
            'Base64':
                {
                    'encoded': expected_result
                }
        }
