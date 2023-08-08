import unittest
from unittest.mock import patch
from HuntingFromIndicatorLayout import hunting_from_indicator_layout


class TestHuntingFromIndicatorLayout(unittest.TestCase):
    @patch('demistomock.executecommand')
    def test_hunting_from_indicator_layout_success(self, mock_executecommand):
        mock_executecommand.return_value = [{'Type': 1, 'Contents': 'Incident created successfully'}]

        sdo_value = 'indicator'
        result = hunting_from_indicator_layout(sdo_value)

        expected_result = {
            'readable_output': f"Proactive Threat Hunting Incident Created: Threat Hunting Session - {sdo_value}"
        }
        self.assertEqual(result.outputs, expected_result)

    @patch('demistomock.executecommand')
    def test_hunting_from_indicator_layout_failure(self, mock_executecommand):
        mock_executecommand.side_effect = Exception('Test error')

        sdo_value = 'indicator'
        with self.assertRaises(DemistoException):
            hunting_from_indicator_layout(sdo_value)


if __name__ == '__main__':
    unittest.main()
