import unittest
from unittest.mock import patch
from HuntingFromIndicatorLayout import hunting_from_indicator_layout


class TestHuntingFromIndicatorLayout(unittest.TestCase):
    @patch('demistomock.executeCommand')
    def test_hunting_from_indicator_layout_success(self, mock_executeCommand):
        mock_executeCommand.return_value = [{'Type': 1, 'Contents': 'Incident created successfully'}]

        sdo_value = 'indicator'
        result = hunting_from_indicator_layout(sdo_value)

        expected_result = {
            f"Proactive Threat Hunting Incident Created: Threat Hunting Session - {sdo_value}"
        }
        self.assertEqual(result.outputs, expected_result)


if __name__ == '__main__':
    unittest.main()
