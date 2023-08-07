import unittest
import pytest
from HuntingFromIndicatorLayout import hunting_from_indicator_layout, CommandResults


class TestHuntingFromIndicatorLayout(unittest.TestCase):

    @pytest.mark.parametrize('sdo_name', ['sdoname'])  # 'sdoname' should be a list
    def test_hunting_from_indicator_layout(self, sdo_name):
        expected_output = CommandResults(
            readable_output=f"Proactive Threat Hunting Incident Created: Threat Hunting Session - {sdo_name}")
        self.assertEqual(hunting_from_indicator_layout(sdo_name), expected_output)


if __name__ == '__main__':
    unittest.main()
