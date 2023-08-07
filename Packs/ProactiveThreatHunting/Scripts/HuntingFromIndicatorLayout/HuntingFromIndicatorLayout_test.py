import unittest
from HuntingFromIndicatorLayout import hunting_from_indicator_layout, CommandResults


def test_hunting_from_indicator_layout(sdo_name):
    expected_output = CommandResults(
        readable_output=f"Proactive Threat Hunting Incident Created: Threat Hunting Session - {sdo_name}")
    assert hunting_from_indicator_layout(sdo_name) == expected_output


def main():
    sdo_name = "sdo"
    test_hunting_from_indicator_layout(sdo_name)


if __name__ == '__main__':
    unittest.main()
