import pytest
from unittest.mock import patch
from HuntingFromIndicatorLayout import hunting_from_indicator_layout, main
from CommonServerPython import DemistoException  # noqa: F401


@pytest.fixture
def mock_executeCommand():
    with patch('demistomock.executeCommand') as mock:
        yield mock


@pytest.mark.parametrize("sdo_value, expected_result",
                         [("indicator", "Proactive Threat Hunting Incident Created: Threat Hunting Session - indicator")])
def test_hunting_from_indicator_layout_success(mock_executeCommand, sdo_value, expected_result):
    """
    Given:
        The 'mock_executeCommand' function is properly patched to mock 'demistomock.executeCommand'.
    When:
        The 'hunting_from_indicator_layout' function is called with the sdo_value parameter set to "indicator".
    Then:
        The result of 'hunting_from_indicator_layout' compared to the 'expected_results'.
    """
    mock_executeCommand.return_value = [{'Type': 1, 'Contents': 'Incident created successfully'}]

    result = hunting_from_indicator_layout(sdo_value)

    assert result.readable_output == expected_result


def test_hunting_from_indicator_layout_failure(mock_executeCommand):
    """
        Given:
            The mock_executeCommand function is properly patched to mock demistomock.executeCommand.
        When:
            The hunting_from_indicator_layout function is called with the sdo_value parameter set to "non_existent_indicator",
                and the mocked executeCommand is configured to raise a DemistoException
        Then:
            he test is expected to raise a DemistoException with the specified message.
    """
    mock_executeCommand.side_effect = DemistoException("The automation was not executed from indicator layout")

    with pytest.raises(DemistoException):
        hunting_from_indicator_layout("non_existent_indicator")


def test_main_indicator_not_in_args():
    """
        Given:
            No additional setup is required.
        When:
            The main function is called.
        Then:
            The test is expected to raise a DemistoException with the message "The automation was not
                executed from indicator layout".
    """
    with pytest.raises(DemistoException, match="The automation was not executed from indicator layout"):

        main()


if __name__ == '__main__':
    pytest.main()
