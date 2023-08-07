import pytest
from unittest.mock import patch
from HuntingFromIndicatorLayout import hunting_from_indicator_layout


@pytest.fixture
def mock_demisto():
    with patch('HuntingFromIndicatorLayout.demisto') as mock:
        yield mock


def test_hunting_from_indicator_layout_success(mock_demisto):
    # Mocking the executeCommand function to return a desired response
    mock_demisto.executeCommand.return_value = [
        {
            "Type": 1,
            "Contents": "Incident created successfully"
        }
    ]

    # Call the hunting_from_indicator_layout function
    sdo = "example_sdo"
    result = hunting_from_indicator_layout(sdo)

    # Assert the expected function calls and return value
    mock_demisto.executeCommand.assert_called_once_with("createNewIncident", {
        "name": f"Threat Hunting Session - {sdo}",
        "sdoname": f"{sdo}",
        "type": "Proactive Threat Hunting"
    })
    assert result.outputs_prefix == 'CreateNewIncident'
    assert result.outputs_key_field == 'id'
    assert result.outputs == [{"id": "Incident created successfully"}]
    assert result.readable_output == f"Proactive Threat Hunting Incident Created: Threat Hunting Session - {sdo}"


def test_hunting_from_indicator_layout_failure(mock_demisto):
    # Mocking the executeCommand function to raise an exception
    mock_demisto.executeCommand.side_effect = Exception("Test exception")

    # Call the hunting_from_indicator_layout function
    sdo = "example_sdo"
    with pytest.raises(DemistoException) as cm:
        hunting_from_indicator_layout(sdo)

    # Assert the raised exception message
    assert str(cm.value) == 'Failed to create hunting session: Test exception'
