import pytest
from CommonServerPython import CommandResults
from DSPMCreateSimpleSlackMessageBlock import create_slack_notification_block, main
from unittest.mock import patch


def test_create_slack_notification_block():
    # Arrange
    message = "Incident response timeout notification"
    incident_link = "https://example.com/incident/12345"

    # Act
    slack_block = create_slack_notification_block(message, incident_link)

    # Assert
    expected_block = {
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": message}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*XSOAR Incident Link:* {incident_link}"}},
        ]
    }
    assert slack_block == expected_block


@pytest.fixture
def mock_demisto_args():
    return {"message": "Incident response timeout", "incidentLink": "https://example.com/incident/12345"}


@patch("DSPMCreateSimpleSlackMessageBlock.demisto")
def test_main(mock_demisto, mock_demisto_args):
    # Arrange
    mock_demisto.args.return_value = mock_demisto_args
    expected_output = CommandResults(
        outputs_prefix="slackBlock",
        outputs={
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": mock_demisto_args["message"]},
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*XSOAR Incident Link:* {mock_demisto_args['incidentLink']}",
                    },
                },
            ]
        },
    )

    # Act
    with patch("DSPMCreateSimpleSlackMessageBlock.return_results") as mock_return_results:
        main()

        # Assert
        actual_output = mock_return_results.call_args[0][0]
        assert actual_output.outputs_prefix == expected_output.outputs_prefix
        assert actual_output.outputs == expected_output.outputs
