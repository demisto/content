from unittest.mock import patch
from DSPMExtractUserResponseFromSlackBlockState import parse_slack_block_builder_res, main

CREATE_JIRA_TICKET = "Create a Jira ticket"
REMEDIATE_RISK = "Remediate a Risk"


def test_parse_slack_block_builder_res_jira_ticket_creation():
    SlackBlockState = {
        "values": {
            "radio_buttons_0": {
                "actionId-0": {
                    "selected_option": {"value": CREATE_JIRA_TICKET}
                }
            },
            "plain_text_input_1": {
                "project_name": {"value": "Project01"}
            },
            "plain_text_input_2": {
                "Issue_type": {"value": "Bug"}
            }
        }
    }

    with patch("DSPMExtractUserResponseFromSlackBlockState.demisto.setContext") as mock_set_context:
        parse_slack_block_builder_res(SlackBlockState)

        # Assert
        mock_set_context.assert_any_call("User.Action", "jira")
        mock_set_context.assert_any_call("User.JiraProjectName", "Project01")
        mock_set_context.assert_any_call("User.JiraTicketType", "Bug")


def test_parse_slack_block_builder_res_remediate_risk():
    SlackBlockState = {
        "values": {
            "radio_buttons_0": {
                "actionId-0": {
                    "selected_option": {"value": REMEDIATE_RISK}
                }
            }
        }
    }
    with patch("DSPMExtractUserResponseFromSlackBlockState.demisto.setContext") as mock_set_context:
        parse_slack_block_builder_res(SlackBlockState)

        # Assert
        mock_set_context.assert_any_call("User.Action", "remediate")


def test_parse_slack_block_builder_res_missing_values_key(capfd):
    SlackBlockState = {
        "values": {
            "radio_buttons_0": {
                "actionId-0": {}
            }
        }
    }

    with patch("DSPMExtractUserResponseFromSlackBlockState.demisto.setContext") as mock_set_context, \
            patch("DSPMExtractUserResponseFromSlackBlockState.return_error") as mock_return_error, \
            capfd.disabled():

        # Run the function with an input that causes an Exception
        parse_slack_block_builder_res(SlackBlockState)
        mock_set_context.assert_called_once_with("User.Action", "invalid_response")
        mock_return_error.assert_called_once_with(
            "Failed to parse Slack block builder response: selected_option value is None or missing")

    SlackBlockState = {}
    with patch("DSPMExtractUserResponseFromSlackBlockState.demisto.setContext") as mock_set_context, \
            patch("DSPMExtractUserResponseFromSlackBlockState.return_error") as mock_return_error, \
            capfd.disabled():

        # Run the function with an input that causes an Exception
        parse_slack_block_builder_res(SlackBlockState)
        mock_set_context.assert_called_once_with("User.Action", "invalid_response")
        mock_return_error.assert_called_once_with(
            "Failed to parse Slack block builder response: values in SlackBlockState is None or missing")


def test_parse_slack_block_builder_res_unsupported_action_type():
    SlackBlockState = [{
        "values": {
            "radio_buttons_0": {
                "actionId-0": {
                    "selected_option": {"value": "unsupported_action"}
                }
            }
        }
    }]

    with patch("DSPMExtractUserResponseFromSlackBlockState.demisto.setContext") as mock_set_context, \
            patch("DSPMExtractUserResponseFromSlackBlockState.return_error") as mock_return_error:

        # Run the function with an input that causes an Exception
        parse_slack_block_builder_res(SlackBlockState)
        mock_set_context.assert_called_once_with("User.Action", "invalid_response")
        mock_return_error.assert_called_once_with(
            "Failed to parse Slack block builder response: Sorry!!, this 'unsupported_action' action type is not supported")


def test_main():
    with patch("DSPMExtractUserResponseFromSlackBlockState.demisto.args", return_value={"SlackBlockState": None}), \
            patch("DSPMExtractUserResponseFromSlackBlockState.demisto.setContext") as mock_set_context, \
            patch("DSPMExtractUserResponseFromSlackBlockState.return_error") as mock_return_error:

        # Call the function, expecting it to handle the Exception
        main()

        mock_set_context.assert_called_once_with("User.Action", "no_response")
        mock_return_error.assert_called_once_with(
            "Failed to execute DSPMExtractUserResponseFromSlackBlockState. Error: SlackBlockState is None")
