from unittest.mock import patch
from DSPMExtractUserResponseFromSlackBlockState import parse_slack_block_builder_res

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
