import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import traceback

CREATE_JIRA_TICKET = "Create a Jira ticket"
REMEDIATE_RISK = "Remediate a Risk"


def parse_slack_block_builder_res(SlackBlockState: Any) -> None:
    """
    Parses the Slack block builder response and sets user action context based on the input received.

    The function extracts the user-selected action from the SlackBlockState and retrieves the project
    name and ticket type if a Jira ticket is being created. It then sets the appropriate context in XSOAR.

    Args:
        SlackBlockState (Any): The state of the Slack block containing user input.

    Raises:
        TypeError: If the 'values' key is missing or if selected_option is None.
        Exception: For unsupported action types or general errors during parsing.
    """
    try:
        if isinstance(SlackBlockState, list):
            SlackBlockState = SlackBlockState[0]

        user_input_data = SlackBlockState.get("values")
        if user_input_data is None:
            raise TypeError("values in SlackBlockState is None or missing")

        action_name = (
            user_input_data.get("radio_buttons_0", {}).get("actionId-0", {}).get("selected_option", {}).get("value")
        )
        if action_name is None:
            raise TypeError("selected_option value is None or missing")

        project_key = None
        ticket_type = None

        if action_name == CREATE_JIRA_TICKET:
            project_key = user_input_data.get("plain_text_input_1", {}).get("project_name", {}).get("value", "")
            ticket_type = user_input_data.get("plain_text_input_2", {}).get("Issue_type", {}).get("value", "")
            if project_key and ticket_type:
                demisto.setContext("User.Action", "jira")
                demisto.setContext("User.JiraProjectName", project_key)
                demisto.setContext("User.JiraTicketType", ticket_type)
            else:
                demisto.setContext("User.Action", "invalid_response")
        elif action_name == REMEDIATE_RISK:
            demisto.setContext("User.Action", "remediate")
        else:
            raise Exception(f"Sorry!!, this '{action_name}' action type is not supported")
    except AttributeError as ae:
        demisto.error(traceback.format_exc())  # log the traceback
        demisto.setContext("User.Action", "invalid_response")
        return_error(f"Failed to parse Slack block builder response: {str(ae)}")
    except TypeError as ex:
        demisto.error(traceback.format_exc())  # log the traceback
        demisto.setContext("User.Action", "invalid_response")
        return_error(f"Failed to parse Slack block builder response: {str(ex)}")
    except Exception as ex:
        demisto.setContext("User.Action", "invalid_response")
        return_error(f"Failed to parse Slack block builder response: {str(ex)}")


""" MAIN FUNCTION """


def main() -> None:
    """
    Main function that executes the user response extraction from the Slack block state.

    It retrieves the Slack block state from the arguments, validates its existence,
    and calls the parsing function. If any error occurs, it sets the appropriate context
    and logs the error.

    Returns:
        None: The result is returned via demisto.setContext() or demisto.error().
    """
    try:
        SlackBlockState = demisto.args().get("SlackBlockState", None)
        if SlackBlockState is None:
            raise AttributeError("SlackBlockState is None")

        parse_slack_block_builder_res(SlackBlockState)
    except Exception as excep:
        demisto.setContext("User.Action", "no_response")
        return_error(f"Failed to execute DSPMExtractUserResponseFromSlackBlockState. Error: {str(excep)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
