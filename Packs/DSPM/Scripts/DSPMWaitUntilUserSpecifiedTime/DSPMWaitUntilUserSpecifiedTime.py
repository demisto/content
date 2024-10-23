import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import time
import traceback


def wait_until_user_specified_time() -> int:
    """
    Retrieves the user-specified time from the DSPM instance configuration and converts it to seconds.

    The script fetches the integration configuration using the 'dspm-get-integration-config' command
    and retrieves the 'slackMsgLifetime' value. This value represents the time in hours, which is then
    converted to seconds. The script simulates waiting for the specified time by using a fixed sleep of
    30 seconds (for testing purposes) instead of the calculated time.

    Returns:
        int: The user-specified time in seconds, converted from hours.
    """
    # Fetch User specified time from the DSPM Instance configuration
    result = demisto.executeCommand("dspm-get-integration-config", {})
    integration_conf = result[0].get("Contents", {})
    sleep_time = integration_conf.get('slackMsgLifetime')

    # Convert time from hours to seconds
    in_seconds = int(sleep_time) * 3600

    time.sleep(int(in_seconds))
    # Simulate waiting for the user-specified time (testing purposes)
    # time.sleep(30)  # Using 30 seconds for testing

    return in_seconds


''' MAIN FUNCTION '''


def main():  # pragma: no cover
    """
    Main function that initiates the waiting process based on the user-specified time.

    It retrieves the user-specified time, logs the converted value, and returns the number of seconds
    the script is configured to wait. In case of an error, it logs the error traceback and returns
    a failure message.

    Returns:
        None: The result is returned via demisto.results() or demisto.error().
    """
    try:
        in_seconds = wait_until_user_specified_time()
        return_results(f"Sleep for {in_seconds} seconds")

    except Exception as excep:
        print(traceback.format_exc())  # Print the traceback for debugging
        return_error(f'Failed to execute DSPMWaitUntilUserSpecifiedTime. Error: {str(excep)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
