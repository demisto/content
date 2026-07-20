"""{
    "additional_needed_packs": {}
}
"""

import time

from demisto_client.demisto_api.rest import ApiException
from demisto_sdk.commands.common.clients import (
    XsiamClient,
    get_client_from_server_type,
    get_client_conf_from_pytest_request,
)
from demisto_sdk.commands.common.clients.errors import PollTimeout
from demisto_sdk.commands.common.constants import InvestigationPlaybookState
from dotenv import load_dotenv
import pytest


load_dotenv()


@pytest.fixture(scope="class")
def client_conf(request):
    # Manually parse command-line arguments
    return get_client_conf_from_pytest_request(request)


@pytest.fixture(scope="class")
def api_client(client_conf: dict):
    if client_conf:  # Running from external pipeline
        client_obj = get_client_from_server_type(**client_conf)

    else:  # Running manually using pytest.
        client_obj = get_client_from_server_type()
    return client_obj


class TestNtdsDitFileWrittenByARareExecutable:
    """Test class for the Uncommon Remote Scheduled Task Created playbook."""

    def setup_class(self) -> None:
        """Setup class method."""

    def teardown_class(self) -> None:
        """Teardown class method."""

    def test_feature_one(self) -> None:
        """Test feature one."""
        # Sanity test
        assert True

    def test_feature_two(self, api_client: XsiamClient, capfd) -> None:
        """Verifies that the playbook successfully disables the scheduled task.

        Args:
            api_client (XsiamClient): The API client to use.
            capfd: pytest capture fixture used for diagnostic logging.

        """
        # consts
        alert_name = "NTDS.dit file written by a rare executable"
        playbook_name = "silent-NTDS.dit file written by an uncommon executable"

        # get recently uploaded alert IDs - retry to allow backend indexing time
        alert_ids = []
        for _ in range(6):  # Retry up to 30 seconds
            alert_ids = api_client.search_alerts_by_name(alert_names=[alert_name])
            if alert_ids:
                break
            time.sleep(5)

        with capfd.disabled():
            print(f"[diag] alert_ids found: {alert_ids}")

        # use the latest alert
        try:
            alert_id = alert_ids[0]
        except IndexError:
            pytest.fail(f"Could not find alert with name '{alert_name}' after waiting.")

        with capfd.disabled():
            print(f"[diag] Using alert_id: {alert_id}")

        # start investigation for the alert
        try:
            api_client.xsoar_client.generic_request(path=f"/xsoar/investigation/{alert_id}", method="POST")

            # trigger playbook to run on alert
            set_pb_resp = api_client.run_cli_command(
                command=f'!setPlaybook name="{playbook_name}" alertId="{alert_id}"', investigation_id=alert_id
            )
            with capfd.disabled():
                set_pb_contents = (
                    [getattr(e, "contents", None) for e in set_pb_resp[0]] if set_pb_resp and set_pb_resp[0] else set_pb_resp
                )
                print(f"[diag] setPlaybook response contents: {set_pb_contents}")

            initial_state = api_client.get_playbook_state(alert_id)
            with capfd.disabled():
                print(f"[diag] initial playbook state: id={initial_state.get('playbookId')} state={initial_state.get('state')}")
        except ApiException as e:
            if "reopen" not in e.body:
                pytest.fail(f"Exception setting playbook: {e.body}")
            with capfd.disabled():
                print(f"[diag] ApiException (reopen path): {e.body}")

        # get playbook state info
        try:
            playbook_state_info = api_client.poll_playbook_state(
                alert_id, expected_states=(InvestigationPlaybookState.COMPLETED,), timeout=1200
            )
        except PollTimeout as e:
            final_state = api_client.get_playbook_state(alert_id)
            with capfd.disabled():
                print(
                    f"[diag] final playbook state on timeout: id={final_state.get('playbookId')} state={final_state.get('state')}"
                )
            pytest.fail(f"Playbook did not reach the completed state. Error: {e}")

        # validate state
        playbook_state = playbook_state_info.get("state")
        if playbook_state != "completed":
            pytest.fail(f"Playbook did not reach the completed state. State: {playbook_state}")

        # get the investigation context
        context = api_client.get_investigation_context(investigation_id=alert_id)

        # validate if terminate process was called
        termination_id = context.get("Core", {}).get("TerminateProcess", {}).get("action_id")
        if not termination_id:
            pytest.fail("Could not find termination ID")

        # validate if terminate process was successful
        action_status_id = context.get("Core", {}).get("GetActionStatus", {}).get("action_id")
        if (not action_status_id) and action_status_id != termination_id:
            pytest.fail("No action ID matches termination ID")

        action_status = context.get("Core", {}).get("GetActionStatus", {}).get("status")
        if (not action_status) and action_status != "COMPLETED_SUCCESSFULLY":
            pytest.fail("Termination failed")

        # all validations passed
        assert True


if __name__ == "__main__":
    pytest.main([__file__])
