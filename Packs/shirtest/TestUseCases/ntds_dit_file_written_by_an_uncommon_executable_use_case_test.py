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
        alert_name = "shirtestname"
        playbook_name = "silent-shirtestname"

        with capfd.disabled():
            print(f"[diag] test_feature_two START — alert_name={alert_name!r} playbook_name={playbook_name!r}")

        # get recently uploaded alert IDs - retry to allow backend indexing time
        alert_ids = []
        for attempt in range(6):  # Retry up to 30 seconds
            with capfd.disabled():
                print(f"[diag] search_alerts_by_name attempt {attempt + 1}/6 for alert_name={alert_name!r}")
            alert_ids = api_client.search_alerts_by_name(alert_names=[alert_name])
            with capfd.disabled():
                print(f"[diag] search_alerts_by_name attempt {attempt + 1}/6 result: {alert_ids}")
            if alert_ids:
                break
            with capfd.disabled():
                print("[diag] no alerts found yet, sleeping 5s before retry")
            time.sleep(5)

        with capfd.disabled():
            print(f"[diag] alert_ids found after retries: {alert_ids}")

        # use the latest alert
        try:
            alert_id = alert_ids[0]
        except IndexError:
            with capfd.disabled():
                print(f"[diag] FAIL — alert_ids is empty, could not find alert with name={alert_name!r}")
            pytest.fail(f"Could not find alert with name '{alert_name}' after waiting.")

        with capfd.disabled():
            print(f"[diag] Using alert_id: {alert_id}")

        # start investigation for the alert
        investigation_path = f"/xsoar/investigation/{alert_id}"
        with capfd.disabled():
            print(f"[diag] Opening investigation — path={investigation_path}")

        try:
            investigation_resp = api_client.xsoar_client.generic_request(path=investigation_path, method="POST")
            with capfd.disabled():
                print(f"[diag] generic_request POST {investigation_path} response: {investigation_resp}")

            # trigger playbook to run on alert
            set_pb_command = f'!setPlaybook name="{playbook_name}" alertId="{alert_id}"'
            with capfd.disabled():
                print(f"[diag] Running CLI command: {set_pb_command} (investigation_id={alert_id})")

            set_pb_resp = api_client.run_cli_command(command=set_pb_command, investigation_id=alert_id)
            with capfd.disabled():
                print(f"[diag] run_cli_command raw response: {set_pb_resp}")
                set_pb_contents = (
                    [getattr(e, "contents", None) for e in set_pb_resp[0]] if set_pb_resp and set_pb_resp[0] else set_pb_resp
                )
                print(f"[diag] setPlaybook response contents: {set_pb_contents}")
                # Highlight if playbook name was not found — this is the key failure signal
                if set_pb_contents:
                    for entry in set_pb_contents:
                        if entry and "not found" in str(entry).lower():
                            print(f"[diag] WARNING — setPlaybook entry suggests playbook was NOT found: {entry!r}")
                        elif entry and "error" in str(entry).lower():
                            print(f"[diag] WARNING — setPlaybook entry contains error: {entry!r}")

            with capfd.disabled():
                print(f"[diag] Fetching initial playbook state for alert_id={alert_id}")
            initial_state = api_client.get_playbook_state(alert_id)
            with capfd.disabled():
                print(f"[diag] initial playbook state (raw): {initial_state}")
                print(f"[diag] initial playbook state: id={initial_state.get('playbookId')} state={initial_state.get('state')}")
                if initial_state.get("playbookId") is None:
                    print(
                        f"[diag] WARNING — playbookId is None after setPlaybook. "
                        f"Possible causes: playbook name mismatch (expected={playbook_name!r}), "
                        f"investigation not yet open, or setPlaybook command failed silently."
                    )
        except ApiException as e:
            with capfd.disabled():
                print(f"[diag] ApiException caught: status={e.status} reason={e.reason} body={e.body}")
            if "reopen" not in e.body:
                with capfd.disabled():
                    print("[diag] FAIL — ApiException body does not contain 'reopen', failing test")
                pytest.fail(f"Exception setting playbook: {e.body}")
            with capfd.disabled():
                print(f"[diag] ApiException (reopen path) — continuing: {e.body}")

        # get playbook state info
        with capfd.disabled():
            print(f"[diag] Starting poll_playbook_state for alert_id={alert_id} " f"expected_states=COMPLETED timeout=1200s")
        try:
            playbook_state_info = api_client.poll_playbook_state(
                alert_id, expected_states=(InvestigationPlaybookState.COMPLETED,), timeout=1200
            )
            with capfd.disabled():
                print(f"[diag] poll_playbook_state completed — raw result: {playbook_state_info}")
        except PollTimeout as e:
            final_state = api_client.get_playbook_state(alert_id)
            with capfd.disabled():
                print(f"[diag] PollTimeout — final playbook state (raw): {final_state}")
                print(
                    f"[diag] final playbook state on timeout: id={final_state.get('playbookId')} state={final_state.get('state')}"
                )
                if final_state.get("playbookId") is None:
                    print(
                        f"[diag] WARNING — playbookId is still None at timeout. "
                        f"The playbook was never attached to the investigation. "
                        f"Check that playbook_name={playbook_name!r} exists on the server."
                    )
            pytest.fail(f"Playbook did not reach the completed state. Error: {e}")

        # validate state
        playbook_state = playbook_state_info.get("state")
        with capfd.disabled():
            print(f"[diag] playbook_state after poll: {playbook_state!r}")
        if playbook_state != "completed":
            with capfd.disabled():
                print(f"[diag] FAIL — playbook_state={playbook_state!r} is not 'completed'")
            pytest.fail(f"Playbook did not reach the completed state. State: {playbook_state}")

        # get the investigation context
        with capfd.disabled():
            print(f"[diag] Fetching investigation context for investigation_id={alert_id}")
        context = api_client.get_investigation_context(investigation_id=alert_id)
        with capfd.disabled():
            print(f"[diag] investigation context keys: {list(context.keys()) if isinstance(context, dict) else type(context)}")
            print(f"[diag] investigation context Core keys: {list(context.get('Core', {}).keys())}")

        # validate if terminate process was called
        termination_id = context.get("Core", {}).get("TerminateProcess", {}).get("action_id")
        with capfd.disabled():
            print(f"[diag] TerminateProcess.action_id: {termination_id!r}")
            print(f"[diag] TerminateProcess full entry: {context.get('Core', {}).get('TerminateProcess')}")
        if not termination_id:
            with capfd.disabled():
                print("[diag] FAIL — termination_id is None/empty, TerminateProcess was not called or context is missing")
            pytest.fail("Could not find termination ID")

        # validate if terminate process was successful
        action_status_id = context.get("Core", {}).get("GetActionStatus", {}).get("action_id")
        with capfd.disabled():
            print(f"[diag] GetActionStatus.action_id: {action_status_id!r} (expected to match termination_id={termination_id!r})")
            print(f"[diag] GetActionStatus full entry: {context.get('Core', {}).get('GetActionStatus')}")
        if (not action_status_id) and action_status_id != termination_id:
            with capfd.disabled():
                print(f"[diag] FAIL — action_status_id={action_status_id!r} does not match termination_id={termination_id!r}")
            pytest.fail("No action ID matches termination ID")

        action_status = context.get("Core", {}).get("GetActionStatus", {}).get("status")
        with capfd.disabled():
            print(f"[diag] GetActionStatus.status: {action_status!r} (expected 'COMPLETED_SUCCESSFULLY')")
        if (not action_status) and action_status != "COMPLETED_SUCCESSFULLY":
            with capfd.disabled():
                print(f"[diag] FAIL — action_status={action_status!r} is not 'COMPLETED_SUCCESSFULLY'")
            pytest.fail("Termination failed")

        # all validations passed
        with capfd.disabled():
            print(f"[diag] test_feature_two PASSED — all validations succeeded for alert_id={alert_id}")
        assert True


if __name__ == "__main__":
    pytest.main([__file__])
