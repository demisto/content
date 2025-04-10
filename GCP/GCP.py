"""Base Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from typing import Any, Dict, Optional

import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    # TODO: REMOVE the following dummy function:
    def baseintegration_dummy(
        self, dummy: str, dummy2: Optional[int]
    ) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        Args:
            dummy: string to add in the dummy dict that is returned. This is a required argument.
            dummy2: int to limit the number of results. This is an optional argument.

        Returns:
            The dict with the arguments
        """
        return {"dummy": dummy, "dummy2": dummy2}

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API


""" HELPER FUNCTIONS """

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        Client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    # TODO: ADD HERE some code to test connectivity and authentication to your service.
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    client.baseintegration_dummy("dummy", 10)  # No errors, the api is working
    return "ok"


# TODO: REMOVE the following dummy command function
def baseintegration_dummy_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    dummy = args.get("dummy")  # dummy is a required argument, no default
    dummy2 = args.get("dummy2")  # dummy2 is not a required argument

    # Call the Client function and get the raw response
    result = client.baseintegration_dummy(dummy, dummy2)

    return CommandResults(
        outputs_prefix="BaseIntegration",
        outputs_key_field="",
        outputs=result,
    )


# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


def main():
    """main function, parses params and runs command functions"""

        try:
            command = demisto.command()
            args = demisto.args()

            # Initialize GCP API client using black box token
            client = get_access_token()  # returns a token string
            creds = Credentials(client)

            if command in [
                "gcp-compute-start-instance",
                "gcp-compute-start-instance-quick-action",
            ]:
                result = compute_start_instance(creds, args)

            elif command in [
                "gcp-compute-stop-instance",
                "gcp-compute-stop-instance-quick-action",
            ]:
                result = compute_stop_instance(creds, args)

            elif command in [
                "gcp-compute-patch-firewall",
                "gcp-compute-patch-firewall-quick-action",
            ]:
                result = compute_patch_firewall(creds, args)

            elif command in [
                "gcs-delete-bucket-policy",
                "gcs-delete-bucket-policy-quick-action",
            ]:
                result = gcs_delete_bucket_policy(creds, args)

            elif command in [
                "gcp-compute-update-subnet-config",
                "gcp-compute-update-subnet-config-quick-action",
            ]:
                result = compute_update_subnet(creds, args)

            elif command in [
                "gcp-compute-project-info-add-metadata",
                "gcp-compute-project-info-add-metadata-quick-action",
            ]:
                result = compute_add_metadata(creds, args)

            elif command in [
                "gcs-set-uniform-bucket-access",
                "gcs-set-uniform-bucket-access-quick-action",
            ]:
                result = gcs_set_ubla(creds, args)

            elif command in [
                "gcloud-clusters-update-security-config",
                "gcloud-clusters-update-security-config-quick-action",
            ]:
                result = gke_update_master_auth_networks(creds, args)

            elif command in [
                "gcs-enable-bucket-versioning",
                "gcs-enable-bucket-versioning-quick-action",
            ]:
                result = gcs_enable_bucket_versioning(creds, args)

            elif command in [
                "gcp-iam-service-account-delete",
                "gcp-iam-service-account-delete-quick-action",
            ]:
                result = iam_delete_service_account(creds, args)

            elif command in [
                "gcp-remove-iam-policy-binding",
                "gcp-remove-iam-policy-binding-quick-action",
            ]:
                result = iam_remove_policy_binding(creds, args)

            elif command in [
                "gcp-iam-project-iam-deny-policy-create",
                "gcp-iam-project-iam-deny-policy-create-quick-action",
            ]:
                result = iam_create_deny_policy(creds, args)

            elif command in [
                "gcp-iam-project-iam-policy-binding-remove",
                "gcp-iam-project-iam-policy-binding-remove-quick-action",
            ]:
                result = iam_remove_project_binding(creds, args)

            elif command in [
                "gcp-compute-instance-set-service-account",
                "gcp-compute-instance-set-service-account-quick-action",
            ]:
                result = compute_instance_set_service_account(creds, args)

            elif command in [
                "gcp-compute-instance-remove-service-account",
                "gcp-compute-instance-remove-service-account-quick-action",
            ]:
                result = compute_instance_remove_service_account(creds, args)

            elif command in [
                "gcp-iam-group-membership-delete",
                "gcp-iam-group-membership-delete-quick-action",
            ]:
                result = iam_group_membership_delete(creds, args)

            elif command in [
                "gsuite-user-update",
                "gsuite-user-update-quick-action",
            ]:
                result = gsuite_user_update(creds, args)

            elif command in [
                "gsuite-user-reset-password",
                "gsuite-user-reset-password-quick-action",
            ]:
                result = gsuite_user_reset_password(creds, args)

            elif command in [
                "gsuite-user-signout",
                "gsuite-user-signout-quick-action",
            ]:
                result = gsuite_user_signout(creds, args)

            else:
                raise NotImplementedError(f"Command not implemented: {command}")

            return_results(result)

        except Exception as e:
            return_error(f"Failed to execute command {demisto.command()}. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
