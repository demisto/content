import re
import pytest
from unittest.mock import MagicMock, patch
from CommonServerPython import CommandResults, DemistoException
from QuarantineFile import (
    get_connected_xdr_endpoints,
    get_endpoints_to_quarantine_with_xdr,
    quarantine_file_script,
    xdr_quarantine_file,
)

""" TEST CONSTANTS """

BRAND_CORE_IR = "Cortex Core - IR"
BRAND_XDR_IR = "Cortex XDR - IR"
BRAND_MDE = "Microsoft Defender for Endpoint"
SUPPORTED_BRANDS = [BRAND_CORE_IR, BRAND_XDR_IR, BRAND_MDE]
SHA_1_HASH = "sha1sha1sha1sha1sha1sha1sha1sha1sha1sha1"
SHA_256_HASH = "sha256sha256sha256sha256sha256sha256sha256sha256sha256sha256sha2"


@pytest.mark.parametrize(
    "endpoint_ids, file_hash, file_path, err_msg",
    [
        ("ids", "", "path", "Please provide the following missing fields ['file_hash']. Aborting command."),  # Missing file_hash
        (
            "",
            "hash",
            "path",
            "Please provide the following missing fields ['endpoint_ids']. Aborting command.",
        ),  # Missing endpoint_ids
        ("ids", "hash", "", "Please provide the following missing fields ['file_path']. Aborting command."),  # Missing file_path
        ("ids", "hash", "path", "A valid file hash must be provided. Supported types are: SHA1 and SHA256"),  # invalid hash type
    ],
)
def test_quarantine_file_script_invalid_input(endpoint_ids: str, file_hash: str, file_path: str, err_msg: str):
    """
    Given:
        - A set of inputs to the 'quarantine_file_script' function with one or more missing or invalid arguments:
            - Missing 'endpoint_ids'
            - Missing 'file_hash'
            - Missing 'file_path'
            - Invalid 'file_hash' format or type
    When:
        - The 'quarantine_file_script' function is called with these invalid arguments
    Then:
        - A ValueError is raised, indicating that the input validation failed as expected
    """
    with pytest.raises(ValueError, match=re.escape(err_msg)):
        quarantine_file_script({"endpoint_ids": endpoint_ids, "file_hash": file_hash, "file_path": file_path})


@pytest.mark.parametrize(
    "file_hash, excpected_function_call , active_brand",
    [
        (
            SHA_1_HASH,
            "Microsoft_atp_quarantine_file",
            BRAND_MDE,
        ),
        (
            SHA_256_HASH,
            "xdr_quarantine_file",
            BRAND_XDR_IR,
        ),
        (
            SHA_256_HASH,
            "xdr_quarantine_file",
            BRAND_CORE_IR,
        ),
    ],
)
def test_quarantine_file_script_valid_hash(file_hash: str, excpected_function_call: str, active_brand: str):
    """
    Given:
        - A valid file hash (SHA-1 or SHA-256)
        - A set of active/inactive integration modules simulating enabled endpoint protection products
    When:
        - 'quarantine_file_script' is called with valid arguments (endpoint ID, hash, file path)
    Then:
        - The appropriate product-specific quarantine function is called:
            - Microsoft ATP for SHA-1 (BRAND_MDE)
            - XDR/Core for SHA-256 depending on which brand is active
    """
    fake_modules = [{"brand": brand, "state": "active" if brand == active_brand else "inactive"} for brand in SUPPORTED_BRANDS]
    with patch("QuarantineFile.demisto.getModules") as mock_getModules:
        mock_getModules.return_value.values.return_value = fake_modules

        with patch(f"QuarantineFile.{excpected_function_call}") as mock_send:
            args = {"endpoint_ids": "ids", "file_hash": file_hash, "file_path": "file_path"}
            quarantine_file_script(args)
            if active_brand == BRAND_MDE:
                mock_send.assert_called_once_with(["ids"], file_hash, "file_path", 300, [], [], [])
            else:
                command_prefix = "core" if active_brand == BRAND_CORE_IR else "xdr"
                mock_send.assert_called_once_with(command_prefix, ["ids"], file_hash, "file_path", 300, [], [], [])


@pytest.mark.parametrize(
    "file_hash, excpected_function_call , quarantine_brands",
    [
        (
            SHA_1_HASH,
            "Microsoft_atp_quarantine_file",
            BRAND_MDE,
        ),
        (
            SHA_256_HASH,
            "xdr_quarantine_file",
            BRAND_XDR_IR,
        ),
        (
            SHA_256_HASH,
            "xdr_quarantine_file",
            BRAND_CORE_IR,
        ),
    ],
)
def test_quarantine_file_script_valid_quarantine_brand(file_hash: str, excpected_function_call: str, quarantine_brands: str):
    """
    Given:
        - A valid file hash (SHA-1 or SHA-256)
        - A 'quarantine_brands' argument explicitly specifying which integration should handle the quarantine
        - A set of active modules for all supported brands
    When:
        - 'quarantine_file_script' is invoked with all required arguments and a specified 'quarantine_brands' value
    Then:
        - The appropriate brand-specific quarantine function is called based on the provided 'quarantine_brands':
            - Microsoft ATP if BRAND_MDE is specified
            - Cortex XDR or Core IR if BRAND_XDR_IR or BRAND_CORE_IR is specified
    """
    fake_modules = [{"brand": brand, "state": "active"} for brand in SUPPORTED_BRANDS]
    with patch("QuarantineFile.demisto.getModules") as mock_getModules:
        mock_getModules.return_value.values.return_value = fake_modules

        with patch(f"QuarantineFile.{excpected_function_call}") as mock_send:
            args = {
                "endpoint_ids": "ids",
                "file_hash": file_hash,
                "file_path": "file_path",
                "quarantine_brands": quarantine_brands,
            }
            quarantine_file_script(args)
            if quarantine_brands == BRAND_MDE:
                mock_send.assert_called_once_with(["ids"], file_hash, "file_path", 300, [], [], [])
            else:
                command_prefix = "core" if quarantine_brands == BRAND_CORE_IR else "xdr"
                mock_send.assert_called_once_with(command_prefix, ["ids"], file_hash, "file_path", 300, [], [], [])


@pytest.mark.parametrize(
    "file_hash , quarantine_brands",
    [
        (
            SHA_1_HASH,
            BRAND_MDE,
        ),
        (
            SHA_256_HASH,
            BRAND_XDR_IR,
        ),
        (
            SHA_256_HASH,
            BRAND_CORE_IR,
        ),
        (
            SHA_1_HASH,
            "",  # No brand specified to trigger auto-selection logic
        ),
        (
            SHA_256_HASH,
            "",  # No brand specified to trigger auto-selection logic
        ),
    ],
)
def test_quarantine_file_script_inactive_brands(file_hash: str, quarantine_brands: str):
    """
    Given:
        - A valid file hash (SHA-1 or SHA-256)
        - A specified 'quarantine_brands' value, or an empty value to trigger auto-selection logic
        - All supported modules set to 'inactive'
    When:
        - 'quarantine_file_script' is executed with these arguments
    Then:
        - A DemistoException is raised because no active integration is available to handle the request
    """
    with_brands_msg = (
        "None of the quarantine brands has an enabled integration instance. Ensure valid integration IDs are specified."
    )
    without_brands_msg = "Could not find enabled integrations for the requested hash type."
    err_msg = with_brands_msg if quarantine_brands else without_brands_msg
    fake_modules = [{"brand": brand, "state": "inactive"} for brand in SUPPORTED_BRANDS]

    with patch("QuarantineFile.demisto.getModules") as mock_getModules:
        mock_getModules.return_value.values.return_value = fake_modules
        args = {"endpoint_ids": "ids", "file_hash": file_hash, "file_path": "file_path", "quarantine_brands": quarantine_brands}
        with pytest.raises(DemistoException, match=err_msg):
            quarantine_file_script(args)


@pytest.mark.parametrize(
    "file_hash , quarantine_brands",
    [
        (
            SHA_256_HASH,
            BRAND_MDE,
        ),  # SHA-256 is invalid for Microsoft Defender (expects SHA-1)
        (
            SHA_1_HASH,
            BRAND_XDR_IR,
        ),  # SHA-1 is invalid for XDR (expects SHA-256)
        (
            SHA_1_HASH,
            BRAND_CORE_IR,
        ),  # SHA-1 is invalid for Core IR (expects SHA-256)
    ],
)
def test_quarantine_file_script_invalid_hash_for_brands(file_hash: str, quarantine_brands: str):
    """
    Given:
        - A file hash of a type that is not supported by the specified 'quarantine_brands':
            - Microsoft Defender only supports SHA-1
            - Cortex XDR and Core IR only support SHA-256
        - The 'quarantine_file_script' is called with an incompatible hash/brand combination
    When:
        - The script is executed with these mismatched inputs
    Then:
        - A DemistoException is raised due to the invalid hash type for the selected brand
    """
    fake_modules = [{"brand": brand, "state": "active"} for brand in SUPPORTED_BRANDS]
    with patch("QuarantineFile.demisto.getModules") as mock_getModules:
        mock_getModules.return_value.values.return_value = fake_modules

        args = {"endpoint_ids": "ids", "file_hash": file_hash, "file_path": "file_path", "quarantine_brands": quarantine_brands}
        with pytest.raises(DemistoException, match="Could not find enabled integrations for the requested hash type."):
            quarantine_file_script(args)


def test_xdr_quarantine_file_sucess():
    """
    Given:
        - A valid set of arguments including endpoint ID, file hash, and file path.
        - The quarantine command returns a status of "COMPLETED_SUCCESSFULLY".
        - The status check command returns {"status": True} indicating success.
    When:
        - 'xdr_quarantine_file' is executed.
    Then:
        - The function appends a "Success" entry to the context and human_readable.
        - The verbose_command_results list contains the quarantine and status command results.
        - The message should indicate the file was successfully quarantined.
    """
    endpoint_ids = ["endpoint-1"]
    file_hash = "abc123"
    file_path = "/tmp/test.exe"
    timeout = 300

    human_readable = []
    context = []
    verbose_command_results = []

    # Mock get_endpoints_to_quarantine_with_xdr return
    mock_status_cmd = MagicMock()
    mock_status_cmd.execute.return_value = (
        [{"endpoint-1": {"status": True}}],  # context
        CommandResults(readable_output="Status OK"),  # verbose result
    )
    fake_status_commands = {"endpoint-1": mock_status_cmd}

    with (
        patch("QuarantineFile.get_endpoints_to_quarantine_with_xdr") as mock_get_endpoints,
        patch("QuarantineFile.Command") as mock_Command,
    ):
        # Simulate endpoint lookup result
        mock_get_endpoints.return_value = (["endpoint-1"], fake_status_commands)

        # Simulate quarantine command execution
        mock_poll_result = MagicMock()
        mock_poll_result.outputs = [{"endpoint_id": "endpoint-1", "status": "COMPLETED_SUCCESSFULLY"}]
        mock_Command.return_value.execute_polling.return_value = mock_poll_result

        xdr_quarantine_file(
            command_prefix="core",
            endpoint_ids=endpoint_ids,
            file_hash=file_hash,
            file_path=file_path,
            timeout=timeout,
            human_readable=human_readable,
            context=context,
            verbose_command_results=verbose_command_results,
        )

    assert len(human_readable) == 1
    assert human_readable[0]["endpoint_id"] == "endpoint-1"
    assert human_readable[0]["message"] == "File successfully quarantined."

    assert len(context) == 1
    assert context[0]["endpoint_id"] == "endpoint-1"
    assert context[0]["status"] == "Success"
    assert context[0]["file_hash"] == "abc123"
    assert context[0]["brand"] == BRAND_CORE_IR

    assert len(verbose_command_results) == 2
    assert verbose_command_results[0] == mock_poll_result
    assert isinstance(verbose_command_results[1], CommandResults)


def test_xdr_quarantine_file_fail():
    """
    Given:
        - A valid set of arguments including endpoint ID, file hash, and file path.
        - The quarantine command returns "Fail".
    When:
        - 'xdr_quarantine_file' is executed.
    Then:
        - The function appends a "Failed" entry to the context and human_readable.
        - The message includes the error description from the polling response.
        - verbose_command_results contains both quarantine and status check results.
    """
    endpoint_ids = ["endpoint-1"]
    file_hash = "abc123"
    file_path = "/tmp/test.exe"
    timeout = 300

    human_readable = []
    context = []
    verbose_command_results = []

    # Mock status command to return status=False
    mock_status_cmd = MagicMock()
    mock_status_cmd.execute.return_value = (
        {"endpoint-1": {"status": False}},  # context
        CommandResults(readable_output="Status failed"),  # verbose output
    )
    fake_status_commands = {"endpoint-1": mock_status_cmd}

    with (
        patch("QuarantineFile.get_endpoints_to_quarantine_with_xdr") as mock_get_endpoints,
        patch("QuarantineFile.Command") as mock_Command,
    ):
        mock_get_endpoints.return_value = (["endpoint-1"], fake_status_commands)

        # Mock polling result from quarantine command
        mock_poll_result = MagicMock()
        mock_poll_result.outputs = [{"endpoint_id": "endpoint-1", "status": "Fail", "error_description": "Not found"}]
        mock_Command.return_value.execute_polling.return_value = mock_poll_result

        xdr_quarantine_file(
            command_prefix="core",
            endpoint_ids=endpoint_ids,
            file_hash=file_hash,
            file_path=file_path,
            timeout=timeout,
            human_readable=human_readable,
            context=context,
            verbose_command_results=verbose_command_results,
        )

    assert len(human_readable) == 1
    assert human_readable[0]["endpoint_id"] == "endpoint-1"
    assert human_readable[0]["message"] == "Failed to quarantine file. Not found"

    assert len(context) == 1
    ctx = context[0]
    assert ctx["endpoint_id"] == "endpoint-1"
    assert ctx["status"] == "Failed"
    assert ctx["message"] == "Failed to quarantine file. Not found"
    assert ctx["brand"] == BRAND_CORE_IR


def test_get_endpoints_to_quarantine_with_xdr():
    """
    Given:
        - A list of connected XDR endpoints returned by 'get_connected_xdr_endpoints'
        - Some endpoints already have the file quarantined (status=True)
        - Others are not quarantined (status=False)
    When:
        - 'get_endpoints_to_quarantine_with_xdr' is called with proper args
    Then:
        - It returns:
            - A list of endpoints that are not yet quarantined
            - A dict mapping all endpoints to their quarantine status command
        - Updates human_readable and context for already quarantined endpoints
        - Appends the CommandResults to verbose_command_results for each status check
    """
    endpoint_ids = ["ep1", "ep2"]
    file_hash = "abc123"
    file_path = "/path/file.exe"

    human_readable = []
    context = []
    verbose_command_results = []

    # Fake the return of get_connected_xdr_endpoints
    with (
        patch("QuarantineFile.get_connected_xdr_endpoints", return_value=["ep1", "ep2"]),
        patch("QuarantineFile.Command") as mock_Command,
    ):
        # Mock command responses
        mock_cmd_ep1 = MagicMock()
        mock_cmd_ep1.execute.return_value = (
            [{"ep1": {"status": True}}],
            CommandResults(readable_output="ep1 already quarantined."),
        )
        mock_cmd_ep2 = MagicMock()
        mock_cmd_ep2.execute.return_value = ([{"ep2": {"status": False}}], CommandResults(readable_output="ep2 not quarantined"))

        def side_effect_create_command(name, args, brand):
            return {"ep1": mock_cmd_ep1, "ep2": mock_cmd_ep2}[args["endpoint_id"]]

        mock_Command.side_effect = side_effect_create_command

        endpoints_to_quarantine, status_commands = get_endpoints_to_quarantine_with_xdr(
            command_prefix="core",
            endpoint_ids=endpoint_ids,
            file_hash=file_hash,
            file_path=file_path,
            human_readable=human_readable,
            context=context,
            verbose_command_results=verbose_command_results,
        )

    assert endpoints_to_quarantine == ["ep2"]
    assert "ep1" in status_commands
    assert "ep2" in status_commands
    assert len(human_readable) == 1
    assert human_readable[0]["endpoint_id"] == "ep1"
    assert human_readable[0]["message"] == "Already quarantined."

    assert len(context) == 1
    assert context[0]["endpoint_id"] == "ep1"
    assert context[0]["status"] == "Success"
    assert context[0]["brand"] == BRAND_CORE_IR

    assert len(verbose_command_results) == 2
    assert all(isinstance(v, CommandResults) for v in verbose_command_results)


def test_get_connected_xdr_endpoints():
    """
    Given:
        - A comma seperated list of endpoint IDs.
        - The 'core-get-endpoints' command returns data showing 'ep1' is connected, 'ep2' is not connected and ep3 is not exists.
    When:
        - 'get_connected_xdr_endpoints' is called.
    Then:
        - The function returns only the connected endpoint ID 'ep1'.
        - human_readable and context are updated with failure message for 'ep2' and 'ep3'.
        - verbose_command_results includes the result(s) of the get-endpoints command.
    """
    endpoint_ids = ["ep1", "ep2", "ep3"]
    file_hash = "abc123"
    file_path = "/tmp/test.exe"

    human_readable = []
    context = []
    verbose_command_results = []

    with patch("QuarantineFile.Command") as mock_Command:
        # Simulate Command.execute() returning results
        fake_endpoint_data = [
            {
                "Core.Endpoint(val.endpoint_id == obj.endpoint_id)": [
                    {"endpoint_id": "ep1", "endpoint_status": "CONNECTED"},
                    {"endpoint_id": "ep2", "endpoint_status": "DISCONNECTED"},
                ]
            }
        ]
        fake_command_results = [CommandResults(readable_output="Endpoint result")]

        mock_cmd = MagicMock()
        mock_cmd.execute.return_value = (fake_endpoint_data, fake_command_results)
        mock_Command.return_value = mock_cmd

        connected = get_connected_xdr_endpoints(
            command_prefix="core",
            endpoint_ids=endpoint_ids,
            file_hash=file_hash,
            file_path=file_path,
            human_readable=human_readable,
            context=context,
            verbose_command_results=verbose_command_results,
        )

    assert connected == ["ep1"]

    # ep2 and ep3 should be in context as unreachable
    assert len(human_readable) == 2
    assert human_readable[0]["endpoint_id"] == "ep2"
    assert human_readable[0]["message"] == "Failed to quarantine file. The endpoint is offline or unreachable."

    assert human_readable[1]["endpoint_id"] == "ep3"
    assert human_readable[1]["message"] == "Failed to quarantine file. The endpoint is offline or unreachable."

    assert len(context) == 2
    assert context[0]["endpoint_id"] == "ep2"
    assert context[0]["status"] == "Failed"
    assert context[0]["brand"] == BRAND_CORE_IR

    assert context[1]["endpoint_id"] == "ep3"
    assert context[1]["status"] == "Failed"
    assert context[1]["brand"] == BRAND_CORE_IR

    assert verbose_command_results == fake_command_results
