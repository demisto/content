import pytest
from unittest.mock import patch
from CommonServerPython import DemistoException
from QuarantineFile import quarantine_file_script

""" TEST CONSTANTS """

BRAND_CORE_IR = "Cortex Core - IR"
BRAND_XDR_IR = "Cortex XDR - IR"
BRAND_MDE = "Microsoft Defender for Endpoint"
SUPPORTED_BRANDS = [BRAND_CORE_IR, BRAND_XDR_IR, BRAND_MDE]
SHA_1_HASH = "sha1sha1sha1sha1sha1sha1sha1sha1sha1sha1"
SHA_256_HASH = "sha256sha256sha256sha256sha256sha256sha256sha256sha256sha256sha2"


@pytest.mark.parametrize(
    "endpoint_ids, file_hash, file_path",
    [
        ("ids", "", "path"),  # Missing file_hash
        ("", "hash", "path"),  # Missing endpoint_ids
        ("ids", "hash", ""),  # Missing file_path
        ("ids", "hash", "path"),  # invalid hash type
    ],
)
def test_quarantine_file_script_invalid_input(endpoint_ids: str, file_hash: str, file_path: str):
    """
    Given:
        - A set of inputs to the `quarantine_file_script` function with one or more missing or invalid arguments:
            - Missing 'endpoint_ids'
            - Missing 'file_hash'
            - Missing 'file_path'
            - Invalid 'file_hash' format or type
    When:
        - The `quarantine_file_script` function is called with these invalid arguments
    Then:
        - A ValueError is raised, indicating that the input validation failed as expected
    """
    required_is_missing_msg = "Missing required fields"
    invalid_hash_msg = "A valid file hash must be provided. Supported types are: SHA1 and SHA256"
    err_msg = invalid_hash_msg if endpoint_ids and file_hash and file_path else required_is_missing_msg
    with pytest.raises(ValueError, match=err_msg):
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
        - `quarantine_file_script` is called with valid arguments (endpoint ID, hash, file path)
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
                mock_send.assert_called_once_with(args, [], [], [])
            else:
                command_prefix = "core" if active_brand == BRAND_CORE_IR else "xdr"
                mock_send.assert_called_once_with(command_prefix, args, [], [], [])


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
        - A `quarantine_brands` argument explicitly specifying which integration should handle the quarantine
        - A set of active modules for all supported brands
    When:
        - `quarantine_file_script` is invoked with all required arguments and a specified `quarantine_brands` value
    Then:
        - The appropriate brand-specific quarantine function is called based on the provided `quarantine_brands`:
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
                mock_send.assert_called_once_with(args, [], [], [])
            else:
                command_prefix = "core" if quarantine_brands == BRAND_CORE_IR else "xdr"
                mock_send.assert_called_once_with(command_prefix, args, [], [], [])


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
        - A specified `quarantine_brands` value, or an empty value to trigger auto-selection logic
        - All supported modules set to 'inactive'
    When:
        - `quarantine_file_script` is executed with these arguments
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
        - A file hash of a type that is not supported by the specified `quarantine_brands`:
            - Microsoft Defender only supports SHA-1
            - Cortex XDR and Core IR only support SHA-256
        - The `quarantine_file_script` is called with an incompatible hash/brand combination
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


# def test_quarantine_file():
#     pass


# def test_get_endpoints_to_quarantine_with_xdr():
#     pass


# def test_get_connected_xdr_endpoints():
#     pass
