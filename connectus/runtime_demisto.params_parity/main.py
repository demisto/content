import json
import logging
import os
import uuid, re
from pathlib import Path
from pprint import pformat

import demisto_client
import urllib3
from demisto_client.demisto_api.rest import ApiException
from ruamel.yaml import YAML
from dotenv import load_dotenv

load_dotenv()
# ============================================================================
# CONFIGURATION — Edit these values before running
# ============================================================================

# Tenant connection details
# Credentials from.env
BASE_URL = os.getenv("DEMISTO_BASE_URL")
API_KEY = os.getenv("DEMISTO_API_KEY")
AUTH_ID = os.getenv("XSIAM_AUTH_ID")
# Path to the integration YML file
INTEGRATION_YML_PATH = os.getenv("INTEGRATION_YML_PATH", "")

# Override specific param values (param_name -> value)
# Use this to inject specific values like isFetch=true for testing certain flows
PARAM_OVERRIDES: dict = {
    # "isFetch": True,
    # "max_fetch": "50",
    # "insecure": True,
}

# Timeout settings (seconds)
REQUEST_TIMEOUT = 120

# ============================================================================
# XSOAR Param Type Constants
# ============================================================================

PARAM_TYPE_SHORT_TEXT = 0
PARAM_TYPE_ENCRYPTED = 4
PARAM_TYPE_BOOLEAN = 8
PARAM_TYPE_AUTH = 9
PARAM_TYPE_MULTI_LINE = 12
PARAM_TYPE_INCIDENT_TYPE = 13
PARAM_TYPE_MULTI_SELECT = 14
PARAM_TYPE_SINGLE_SELECT = 15
PARAM_TYPE_LONG_TEXT = 16
PARAM_TYPE_EXPIRATION = 17

# ============================================================================
# Logging setup
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sanity_test")


# ============================================================================
# Smart Param Filler
# ============================================================================


def generate_dummy_value_for_param(param: dict) -> object:
    """Generate a smart dummy value based on param type and name.

    Args:
        param: A parameter configuration dict from the integration YML.

    Returns:
        A dummy value appropriate for the param type.
    """
    param_name = param.get("name", "").lower()
    param_type = param.get("type", 0)
    default_value = param.get("defaultvalue") or param.get("defaultValue")
    options = param.get("options", [])

    # If there's a default value, use it
    if default_value is not None and default_value != "":
        return default_value

    # Name-based heuristics (applied before type-based defaults)
    name_defaults = {
        "url": "https://dummy.example.com",
        "base_url": "https://dummy.example.com",
        "server_url": "https://dummy.example.com",
        "server": "https://dummy.example.com",
        "port": "443",
        "max_fetch": "50",
        "fetch_limit": "50",
        "first_fetch": "3 days",
        "fetch_time": "3 days",
    }
    for pattern, value in name_defaults.items():
        if param_name == pattern or param_name.endswith(f"_{pattern}"):
            return value

    # Type-based defaults
    if param_type == PARAM_TYPE_SHORT_TEXT:
        return "dummy_text"
    elif param_type == PARAM_TYPE_ENCRYPTED:
        return "dummy_encrypted_value"
    elif param_type == PARAM_TYPE_BOOLEAN:
        return False
    elif param_type == PARAM_TYPE_AUTH:
        return {
            "credential": "",
            "identifier": "dummy_user",
            "password": "dummy_password",
            "passwordChanged": False,
        }
    elif param_type == PARAM_TYPE_MULTI_LINE:
        return ""
    elif param_type == PARAM_TYPE_INCIDENT_TYPE:
        return ""
    elif param_type == PARAM_TYPE_MULTI_SELECT:
        return []
    elif param_type == PARAM_TYPE_SINGLE_SELECT:
        return options[0] if options else ""
    elif param_type == PARAM_TYPE_LONG_TEXT:
        return ""
    elif param_type == PARAM_TYPE_EXPIRATION:
        return ""
    else:
        return ""


def fill_params_from_yml(yml_config: list[dict], overrides: dict) -> dict:
    """Fill integration params with smart dummy values.

    Args:
        yml_config: The 'configuration' list from the integration YML.
        overrides: User-provided param overrides.

    Returns:
        Dict mapping param name -> filled value.
    """
    filled = {}
    for param in yml_config:
        param_name = param.get("name", "")
        if not param_name:
            continue

        # Check overrides first (by name)
        if param_name in overrides:
            filled[param_name] = overrides[param_name]
            log.debug(f"  Param '{param_name}': using override = {overrides[param_name]}")
            continue

        # Check overrides by display name
        display = param.get("display", "")
        if display in overrides:
            filled[param_name] = overrides[display]
            log.debug(f"  Param '{param_name}': using override (by display) = {overrides[display]}")
            continue

        # Generate dummy value
        value = generate_dummy_value_for_param(param)
        filled[param_name] = value
        log.debug(f"  Param '{param_name}' (type={param.get('type', 0)}): filled = {value}")

    return filled


# ============================================================================
# Tenant Client
# ============================================================================


def create_client(base_url: str, api_key: str, auth_id: str):
    """Create and return a demisto_client configured for the tenant."""
    client = demisto_client.configure(
        base_url=base_url,
        api_key=api_key,
        auth_id=auth_id,
        verify_ssl=False,
    )
    client.api_client.user_agent = "connector-validator/sanity-test"
    return client


# ============================================================================
# Integration Config from Server
# ============================================================================


def get_integration_config(client, integration_name: str) -> dict | None:
    """Fetch the integration configuration from the server.

    This retrieves the full config schema that the server knows about,
    which includes all param fields needed for instance creation.

    Args:
        client: The demisto_client instance.
        integration_name: The name of the integration.

    Returns:
        The integration configuration dict, or None if not found.
    """
    log.info(f"Fetching integration config for '{integration_name}' from server...")

    try:
        # Try cloud endpoint first (XSIAM / XSOAR SaaS / Platform)
        res_raw = demisto_client.generic_request_func(
            self=client,
            path=f"/settings/integration/search/{integration_name}",
            method="GET",
            _request_timeout=REQUEST_TIMEOUT,
            response_type="object",
            
        )
        res = res_raw[0]
        if "Module" in res:
            log.info("Found integration config via cloud endpoint")
            return res["Module"]
    except ApiException:
        log.debug("Cloud endpoint failed, trying on-prem endpoint...")

    try:
        # Fallback to on-prem endpoint
        res_raw = demisto_client.generic_request_func(
            self=client,
            path="/settings/integration/search",
            method="POST",
            body={},
            _request_timeout=REQUEST_TIMEOUT,
            response_type="object",
        )
        all_configurations = res_raw[0].get("configurations", [])
        match = [x for x in all_configurations if x["name"] == integration_name]
        if match:
            log.info("Found integration config via on-prem endpoint")
            return match[0]
    except ApiException as e:
        log.error(f"Failed to get integration config: {e}")

    log.error(f"Integration '{integration_name}' not found on the server. "
              f"Make sure the pack is installed on the tenant.")
    return None


def get_instances_by_brand(client, brand_name: str) -> list[dict]:
    """Get all integration instances for a specific brand/integration name."""
    res, status, _ = demisto_client.generic_request_func(
        self=client,
        method="POST",
        path="/settings/integration/search",
        body={"size": 1000},
        _request_timeout=120,
        response_type="object",
    )

    if int(status) != 200 or "instances" not in res:
        return []

    return [inst for inst in res["instances"] if inst.get("brand") == brand_name]


# ============================================================================
# Instance Creation
# ============================================================================


def create_integration_instance(
    client,
    integration_name: str,
    server_configuration: dict,
    filled_params: dict,
) -> tuple[dict | None, str]:
    """Create an integration instance on the tenant.

    Args:
        client: The demisto_client instance.
        integration_name: The integration name.
        server_configuration: The integration config fetched from the server.
        filled_params: Dict of param_name -> value to configure.

    Returns:
        Tuple of (module_instance dict, error_message).
        On success, module_instance is populated and error_message is empty.
        On failure, module_instance is None and error_message describes the issue.
    """
    instance_name = f'{integration_name.replace(" ", "_")}_sanity_{uuid.uuid4().hex[:8]}'
    log.info(f"Creating instance '{instance_name}' for integration '{integration_name}'...")

    module_configuration = server_configuration.get("configuration", [])
    if not module_configuration:
        module_configuration = []

    # Build the module instance payload
    module_instance = {
        "brand": server_configuration["name"],
        "category": server_configuration.get("category", ""),
        "configuration": server_configuration,
        "data": [],
        "enabled": "true",
        "engine": "",
        "id": "",
        "isIntegrationScript": True,
        "name": instance_name,
        "passwordProtected": False,
        "version": 0,
    }

    # Fill in param values
    for param_conf in module_configuration:
        param_name = param_conf.get("name", "")
        param_display = param_conf.get("display", "")

        if param_name in filled_params:
            value = filled_params[param_name]
        elif param_display in filled_params:
            value = filled_params[param_display]
        elif param_conf.get("defaultValue"):
            value = param_conf["defaultValue"]
        else:
            value = ""

        # Handle credentials type specially
        if param_conf.get("type") == PARAM_TYPE_AUTH and isinstance(value, dict):
            param_conf["value"] = {
                "credential": value.get("credential", ""),
                "identifier": value.get("identifier", ""),
                "password": value.get("password", ""),
                "passwordChanged": False,
            }
        else:
            param_conf["value"] = value

        if value:
            param_conf["hasvalue"] = True

        module_instance["data"].append(param_conf)

    # Send the creation request
    try:
        res = demisto_client.generic_request_func(
            self=client,
            method="PUT",
            path="/settings/integration",
            body=module_instance,
            _request_timeout=REQUEST_TIMEOUT,
            response_type="object",
        )
    except ApiException as e:
        error_msg = f"Failed to create instance: {e}"
        log.error(error_msg)
        return None, error_msg

    if res[1] != 200:
        error_msg = f"Create instance failed with status {res[1]}: {pformat(res[0])}"
        log.error(error_msg)
        return None, error_msg

    # Update the instance with the server-assigned ID
    module_instance["id"] = res[0]["id"]
    log.info(f"Instance created successfully. ID: {module_instance['id']}, Name: {instance_name}")
    return module_instance, ""


# ============================================================================
# Test Integration Instance (modeled after Tests/test_integration.py)
# ============================================================================


def test_integration_instance(client, module_instance: dict) -> tuple[bool, str | None]:
    """Run test-module on an integration instance via the server API.

    Uses POST /settings/integration/test with the full module_instance dict
    as the request body. Includes retry logic for transient connection issues.

    This follows the proven pattern from Tests/test_integration.py.

    Args:
        client: The demisto_client instance.
        module_instance: The full module instance dict (as returned by create_integration_instance).

    Returns:
        Tuple of (success, message):
            - success: True if test-module passed.
            - message: The output message from test-module, or None.
    """
    connection_retries = 5
    response_code = 0
    integration_of_instance = module_instance.get("brand", "")
    instance_name = module_instance.get("name", "")
    log.info(f'Running "test-module" for instance "{instance_name}" of integration "{integration_of_instance}".')

    for i in range(connection_retries):
        try:
            response_data, response_code, _ = demisto_client.generic_request_func(
                self=client,
                method="POST",
                path="/settings/integration/test",
                body=module_instance,
                _request_timeout=REQUEST_TIMEOUT,
                response_type="object",
            )
            break
        except ApiException as e:
            log.exception(f"API exception on test-module request (attempt {i + 1}/{connection_retries}): {e}")
            return False, None
        except urllib3.exceptions.ReadTimeoutError:
            log.warning(
                f"Read timeout on test-module request (attempt {i + 1}/{connection_retries}). "
                f"Retrying..."
            )
    else:
        log.error("All connection retries exhausted for test-module request.")
        return False, None

    if int(response_code) != 200:
        log.error(f"test-module request returned non-200 status code: {response_code}")
        return False, None

    success = bool(response_data.get("success"))
    failure_message = response_data.get("message")

    if not success:
        log.error(
            f'test-module failed for instance "{instance_name}" of integration '
            f'"{integration_of_instance}".\nFailure message: {failure_message}'
        )

    return success, failure_message


# ============================================================================
# Test Module Output Parser
# ============================================================================


def parse_test_module_output(message: str | None) -> dict | None:
    """Parse the test-module output message into a JSON dict.

    The test-module response message contains the demisto.params() JSON output,
    but may have a trailing suffix like ' (85)' appended by the server.

    Args:
        message: The raw message string from test_integration_instance.

    Returns:
        Parsed dict of the params, or None if parsing fails.
    """
    if message is None:
        log.warning("test-module returned no message (None)")
        return None

    # Strip trailing suffix like ' (85)' — a number in parentheses at the end
    cleaned = re.sub(r"\s*\(\d+\)\s*$", "", message)

    if not cleaned.strip():
        log.warning("test-module message is empty after stripping suffix")
        return None

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse test-module output as JSON: {e}")
        log.debug(f"Cleaned message was: {cleaned}")
        return None

    if not isinstance(parsed, dict):
        log.warning(f"Parsed test-module output is not a dict (got {type(parsed).__name__})")
        return None

    return parsed


# ============================================================================
# Cleanup
# ============================================================================


def delete_integration_instance(client, instance_id: str) -> bool:
    """Delete an integration instance.

    Args:
        client: The demisto_client instance.
        instance_id: The ID of the instance to delete.

    Returns:
        True if deletion succeeded.
    """
    log.info(f"Deleting integration instance {instance_id}...")
    try:
        res = demisto_client.generic_request_func(
            self=client,
            method="DELETE",
            path=f"/settings/integration/{instance_id}",
            _request_timeout=REQUEST_TIMEOUT,
        )
        if int(res[1]) == 200:
            log.info("Instance deleted successfully")
            return True
        else:
            log.error(f"Delete instance failed with status {res[1]}")
            return False
    except ApiException as e:
        log.error(f"Failed to delete instance: {e}")
        return False


# ============================================================================
# YML Parser
# ============================================================================


def parse_integration_yml(yml_path: str) -> dict:
    """Parse an integration YML file and return its contents.

    Args:
        yml_path: Path to the integration YML file.

    Returns:
        The parsed YML as a dict.
    """
    yaml = YAML()
    yaml.preserve_quotes = True
    with open(yml_path) as f:
        data = yaml.load(f)
    return data


# ============================================================================
# Main
# ============================================================================


def main():
    log.info("=" * 60)
    log.info("Integration Instance Sanity Test")
    log.info("=" * 60)

    # Track resources for cleanup
    instance_id = None

    if not INTEGRATION_YML_PATH:
        log.error("INTEGRATION_YML_PATH is not set. Please set it in .env or as an environment variable.")
        return

    try:
        # --- Step 1: Parse the integration YML ---
        log.info(f"\n--- Step 1: Parsing integration YML ---")
        log.info(f"YML path: {INTEGRATION_YML_PATH}")

        yml_data = parse_integration_yml(INTEGRATION_YML_PATH)
        integration_name = yml_data.get("name", "")
        yml_params = yml_data.get("configuration", [])

        log.info(f"Integration name: {integration_name}")
        log.info(f"Number of params in YML: {len(yml_params)}")

        if not integration_name:
            log.error("Could not find integration name in YML. Aborting.")
            return

        # --- Step 2: Fill params with smart defaults + overrides ---
        log.info(f"\n--- Step 2: Filling params ---")
        filled_params = fill_params_from_yml(yml_params, PARAM_OVERRIDES)
        log.info("Filled params:")
        for name, value in filled_params.items():
            display_value = "****" if isinstance(value, dict) and "password" in value else value
            log.info(f"  {name} = {display_value}")

        # --- Step 3: Connect to tenant ---
        log.info(f"\n--- Step 3: Connecting to tenant ---")
        log.info(f"Base URL: {BASE_URL}")
        client = create_client(BASE_URL, API_KEY, AUTH_ID)
        log.info("Client configured")

        # --- Step 4: Get integration config from server ---
        log.info(f"\n--- Step 4: Getting integration config from server ---")
        server_config = get_integration_config(client, integration_name)
        if not server_config:
            log.error("Could not find integration on server. Make sure the pack is installed.")
            return

        # --- Step 5: Create integration instance ---
        log.info(f"\n--- Step 5: Creating integration instance ---")
        module_instance, error = create_integration_instance(
            client, integration_name, server_config, filled_params
        )

        if not module_instance:
            log.error(f"Failed to create instance: {error}")
            return

        instance_id = module_instance["id"]

        # --- Step 6: Run test-module on the instance ---
        log.info(f"\n--- Step 6: Running test-module ---")
        success, message = test_integration_instance(client, module_instance)

        log.info(f"\n--- Test Module Results ---")
        log.info(f"Success: {success}")

        if message:
            params_dict = parse_test_module_output(message)
            if params_dict:
                log.info("Parsed demisto.params() output:")
                log.info(json.dumps(params_dict, indent=2))
            else:
                log.warning("Could not parse test-module output as JSON")
                log.info(f"Raw message: {message}")
        else:
            log.info("No message returned from test-module")

    except Exception as e:
        log.exception(f"An unexpected error occurred: {e}")

    finally:
        log.info(f"\n--- Step 7: Cleanup ---")
        if instance_id:
            delete_integration_instance(client, instance_id)


if __name__ == "__main__":
    main()
