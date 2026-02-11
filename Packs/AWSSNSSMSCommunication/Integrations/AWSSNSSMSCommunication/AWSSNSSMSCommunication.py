# VERSION: 1.0.37
# CHANGELOG:
# v1.0.37 - Added replyCodeMode configuration parameter: 'sequential' mode uses simple incrementing numbers (1, 2, 3...) instead of random 4-digit codes for simpler UX.
# v1.0.36 - Security: Replaced kwargs logging with explicit parameter names to ensure no secrets are ever logged accidentally.
# v1.0.35 - Enhanced debug logging throughout for better troubleshooting: added descriptive logs for entitlement parsing, feedback settings, AWS client creation, and reply processing decisions.
# v1.0.34 - Split reply feedback into separate toggles: successFeedbackEnabled and failureFeedbackEnabled. Added customizable failureMessage template.
# v1.0.33 - Added SMS reply feedback feature: sends confirmation SMS for successful replies and lists available codes for unrecognized replies. Configurable success message.
# v1.0.32 - Fixed multi-line message handling in clean_ask_task_message_and_generate_codes (added re.DOTALL flag). Added support for 2-4 options in SMSAskUser (option3, option4)
# v1.0.31 - Removed dramatic language from documentation (CRITICAL, warning emoji) for professional tone
# v1.0.30 - Updated documentation: clarified built-in Ask tasks work (via browser), SMSAskUser is recommended for native SMS. Removed playbook YAML examples
# v1.0.29 - Created AWSSNSSMSCommunication_description.md file (proper XSOAR pattern for Help tab), removed inline detaileddescription
# v1.0.28 - Added full README.md contents to detaileddescription field for comprehensive Help tab documentation
# v1.0.27 - Added detaileddescription field (lowercase) with comprehensive markdown documentation for Help tab
# v1.0.26 - Simplified integration description to single line
# v1.0.25 - Removed detailedDescription from YAML (not rendering in XSOAR UI), moved key info to main description field
# v1.0.24 - CRITICAL FIX: Fixed task ID not being saved in entitlements. extract_entitlement_from_message() now extracts full GUID@incident|task string instead of just GUID
# v1.0.23 - Fixed SMSAskUser Python 2 compatibility (replaced f-strings with .format())
# v1.0.22 - Added debug logging to SMSAskUser for task ID parameter troubleshooting
# v1.0.21 - Enhanced detailedDescription in YAML with clearer formatting, visual separators, and better readability for integration configuration UI
# v1.0.20 - CRITICAL FIX: Added automatic AWS credential refresh in long-running execution to prevent ExpiredToken errors. Refreshes at 80% of sessionDuration
# v1.0.19 - Completely rewrote integration README.md with critical Ask task documentation, SMSAskUser examples, and complete version history
# v1.0.18 - Updated integration detailed description with Ask task documentation. Beautified SMSAskUser script with versioning and comments
# v1.0.17 - Added aws-sns-sms-inject-reply test command to simulate SMS replies for debugging without requiring SQS
# v1.0.16 - REMOVED non-functional URL decoding. SMSAskUser is the ONLY supported method for Ask-style communication (built-in Ask tasks not supported)
# v1.0.15 - DEPRECATED: Attempted URL decoding for built-in Ask tasks (does not work - URLs created after send-notification returns)
# v1.0.14 - Added support for SMSAskUser automation script format (Question - Reply Yes or No: GUID@incident)
# v1.0.13 - BREAKING: Redesigned reply code system - each option now has unique code (e.g., Yes(1234) No(5678)) for proper multi-question support
# v1.0.12 - Fixed XSOAR Ask task integration by cleaning URL-based messages and converting to SMS-friendly format with reply codes
# v1.0.11 - Added aws-sns-sms-list-entitlements command to list active entitlements with phone numbers and reply codes, added comprehensive debug logging throughout
# v1.0.10 - Changed test-module to use SQS get_queue_attributes instead of SNS list_topics (matches official AWS integrations pattern and required IAM permissions)
# v1.0.9 - Fixed test-module command by removing unsupported MaxItems parameter from SNS list_topics API call
# v1.0.8 - Added SMSAskUser automation script for Ask task integration
# v1.0.7 - Updated Docker image to demisto/boto3py3:1.0.0.115129
# v1.0.6 - Added version tracking and changelog to integration Python code
# v1.0.5 - Added messaging/communication tags, updated category to "Messaging and Conferencing"
# v1.0.4 - Renamed command to "send-notification" for Ask task compatibility
# v1.0.3 - Added Role ARN authentication, timeout/retries config, STS regional endpoints
# v1.0.2 - Updated author and community support notice
# v1.0.1 - Added integration image
# v1.0.0 - Initial release with SNS SMS sending, SQS reply polling, entitlement handling

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime, timedelta
import json
import random
import string
import time
import traceback
from typing import Any

# ===== CONSTANTS =====
INTEGRATION_NAME = "AWS SNS SMS Communication"
INTEGRATION_VERSION = "1.0.37"

# Default feedback messages
DEFAULT_SUCCESS_MESSAGE = "{reply_code} - Thank you for your response!"
DEFAULT_FAILURE_MESSAGE = "We couldn't process your response. Please respond with one of the available reply codes: {available_codes}"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
DEFAULT_TTL_HOURS = 24
DEFAULT_POLL_INTERVAL_SECONDS = 10
DEFAULT_REPLY_CODE = "0000"  # Implicit code when no other entitlements active
REPLY_CODE_MODE_RANDOM = "random"
REPLY_CODE_MODE_SEQUENTIAL = "sequential"

# Entitlement regex pattern (from Slack integration)
GUID_REGEX = r"(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}"

# Integration context keys
OBJECTS_TO_KEYS = {
    "entitlements": "entitlement_id"
}


# ===== HELPER FUNCTIONS =====
def get_integration_context_with_sync() -> dict:
    """Get integration context with thread safety."""
    try:
        ctx = demisto.getIntegrationContext()
        return ctx if ctx else {}
    except Exception as e:
        demisto.error(f"Error getting integration context: {str(e)}")
        return {}


def set_integration_context_with_sync(context: dict):
    """Set integration context with thread safety."""
    try:
        demisto.setIntegrationContext(context)
    except Exception as e:
        demisto.error(f"Error setting integration context: {str(e)}")


def generate_reply_code() -> str:
    """Generate a unique 4-digit reply code."""
    return ''.join(random.choices(string.digits, k=4))


def generate_sequential_codes(count: int, existing_codes: set) -> list:
    """Generate sequential reply codes (1, 2, 3...) skipping any already in use.

    Args:
        count: Number of codes to generate
        existing_codes: Set of codes already assigned to active entitlements

    Returns:
        List of string codes, e.g. ["1", "2"] or ["3", "4"]
    """
    codes = []
    candidate = 1
    while len(codes) < count:
        if str(candidate) not in existing_codes:
            codes.append(str(candidate))
        candidate += 1
    return codes


def extract_entitlement_from_message(message: str) -> tuple:
    """
    Extract full entitlement string from a message.

    Only supports SMSAskUser format: "Question - Reply Yes or No: GUID@incident|task"
    Built-in XSOAR Ask tasks are NOT supported (URLs created after send-notification returns).

    Args:
        message: The message containing the entitlement

    Returns:
        Tuple of (full_entitlement_string or None, remaining_message)
        Full entitlement string format: "GUID@incident_id|task_id" or "GUID@incident_id" (task optional)
    """
    import re

    # Find entitlement in SMSAskUser format: GUID@incident_id|task_id or GUID@incident_id
    # Pattern: GUID followed by @number and optionally |task_id
    entitlement_pattern = r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})@(\d+)(?:\|([^\s]+))?'
    match = re.search(entitlement_pattern, message, re.IGNORECASE)

    if match:
        guid = match.group(1)
        incident_id = match.group(2)
        task_id = match.group(3)  # May be None

        # Reconstruct full entitlement string
        full_entitlement = f"{guid}@{incident_id}"
        if task_id:
            full_entitlement += f"|{task_id}"

        remaining = message.replace(match.group(0), "", 1).strip()
        demisto.debug(f"Found SMSAskUser entitlement: {full_entitlement}")
        return full_entitlement, remaining

    demisto.debug("No entitlement found - use SMSAskUser script for Ask-style communication")
    return None, message


def clean_ask_task_message_and_generate_codes(message: str, existing_codes: set,
                                               reply_code_mode: str = REPLY_CODE_MODE_RANDOM) -> tuple:
    """
    Clean SMSAskUser message and generate reply codes for each option.

    Only supports SMSAskUser format: "Question - Reply option1 or option2 [or option3 [or option4]]: GUID@incident|task"
    Built-in XSOAR Ask tasks are NOT supported.

    Converts to: "Question\noption1 (1234) or option2 (5678)" (random mode)
    Or: "Question\noption1 (1) or option2 (2)" (sequential mode)

    Args:
        message: Original message in SMSAskUser format (supports 2-4 options)
        existing_codes: Set of already-used reply codes to avoid duplicates
        reply_code_mode: Code generation mode - "random" (4-digit) or "sequential" (1, 2, 3...)

    Returns:
        Tuple of (cleaned_message, options_to_codes_dict)
        Example: ("Do you like PANcakes?\nYes (1) or No (2)", {"1": "Yes", "2": "No"})
    """
    import re

    demisto.debug(f"Processing message for reply codes (mode={reply_code_mode}, first 200 chars): {message[:200]}...")

    # SMSAskUser format: "Question - Reply option1 or option2 [or option3 [or option4]]: GUID@incident"
    # Pattern: anything - Reply <options separated by 'or'>: <entitlement>
    # Use DOTALL flag to allow newlines in question text
    sms_ask_pattern = r'^(.+?)\s*-\s*Reply\s+(.+?)\s*:\s*[a-fA-F0-9\-@|]+$'
    sms_match = re.match(sms_ask_pattern, message, re.DOTALL)

    if not sms_match:
        # Not SMSAskUser format - return original message without codes
        demisto.debug("Not SMSAskUser format - returning original message (use SMSAskUser script for Ask tasks)")
        return message, {}

    question_text = sms_match.group(1).strip()
    options_string = sms_match.group(2).strip()

    # Split options by "or" - supports 2-4 options
    options = [opt.strip() for opt in re.split(r'\s+or\s+', options_string) if opt.strip()]

    if len(options) < 2 or len(options) > 4:
        demisto.debug(f"Invalid number of options: {len(options)}. Must be 2-4. Returning original message.")
        return message, {}

    demisto.debug(f"SMSAskUser detected. Question: {question_text}, Options: {options}")

    # Generate reply codes based on mode
    codes_to_options = {}
    formatted_options = []

    if reply_code_mode == REPLY_CODE_MODE_SEQUENTIAL:
        sequential_codes = generate_sequential_codes(len(options), existing_codes)
        for option, code in zip(options, sequential_codes):
            codes_to_options[code] = option
            formatted_options.append(f"{option} ({code})")
    else:
        # Random 4-digit codes (default)
        for option in options:
            code = generate_reply_code()
            while code in existing_codes or code in codes_to_options:
                code = generate_reply_code()
            codes_to_options[code] = option
            formatted_options.append(f"{option} ({code})")

    # Build final message
    options_text = " or ".join(formatted_options)
    cleaned_message = f"{question_text}\n{options_text}"

    demisto.debug(f"Cleaned message: {cleaned_message}")
    demisto.debug(f"Code mappings: {codes_to_options}")

    return cleaned_message, codes_to_options


def parse_entitlement_string(entitlement: str) -> dict:
    """
    Parse an entitlement string into components.
    Format: <GUID>@<incident_id>|<task_id>

    Args:
        entitlement: The full entitlement string

    Returns:
        Dict with guid, incident_id, task_id
    """
    demisto.debug(f"parse_entitlement_string: parsing '{entitlement}'")

    parts = entitlement.split("@")
    if len(parts) < 2:
        demisto.debug(f"parse_entitlement_string: invalid format - missing '@' separator in '{entitlement}'")
        return {}

    guid = parts[0]
    id_and_task = parts[1].split("|")
    incident_id = id_and_task[0]
    task_id = id_and_task[1] if len(id_and_task) > 1 else ""

    demisto.debug(f"parse_entitlement_string: parsed guid={guid}, incident_id={incident_id}, task_id={task_id or 'None'}")

    return {
        "guid": guid,
        "incident_id": incident_id,
        "task_id": task_id
    }


def cleanup_expired_entitlements(ttl_hours: int = DEFAULT_TTL_HOURS):
    """
    Remove expired entitlements from integration context.

    Args:
        ttl_hours: Time-to-live in hours for entitlements
    """
    ctx = get_integration_context_with_sync()
    entitlements = ctx.get("entitlements", [])

    if not entitlements:
        return

    now = datetime.utcnow()
    active_entitlements = []
    removed_count = 0

    for ent in entitlements:
        created = datetime.strptime(ent.get("created", now.strftime(DATE_FORMAT)), DATE_FORMAT)
        age_hours = (now - created).total_seconds() / 3600

        if age_hours < ttl_hours:
            active_entitlements.append(ent)
        else:
            removed_count += 1
            demisto.debug(f"Removing expired entitlement: {ent.get('entitlement_id')}")

    if removed_count > 0:
        ctx["entitlements"] = active_entitlements
        set_integration_context_with_sync(ctx)
        demisto.info(f"Cleaned up {removed_count} expired entitlements")


def get_active_entitlements_for_phone(phone_number: str) -> list:
    """
    Get all active (unanswered) entitlements for a phone number.

    Args:
        phone_number: The phone number to check

    Returns:
        List of active entitlement dicts
    """
    demisto.debug(f"get_active_entitlements_for_phone: searching for phone={phone_number}")

    ctx = get_integration_context_with_sync()
    entitlements = ctx.get("entitlements", [])

    active = [e for e in entitlements if e.get("phone_number") == phone_number and not e.get("answered", False)]

    demisto.debug(f"get_active_entitlements_for_phone: found {len(active)} active entitlements out of {len(entitlements)} total for phone={phone_number}")

    return active


def find_entitlement_by_reply_code(phone_number: str, reply_code: str) -> tuple:
    """
    Find an entitlement by phone number and reply code, and determine which option was chosen.

    Args:
        phone_number: The sender's phone number
        reply_code: The reply code from the SMS

    Returns:
        Tuple of (entitlement_dict, chosen_option) or (None, None)
        Example: ({"entitlement_id": "...", ...}, "Yes")
    """
    demisto.debug(f"find_entitlement_by_reply_code: phone={phone_number}, code={reply_code}")

    ctx = get_integration_context_with_sync()
    entitlements = ctx.get("entitlements", [])
    demisto.debug(f"Searching through {len(entitlements)} entitlements")

    for ent in entitlements:
        if ent.get("phone_number") == phone_number and not ent.get("answered", False):
            # Check if this reply code is in this entitlement's codes_to_options mapping
            codes_to_options = ent.get("codes_to_options", {})
            if reply_code in codes_to_options:
                chosen_option = codes_to_options[reply_code]
                demisto.debug(f"Found matching entitlement: {ent.get('entitlement_id')}, chosen option: {chosen_option}")
                return ent, chosen_option

    demisto.debug(f"No matching entitlement found for phone={phone_number}, code={reply_code}")
    return None, None


def save_entitlement(entitlement_id: str, phone_number: str, codes_to_options: dict, message: str):
    """
    Save an entitlement to integration context.

    Args:
        entitlement_id: The full entitlement string (GUID@incident|task)
        phone_number: The destination phone number
        codes_to_options: Dict mapping reply codes to option names (e.g., {"1234": "Yes", "5678": "No"})
        message: The sent message
    """
    demisto.debug(f"save_entitlement called: entitlement_id={entitlement_id}, phone={phone_number}, codes={codes_to_options}")

    ctx = get_integration_context_with_sync()
    entitlements = ctx.get("entitlements", [])
    demisto.debug(f"Current entitlements count: {len(entitlements)}")

    # Check if this entitlement already exists (retry scenario)
    existing = None
    for ent in entitlements:
        if ent.get("entitlement_id") == entitlement_id:
            existing = ent
            break

    if existing:
        # Reuse existing entitlement on retry
        demisto.info(f"Reusing existing entitlement with codes: {existing.get('codes_to_options')}")
        return existing.get('codes_to_options', {})

    # Create new entitlement entry
    entitlement_entry = {
        "entitlement_id": entitlement_id,
        "phone_number": phone_number,
        "codes_to_options": codes_to_options,  # Map of code -> option name
        "message": message,
        "created": datetime.utcnow().strftime(DATE_FORMAT),
        "answered": False
    }

    entitlements.append(entitlement_entry)
    ctx["entitlements"] = entitlements
    set_integration_context_with_sync(ctx)

    demisto.info(f"Saved entitlement {entitlement_id} with {len(codes_to_options)} option codes")
    demisto.debug(f"New entitlements count: {len(entitlements)}")
    return codes_to_options


def mark_entitlement_answered(entitlement_id: str):
    """
    Mark an entitlement as answered.

    Args:
        entitlement_id: The full entitlement string
    """
    demisto.debug(f"mark_entitlement_answered: marking entitlement_id={entitlement_id}")

    ctx = get_integration_context_with_sync()
    entitlements = ctx.get("entitlements", [])

    found = False
    for ent in entitlements:
        if ent.get("entitlement_id") == entitlement_id:
            ent["answered"] = True
            ent["answered_at"] = datetime.utcnow().strftime(DATE_FORMAT)
            found = True
            demisto.debug(f"mark_entitlement_answered: successfully marked entitlement_id={entitlement_id} as answered at {ent['answered_at']}")
            break

    if not found:
        demisto.debug(f"mark_entitlement_answered: entitlement_id={entitlement_id} not found in {len(entitlements)} entitlements")

    ctx["entitlements"] = entitlements
    set_integration_context_with_sync(ctx)


def send_feedback_sms(phone_number: str, message: str, params: dict):
    """
    Send a feedback SMS to the user.

    Args:
        phone_number: The destination phone number
        message: The feedback message to send
        params: Integration parameters (for AWS client)
    """
    try:
        sns_client = get_aws_client(params, "sns")
        response = sns_client.publish(
            PhoneNumber=phone_number,
            Message=message
        )
        demisto.debug(f"Sent feedback SMS to {phone_number}: {message[:50]}... MessageId: {response.get('MessageId')}")
    except Exception as e:
        demisto.error(f"Failed to send feedback SMS to {phone_number}: {str(e)}")


def get_available_codes_for_phone(phone_number: str) -> list:
    """
    Get all available reply codes for active entitlements for a phone number.

    Args:
        phone_number: The phone number to check

    Returns:
        List of tuples (code, option_name) for all active entitlements
    """
    demisto.debug(f"get_available_codes_for_phone: getting codes for phone={phone_number}")

    active_entitlements = get_active_entitlements_for_phone(phone_number)
    available_codes = []

    for ent in active_entitlements:
        codes_to_options = ent.get("codes_to_options", {})
        for code, option in codes_to_options.items():
            available_codes.append((code, option))

    demisto.debug(f"get_available_codes_for_phone: found {len(available_codes)} available codes for phone={phone_number}: {available_codes}")

    return available_codes


# ===== AWS CLIENT SETUP =====
def get_aws_client(params: dict, service_name: str):
    """
    Create an AWS boto3 client for the specified service, with Role ARN support.

    Args:
        params: Integration parameters
        service_name: AWS service name (sns or sqs)

    Returns:
        boto3 client
    """
    import boto3
    from botocore.config import Config

    # Extract parameters
    aws_region = params.get("defaultRegion", "us-east-1")
    role_arn = params.get("roleArn")
    role_session_name = params.get("roleSessionName")
    session_duration = params.get("sessionDuration", "900")

    # Get credentials if provided
    credentials = params.get("credentials")
    aws_access_key_id = credentials.get("identifier", "") if credentials else ""
    aws_secret_access_key = credentials.get("password", "") if credentials else ""

    # Timeout and retry configuration
    timeout_param = params.get("timeout", "60")
    timeout = int(timeout_param) if timeout_param else 60
    retries_param = params.get("retries", "5")
    retries = min(int(retries_param) if retries_param else 5, 10)

    # Proxy and SSL
    insecure = params.get("insecure", False)
    verify_certificate = not insecure

    # Set STS regional endpoint
    sts_regional_endpoint = params.get("sts_regional_endpoint", "legacy")
    if sts_regional_endpoint:
        import os
        os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = sts_regional_endpoint.lower()
        demisto.debug(f"Sets the environment variable AWS_STS_REGIONAL_ENDPOINTS={sts_regional_endpoint}")

    # Configure boto3
    config = Config(
        region_name=aws_region,
        connect_timeout=10,
        read_timeout=timeout,
        retries={"max_attempts": retries, "mode": "standard"}
    )

    # Authentication logic (matches AWS API Module pattern)
    if role_arn and role_session_name:
        # Method 1: Role ARN only (no access keys)
        if not aws_access_key_id:
            demisto.debug(f"Using Role ARN authentication: {role_arn}")
            sts_client = boto3.client(
                "sts",
                config=config,
                verify=verify_certificate,
                region_name=aws_region
            )
            kwargs = {
                "RoleArn": role_arn,
                "RoleSessionName": role_session_name,
            }
            if session_duration:
                kwargs["DurationSeconds"] = int(session_duration)

            demisto.debug(f"STS AssumeRole: role_arn={role_arn}, session_name={role_session_name}, duration={session_duration}s")
            sts_response = sts_client.assume_role(**kwargs)
            demisto.debug(f"STS AssumeRole successful, credentials expire at: {sts_response['Credentials'].get('Expiration')}")

            client = boto3.client(
                service_name=service_name,
                region_name=aws_region,
                aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
                aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
                aws_session_token=sts_response["Credentials"]["SessionToken"],
                verify=verify_certificate,
                config=config
            )
        # Method 2: Access Key + Role ARN (assume role with keys)
        else:
            demisto.debug(f"Using Access Key + Role ARN authentication: {role_arn}")
            sts_client = boto3.client(
                service_name="sts",
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                config=config,
                verify=verify_certificate,
                region_name=aws_region
            )
            kwargs = {
                "RoleArn": role_arn,
                "RoleSessionName": role_session_name,
            }
            if session_duration:
                kwargs["DurationSeconds"] = int(session_duration)

            demisto.debug(f"STS AssumeRole (with access key): role_arn={role_arn}, session_name={role_session_name}, duration={session_duration}s")
            sts_response = sts_client.assume_role(**kwargs)
            demisto.debug(f"STS AssumeRole successful, credentials expire at: {sts_response['Credentials'].get('Expiration')}")

            client = boto3.client(
                service_name=service_name,
                region_name=aws_region,
                aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
                aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
                aws_session_token=sts_response["Credentials"]["SessionToken"],
                verify=verify_certificate,
                config=config
            )
    # Method 3: Access Key only
    elif aws_access_key_id and aws_secret_access_key:
        demisto.debug("Using Access Key authentication")
        client = boto3.client(
            service_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=aws_region,
            config=config,
            verify=verify_certificate
        )
    # Method 4: Default credentials (EC2 instance role, etc.)
    else:
        demisto.debug("Using default AWS credentials")
        client = boto3.client(
            service_name,
            region_name=aws_region,
            config=config,
            verify=verify_certificate
        )

    demisto.debug(f"get_aws_client: created {service_name} client for region={aws_region}")
    return client


# ===== COMMAND: send-notification =====
def send_notification_command(args: dict, params: dict) -> CommandResults:
    """
    Send an SMS notification with entitlement handling.

    Args:
        args: Command arguments (to, message)
        params: Integration parameters

    Returns:
        CommandResults with send status
    """
    phone_number = args.get("to")
    message = args.get("message")

    demisto.debug(f"send_notification_command called: to={phone_number}, message_length={len(message) if message else 0}")

    if not phone_number or not message:
        raise ValueError("Both 'to' and 'message' arguments are required")

    # Extract full entitlement string from message (includes GUID@incident|task)
    entitlement_full, _ = extract_entitlement_from_message(message)
    demisto.debug(f"Extracted entitlement string: {entitlement_full}")

    if not entitlement_full:
        # No entitlement, just send the message
        sns_client = get_aws_client(params, "sns")
        response = sns_client.publish(
            PhoneNumber=phone_number,
            Message=message
        )

        return CommandResults(
            outputs_prefix="AWS.SNS.SMS",
            outputs={"MessageId": response.get("MessageId"), "PhoneNumber": phone_number},
            readable_output=f"SMS sent successfully to {phone_number}\nMessageId: {response.get('MessageId')}"
        )

    demisto.debug(f"Using full entitlement string for storage: {entitlement_full}")

    # Get all existing codes from active entitlements to avoid duplicates
    active_entitlements = get_active_entitlements_for_phone(phone_number)
    existing_codes = set()
    for ent in active_entitlements:
        codes_to_options = ent.get("codes_to_options", {})
        existing_codes.update(codes_to_options.keys())

    demisto.debug(f"Existing codes for {phone_number}: {existing_codes}")

    # Get reply code mode from configuration
    reply_code_mode = params.get("replyCodeMode", REPLY_CODE_MODE_RANDOM)
    demisto.debug(f"Reply code mode: {reply_code_mode}")

    # Clean the message and generate reply codes for each option
    formatted_message, codes_to_options = clean_ask_task_message_and_generate_codes(
        message, existing_codes, reply_code_mode
    )

    if not codes_to_options:
        # No options found in message (shouldn't happen with Ask tasks)
        demisto.error(f"No options extracted from Ask task message: {message}")
        codes_to_options = {DEFAULT_REPLY_CODE: "response"}  # Fallback

    # Save entitlement with code-to-option mappings
    save_entitlement(entitlement_full, phone_number, codes_to_options, formatted_message)

    # Send SMS via SNS
    sns_client = get_aws_client(params, "sns")
    response = sns_client.publish(
        PhoneNumber=phone_number,
        Message=formatted_message
    )

    # Format codes for display
    codes_display = ", ".join([f"{opt}={code}" for code, opt in codes_to_options.items()])

    return CommandResults(
        outputs_prefix="AWS.SNS.SMS",
        outputs={
            "MessageId": response.get("MessageId"),
            "PhoneNumber": phone_number,
            "Entitlement": entitlement_full,
            "CodesToOptions": codes_to_options
        },
        readable_output=f"SMS sent successfully to {phone_number}\nMessageId: {response.get('MessageId')}\nReply Codes: {codes_display}\nEntitlement: {entitlement_full}"
    )


def list_entitlements_command(args: dict, params: dict) -> CommandResults:
    """
    List all active entitlements with phone numbers and reply codes.

    Args:
        args: Command arguments (optional: phone_number, show_answered)
        params: Integration parameters

    Returns:
        CommandResults with entitlement details
    """
    demisto.debug("Executing list-entitlements command")

    # Get optional filters
    filter_phone = args.get("phone_number")
    show_answered = argToBoolean(args.get("show_answered", False))

    # Get all entitlements from context
    ctx = get_integration_context_with_sync()
    entitlements = ctx.get("entitlements", [])

    demisto.debug(f"Found {len(entitlements)} total entitlements in context")

    # Apply filters
    filtered_entitlements = []
    for ent in entitlements:
        # Filter by phone number if specified
        if filter_phone and ent.get("phone_number") != filter_phone:
            continue

        # Filter by answered status
        if not show_answered and ent.get("answered", False):
            continue

        filtered_entitlements.append(ent)

    demisto.debug(f"Filtered to {len(filtered_entitlements)} entitlements after applying filters")

    # Prepare output data
    output_data = []
    for ent in filtered_entitlements:
        # Calculate age
        created = datetime.strptime(ent.get("created", datetime.utcnow().strftime(DATE_FORMAT)), DATE_FORMAT)
        age_hours = (datetime.utcnow() - created).total_seconds() / 3600

        # Format codes to options mapping for display
        codes_to_options = ent.get("codes_to_options", {})
        codes_display = ", ".join([f"{opt}={code}" for code, opt in codes_to_options.items()])

        entry = {
            "EntitlementID": ent.get("entitlement_id"),
            "PhoneNumber": ent.get("phone_number"),
            "ReplyCodes": codes_display,
            "Message": ent.get("message", "")[:100] + ("..." if len(ent.get("message", "")) > 100 else ""),
            "Created": ent.get("created"),
            "AgeHours": round(age_hours, 2),
            "Answered": ent.get("answered", False),
            "AnsweredAt": ent.get("answered_at", "N/A")
        }
        output_data.append(entry)

    # Create readable output
    if not output_data:
        readable_output = "No entitlements found matching the criteria."
    else:
        headers = ["PhoneNumber", "ReplyCodes", "AgeHours", "Answered", "Created", "EntitlementID"]
        readable_output = tableToMarkdown(
            f"Active Entitlements ({len(output_data)} found)",
            output_data,
            headers=headers,
            removeNull=True
        )

    demisto.debug(f"Returning {len(output_data)} entitlements in command results")

    return CommandResults(
        outputs_prefix="AWS.SNS.SMS.Entitlement",
        outputs_key_field="EntitlementID",
        outputs=output_data,
        readable_output=readable_output
    )


# ===== LONG-RUNNING EXECUTION =====
def long_running_execution_command(params: dict):
    """
    Long-running execution loop that polls SQS for SMS replies.

    CRITICAL: AWS STS tokens expire (default 15 minutes, configurable via sessionDuration).
    This loop periodically recreates the AWS client to refresh credentials.

    Args:
        params: Integration parameters
    """
    sqs_queue_url = params.get("sqsQueueUrl")
    poll_interval = int(params.get("pollInterval", DEFAULT_POLL_INTERVAL_SECONDS))
    ttl_hours = int(params.get("entitlementTTL", DEFAULT_TTL_HOURS))

    # Get session duration (default 900 seconds = 15 minutes)
    session_duration = int(params.get("sessionDuration", 900))

    # Calculate token refresh interval:
    # Refresh at 80% of session duration to avoid expiration errors
    # E.g., 900 seconds → refresh every 720 seconds (12 minutes)
    token_refresh_interval = int(session_duration * 0.8)

    if not sqs_queue_url:
        raise ValueError("SQS Queue URL is required for long-running execution")

    # Log all configuration at startup for debugging
    demisto.info(f"{INTEGRATION_NAME} v{INTEGRATION_VERSION} - Starting long-running execution")
    demisto.info(f"Configuration: sqs_queue_url={sqs_queue_url}")
    demisto.info(f"Configuration: poll_interval={poll_interval}s, ttl_hours={ttl_hours}h, session_duration={session_duration}s")
    demisto.info(f"Configuration: token_refresh_interval={token_refresh_interval}s ({token_refresh_interval / 60:.1f} minutes)")
    demisto.info(f"Configuration: success_feedback={params.get('successFeedbackEnabled', True)}, failure_feedback={params.get('failureFeedbackEnabled', True)}")

    # Create initial SQS client
    sqs_client = get_aws_client(params, "sqs")
    last_token_refresh = datetime.utcnow()

    demisto.info("SQS client created successfully, entering polling loop")
    demisto.updateModuleHealth("")

    last_cleanup = datetime.utcnow()

    while True:
        try:
            # Refresh AWS credentials periodically to prevent token expiration
            # STS temporary credentials expire after sessionDuration (default 900 seconds)
            time_since_refresh = (datetime.utcnow() - last_token_refresh).total_seconds()
            if time_since_refresh > token_refresh_interval:
                demisto.debug(f"Refreshing AWS credentials (last refresh: {time_since_refresh:.0f}s ago)")
                sqs_client = get_aws_client(params, "sqs")
                last_token_refresh = datetime.utcnow()
                demisto.debug("AWS credentials refreshed successfully")

            # Cleanup expired entitlements every hour
            if (datetime.utcnow() - last_cleanup).total_seconds() > 3600:
                cleanup_expired_entitlements(ttl_hours)
                last_cleanup = datetime.utcnow()

            # Poll SQS for messages
            response = sqs_client.receive_message(
                QueueUrl=sqs_queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=5,  # Long polling
                AttributeNames=["All"],
                MessageAttributeNames=["All"]
            )

            messages = response.get("Messages", [])

            if messages:
                demisto.debug(f"Received {len(messages)} messages from SQS")

            for message in messages:
                try:
                    process_sms_reply(message, params)

                    # Delete message after successful processing
                    sqs_client.delete_message(
                        QueueUrl=sqs_queue_url,
                        ReceiptHandle=message.get("ReceiptHandle")
                    )

                except Exception as e:
                    demisto.error(f"Error processing message: {str(e)}\n{traceback.format_exc()}")
                    # Don't delete message on error - it will be reprocessed

            # Sleep before next poll
            time.sleep(poll_interval)

        except KeyboardInterrupt:
            demisto.info("Long-running execution interrupted")
            break
        except Exception as e:
            error_msg = f"Error in long-running execution: {str(e)}"
            demisto.error(f"{error_msg}\n{traceback.format_exc()}")
            demisto.updateModuleHealth(error_msg)

            # Check if error is token-related, force refresh on next iteration
            if "ExpiredToken" in str(e) or "Expired" in str(e):
                demisto.info("Detected expired token error - will refresh credentials on next iteration")
                last_token_refresh = datetime.utcnow() - timedelta(seconds=token_refresh_interval + 1)

            time.sleep(poll_interval)


def process_sms_reply(sqs_message: dict, params: dict):
    """
    Process an SMS reply message from SQS.

    Sends feedback SMS to user:
    - On success: Confirmation message with reply code
    - On failure: Available reply codes for active questions

    Args:
        sqs_message: SQS message containing SNS notification
        params: Integration parameters
    """
    demisto.debug(f"process_sms_reply called with SQS message ID: {sqs_message.get('MessageId')}")

    # Get feedback settings from params (separate toggles for success and failure)
    success_feedback_enabled = argToBoolean(params.get("successFeedbackEnabled", True))
    failure_feedback_enabled = argToBoolean(params.get("failureFeedbackEnabled", True))
    success_message_template = params.get("successMessage", DEFAULT_SUCCESS_MESSAGE)
    failure_message_template = params.get("failureMessage", DEFAULT_FAILURE_MESSAGE)

    demisto.debug(f"process_sms_reply: feedback settings - success_enabled={success_feedback_enabled}, failure_enabled={failure_feedback_enabled}")

    # Parse SNS message from SQS body
    body = json.loads(sqs_message.get("Body", "{}"))
    demisto.debug(f"SQS body type: {body.get('Type')}, raw body keys: {list(body.keys())}")

    # SNS wraps the actual SMS message
    if body.get("Type") == "Notification":
        sns_message = json.loads(body.get("Message", "{}"))
    else:
        sns_message = body

    # Extract phone number and message text
    # AWS SNS SMS format: {"originationNumber": "+1234567890", "messageBody": "user reply"}
    phone_number = sns_message.get("originationNumber", "")
    message_text = sns_message.get("messageBody", "")

    if not phone_number or not message_text:
        demisto.debug(f"Skipping message without phone/text: {sns_message}")
        return

    demisto.info(f"Processing SMS reply from {phone_number}: {message_text}")

    # Parse reply: User sends just the reply code (e.g., "1234" or "1")
    # The code maps to an option like "Yes" or "No"
    reply_code = message_text.strip()
    demisto.debug(f"Reply code from SMS: {reply_code}")

    # Check if there are any active entitlements for this phone number
    available_codes = get_available_codes_for_phone(phone_number)

    # Validate it's a numeric code (supports both 4-digit random and sequential modes)
    if not reply_code.isdigit():
        demisto.debug(f"Invalid reply code format: '{reply_code}' (expected digits, isdigit={reply_code.isdigit()})")
        # Send failure feedback if enabled and there are active entitlements
        if failure_feedback_enabled and available_codes:
            codes_list = ", ".join([f"{opt} ({code})" for code, opt in available_codes])
            failure_message = failure_message_template.format(available_codes=codes_list, phone_number=phone_number)
            demisto.debug(f"Sending failure feedback SMS to {phone_number} (invalid format, {len(available_codes)} active codes available)")
            send_feedback_sms(phone_number, failure_message, params)
        elif not failure_feedback_enabled:
            demisto.debug(f"Skipping failure feedback SMS - failure_feedback_enabled=False")
        elif not available_codes:
            demisto.debug(f"Skipping failure feedback SMS - no active entitlements for {phone_number}")
        return

    # Find matching entitlement and get the chosen option
    entitlement, chosen_option = find_entitlement_by_reply_code(phone_number, reply_code)

    if not entitlement:
        demisto.debug(f"No matching entitlement found for phone={phone_number} with code={reply_code}")
        # Send failure feedback if enabled and there are active entitlements
        if failure_feedback_enabled and available_codes:
            codes_list = ", ".join([f"{opt} ({code})" for code, opt in available_codes])
            failure_message = failure_message_template.format(available_codes=codes_list, phone_number=phone_number)
            demisto.debug(f"Sending failure feedback SMS to {phone_number} (code not found, {len(available_codes)} active codes available)")
            send_feedback_sms(phone_number, failure_message, params)
        elif not failure_feedback_enabled:
            demisto.debug(f"Skipping failure feedback SMS - failure_feedback_enabled=False")
        elif not available_codes:
            demisto.debug(f"Skipping failure feedback SMS - no active entitlements for {phone_number}")
        return

    demisto.info(f"Found entitlement, user chose option: {chosen_option}")

    # Parse entitlement components
    entitlement_id = entitlement.get("entitlement_id", "")
    parsed = parse_entitlement_string(entitlement_id)

    if not parsed:
        demisto.error(f"Failed to parse entitlement: {entitlement_id}")
        return

    guid = parsed.get("guid")
    incident_id = parsed.get("incident_id")
    task_id = parsed.get("task_id", "")

    # Handle entitlement response with the chosen option as the user's answer
    try:
        demisto.info(f"Handling entitlement {guid} for incident {incident_id} with response: {chosen_option}")
        demisto.handleEntitlementForUser(incident_id, guid, phone_number, chosen_option, task_id)

        # Mark as answered
        mark_entitlement_answered(entitlement_id)

        demisto.info(f"Successfully processed entitlement response from {phone_number}")

        # Send success feedback SMS if enabled
        if success_feedback_enabled:
            success_message = success_message_template.format(
                reply_code=reply_code,
                chosen_option=chosen_option,
                phone_number=phone_number
            )
            demisto.debug(f"Sending success feedback SMS to {phone_number} (reply_code={reply_code}, chosen_option={chosen_option})")
            send_feedback_sms(phone_number, success_message, params)
        else:
            demisto.debug(f"Skipping success feedback SMS - success_feedback_enabled=False")

    except Exception as e:
        demisto.error(f"Failed to handle entitlement {entitlement_id}: {str(e)}\n{traceback.format_exc()}")


# ===== TEST MODULE =====
def test_module_command(params: dict) -> str:
    """
    Test the integration configuration.

    Tests connectivity by checking SQS queue access (required for receiving SMS replies).
    We test SQS instead of SNS because:
    1. The IAM role needs SQS permissions for the long-running execution
    2. SQS queue URL is always configured, while SNS operations are destination-specific
    3. Getting queue attributes is non-destructive and validates authentication

    Args:
        params: Integration parameters

    Returns:
        'ok' if successful
    """
    try:
        # Test SQS connection - this is the primary operation for this integration
        sqs_queue_url = params.get("sqsQueueUrl")
        if not sqs_queue_url:
            raise Exception("SQS Queue URL is required for this integration")

        sqs_client = get_aws_client(params, "sqs")
        response = sqs_client.get_queue_attributes(
            QueueUrl=sqs_queue_url,
            AttributeNames=["QueueArn"]
        )

        # Verify response
        if response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200:
            demisto.debug(f"Successfully connected to SQS queue: {sqs_queue_url}")
            return "ok"
        else:
            raise Exception(f"Unexpected response from SQS: {response}")

    except Exception as e:
        raise Exception(f"Test failed: {str(e)}")


# ===== TEST/DEBUG COMMANDS =====
def inject_reply_command(args: dict, params: dict) -> CommandResults:
    """
    Test command to inject a simulated SMS reply for debugging.

    Bypasses AWS SQS and directly tests the entitlement matching and processing logic.

    Args:
        args: Command arguments (phone_number, reply_code)
        params: Integration parameters

    Returns:
        CommandResults with processing details
    """
    phone_number = args.get("phone_number")
    reply_code = args.get("reply_code")

    if not phone_number or not reply_code:
        raise ValueError("Both phone_number and reply_code are required")

    demisto.debug(f"inject_reply_command: phone={phone_number}, code={reply_code}")

    # Validate reply code format (supports both 4-digit random and sequential modes)
    if not reply_code.isdigit():
        return CommandResults(
            readable_output=f"Invalid reply code format: {reply_code}\nMust be numeric",
            outputs_prefix="AWS.SNS.SMS.TestReply",
            outputs={
                "Success": False,
                "Error": "Invalid reply code format - must be numeric",
                "PhoneNumber": phone_number,
                "ReplyCode": reply_code
            }
        )

    # Find matching entitlement
    entitlement, chosen_option = find_entitlement_by_reply_code(phone_number, reply_code)

    if not entitlement:
        # Get all active entitlements for debugging
        active_entitlements = get_active_entitlements_for_phone(phone_number)
        codes_info = []
        for ent in active_entitlements:
            codes = ent.get("codes_to_options", {})
            codes_info.append({
                "EntitlementID": ent.get("entitlement_id"),
                "Codes": codes
            })

        return CommandResults(
            readable_output=f"❌ No matching entitlement found\n\n"
                          f"Phone: {phone_number}\n"
                          f"Reply Code: {reply_code}\n\n"
                          f"Active entitlements for this phone:\n{json.dumps(codes_info, indent=2)}",
            outputs_prefix="AWS.SNS.SMS.TestReply",
            outputs={
                "Success": False,
                "Error": "No matching entitlement found",
                "PhoneNumber": phone_number,
                "ReplyCode": reply_code,
                "ActiveEntitlements": codes_info
            }
        )

    # Parse entitlement components
    entitlement_id = entitlement.get("entitlement_id", "")
    parsed = parse_entitlement_string(entitlement_id)

    if not parsed:
        return CommandResults(
            readable_output=f"❌ Failed to parse entitlement: {entitlement_id}",
            outputs_prefix="AWS.SNS.SMS.TestReply",
            outputs={
                "Success": False,
                "Error": f"Failed to parse entitlement: {entitlement_id}",
                "PhoneNumber": phone_number,
                "ReplyCode": reply_code
            }
        )

    guid = parsed.get("guid")
    incident_id = parsed.get("incident_id")
    task_id = parsed.get("task_id", "")

    # Handle entitlement response
    try:
        demisto.info(f"[TEST] Handling entitlement {guid} for incident {incident_id} with response: {chosen_option}")
        demisto.handleEntitlementForUser(incident_id, guid, phone_number, chosen_option, task_id)

        # Mark as answered
        mark_entitlement_answered(entitlement_id)

        success_msg = (
            f"✅ Successfully processed test reply!\n\n"
            f"Phone Number: {phone_number}\n"
            f"Reply Code: {reply_code}\n"
            f"Chosen Option: {chosen_option}\n"
            f"Entitlement GUID: {guid}\n"
            f"Incident ID: {incident_id}\n"
            f"Task ID: {task_id or 'N/A'}\n"
        )

        return CommandResults(
            readable_output=success_msg,
            outputs_prefix="AWS.SNS.SMS.TestReply",
            outputs={
                "Success": True,
                "PhoneNumber": phone_number,
                "ReplyCode": reply_code,
                "ChosenOption": chosen_option,
                "EntitlementGUID": guid,
                "IncidentID": incident_id,
                "TaskID": task_id
            }
        )

    except Exception as e:
        error_msg = f"❌ Failed to handle entitlement\n\nError: {str(e)}\n\n{traceback.format_exc()}"
        demisto.error(error_msg)
        return CommandResults(
            readable_output=error_msg,
            outputs_prefix="AWS.SNS.SMS.TestReply",
            outputs={
                "Success": False,
                "Error": str(e),
                "PhoneNumber": phone_number,
                "ReplyCode": reply_code
            }
        )


# ===== MAIN =====
def main():
    """Main execution function."""
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f"Command being called is {command}")

    try:
        if command == "test-module":
            result = test_module_command(params)
            return_results(result)

        elif command == "send-notification":
            return_results(send_notification_command(args, params))

        elif command == "aws-sns-sms-list-entitlements":
            return_results(list_entitlements_command(args, params))

        elif command == "aws-sns-sms-inject-reply":
            return_results(inject_reply_command(args, params))

        elif command == "long-running-execution":
            long_running_execution_command(params)

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        error_msg = f"Failed to execute {command} command.\nError: {str(e)}\n{traceback.format_exc()}"
        demisto.error(error_msg)
        return_error(error_msg)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
