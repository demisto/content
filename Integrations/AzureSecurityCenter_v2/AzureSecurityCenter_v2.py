from CommonServerPython import *

""" IMPORTS """
import requests
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import ast
from datetime import datetime

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

""" GLOBAL VARS """

PARAMS = demisto.params()
TENANT_ID = PARAMS.get("tenant_id")
AUTH_AND_TOKEN_URL = PARAMS.get("auth_id", "").split("@")
AUTH_ID = AUTH_AND_TOKEN_URL[0]
ENC_KEY = PARAMS.get("enc_key")
if len(AUTH_AND_TOKEN_URL) != 2:
    TOKEN_RETRIEVAL_URL = "https://oproxy.demisto.ninja/obtain-token"  # disable-secrets-detection
else:
    TOKEN_RETRIEVAL_URL = AUTH_AND_TOKEN_URL[1]
# Remove trailing slash to prevent wrong URL path to service
SERVER = PARAMS.get("server_url", "")

APP_NAME = "ms-azure-sc"
USE_SSL = not PARAMS.get("unsecure", False)
SUBSCRIPTION_ID = demisto.args().get("subscription_id") or PARAMS.get("default_sub_id")

# API Versions
SUBSCRIPTION_API_VERSION = "2015-01-01"
ALERT_API_VERSION = "2015-06-01-preview"
LOCATION_API_VERSION = "2015-06-01-preview"
ATP_API_VERSION = "2017-08-01-preview"
APS_API_VERSION = "2017-08-01-preview"
IPP_API_VERSION = "2017-08-01-preview"
JIT_API_VERSION = "2015-06-01-preview"
STORAGE_API_VERSION = "2018-07-01"

""" HELPER FUNCTIONS """


def epoch_seconds(d=None):
    """
    Return the number of seconds for given date. If no date, return current.
    """
    if not d:
        d = datetime.utcnow()
    return int((d - datetime.utcfromtimestamp(0)).total_seconds())


def get_encrypted(content: str, key: str) -> str:
    """
    Encrypt content using a specified key
    """
    def create_nonce() -> bytes:
        return os.urandom(12)

    def encrypt(string: str, enc_key: str) -> bytes:
        # String to bytes
        enc_key = base64.b64decode(enc_key)
        # Create key
        aes_gcm = AESGCM(enc_key)
        # Create nonce
        nonce = create_nonce()
        # Create ciphered data
        data = string.encode()
        ct = aes_gcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + ct)
    now = epoch_seconds()
    encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
    return encrypted


def get_access_token():
    integration_context = demisto.getIntegrationContext()
    access_token = integration_context.get('access_token')
    valid_until = integration_context.get('valid_until')
    if access_token and valid_until:
        if epoch_seconds() < valid_until:
            return access_token
    headers = {'Accept': 'application/json'}

    dbot_response = requests.post(
        TOKEN_RETRIEVAL_URL,
        headers=headers,
        data=json.dumps({
            'app_name': APP_NAME,
            'registration_id': AUTH_ID,
            'encrypted_token': get_encrypted(TENANT_ID, ENC_KEY)
        }),
        verify=USE_SSL
    )
    if dbot_response.status_code not in {200, 201}:
        msg = 'Error in authentication. Try checking the credentials you entered.'
        try:
            demisto.info('Authentication failure from server: {} {} {}'.format(
                dbot_response.status_code, dbot_response.reason, dbot_response.text))
            err_response = dbot_response.json()
            server_msg = err_response.get('message')
            if not server_msg:
                title = err_response.get('title')
                detail = err_response.get('detail')
                if title:
                    server_msg = f'{title}. {detail}'
            if server_msg:
                msg += ' Server message: {}'.format(server_msg)
        except Exception as ex:
            demisto.error('Failed parsing error response - Exception: {}'.format(ex))
        raise Exception(msg)
    try:
        gcloud_function_exec_id = dbot_response.headers.get('Function-Execution-Id')
        demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
        parsed_response = dbot_response.json()
    except ValueError:
        raise Exception(
            'There was a problem in retrieving an updated access token.\n'
            'The response from the Demistobot server did not contain the expected content.'
        )
    access_token = parsed_response.get('access_token')
    expires_in = parsed_response.get('expires_in', 3595)
    time_now = epoch_seconds()
    time_buffer = 5  # seconds by which to shorten the validity period
    if expires_in - time_buffer > 0:
        # err on the side of caution with a slightly shorter access token validity period
        expires_in = expires_in - time_buffer

    demisto.setIntegrationContext({
        'access_token': access_token,
        'valid_until': time_now + expires_in
    })
    return access_token


def http_request(method, url_suffix, body=None, params=None, add_subscription=True):
    """
    Generic request to the graph
    """
    token = get_access_token()
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if add_subscription:
        url = "{}subscriptions/{}/{}".format(SERVER, SUBSCRIPTION_ID, url_suffix)
    else:
        url = SERVER + url_suffix

    r = requests.request(method, url, json=body, params=params, headers=headers, verify=USE_SSL)
    if r.status_code not in {200, 201, 202, 204}:
        if r.status_code in {401, 403}:
            return_error(
                "Permission error in API call to Azure Security Center, make sure the application has access "
                "to the relevant resources.")
        return_error(
            "Error in API call to Azure Security Center [{}] - {}".format(
                r.status_code, r.text
            )
        )
    try:
        r = r.json()
        return r
    except ValueError:
        return dict()


# Format ports in JIT access policy rule to (portNum, protocol, allowedAddress, maxDuration)
def format_jit_port_rule(ports):
    port_array = list()
    for port in ports:
        # for each item in unicode, has to use str to decode to ascii
        p_num = str(port.get("number"))
        p_src_addr = (
            str(port.get("allowedSourceAddressPrefix"))
            if port.get("allowedSourceAddressPrefix") != "*"
            else "any"
        )
        p_protocol = str(port.get("protocol")) if port.get("protocol") != "*" else "any"
        p_max_duration = str(port.get("maxRequestAccessDuration"))
        port_array.append(str((p_num, p_protocol, p_src_addr, p_max_duration)))
    return ", ".join(port_array)


# Format ports in JIT access request to (portNum, allowedAddress, endTime, status)
def format_jit_port_request(ports):
    port_array = list()
    for port in ports:
        # for each item in unicode, has to use str to decode to ascii
        p_num = str(port.get("number"))
        p_src_addr = (
            str(port.get("allowedSourceAddressPrefix"))
            if port.get("allowedSourceAddressPrefix") != "*"
            else "any"
        )
        p_status = str(port.get("status"))
        p_end_time = str(port.get("endTimeUtc"))
        port_array.append(str((p_num, p_src_addr, p_end_time, p_status)))
    return ", ".join(port_array)


def normalize_context_key(string):
    """Normalize context keys
    Function will normalize the string (remove white spaces and tailings)
    Args:
        string (str):
    Returns:
        Normalized string
    """
    tmp = string[:1].upper() + string[1:]
    return tmp.replace(" ", "")


""" FUNCTIONS """
""" Alert Start """


def get_alert_command(args):
    """Getting specified alert from API
    Args
        args (dict): dictionary containing commands args
    """
    resource_group_name = args.get("resource_group_name")
    asc_location = args.get("asc_location")
    alert_id = args.get("alert_id")
    alert = get_alert(resource_group_name, asc_location, alert_id)
    final_output = list()

    # Basic Property Table
    properties = alert.get("properties")
    if properties:
        basic_table_output = [
            {
                "DisplayName": properties.get("alertDisplayName"),
                "CompromisedEntity": properties.get("compromisedEntity"),
                "Description": properties.get("description"),
                "DetectedTime": properties.get("detectedTimeUtc"),
                "ReportedTime": properties.get("reportedTimeUtc"),
                "ReportedSeverity": properties.get("reportedSeverity"),
                "ConfidenceScore": properties.get("confidenceScore", "None"),
                "State": properties.get("state"),
                "ActionTaken": properties.get("actionTaken"),
                "CanBeInvestigated": properties.get("canBeInvestigated"),
                "RemediationSteps": properties.get("remediationSteps"),
                "VendorName": properties.get("vendorName"),
                "AssociatedResource": properties.get("associatedResource"),
                "AlertName": properties.get("alertName"),
                "InstanceID": properties.get("instanceId", "None"),
                "ID": alert.get("name"),
                "ExtendedProperties": properties.get("extendedProperties"),
                "Entities": properties.get("entities"),
                "SubscriptionID": properties.get("subscriptionId"),
            }
        ]

        md = tableToMarkdown(
            "Azure Security Center - Get Alert - Basic Property",
            basic_table_output,
            [
                "DisplayName",
                "CompromisedEntity",
                "Description",
                "DetectedTime",
                "ReportedTime",
                "ReportedSeverity",
                "ConfidenceScore",
                "State",
                "ActionTaken",
                "CanBeInvestigated",
                "RemediationSteps",
                "VendorName",
                "AssociatedResource",
                "AlertName",
                "InstanceID",
                "ID",
            ],
            removeNull=True,
        )

        ec = {
            "AzureSecurityCenter.Alert(val.ID && val.ID === obj.ID)": basic_table_output
        }

        basic_table_entry = {
            "Type": entryTypes["note"],
            "Contents": alert,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": md,
            "EntryContext": ec,
        }
        final_output.append(basic_table_entry)

        # Extended Properties Table
        if (
            alert.get("properties")
            and alert.get("properties")
            and alert.get("properties").get("extendedProperties")
        ):
            extended_properties = dict()
            properties = alert.get("properties")
            if isinstance(properties.get("extendedProperties"), dict):
                for key, value in alert["properties"]["extendedProperties"].items():
                    extended_properties[normalize_context_key(key)] = value
                extended_table_entry = {
                    "Type": entryTypes["note"],
                    "Contents": alert["properties"]["extendedProperties"],
                    "ContentsFormat": formats["json"],
                    "ReadableContentsFormat": formats["markdown"],
                    "HumanReadable": tableToMarkdown(
                        "Azure Security Center - Get Alert - Extended Property",
                        extended_properties,
                        removeNull=True,
                    ),
                }
                final_output.append(extended_table_entry)

            # Entities Table
            entities = properties.get("entities")
            if entities:
                if isinstance(entities, dict):
                    entities_table_output = list()
                    for entity in entities:
                        entities_table_output.append(
                            {
                                "Content": ast.literal_eval(str(entity)),
                                "Type": entity["type"],
                            }
                        )

                    md = tableToMarkdown(
                        "Azure Security Center - Get Alert - Entity",
                        entities_table_output,
                        removeNull=True,
                    )

                    entities_table_entry = {
                        "Type": entryTypes["note"],
                        "Contents": alert.get("properties").get("entities"),
                        "ContentsFormat": formats["json"],
                        "ReadableContentsFormat": formats["markdown"],
                        "HumanReadable": md,
                    }
                    final_output.append(entities_table_entry)
    demisto.results(final_output)


def get_alert(resource_group_name, asc_location, alert_id):
    """Building query

    Args:
        resource_group_name (str): ResourceGroupName
        asc_location (str): Azure Security Center location
        alert_id (str): Alert ID
        subscription (str): Subscription ID

    Returns:
        response body (dict)

    """
    cmd_url = ""
    if resource_group_name:
        cmd_url += "/resourceGroups/{}".format(resource_group_name)
    cmd_url += "/providers/Microsoft.Security/locations/{}/alerts/{}?api-version={}".format(
        asc_location, alert_id, ALERT_API_VERSION
    )
    response = http_request("GET", cmd_url)
    return response


def list_alerts_command(args):
    """Getting all alerts

    Args:
        args (dict): usually demisto.args()
    """
    resource_group_name = args.get("resource_group_name")
    asc_location = args.get("asc_location")
    filter_query = args.get("filter")
    select_query = args.get("select")
    expand_query = args.get("expand")

    alerts = list_alerts(
        resource_group_name, asc_location, filter_query, select_query, expand_query
    ).get("value")
    outputs = list()
    for alert in alerts:
        properties = alert.get("properties")
        if properties:
            outputs.append(
                {
                    "DisplayName": properties.get("alertDisplayName"),
                    "CompromisedEntity": properties.get("compromisedEntity"),
                    "DetectedTime": properties.get("detectedTimeUtc"),
                    "ReportedSeverity": properties.get("reportedSeverity"),
                    "State": properties.get("state"),
                    "ActionTaken": properties.get("actionTaken"),
                    "Description": properties.get("description"),
                    "ID": alert.get("name"),
                }
            )

    md = tableToMarkdown(
        "Azure Security Center - List Alerts",
        outputs,
        [
            "DisplayName",
            "CompromisedEntity",
            "DetectedTime",
            "ReportedSeverity",
            "State",
            "ActionTaken",
            "Description",
            "ID",
        ],
        removeNull=True,
    )
    ec = {"AzureSecurityCenter.Alert(val.ID && val.ID === obj.ID)": outputs}
    entry = {
        "Type": entryTypes["note"],
        "Contents": alerts,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def get_alerts(
    resource_group_name, asc_location, filter_query, select_query, expand_query
):
    """Building query

    Args:
        resource_group_name (str): ResourceGroupName
        asc_location (str): Azure Security Center location
        filter_query (str): what to filter
        select_query (str): what to select
        expand_query (str): what to expand

    Returns:
        dict: contains response body
    """
    cmd_url = ""
    if resource_group_name:
        cmd_url += "/resourceGroups/{}/providers/Microsoft.Security".format(
            resource_group_name
        )
        # ascLocation muse be using with specifying resourceGroupName
        if asc_location:
            cmd_url += "/locations/{}".format(asc_location)
    else:
        cmd_url += "/providers/Microsoft.Security"
    cmd_url += "/alerts?api-version={}".format(ALERT_API_VERSION)

    if filter_query:
        cmd_url += "&$filter={}".format(filter_query)
    if select_query:
        cmd_url += "&$select={}".format(select_query)
    if expand_query:
        cmd_url += "&$expand={}".format(expand_query)

    response = http_request("GET", cmd_url)
    return response


def list_alerts(
    resource_group_name, asc_location, filter_query, select_query, expand_query
):
    """Listing alerts

    Args:
        resource_group_name (str): ResourceGroupName
        asc_location (str): Azure Security Center location
        filter_query (str): what to filter
        select_query (str): what to select
        expand_query (str): what to expand

    Returns:
        dict: contains response body
    """
    cmd_url = ""
    if resource_group_name:
        cmd_url += "/resourceGroups/{}/providers/Microsoft.Security".format(
            resource_group_name
        )
        # ascLocation must be using with specifying resourceGroupName
        if asc_location:
            cmd_url += "/locations/{}".format(asc_location)
    else:
        cmd_url += "/providers/Microsoft.Security"
    cmd_url += "/alerts?api-version={}".format(ALERT_API_VERSION)

    if filter_query:
        cmd_url += "&$filter={}".format(filter_query)
    if select_query:
        cmd_url += "&$select={}".format(select_query)
    if expand_query:
        cmd_url += "&$expand={}".format(expand_query)

    response = http_request("GET", cmd_url)
    return response


def update_alert_command(args):
    """Update given alert

    Args:
        args (dict): usually demisto.args()
    """
    resource_group_name = args.get("resource_group_name")
    asc_location = args.get("asc_location")
    alert_id = args.get("alert_id")
    alert_update_action_type = args.get("alert_update_action_type")
    response = update_alert(
        resource_group_name, asc_location, alert_id, alert_update_action_type
    )
    outputs = {"ID": response.get("id"), "ActionTaken": alert_update_action_type}

    ec = {"AzureSecurityCenter.Alert(val.ID && val.ID === obj.ID)": outputs}

    demisto.results(
        {
            "Type": entryTypes["note"],
            "Contents": "Alert - {} has been set to {}.".format(
                alert_id, alert_update_action_type
            ),
            "ContentsFormat": formats["text"],
            "EntryContext": ec,
        }
    )


def update_alert(resource_group_name, asc_location, alert_id, alert_update_action_type):
    """Building query

    Args:
        resource_group_name (str): Resource Name Group
        asc_location (str): Azure Security Center Location
        alert_id (str): Alert ID
        alert_update_action_type (str): What update type need to update

    Returns:
        dict: response body
    """
    cmd_url = ""
    if resource_group_name:
        cmd_url += "/resourceGroups/{}".format(resource_group_name)
    cmd_url += "/providers/Microsoft.Security/locations/{}/alerts/{}/{}?api-version={}".format(
        asc_location, alert_id, alert_update_action_type, ALERT_API_VERSION
    )
    return http_request("POST", cmd_url)


""" Alert End """

""" Location Start """


def list_locations_command():
    """Getting all locations
    """
    locations = list_locations().get("value")
    outputs = list()
    if locations:
        for location in locations:
            if location.get("properties") and location.get("properties").get(
                "homeRegionName"
            ):
                home_region_name = location.get("properties").get("homeRegionName")
            else:
                home_region_name = None
            outputs.append(
                {
                    "HomeRegionName": home_region_name,
                    "Name": location.get("name"),
                    "ID": location.get("id"),
                }
            )
            md = tableToMarkdown(
                "Azure Security Center - List Locations",
                outputs,
                ["HomeRegionName", "Name", "ID"],
                removeNull=True,
            )
            ec = {"AzureSecurityCenter.Location(val.ID && val.ID === obj.ID)": outputs}
            entry = {
                "Type": entryTypes["note"],
                "Contents": locations,
                "ContentsFormat": formats["json"],
                "ReadableContentsFormat": formats["markdown"],
                "HumanReadable": md,
                "EntryContext": ec,
            }
            demisto.results(entry)
    else:
        demisto.results("No locations found")


def list_locations():
    """Building query

    Returns:
        dict: response body
    """
    cmd_url = "/providers/Microsoft.Security/locations?api-version={}".format(
        LOCATION_API_VERSION
    )
    response = http_request("GET", cmd_url)
    return response


""" Location End """

""" Advanced Threat Protection Start """


def update_atp_command(args):
    """Updating given Advanced Threat Protection (enable/disable)

    Args:
        args (dict): usually demisto.args()
    """
    resource_group_name = args.get("resource_group_name")
    setting_name = args.get("setting_name")
    is_enabled = args.get("is_enabled")
    storage_account = args.get("storage_account")
    response = update_atp(
        resource_group_name, storage_account, setting_name, is_enabled
    )
    outputs = {
        "ID": response.get("id"),
        "Name": response.get("name"),
        "IsEnabled": response.get("properties").get("is_enabled"),
    }
    md = tableToMarkdown(
        "Azure Security Center - Update Advanced Threat Detection Setting",
        outputs,
        ["ID", "Name", "IsEnabled"],
        removeNull=True,
    )
    ec = {
        "AzureSecurityCenter.AdvancedThreatProtection(val.ID && val.ID === obj.ID)": outputs
    }

    demisto.results(
        {
            "Type": entryTypes["note"],
            "Contents": response,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": md,
            "EntryContext": ec,
        }
    )


def update_atp(resource_group_name, storage_account, setting_name, is_enabled):
    """Building query

    Args:
        resource_group_name (str): Resource Group Name
        storage_account (str): Storange Account
        setting_name (str):  Setting Name
        is_enabled (str): true/false

    Returns:
        dict: respones body
    """
    cmd_url = (
        "/resourceGroups/{}/providers/Microsoft.Storage/storageAccounts/{}"
        "/providers/Microsoft.Security/advancedThreatProtectionSettings/{}?api-version={}".format(
            resource_group_name, storage_account, setting_name, ATP_API_VERSION
        )
    )
    data = {
        "id": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Storage"
        "/storageAccounts/{}/providers/Microsoft.Security/advancedThreatProtectionSettings/{}".format(
            SUBSCRIPTION_ID, resource_group_name, storage_account, setting_name
        ),
        "name": setting_name,
        "type": "Microsoft.Security/advancedThreatProtectionSettings",
        "properties": {"is_enabled": is_enabled},
    }
    response = http_request("PUT", cmd_url, body=data)
    return response


def get_atp_command(args):
    """Get given Advanced Threat Protection settings

    Args:
        args (dict): usually demisto.args()
    """
    resource_group_name = args.get("resource_group_name")
    setting_name = args.get("setting_name")
    storage_account = args.get("storage_account")
    response = get_atp(resource_group_name, storage_account, setting_name)
    outputs = {
        "ID": response.get("id"),
        "Name": response.get("name"),
        "IsEnabled": response["properties"]["isEnabled"]
        if response.get("properties") and response.get("properties").get("isEnabled")
        else None,
    }
    md = tableToMarkdown(
        "Azure Security Center - Get Advanced Threat Detection Setting",
        outputs,
        ["ID", "Name", "IsEnabled"],
        removeNull=True,
    )
    ec = {
        "AzureSecurityCenter.AdvancedThreatProtection(val.ID && val.ID === obj.ID)": outputs
    }
    demisto.results(
        {
            "Type": entryTypes["note"],
            "Contents": response,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": md,
            "EntryContext": ec,
        }
    )


def get_atp(resource_group_name, storage_account, setting_name):
    """Building query

    Args:
        resource_group_name (str): Resource Group Name
        storage_account (str): Storange Account
        setting_name (str):  Setting Name

    Returns:

    """
    cmd_url = (
        "/resourceGroups/{}/providers/Microsoft.Storage/storageAccounts"
        "/{}/providers/Microsoft.Security/advancedThreatProtectionSettings/{}?api-version={}".format(
            resource_group_name, storage_account, setting_name, ATP_API_VERSION
        )
    )
    response = http_request("GET", cmd_url)
    return response


""" Advanced Threat Protection End """

""" Auto Provisioning Settings Start """


def update_aps_command(args):
    """Updating Analytics Platform System

    Args:
        args (dict): usually demisto.args()
    """
    setting_name = args.get("setting_name")
    auto_provision = args.get("auto_provision")
    setting = update_aps(setting_name, auto_provision)
    outputs = [
        {
            "Name": setting.get("name"),
            "AutoProvision": setting["properties"]["auto_provision"]
            if setting.get("properties")
            and setting.get("properties").get("auto_provision")
            else None,
            "ID": setting.get("id"),
        }
    ]

    md = tableToMarkdown(
        "Azure Security Center - Update Auto Provisioning Setting",
        outputs,
        ["Name", "AutoProvision", "ID"],
        removeNull=True,
    )
    ec = {
        "AzureSecurityCenter.AutoProvisioningSetting(val.ID && val.ID === obj.ID)": outputs
    }
    entry = {
        "Type": entryTypes["note"],
        "Contents": setting,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def update_aps(setting_name, auto_provision):
    """Building query

    Args:
        setting_name (str): Setting name
        auto_provision (str): Auto provision setting (On/Off)

    Returns:
        dict: response body
    """
    cmd_url = "/providers/Microsoft.Security/autoProvisioningSettings/{}?api-version={}".format(
        setting_name, APS_API_VERSION
    )
    data = {"properties": {"autoProvision": auto_provision}}
    response = http_request("PUT", cmd_url, body=data)
    return response


def list_aps_command():
    """List all Analytics Platform System

    """
    settings = list_aps().get("value")
    outputs = []
    for setting in settings:
        outputs.append(
            {
                "Name": setting.get("name"),
                "AutoProvision": setting.get("properties").get("autoProvision")
                if setting.get("properties")
                and setting.get("properties").get("autoProvision")
                else None,
                "ID": setting.get("id"),
            }
        )

    md = tableToMarkdown(
        "Azure Security Center - List Auto Provisioning Settings",
        outputs,
        ["Name", "AutoProvision", "ID"],
        removeNull=True,
    )

    ec = {
        "AzureSecurityCenter.AutoProvisioningSetting(val.ID && val.ID === obj.ID)": outputs
    }

    entry = {
        "Type": entryTypes["note"],
        "Contents": settings,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def list_aps():
    """Build query

    Returns:
        dict: response body
    """
    cmd_url = "/providers/Microsoft.Security/autoProvisioningSettings?api-version={}".format(
        APS_API_VERSION
    )
    response = http_request("GET", cmd_url)
    return response


def get_aps_command(args):
    """Get given Analytics Platform System setting

    Args:
        args (dict): usually demisto.args()
    """
    setting_name = args.get("setting_name")
    setting = get_aps(setting_name)
    outputs = [
        {
            "Name": setting.get("name"),
            "AutoProvision": setting.get("properties").get("autoProvision")
            if setting.get("properties")
            and setting.get("properties").get("autoProvision")
            else None,
            "ID": setting["id"],
        }
    ]
    md = tableToMarkdown(
        "Azure Security Center - Get Auto Provisioning Setting",
        outputs,
        ["Name", "AutoProvision", "ID"],
        removeNull=True,
    )
    ec = {
        "AzureSecurityCenter.AutoProvisioningSetting(val.ID && val.ID === obj.ID)": outputs
    }

    entry = {
        "Type": entryTypes["note"],
        "Contents": setting,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def get_aps(setting_name):
    """Build query

    Args:
        setting_name: Setting name

    Returns:
        dict: response body
    """
    cmd_url = "/providers/Microsoft.Security/autoProvisioningSettings/{}?api-version={}".format(
        setting_name, APS_API_VERSION
    )
    response = http_request("GET", cmd_url)
    return response


""" Auto Provisioning Settings End """

""" Information Protection Policies Start """


def list_ipp_command(args):
    """Listing all Internet Presence Provider

    Args:
        args (dict): usually demisto.args()
    """
    management_group = args.get("management_group")
    policies = list_ipp(management_group).get("value")
    outputs = list()
    if policies:
        for policy in policies:
            if policy.get("properties") and policy.get("properties").get("labels"):
                label_names = ", ".join(
                    [
                        label.get("displayName")
                        for label in policy["properties"]["labels"].values()
                    ]
                )
                information_type_names = ", ".join(
                    [
                        it["displayName"]
                        for it in policy["properties"]["informationTypes"].values()
                    ]
                )
            else:
                label_names, information_type_names = '', ''
            outputs.append(
                {
                    "Name": policy.get("name"),
                    "Labels": label_names,
                    "InformationTypeNames": information_type_names,
                    "InformationTypes": policy.get("properties").get("informationTypes")
                    if policy.get("properties")
                    and policy.get("properties").get("informationTypes")
                    else None,
                    "ID": policy["id"],
                }
            )
        md = tableToMarkdown(
            "Azure Security Center - List Information Protection Policies",
            outputs,
            ["Name", "Labels", "InformationTypeNames", "ID"],
            removeNull=True,
        )

        ec = {
            "AzureSecurityCenter.InformationProtectionPolicy(val.ID && val.ID === obj.ID)": outputs
        }

        entry = {
            "Type": entryTypes["note"],
            "Contents": policies,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": md,
            "EntryContext": ec,
        }
        demisto.results(entry)
    else:
        demisto.results("No policies found")


def list_ipp(management_group=None):
    """Building query

    Args:
        management_group: Managment group to pull (if needed)

    Returns:
        dict: response body

    """
    cmd_url = str()
    scope_is_subscription = True
    if management_group:
        cmd_url += "/providers/Microsoft.Management/managementGroups/{}".format(
            management_group
        )
        scope_is_subscription = False
    cmd_url += "/providers/Microsoft.Security/informationProtectionPolicies?api-version={}".format(
        IPP_API_VERSION
    )
    response = http_request("GET", cmd_url, add_subscription=scope_is_subscription)
    return response


def get_ipp_command(args):
    """Getting Internet Presence Provider information
    Args:
        args (dict): usually demisto.args()
    """
    policy_name = args.get("policy_name")
    management_group = args.get("management_group")
    policy = get_ipp(policy_name, management_group)
    properties = policy.get("properties")
    labels = properties.get("labels")
    if properties and isinstance(labels, dict):
        # Basic Property table
        labels = ", ".join(
            [
                (str(label.get("displayName")) + str(label.get("enabled")))
                for label in labels.values()
            ]
        )
        basic_table_output = [
            {"Name": policy.get("name"), "Labels": labels, "ID": policy.get("id")}
        ]

        md = tableToMarkdown(
            "Azure Security Center - Get Information Protection Policy - Basic Property",
            basic_table_output,
            ["Name", "Labels", "ID"],
            removeNull=True,
        )
        ec = {
            "AzureSecurityCenter.InformationProtectionPolicy(val.ID && val.ID === obj.ID)": basic_table_output
        }

        basic_table_entry = {
            "Type": entryTypes["note"],
            "Contents": policy,
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": md,
            "EntryContext": ec,
        }

        # Information Type table
        info_type_table_output = list()
        for information_type_data in properties.get("informationTypes").values():
            keywords = ", ".join(
                [
                    (
                        str(keyword.get("displayName"))
                        + str(keyword.get("custom"))
                        + str(keyword.get("canBeNumeric"))
                    )
                    for keyword in information_type_data.get("keywords")
                ]
            )
            info_type_table_output.append(
                {
                    "DisplayName": information_type_data.get("displayname"),
                    "Enabled": information_type_data("enabled"),
                    "Custom": information_type_data("custom"),
                    "Keywords": keywords,
                    "RecommendedLabelID": information_type_data("recommendedLabelId"),
                }
            )
        md = tableToMarkdown(
            "Azure Security Center - Get Information Protection Policy - Information Types",
            info_type_table_output,
            ["DisplayName", "Enabled", "Custom", "Keywords", "RecommendedLabelID"],
            removeNull=True,
        )
        info_type_table_entry = {
            "Type": entryTypes["note"],
            "Contents": properties.get("informationTypes"),
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": md,
        }
        demisto.results([basic_table_entry, info_type_table_entry])
    else:
        demisto.results("No properties found in {}".format(management_group))


def get_ipp(policy_name, management_group):
    """Building query

    Args:
        policy_name (str): Policy name
        management_group (str): Managment group

    Returns:
        dict: respone body
    """
    cmd_url = ""
    score_is_subscription = True
    if management_group:
        cmd_url += "/providers/Microsoft.Management/managementGroups/{}".format(
            management_group
        )
        score_is_subscription = False
    cmd_url += "/providers/Microsoft.Security/informationProtectionPolicies/{}?api-version={}".format(
        policy_name, IPP_API_VERSION
    )
    response = http_request("GET", cmd_url, add_subscription=score_is_subscription)
    return response


""" Information Protection Policies End """

""" Jit Network Access Policies Start """


def list_jit_command(args):
    """Lists all Just-in-time Virtual Machines

    Args:
        args (dict): usually demisto.args()
    """
    asc_location = args.get("asc_location")
    resource_group_name = args.get("resource_group_name")
    policies = list_jit(asc_location, resource_group_name)["value"]
    outputs = []
    for policy in policies:
        # summarize rules in (VMName: allowPort,...) format
        if policy.get("properties") and policy.get("properties").get("virtualMachines"):
            rules_data = policy["properties"]["virtualMachines"]
            rules_summary_array = []
            for rule in rules_data:
                ID = rule.get("id")
                if isinstance(ID, str):
                    vm_name = ID.split("/")[-1]
                else:
                    vm_name = None  # type: ignore
                vm_ports = [str(port.get("number")) for port in rule.get("ports")]
                rules_summary_array.append(
                    "({}: {})".format(vm_name, ", ".join(vm_ports))
                )
            rules = ", ".join(rules_summary_array)

            outputs.append(
                {
                    "Name": policy.get("name"),
                    "Rules": rules,
                    "Location": policy.get("location"),
                    "Kind": policy.get("kind"),
                    "ID": policy.get("id"),
                }
            )
    md = tableToMarkdown(
        "Azure Security Center - List JIT Access Policies",
        outputs,
        ["Name", "Rules", "Location", "Kind"],
        removeNull=True,
    )
    ec = {"AzureSecurityCenter.JITPolicy(val.ID && val.ID === obj.ID)": outputs}
    entry = {
        "Type": entryTypes["note"],
        "Contents": policies,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def list_jit(asc_location, resource_group_name):
    """Building query

    Args:
        asc_location: Machine location
        resource_group_name: Resource group name

    Returns:
        dict: response body
    """
    cmd_url = ""
    if resource_group_name:
        cmd_url += "/resourceGroups/{}".format(resource_group_name)
    if asc_location:
        cmd_url += "/providers/Microsoft.Security/locations/{}".format(asc_location)
    cmd_url += "/providers/Microsoft.Security/jitNetworkAccessPolicies?api-version={}".format(
        JIT_API_VERSION
    )
    response = http_request("GET", cmd_url)
    return response


def get_jit_command(args):
    """Getting given Just-in-time machine

    Args:
        args (dict): usually demisto.args()
    """
    policy_name = args.get("policy_name")
    asc_location = args.get("asc_location")
    resource_group_name = args.get("resource_group_name")
    policy = get_jit(policy_name, asc_location, resource_group_name)

    # Property table
    property_table_output = [
        {
            "Name": policy.get("name"),
            "Kind": policy.get("kind"),
            "ProvisioningState": policy.get("properties").get("provisioningState")
            if policy.get("properties")
            and policy.get("properties").get("provisioningState")
            else None,
            "Location": policy.get("location"),
            "Rules": policy.get("properties").get("virtualMachines")
            if policy.get("properties")
            and policy.get("properties").get("virtualMachines")
            else None,
            "Requests": policy.get("properties").get("requests")
            if policy.get("properties") and policy.get("properties").get("requests")
            else None,
            "ID": policy.get("id"),
        }
    ]
    md = tableToMarkdown(
        "Azure Security Center - Get JIT Access Policy - Properties",
        property_table_output,
        ["Name", "Kind", "ProvisioningState", "Location", "ID"],
        removeNull=True,
    )

    ec = {
        "AzureSecurityCenter.JITPolicy(val.ID && val.ID === obj.ID)": property_table_output
    }

    property_table_entry = {
        "Type": entryTypes["note"],
        "Contents": policy,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }

    # Rules table
    rules_table_output = list()
    properties = policy.get("properties")
    virtual_machines = properties.get("virtualMachines")
    if isinstance(properties, dict) and virtual_machines:
        for rule in virtual_machines:
            rules_table_output.append(
                {
                    "VmID": rule.get("id"),
                    "Ports": format_jit_port_rule(rule.get("ports")),
                }
            )
        md = tableToMarkdown(
            "Azure Security Center - Get JIT Access Policy - Rules",
            rules_table_output,
            ["VmID", "Ports"],
            removeNull=True,
        )
        rules_table_entry = {
            "Type": entryTypes["note"],
            "Contents": properties.get("virtualMachines"),
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": md,
        }

        # Requests table
        requests_table_output = list()

        for requestData in properties.get("requests", []):
            vms = list()
            for vm in requestData.get("virtualMachines"):
                vm_name = vm["id"].split("/")[-1]
                vm_ports = format_jit_port_request(vm.get("ports"))
                vms.append("[{}: {}]".format(vm_name, vm_ports))
            requests_table_output.append(
                {
                    "VirtualMachines": ", ".join(vms),
                    "Requestor": requestData.get("requestor")
                    if requestData.get("requestor")
                    else "service-account",
                    "StartTimeUtc": requestData.get("startTimeUtc"),
                }
            )
        md = tableToMarkdown(
            "Azure Security Center - Get JIT Access Policy - Requests",
            requests_table_output,
            ["VirtualMachines", "Requestor", "StartTimeUtc"],
            removeNull=True,
        )

        requests_table_entry = {
            "Type": entryTypes["note"],
            "Contents": properties.get("requests"),
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": md,
        }
        demisto.results([property_table_entry, rules_table_entry, requests_table_entry])


def get_jit(policy_name, asc_location, resource_group_name):
    """Building query

    Args:
        policy_name: Policy name
        asc_location: Machine location
        resource_group_name: Resource name group

    Returns:
        dict: response body
    """
    cmd_url = (
        "/resourceGroups/{}/providers/Microsoft.Security/locations/{}/jitNetworkAccessPolicies/"
        "{}?api-version={}".format(
            resource_group_name, asc_location, policy_name, JIT_API_VERSION
        )
    )
    response = http_request("GET", cmd_url)
    return response


def initiate_jit_command(args):
    resource_group_name = args.get("resource_group_name")
    asc_location = args.get("asc_location")
    policy_name = args.get("policy_name")
    vm_id = args.get("vmID")
    port = args.get("port")
    source_address = args.get("source_address")
    duration = args.get("duration")
    response = initiate_jit(
        resource_group_name,
        asc_location,
        policy_name,
        vm_id,
        port,
        source_address,
        duration,
    )
    policy_id = (
        "/subscriptions/{}/resourceGroups/{}/providers/"
        "Microsoft.Security/locations/{}/jitNetworkAccessPolicies/{}".format(
            SUBSCRIPTION_ID, resource_group_name, asc_location, policy_name
        )
    )
    virtual_machines = response.get("virtualMachines")
    if virtual_machines and len(virtual_machines) > 0:
        machine = virtual_machines[0]
        port = machine.get("ports")[0]

        outputs = {
            "VmID": machine.get("id"),
            "PortNum": port.get("number"),
            "AllowedSourceAddress": port.get("allowedSourceAddressPrefix"),
            "EndTimeUtc": port.get("endTimeUtc"),
            "Status": port.get("status"),
            "Requestor": response.get("requestor"),
            "PolicyID": policy_id,
        }

        md = tableToMarkdown(
            "Azure Security Center - Initiate JIT Access Request",
            outputs,
            [
                "VmID",
                "PortNum",
                "AllowedSourceAddress",
                "EndTimeUtc",
                "Status",
                "Requestor",
            ],
            removeNull=True,
        )

        ec = {
            "AzureSecurityCenter.JITPolicy(val.ID && val.ID ="
            "== obj.{}).Initiate(val.endTimeUtc === obj.EndTimeUtc)".format(
                policy_id
            ): outputs
        }

        demisto.results(
            {
                "Type": entryTypes["note"],
                "Contents": response,
                "ContentsFormat": formats["json"],
                "ReadableContentsFormat": formats["markdown"],
                "HumanReadable": md,
                "EntryContext": ec,
            }
        )


def initiate_jit(
    resource_group_name,
    asc_location,
    policy_name,
    vm_id,
    port,
    source_address,
    duration,
):
    """Starting new Just-in-time machine

    Args:
        resource_group_name: Resource group name
        asc_location: Machine location
        policy_name: Policy name
        vm_id: Virtual Machine ID
        port: ports to be used
        source_address: Source address
        duration: Time in

    Returns:
        dict: response body
    """
    cmd_url = (
        "/resourceGroups/{}/providers/Microsoft.Security/"
        "locations/{}/jitNetworkAccessPolicies/{}/initiate?api-version={}".format(
            resource_group_name, asc_location, policy_name, JIT_API_VERSION
        )
    )
    # only supports init access for one vm and one port now
    data = {
        "virtualMachines": [
            {
                "ID": vm_id,
                "ports": [
                    {
                        "number": port,
                        "duration": duration,
                        "allowedSourceAddressPrefix": source_address,
                    }
                ],
            }
        ]
    }
    response = http_request("POST", cmd_url, body=data)
    return response


def delete_jit_command(args):
    """Deletes a Just-in-time machine

    Args:
        args (dict): usually demisto.args()
    """
    asc_location = args.get("asc_location")
    resource_group_name = args.get("resource_group_name")
    policy_name = args.get("policy_name")
    delete_jit(asc_location, resource_group_name, policy_name)

    policy_id = (
        "/subscriptions/{}/resourceGroups/"
        "{}/providers/Microsoft.Security/locations/{}/jitNetworkAccessPolicies/{}".format(
            SUBSCRIPTION_ID, resource_group_name, asc_location, policy_name
        )
    )

    outputs = {"ID": policy_id, "Action": "deleted"}

    ec = {"AzureSecurityCenter.JITPolicy(val.ID && val.ID === obj.ID)": outputs}
    demisto.results(
        {
            "Type": entryTypes["note"],
            "Contents": "Policy - {} has been deleted sucessfully.".format(policy_name),
            "ContentsFormat": formats["text"],
            "EntryContext": ec,
        }
    )


def delete_jit(asc_location, resource_group_name, policy_name):
    """Building query

    Args:
        asc_location: Machine location
        resource_group_name: Resource group name
        policy_name: Policy name
    """
    cmd_url = (
        "/resourceGroups/{}/providers/Microsoft.Security/"
        "locations/{}/jitNetworkAccessPolicies/{}?api-version={}"
        "".format(resource_group_name, asc_location, policy_name, JIT_API_VERSION)
    )
    http_request("DELETE", cmd_url)


""" Jit Network Access Policies End """

""" Storage Start """


# Add this command to security center integration because ATP-related command requires storage account info
def list_sc_storage_command():
    """Listing all Security Center Storages

    """
    accounts = list_sc_storage().get("value")
    outputs = list()
    for account in accounts:
        account_id_array = account.get("id", str()).split("/")
        resource_group_name = account_id_array[
            account_id_array.index("resourceGroups") + 1
        ]
        outputs.append(
            {
                "Name": account.get("name"),
                "ResourceGroupName": resource_group_name,
                "Location": account.get("location"),
                "ID": account.get("id"),
            }
        )
    md = tableToMarkdown(
        "Azure Security Center - List Storage Accounts",
        outputs,
        ["Name", "ResourceGroupName", "Location"],
        removeNull=True,
    )
    ec = {"AzureSecurityCenter.Storage(val.ID && val.ID === obj.ID)": outputs}

    entry = {
        "Type": entryTypes["note"],
        "Contents": accounts,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def list_sc_storage():
    """Building query

    Returns:
        dict: response body

    """
    cmd_url = "/providers/Microsoft.Storage/storageAccounts?api-version={}".format(
        STORAGE_API_VERSION
    )
    response = http_request("GET", cmd_url)
    return response


""" Storage End """

""" Subscriptions Start """


def list_sc_subscriptions_command():
    """Listing Subscriptions for this application

    """
    subscriptions = list_sc_subscriptions().get("value")
    outputs = list()
    for sub in subscriptions:
        outputs.append(
            {
                "Name": sub.get("displayName"),
                "State": sub.get("state"),
                "ID": sub.get("id"),
            }
        )
    md = tableToMarkdown(
        "Azure Security Center - Subscriptions",
        outputs,
        ["ID", "Name", "State"],
        removeNull=True,
    )
    ec = {"Azure.Subscription(val.ID && val.ID === obj.ID)": outputs}

    entry = {
        "Type": entryTypes["note"],
        "Contents": subscriptions,
        "ContentsFormat": formats["json"],
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": md,
        "EntryContext": ec,
    }
    demisto.results(entry)


def list_sc_subscriptions():
    """Building query

    Returns:
        dict: response body

    """
    cmd_url = "/subscriptions?api-version={}".format(
        SUBSCRIPTION_API_VERSION
    )
    response = http_request("GET", cmd_url, add_subscription=False)
    return response


""" Subscriptions end """


""" Functions start """
try:
    handle_proxy()

    if not SUBSCRIPTION_ID:
        return_error("A subscription ID must be provided.")

    if demisto.command() == "test-module":
        # If the command will fail, error will be thrown from the request itself
        list_locations()
        demisto.results("ok")
    elif demisto.command() == "azure-sc-get-alert":
        get_alert_command(demisto.args())
    elif demisto.command() == "azure-sc-list-alert":
        list_alerts_command(demisto.args())
    elif demisto.command() == "azure-sc-update-alert":
        update_alert_command(demisto.args())
    elif demisto.command() == "azure-sc-list-location":
        list_locations_command()
    elif demisto.command() == "azure-sc-update-atp":
        update_atp_command(demisto.args())
    elif demisto.command() == "azure-sc-get-atp":
        get_atp_command(demisto.args())
    elif demisto.command() == "azure-sc-update-aps":
        update_aps_command(demisto.args())
    elif demisto.command() == "azure-sc-list-aps":
        list_aps_command()
    elif demisto.command() == "azure-sc-get-aps":
        get_aps_command(demisto.args())
    elif demisto.command() == "azure-sc-list-ipp":
        list_ipp_command(demisto.args())
    elif demisto.command() == "azure-sc-get-ipp":
        get_ipp_command(demisto.args())
    elif demisto.command() == "azure-sc-list-jit":
        list_jit_command(demisto.args())
    elif demisto.command() == "azure-sc-get-jit":
        get_jit_command(demisto.args())
    elif demisto.command() == "azure-sc-initiate-jit":
        initiate_jit_command(demisto.args())
    elif demisto.command() == "azure-sc-delete-jit":
        delete_jit_command(demisto.args())
    elif demisto.command() == "azure-sc-list-storage":
        list_sc_storage_command()
    elif demisto.command() == "azure-list-subscriptions":
        list_sc_subscriptions_command()
except Exception as e:
    LOG(str(e))
    LOG.print_log()
    return_error(str(e))
