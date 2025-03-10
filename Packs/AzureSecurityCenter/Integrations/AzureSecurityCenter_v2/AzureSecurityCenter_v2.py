import demistomock as demisto
from CommonServerPython import *
import ast
from MicrosoftApiModule import *  # noqa: E402


""" GLOBAL VARS """

APP_NAME = "ms-azure-sc"
SUB_ID_REQUIRING_CMD = (
    "azure-sc-get-alert",
    "azure-sc-list-alert",
    "azure-sc-update-alert",
    "azure-sc-list-location",
    "azure-sc-update-atp",
    "azure-sc-get-atp",
    "azure-sc-update-aps",
    "azure-sc-list-aps",
    "azure-sc-get-aps",
    "azure-sc-list-jit",
    "azure-sc-get-jit",
    "azure-sc-initiate-jit",
    "azure-sc-delete-jit",
    "azure-sc-list-storage",
)
RESOURCE_GROUP_REQUIRING_CMD = (
    "azure-sc-update-atp",
    "azure-sc-get-atp"
)
DEFAULT_LIMIT = 50
# API Versions
SUBSCRIPTION_API_VERSION = "2015-01-01"
ALERT_API_VERSION = "2022-01-01"
LOCATION_API_VERSION = "2015-06-01-preview"
ATP_API_VERSION = "2017-08-01-preview"
APS_API_VERSION = "2017-08-01-preview"
IPP_API_VERSION = "2017-08-01-preview"
JIT_API_VERSION = "2015-06-01-preview"
STORAGE_API_VERSION = "2018-07-01"
SECURE_STORES_API_VERSION = "2020-01-01"
LIST_RESOURCE_GROUP_VERSION = "2021-04-01"

""" HELPER FUNCTIONS """


# Format ports in JIT access policy rule to (portNum, protocol, allowedAddress, maxDuration)
def format_jit_port_rule(ports):
    port_array = []
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
    port_array = []
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


class MsClient:
    """
    Microsoft Client enables authorized access to Azure Security Center.
    """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, server, verify, proxy, self_deployed, subscription_id,
                 ok_codes, certificate_thumbprint, private_key,
                 resource_group_name=None, managed_identities_client_id=None):
        base_url_with_subscription = f"{server}subscriptions/{subscription_id}/"
        self.ms_client = MicrosoftClient(
            tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
            base_url=base_url_with_subscription, verify=verify, proxy=proxy, self_deployed=self_deployed,
            ok_codes=ok_codes, scope="https://management.azure.com/.default",
            certificate_thumbprint=certificate_thumbprint, private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure,
            command_prefix="azure-sc"
        )
        self.server = server
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name

    def get_alert(self, asc_location, alert_id):
        """
        Args:
            asc_location (str): Azure Security Center location
            alert_id (str): Alert ID

        Returns:
            response body (dict)

        """
        cmd_url = f"/resourceGroups/{self.resource_group_name}" if self.resource_group_name else ""
        cmd_url += f"/providers/Microsoft.Security/locations/{asc_location}/alerts/{alert_id}"
        params = {'api-version': ALERT_API_VERSION}
        return self.ms_client.http_request(
            method="GET", url_suffix=cmd_url, params=params)

    def list_alerts(self, asc_location, filter_query, select_query, expand_query):
        """Listing alerts

        Args:
            asc_location (str): Azure Security Center location
            filter_query (str): what to filter
            select_query (str): what to select
            expand_query (str): what to expand

        Returns:
            dict: contains response body
        """
        if self.resource_group_name:
            cmd_url = f"/resourceGroups/{self.resource_group_name}/providers/Microsoft.Security"
            # ascLocation must be using with specifying resourceGroupName
            if asc_location:
                cmd_url += f"/locations/{asc_location}"
            cmd_url += "/alerts"
        else:
            cmd_url = "/providers/Microsoft.Security/alerts"

        params = {'api-version': ALERT_API_VERSION}
        if filter_query:
            params['$filter'] = filter_query
        if select_query:
            params['$select'] = select_query
        if expand_query:
            params['$expand'] = expand_query

        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def update_alert(self, asc_location, alert_id, alert_update_action_type):
        """
        Args:
            asc_location (str): Azure Security Center Location
            alert_id (str): Alert ID
            alert_update_action_type (str): What update type need to update

        Returns:
            dict: response body
        """
        cmd_url = f"/resourceGroups/{self.resource_group_name}" if self.resource_group_name else ""
        cmd_url += f"/providers/Microsoft.Security/locations/{asc_location}/alerts/{alert_id}/" \
                   f"{alert_update_action_type}"
        params = {"api-version": ALERT_API_VERSION}
        #  Using resp_type=response to avoid parsing error.
        self.ms_client.http_request(method="POST", url_suffix=cmd_url, params=params, resp_type='response')

    def list_locations(self):
        """
        Returns:
            dict: response body
        """
        cmd_url = "/providers/Microsoft.Security/locations"
        params = {"api-version": LOCATION_API_VERSION}
        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def update_atp(self, storage_account, setting_name, is_enabled):
        """
        Args:
            storage_account (str): Storange Account
            setting_name (str):  Setting Name
            is_enabled (str): true/false

        Returns:
            dict: respones body
        """
        cmd_url = f"/resourceGroups/{self.resource_group_name}/providers/Microsoft.Storage/storageAccounts/" \
                  f"{storage_account}/providers/Microsoft.Security/advancedThreatProtectionSettings/{setting_name}"
        params = {"api-version": ATP_API_VERSION}
        data = {
            "id": f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group_name}/providers/"
                  f"Microsoft.Storage/storageAccounts/{storage_account}/providers/Microsoft.Security/"
                  f"advancedThreatProtectionSettings/{setting_name}",
            "name": setting_name,
            "type": "Microsoft.Security/advancedThreatProtectionSettings",
            "properties": {"isEnabled": is_enabled},
        }

        #  Using resp_type=response to avoid parsing error.
        return self.ms_client.http_request(method="PUT", url_suffix=cmd_url, json_data=data, params=params)

    def get_atp(self, storage_account, setting_name):
        """
        Args:
            storage_account (str): Storange Account
            setting_name (str):  Setting Name

        Returns:

        """
        cmd_url = f"/resourceGroups/{self.resource_group_name}/providers/Microsoft.Storage/storageAccounts" \
                  f"/{storage_account}/providers/Microsoft.Security/advancedThreatProtectionSettings/{setting_name}"
        params = {"api-version": ATP_API_VERSION}
        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def update_aps(self, setting_name, auto_provision):
        """
        Args:
            setting_name (str): Setting name
            auto_provision (str): Auto provision setting (On/Off)

        Returns:
            dict: response body
        """
        cmd_url = f"/providers/Microsoft.Security/autoProvisioningSettings/{setting_name}"
        params = {"api-version": APS_API_VERSION}

        data = {"properties": {"autoProvision": auto_provision}}

        return self.ms_client.http_request(method="PUT", url_suffix=cmd_url, json_data=data, params=params)

    def list_aps(self):
        """
        Returns:
            dict: response body
        """
        cmd_url = "/providers/Microsoft.Security/autoProvisioningSettings"
        params = {"api-version": APS_API_VERSION}
        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def get_aps(self, setting_name):
        """
        Args:
            setting_name: Setting name

        Returns:
            dict: response body
        """
        cmd_url = f"/providers/Microsoft.Security/autoProvisioningSettings/{setting_name}"
        params = {"api-version": APS_API_VERSION}

        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def list_ipp(self, management_group=None):
        """
        Args:
            management_group: Managment group to pull (if needed)

        Returns:
            dict: response body

        """
        params = {"api-version": IPP_API_VERSION}
        cmd_url = "/providers/Microsoft.Security/informationProtectionPolicies"
        if management_group:
            full_url = f"{self.server}/providers/Microsoft.Management/managementGroups/{management_group}"
            full_url += cmd_url
            return self.ms_client.http_request(method="GET", full_url=full_url, url_suffix="", params=params)
        if not self.subscription_id:
            raise DemistoException("A subscription ID must be provided.")
        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def get_ipp(self, policy_name, management_group):
        """
        Args:
            policy_name (str): Policy name
            management_group (str): Managment group

        Returns:
            dict: respone body
        """
        params = {"api-version": IPP_API_VERSION}

        cmd_url = f"/providers/Microsoft.Security/informationProtectionPolicies/{policy_name}"
        if management_group:
            full_url = f"{self.server}/providers/Microsoft.Management/managementGroups/{management_group}"
            full_url += cmd_url
            return self.ms_client.http_request(method="GET", full_url=full_url, url_suffix="", params=params)
        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def list_jit(self, asc_location):
        """
        Args:
            asc_location: Machine location

        Returns:
            dict: response body
        """
        params = {"api-version": JIT_API_VERSION}
        cmd_url = f"/resourceGroups/{self.resource_group_name}" if self.resource_group_name else ""
        cmd_url += f"/providers/Microsoft.Security/locations/{asc_location}" if asc_location else ""
        cmd_url += "/providers/Microsoft.Security/jitNetworkAccessPolicies"
        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def get_jit(self, policy_name, asc_location, resource_group_name):
        """
        Args:
            policy_name: Policy name
            asc_location: Machine location
            resource_group_name: Resource name group

        Returns:
            dict: response body
        """
        cmd_url = f"/resourceGroups/{resource_group_name}/providers/Microsoft.Security/locations/{asc_location}/" \
                  f"jitNetworkAccessPolicies/{policy_name}"
        params = {"api-version": JIT_API_VERSION}

        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def initiate_jit(self, resource_group_name, asc_location, policy_name, vm_id, port, source_address, duration):
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
        cmd_url = f"/resourceGroups/{resource_group_name}/providers/Microsoft.Security/locations/{asc_location}/" \
                  f"jitNetworkAccessPolicies/{policy_name}/initiate"
        params = {"api-version": JIT_API_VERSION}

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
        # response code should be 202 Accepted
        return self.ms_client.http_request(method="POST", url_suffix=cmd_url, json_data=data, params=params,
                                           resp_type="response")

    def delete_jit(self, asc_location, resource_group_name, policy_name):
        """
        Args:
            asc_location: Machine location
            resource_group_name: Resource group name
            policy_name: Policy name
        """
        cmd_url = f"/resourceGroups/{resource_group_name}/providers/Microsoft.Security/locations/{asc_location}/" \
                  f"jitNetworkAccessPolicies/{policy_name}"

        params = {"api-version": JIT_API_VERSION}

        #  Using resp_type=text to avoid parsing error. response should be 204
        self.ms_client.http_request(method="DELETE", url_suffix=cmd_url, params=params, resp_type='text')

    def list_sc_storage(self):
        """
        Returns:
            dict: response body

        """
        cmd_url = "/providers/Microsoft.Storage/storageAccounts"
        params = {"api-version": STORAGE_API_VERSION}
        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def list_sc_subscriptions(self):
        """
        Returns:
            dict: response body

        """
        full_url = f"{self.server}/subscriptions"
        params = {"api-version": SUBSCRIPTION_API_VERSION}
        return self.ms_client.http_request(method="GET", full_url=full_url, url_suffix="", params=params)

    def get_secure_scores(self, secure_score_name):
        """
        Returns:
            dict: response body

        """

        cmd_url = f"/providers/Microsoft.Security/secureScores/{secure_score_name}"
        params = {"api-version": SECURE_STORES_API_VERSION}
        return self.ms_client.http_request(method="GET", url_suffix=cmd_url, params=params)

    def list_resource_groups(self, tag: str, limit: int, full_url: Optional[str] = None) -> dict:
        """
        List all resource groups.

        Args:
            tag str: Tag to filter by.
            limit (int): Maximum number of resource groups to retrieve. Default is 50.

        Returns:
            List[dict]: API response from Azure.
        """
        filter_by_tag = azure_tag_formatter(tag) if tag else None
        params = {"$filter": filter_by_tag, "$top": limit, "api-version": LIST_RESOURCE_GROUP_VERSION} if not full_url else {}
        return self.ms_client.http_request(method="GET", url_suffix="resourcegroups", params=params, full_url=full_url)


""" FUNCTIONS """

""" Alert Start """


def get_alert_command(client: MsClient, args: dict):
    """Getting specified alert from API
    Args
        args (dict): dictionary containing commands args
    """
    asc_location = args.get("asc_location")
    alert_id = args.get("alert_id")
    alert = client.get_alert(asc_location, alert_id)
    final_output = []

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
                "ID"],
            removeNull=True)

        ec = {"AzureSecurityCenter.Alert(val.ID && val.ID === obj.ID)": basic_table_output}

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
            extended_properties = {}
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
            if entities and isinstance(entities, dict):
                entities_table_output = []
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
    return final_output


def list_alerts_command(client: MsClient, args: dict):
    """Getting all alerts

    Args:
        client:
        args (dict): usually demisto.args()
    """
    asc_location = args.get("asc_location")
    filter_query = args.get("filter")
    select_query = args.get("select")
    expand_query = args.get("expand")

    alerts = client.list_alerts(
        asc_location, filter_query, select_query, expand_query
    ).get("value")
    outputs = []
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
    return md, ec, alerts


# There's a Microsoft API bug for reactivate alert -
# https://social.msdn.microsoft.com/Forums/windows/en-US/c2139e1b-b26c-4264-a558-fa4b180b70e7/issue-while-setting-security-alert-state-from-dismiss-to-active?forum=AzureSecurityCenter
def update_alert_command(client: MsClient, args: dict):
    """Update given alert

    Args:
        client: MsClient
        args (dict): usually demisto.args()
    """
    asc_location = args.get("asc_location")
    alert_id = args.get("alert_id")
    alert_update_action_type = args.get("alert_update_action_type")
    if alert_update_action_type == "in_progress":
        alert_update_action_type = "inProgress"
    client.update_alert(asc_location, alert_id, alert_update_action_type)
    outputs = {"ID": alert_id, "ActionTaken": alert_update_action_type}

    ec = {"AzureSecurityCenter.Alert(val.ID && val.ID === obj.ID)": outputs}
    return f"Alert - {alert_id} has been set to {alert_update_action_type}.", ec, None


""" Alert End """

""" Location Start """


def list_locations_command(client: MsClient):
    """Getting all locations
    """
    locations = client.list_locations().get("value")
    outputs = []
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
            return md, ec, locations
        return None
    else:
        return "No locations found", None, None


""" Location End """

""" Advanced Threat Protection Start """


def update_atp_command(client: MsClient, args: dict):
    """Updating given Advanced Threat Protection (enable/disable)

    Args:
        client:
        args (dict): usually demisto.args()
    """
    setting_name = args.get("setting_name")
    is_enabled = args.get("is_enabled")
    storage_account = args.get("storage_account")
    response = client.update_atp(storage_account, setting_name, is_enabled)
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
    return md, ec, response


def get_atp_command(client: MsClient, args: dict):
    """Get given Advanced Threat Protection settings

    Args:
        client:
        args (dict): usually demisto.args()
    """
    setting_name = args.get("setting_name")
    storage_account = args.get("storage_account")
    response = client.get_atp(storage_account, setting_name)
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
    return md, ec, response


""" Advanced Threat Protection End """

""" Auto Provisioning Settings Start """


def update_aps_command(client: MsClient, args: dict):
    """Updating Analytics Platform System

    Args:
        client:
        args (dict): usually demisto.args()
    """
    setting_name = args.get("setting_name")
    auto_provision = args.get("auto_provision")
    setting = client.update_aps(setting_name, auto_provision)
    outputs = [
        {
            "Name": setting.get("name"),
            "AutoProvision": setting["properties"]["auto_provision"]
            if setting.get("properties") and setting.get("properties").get("auto_provision")
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
    return md, ec, setting


def list_aps_command(client: MsClient):
    """List all Analytics Platform System

    """
    settings = client.list_aps().get("value")
    outputs = []
    for setting in settings:
        outputs.append(
            {
                "Name": setting.get("name"),
                "AutoProvision": setting.get("properties").get("autoProvision")
                if setting.get("properties") and setting.get("properties").get("autoProvision") else None,
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
    return md, ec, settings


def get_aps_command(client: MsClient, args: dict):
    """Get given Analytics Platform System setting

    Args:
        client:
        args (dict): usually demisto.args()
    """
    setting_name = args.get("setting_name")
    setting = client.get_aps(setting_name)
    outputs = [
        {
            "Name": setting.get("name"),
            "AutoProvision": setting.get("properties").get("autoProvision")
            if setting.get("properties") and setting.get("properties").get("autoProvision") else None,
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

    return md, ec, setting


""" Auto Provisioning Settings End """

""" Information Protection Policies Start """


# Unsupported command. issue: issues/24583
def list_ipp_command(client: MsClient, args: dict):
    """Listing all Internet Presence Provider

    Args:
        client:
        args (dict): usually demisto.args()
    """
    management_group = args.get("management_group")
    policies = client.list_ipp(management_group).get("value")
    outputs = []
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
                    if policy.get("properties") and policy.get("properties").get("informationTypes") else None,
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


# Unsupported command. issue: issues/24583
def get_ipp_command(client: MsClient, args: dict):
    """Getting Internet Presence Provider information
    Args:
        client:
        args (dict): usually demisto.args()
    """
    policy_name = args.get("policy_name")
    management_group = args.get("management_group")
    policy = client.get_ipp(policy_name, management_group)
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
        info_type_table_output = []
        for information_type_data in properties.get("informationTypes").values():
            keywords = ", ".join(
                [(str(keyword.get("displayName")) + str(keyword.get("custom")) + str(keyword.get("canBeNumeric")))
                 for keyword in information_type_data.get("keywords", [])])
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
        demisto.results(f"No properties found in {management_group}")


""" Information Protection Policies End """

""" Jit Network Access Policies Start """


def list_jit_command(client: MsClient, args: dict):
    """Lists all Just-in-time Virtual Machines

    Args:
        client:
        args (dict): usually demisto.args()
    """
    asc_location = args.get("asc_location")
    policies = client.list_jit(asc_location)["value"]
    outputs = []
    for policy in policies:
        # summarize rules in (VMName: allowPort,...) format
        if policy.get("properties") and policy.get("properties").get("virtualMachines"):
            rules_data = policy["properties"]["virtualMachines"]
            rules_summary_array = []
            for rule in rules_data:
                ID = rule.get("id")
                vm_name = ID.split("/")[-1] if isinstance(ID, str) else None
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
    return md, ec, policies


# Unsupported command. issue: issues/24583
def get_jit_command(client: MsClient, args: dict):
    """Getting given Just-in-time machine

    Args:
        client:
        args (dict): usually demisto.args()
    """
    policy_name = args.get("policy_name")
    asc_location = args.get("asc_location")
    resource_group_name = args.get("resource_group_name")
    policy = client.get_jit(policy_name, asc_location, resource_group_name)

    # Property table
    property_table_output = [
        {
            "Name": policy.get("name"),
            "Kind": policy.get("kind"),
            "ProvisioningState": policy.get("properties").get("provisioningState")
            if policy.get("properties") and policy.get("properties", {}).get("provisioningState") else None,
            "Location": policy.get("location"),
            "Rules": policy.get("properties").get("virtualMachines")
            if policy.get("properties") and policy.get("properties", {}).get("virtualMachines") else None,
            "Requests": policy.get("properties").get("requests")
            if policy.get("properties") and policy.get("properties", {}).get("requests")
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
    rules_table_output = []
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
        requests_table_output = []

        for requestData in properties.get("requests", []):
            vms = []
            for vm in requestData.get("virtualMachines"):
                vm_name = vm["id"].split("/")[-1]
                vm_ports = format_jit_port_request(vm.get("ports"))
                vms.append(f"[{vm_name}: {vm_ports}]")
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


# Unsupported command. issue: issues/24583
def initiate_jit_command(client: MsClient, args: dict):
    resource_group_name = args.get("resource_group_name")
    asc_location = args.get("asc_location")
    policy_name = args.get("policy_name")
    vm_id = args.get("vmID")
    port = args.get("port")
    source_address = args.get("source_address")
    duration = args.get("duration")
    response = client.initiate_jit(
        resource_group_name,
        asc_location,
        policy_name,
        vm_id,
        port,
        source_address,
        duration,
    )
    policy_id = f"/subscriptions/{client.subscription_id}/resourceGroups/{resource_group_name}/providers/" \
                f"Microsoft.Security/locations/{asc_location}/jitNetworkAccessPolicies/{policy_name}"
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
            f"== obj.{policy_id}).Initiate(val.endTimeUtc === obj.EndTimeUtc)": outputs
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


# Unsupported command. issue: issues/24583
def delete_jit_command(client: MsClient, args: dict):
    """Deletes a Just-in-time machine

    Args:
        client:
        args (dict): usually demisto.args()
    """
    asc_location = args.get("asc_location")
    resource_group_name = args.get("resource_group_name")
    policy_name = args.get("policy_name")
    client.delete_jit(asc_location, resource_group_name, policy_name)

    policy_id = f"/subscriptions/{client.subscription_id}/resourceGroups/{resource_group_name}/providers/" \
                f"Microsoft.Security/locations/{asc_location}/jitNetworkAccessPolicies/{policy_name}"

    outputs = {"ID": policy_id, "Action": "deleted"}

    ec = {"AzureSecurityCenter.JITPolicy(val.ID && val.ID === obj.ID)": outputs}
    demisto.results(
        {
            "Type": entryTypes["note"],
            "Contents": f"Policy - {policy_name} has been deleted sucessfully.",
            "ContentsFormat": formats["text"],
            "EntryContext": ec,
        }
    )


""" Jit Network Access Policies End """

""" Storage Start """


# Add this command to security center integration because ATP-related command requires storage account info
def list_sc_storage_command(client: MsClient):
    """Listing all Security Center Storages

    """
    accounts = client.list_sc_storage().get("value")
    outputs = []
    for account in accounts:
        account_id_array = account.get("id", "").split("/")
        resource_group_name = account_id_array[account_id_array.index("resourceGroups") + 1]
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

    return md, ec, accounts


""" Storage End """

""" Subscriptions Start """


def list_sc_subscriptions_command(client: MsClient):
    """Listing Subscriptions for this application

    """
    subscriptions = client.list_sc_subscriptions().get("value")
    outputs = []
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

    return md, ec, subscriptions


""" Subscriptions end """

""" Secure Score Start"""


def get_secure_scores_command(client: MsClient, args: dict):

    secure_score_name = args.get("secure_score_name", "ascScore")

    securescore = client.get_secure_scores(secure_score_name)

    md = tableToMarkdown(
        "Azure Security Center - Secure Score",
        securescore['properties']
    )

    ec = {"Azure.Securescore(val.ID && val.ID === obj.ID)": securescore['properties']}

    return md, ec, securescore


""" Secure Scores End"""


def list_resource_groups_command(client: MsClient, args: dict[str, Any]) -> CommandResults:
    """
    List all resource groups in the subscription.

    Args:
        client (KeyVaultClient):  Azure Key Vault API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        CommandResults: Command results with raw response, outputs and readable outputs.

    """
    tag = args.get('tag', '')
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT

    raw_responses = []
    resource_groups: List[dict] = []

    next_link: bool | str = True
    while next_link and len(resource_groups) < limit:
        full_url = next_link if isinstance(next_link, str) else None
        response = client.list_resource_groups(tag=tag, limit=limit, full_url=full_url)
        value = response.get('value', [])
        next_link = response.get('nextLink', '')

        raw_responses.extend(value)
        for resource_group in value:
            resource_group_context = {
                'Name': resource_group.get('name'),
                'Location': resource_group.get('location'),
                'Tags': resource_group.get('tags'),
                'Provisioning State': resource_group.get('properties', {}).get('provisioningState')
            }
            resource_groups.append(resource_group_context)

    raw_responses = raw_responses[:limit]
    resource_groups = resource_groups[:limit]
    readable_output = tableToMarkdown('Resource Groups List', resource_groups, removeNull=True)

    return CommandResults(
        outputs_prefix='Azure.ResourceGroupName',
        outputs_key_field='id',
        outputs=raw_responses,
        raw_response=raw_responses,
        readable_output=readable_output,
    )


def test_module(client: MsClient):
    """
       Performs basic GET request to check if the API is reachable and authentication is successful.
       Returns ok if successful.
       """
    if client.subscription_id:
        client.list_locations()
    else:
        client.list_sc_subscriptions()
    demisto.results('ok')


def main():
    params: dict = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        server = params.get('server_url', '').rstrip('/') + '/'
        tenant = params.get('credentials_tenant_id', {}).get('password') or params.get('tenant_id')
        auth_and_token_url = params.get('credentials_auth_id', {}).get('password') or params.get('auth_id', '')
        if not auth_and_token_url:
            raise DemistoException('ID must be provided.')
        enc_key = params.get('credentials_enc_key', {}).get('password') or params.get('enc_key')
        use_ssl = not params.get('unsecure', False)
        proxy = params.get('proxy', False)
        subscription_id = args.get("subscription_id") or params.get(
            'credentials_default_sub_id', {}).get('password') or params.get("default_sub_id")
        resource_group_name = args.get("resource_group_name") or params.get('resource_group_name')
        ok_codes = (200, 201, 202, 204)
        certificate_thumbprint = params.get('credentials_certificate_thumbprint', {}).get(
            'password') or params.get('certificate_thumbprint')
        private_key = params.get('private_key')
        managed_identities_client_id = get_azure_managed_identities_client_id(params)
        self_deployed: bool = params.get('self_deployed', False) or managed_identities_client_id is not None

        if not managed_identities_client_id:
            if not (tenant and auth_and_token_url):
                raise DemistoException('Token and ID must be provided. For further information see '
                                       'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')

            if not self_deployed and not enc_key:
                raise DemistoException('Key must be provided. For further information see '
                                       'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
            elif not enc_key and not (certificate_thumbprint and private_key):
                raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.'
                                       'For further information see '
                                       'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')

        if command in SUB_ID_REQUIRING_CMD and not subscription_id:
            raise DemistoException("A subscription ID must be provided.")
        if command in RESOURCE_GROUP_REQUIRING_CMD and not resource_group_name:
            raise DemistoException("A Resource Group Name must be provided.")
        client = MsClient(tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key, app_name=APP_NAME, proxy=proxy,
                          server=server, verify=use_ssl, self_deployed=self_deployed, subscription_id=subscription_id,
                          ok_codes=ok_codes, certificate_thumbprint=certificate_thumbprint, private_key=private_key,
                          resource_group_name=resource_group_name, managed_identities_client_id=managed_identities_client_id)

        if command == "test-module":
            # If the command will fail, error will be thrown from the request itself
            test_module(client)
        elif command == "azure-sc-get-alert":
            return_results(get_alert_command(client, args))
        elif command == "azure-sc-list-alert":
            return_outputs(*list_alerts_command(client, args))
        elif command == "azure-sc-update-alert":
            return_outputs(*update_alert_command(client, args))
        elif command == "azure-sc-list-location":
            return_outputs(*list_locations_command(client))
        elif command == "azure-sc-update-atp":
            return_outputs(*update_atp_command(client, args))
        elif command == "azure-sc-get-atp":
            return_outputs(*get_atp_command(client, args))
        elif command == "azure-sc-update-aps":
            return_outputs(*update_aps_command(client, args))
        elif command == "azure-sc-list-aps":
            return_outputs(*list_aps_command(client))
        elif command == "azure-sc-get-aps":
            return_outputs(*get_aps_command(client, args))
        elif command == "azure-sc-list-ipp":
            list_ipp_command(client, args)
        elif command == "azure-sc-get-ipp":
            get_ipp_command(client, args)
        elif command == "azure-sc-list-jit":
            return_outputs(*list_jit_command(client, args))
        elif command == "azure-sc-get-jit":
            get_jit_command(client, args)
        elif command == "azure-sc-initiate-jit":
            initiate_jit_command(client, args)
        elif command == "azure-sc-delete-jit":
            delete_jit_command(client, args)
        elif command == "azure-sc-list-storage":
            return_outputs(*list_sc_storage_command(client))
        elif command == "azure-list-subscriptions":
            return_outputs(*list_sc_subscriptions_command(client))
        elif command == "azure-get-secure-score":
            return_outputs(*get_secure_scores_command(client, args))
        elif command == "azure-resource-group-list":
            return_results(list_resource_groups_command(client, args))
        elif command == "azure-sc-auth-reset":
            return_results(reset_auth())
    except Exception as err:
        return_error(
            f'Failed to execute {command} command. Error: {str(err)}'
        )


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
