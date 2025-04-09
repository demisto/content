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
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
PREFIX_URL = "https://management.azure.com/subscriptions/"
GRANT_BY_CONNECTION = {
    "Device Code": DEVICE_CODE,
    "Authorization Code": AUTHORIZATION_CODE,
    "Client Credentials": CLIENT_CREDENTIALS,
}
SCOPE_BY_CONNECTION = {
    "Device Code": "https://management.azure.com/user_impersonation offline_access user.read",
    "Authorization Code": "https://management.azure.com/.default",
    "Client Credentials": "https://management.azure.com/.default",
}

""" CLIENT CLASS """


class AzureNSGClient:
    @logger
    def __init__(
        self,
        app_id,
        subscription_id,
        resource_group_name,
        verify,
        proxy,
        connection_type: str,
        azure_ad_endpoint="https://login.microsoftonline.com",
        tenant_id: str = None,
        enc_key: str = None,
        auth_code: str = None,
        redirect_uri: str = None,
        managed_identities_client_id=None,
    ):
        if "@" in app_id:
            app_id, refresh_token = app_id.split("@")
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)
        base_url = (
            f"{PREFIX_URL}{subscription_id}/"
            f"resourceGroups/{resource_group_name}/providers/Microsoft.Network/networkSecurityGroups"
        )
        client_args = assign_params(
            self_deployed=True,  # We always set the self_deployed key as True because when not using a self
            # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
            # flow and most of the same arguments should be set, as we're !not! using OProxy.
            auth_id=app_id,
            token_retrieval_url="https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
            if "Device Code" in connection_type
            else None,
            grant_type=GRANT_BY_CONNECTION.get(connection_type),  # disable-secrets-detection
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            resource="https://management.core.windows.net"
            if "Device Code" in connection_type
            else None,  # disable-secrets-detection
            scope=SCOPE_BY_CONNECTION.get(connection_type),
            ok_codes=(200, 201, 202, 204),
            azure_ad_endpoint=azure_ad_endpoint,
            tenant_id=tenant_id,
            enc_key=enc_key,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure,
            command_prefix="azure-nsg",
        )
        self.ms_client = MicrosoftClient(**client_args)
        self.connection_type = connection_type

    @logger
    def http_request(
        self,
        method: str,
        url_suffix: str = None,
        full_url: str = None,
        params: dict = None,
        data: dict = None,
        resp_type: str = "json",
    ) -> requests.Response:
        params = params or {}
        if not params.get("api-version"):
            params["api-version"] = API_VERSION
        return self.ms_client.http_request(
            method=method, url_suffix=url_suffix, full_url=full_url, json_data=data, params=params, resp_type=resp_type
        )

    @logger
    def create_rule(self, security_group: str, rule_name: str, properties: dict, subscription_id: str, resource_group_name: str):
        return self.http_request(
            "PUT",
            full_url=f"{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}\
/providers/Microsoft.Network/networkSecurityGroups/{security_group}/securityRules/{rule_name}?",
            data={"properties": properties},
        )

    @logger
    def get_rule(self, security_group: str, rule_name: str, subscription_id: str, resource_group_name: str):
        try:
            return self.http_request(
                "GET",
                full_url=f"{PREFIX_URL}{subscription_id}/\
resourceGroups/{resource_group_name}/providers/Microsoft.Network/\
networkSecurityGroups/{security_group}/securityRules/{rule_name}?",
            )
        except Exception as e:
            if "404" in str(e):
                raise ValueError(f'Rule {rule_name} under subscription ID "{subscription_id}" \
and resource group "{resource_group_name}" was not found.')
            raise


""" HELPER FUNCTIONS """
def format_rule(rule_json: dict | list, security_rule_name: str):
    """
    format the rule and create the commandResult object with it
    Args:
        rule_json: the json returned from the http_request
        security_rule_name: the name of the rule

    Returns:
        CommandResults for the rule
    """
    # We want to flatten the rules `properties` key as this is the more important key and we'd like
    # to be able to display it nicely
    if isinstance(rule_json, dict):
        rule_json.update(rule_json.pop("properties", {}))
    if isinstance(rule_json, list):
        for rule in rule_json:
            rule.update(rule.pop("properties", {}))

    hr = tableToMarkdown(f"Rules {security_rule_name}", rule_json, removeNull=True)

    return CommandResults(outputs_prefix="AzureNSG.Rule", outputs_key_field="id", outputs=rule_json, readable_output=hr)

def get_from_args_or_params(args: dict[str, Any], params: dict[str, Any], key: str) -> Any:
    """
    Get a value from args or params, if the value is provided in both args and params, the value from args will be used.
    if the value is not provided in args or params, an exception will be raised.
    this function is used in commands that have a value that can be provided in the instance parameters or in the command,
    e.g in azure-key-vault-delete 'subscription_id' can be provided in the instance parameters or in the command.
    Args:
        args (Dict[str, Any]): Demisto args.
        params (Dict[str, Any]): Demisto params
        key (str): Key to get.
    """
    if value := args.get(key, params.get(key)):
        return value
    else:
        raise Exception(f'No {key} was provided. Please provide a {key} either in the \
instance configuration or as a command argument.')

""" COMMAND FUNCTIONS """

@logger
def update_rule_command(client: AzureNSGClient, params: Dict, args: Dict) -> CommandResults:
    """
    Update an existing rule.

    As I couldn't find a way to just update specific fields, the command gets the existing rule, then updates
    the wanted fields and sends that as a "new" rule. This will update the rule and not create a new rule.

    Args:
        client: The MS Client
        params: configuration parameters
        args: args dictionary.

    Returns:
    an updated rule
    """
    security_group_name = args.get("security_group_name", "")
    security_rule_name = args.get("security_rule_name", "")
    direction = args.get("direction", "")
    action = args.get("action", "")
    protocol = args.get("protocol", "")
    source = args.get("source", "")
    source_ports = args.get("source_ports", "")
    destination = args.get("destination", "")
    destination_ports = args.get("destination_ports", "")
    priority = args.get("priority", "")
    description = args.get("description", "")
    # subscription_id and resource_group_name can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key="subscription_id")
    resource_group_name = get_from_args_or_params(params=params, args=args, key="resource_group_name")

    rule = client.get_rule(
        security_group=security_group_name,
        rule_name=security_rule_name,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )
    properties = rule.get("properties")

    updated_properties = assign_params(
        protocol="*" if protocol == "Any" else protocol,
        access=action,
        priority=priority,
        direction=direction,
        description=description,
    )
    if source_ports:
        source_ports_list = argToList(source_ports)
        if len(source_ports_list) > 1:
            properties.pop("sourcePortRange", None)  # Can't supply both sourcePortRange and sourcePortRanges
            updated_properties["sourcePortRanges"] = source_ports_list
        else:
            properties.pop("sourcePortRanges", None)  # Can't supply both sourcePortRange and sourcePortRanges
            updated_properties["sourcePortRange"] = source_ports

    if destination_ports:
        dest_ports_list = argToList(destination_ports)
        if len(dest_ports_list) > 1:
            properties.pop("destinationPortRange", None)  # Can't supply both destinationPortRange,destinationPortRanges
            updated_properties["destinationPortRanges"] = dest_ports_list
        else:
            properties.pop("destinationPortRanges", None)  # Can't supply destinationPortRange and destinationPortRanges
            updated_properties["destinationPortRange"] = destination_ports

    if destination:
        dest_list = argToList(destination)
        if len(dest_list) > 1:
            properties.pop("destinationAddressPrefix", None)  # Can't supply both destinationAddressPrefix and
            # destinationAddressPrefix
            updated_properties["destinationAddressPrefixes"] = dest_list
        else:
            properties.pop("destinationAddressPrefixes", None)  # Can't supply both
            # destinationAddressPrefixes, destinationAddressPrefixes
            updated_properties["destinationAddressPrefix"] = "*" if destination == "Any" else destination

    if source:
        source_list = argToList(source)
        if len(source_list) > 1:
            properties.pop("sourceAddressPrefix", None)  # Can't supply both sourceAddressPrefixes, sourceAddressPrefix
            updated_properties["sourceAddressPrefixes"] = source_list
        else:
            properties.pop("sourceAddressPrefixes", None)  # Can't supply both sourceAddressPrefixes,sourceAddressPrefix
            updated_properties["sourceAddressPrefix"] = "*" if source == "Any" else source

    properties.update(updated_properties)

    rule = client.create_rule(
        security_group=security_group_name,
        rule_name=security_rule_name,
        properties=properties,
        subscription_id=subscription_id,
        resource_group_name=resource_group_name,
    )

    return format_rule(rule, security_rule_name)





def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f"Command being called is {command}")
    try:
        client = AzureNSGClient(
            app_id=params.get("app_id", ""),
            subscription_id=params.get("subscription_id", ""),
            resource_group_name=params.get("resource_group_name", ""),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            connection_type=params.get("auth_type", "Device Code"),
            azure_ad_endpoint=params.get("azure_ad_endpoint", "https://login.microsoftonline.com")
            or "https://login.microsoftonline.com",
            tenant_id=params.get("tenant_id"),
            enc_key=params.get("credentials", {}).get("password", ""),
            auth_code=(params.get("auth_code", {})).get("password"),
            redirect_uri=params.get("redirect_uri"),
            managed_identities_client_id=get_azure_managed_identities_client_id(params),
        )
        commands_with_params_and_args = {
            "azure-nsg-security-rule-update": update_rule_command
        }
       
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
        elif command in commands_with_params_and_args:
            return_results(commands_with_params_and_args[command](client=client, params=params, args=args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented")
        return_results(
            result
        )  # Returns either str, CommandResults and a list of CommandResults
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
