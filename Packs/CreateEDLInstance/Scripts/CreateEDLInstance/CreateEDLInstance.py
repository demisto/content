import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import random

edl_instance_name = demisto.args().get('InstanceName')
edl_port_list_name = demisto.args().get('PortListName')
edl_query = demisto.args().get('Query')

try:
    existing_port_list = demisto.executeCommand('getList', {'listName': edl_port_list_name})[0].get('Contents').split(',')
except Exception as e:
    return_error(e)


def generate_random_port():
    return random.randint(3000, 50000)


# create initial random port
random_port = generate_random_port()

# keep generating a random port until one is found
# which is not in existing port list
i = 0
while str(random_port) in existing_port_list:
    random_port = generate_random_port()
    i += 1
    if i > 30:
        return_error("Looks like there are no more free ports!")

existing_port_list.append(str(random_port))

# Add new port to existing port list
try:
    new_list = demisto.executeCommand('setList', {'listName': edl_port_list_name, 'listData': ",".join(existing_port_list)})
except Exception as e:
    return_error(e)

body = {
    "name": edl_instance_name,
    "id": "",
    "engine": "",
    "engineGroup": "",
    "defaultIgnore": False,
    "configuration": {
        "sortValues": None,
        "display": "Palo Alto Networks PAN-OS EDL Service",
        "canGetSamples": True,
        "itemVersion": "2.1.5",
        "brand": "",
        "modified": "2021-12-06T19:38:01.956979888Z",
        "shouldCommit": False,
        "hidden": False,
        "fromServerVersion": "5.5.0",
        "propagationLabels": [],
        "name": "EDL",
        "vcShouldKeepItemLegacyProdMachine": False,
        "system": True,
        "commitMessage": "",
        "vcShouldIgnore": False,
        "packPropagationLabels": [
            "all"
        ],
        "packID": "EDL",
        "configuration": [
            {
                "hiddenUsername": False,
                "display": "Indicator Query",
                "hiddenPassword": False,
                "hidden": False,
                "name": "indicators_query",
                "info": "The query to run to update the EDL. To view expected results, you can run the following command"
                        " from the Cortex XSOAR CLI `!findIndicators query=<your query>`",
                "defaultValue": "",
                "type": 0,
                "displayPassword": "",
                "options": None,
                "required": False,
                "value": edl_query,
                "hasvalue": True
            },
            {
                "hiddenUsername": False,
                "display": "EDL Size",
                "hiddenPassword": False,
                "hidden": False,
                "name": "edl_size",
                "info": "Maximum number of items in the EDL",
                "defaultValue": "2500",
                "type": 0,
                "displayPassword": "",
                "options": None,
                "required": True,
                "value": "2500",
                "hasvalue": True
            },
            {
                "hiddenUsername": False,
                "display": "Update EDL On Demand Only",
                "hiddenPassword": False,
                "hidden": False,
                "name": "on_demand",
                "info": "Enabling this will prevent automatic EDL refresh",
                "defaultValue": "",
                "type": 8,
                "displayPassword": "",
                "options": None,
                "required": False
            },
            {
                "hiddenUsername": False,
                "display": "Refresh Rate",
                "hiddenPassword": False,
                "hidden": False,
                "name": "cache_refresh_rate",
                "info": "How often to refresh the EDL (e.g., 5 minutes, 12 hours, 7 days, 3 months, 1 year)."
                        " For performance reasons, we do not recommend setting this value to less than 1 minute.",
                "defaultValue": "5 minutes",
                "type": 0,
                "displayPassword": "",
                "options": None,
                "required": False,
                "value": "5 minutes",
                "hasvalue": True
            },
            {
                "hiddenUsername": False,
                "display": "Long Running Instance",
                "hiddenPassword": False,
                "hidden": True,
                "name": "longRunning",
                "info": "",
                "defaultValue": "true",
                "type": 8,
                "displayPassword": "",
                "options": None,
                "required": False,
                "value": "true",
                "hasvalue": True
            },
            {
                "hiddenUsername": False,
                "display": "Listen Port",
                "hiddenPassword": False,
                "hidden": False,
                "name": "longRunningPort",
                "info": "Will run the EDL service on this port from within Cortex XSOAR. Requires a unique port for"
                        " each long-running integration instance. Do not use the same port for multiple instances.",
                "defaultValue": "",
                "type": 0,
                "displayPassword": "",
                "options": None,
                "required": True,
                "value": str(random_port),
                "hasvalue": True
            },
            {
                "hiddenUsername": False,
                "display": "Certificate (Required for HTTPS)",
                "hiddenPassword": False,
                "hidden": False,
                "name": "certificate",
                "info": "",
                "defaultValue": "",
                "type": 12,
                "displayPassword": "",
                "options": None,
                "required": False
            },
            {
                "hiddenUsername": False,
                "display": "Private Key (Required for HTTPS)",
                "hiddenPassword": False,
                "hidden": False,
                "name": "key",
                "info": "",
                "defaultValue": "",
                "type": 14,
                "displayPassword": "",
                "options": None,
                "required": False
            },
            {
                "hiddenUsername": False,
                "display": "Username",
                "hiddenPassword": False,
                "hidden": False,
                "name": "credentials",
                "info": "Uses basic authentication for accessing the EDL. If empty, no authentication is enforced.",
                "defaultValue": "",
                "type": 9,
                "displayPassword": "",
                "options": None,
                "required": False
            },
            {
                "hiddenUsername": False,
                "display": "Strip Ports from URLs",
                "hiddenPassword": False,
                "hidden": False,
                "name": "url_port_stripping",
                "info": "If selected, a URL that includes a port number will be reformatted to remove the port."
                        " For example, 'www.example.com:9999/path' would become 'www.example.com/path'.",
                "defaultValue": "true",
                "type": 8,
                "displayPassword": "",
                "options": None,
                "required": False,
                "value": "true",
                "hasvalue": True
            },
            {
                "hiddenUsername": False,
                "display": "PAN-OS URL Drop Invalid Entries",
                "hiddenPassword": False,
                "hidden": False,
                "name": "drop_invalids",
                "info": "If selected, any URL entry that is not compliant with PAN-OS EDL URL format is dropped instead"
                        " of being rewritten.",
                "defaultValue": "",
                "type": 8,
                "displayPassword": "",
                "options": None,
                "required": False
            },
            {
                "hiddenUsername": False,
                "display": "Add Comment To Empty EDL",
                "hiddenPassword": False,
                "hidden": False,
                "name": "add_comment_if_empty",
                "info": "If selected, add to an empty EDL the comment \"# Empty EDL\".",
                "defaultValue": "true",
                "type": 8,
                "displayPassword": "",
                "options": None,
                "required": False,
                "value": "true",
                "hasvalue": True
            },
            {
                "hiddenUsername": False,
                "display": "Should Collapse IPs:",
                "hiddenPassword": False,
                "hidden": False,
                "name": "collapse_ips",
                "info": "",
                "defaultValue": "Don't Collapse",
                "type": 15,
                "displayPassword": "",
                "options": [
                    "Don't Collapse",
                    "To CIDRS",
                    "To Ranges"
                ],
                "required": False,
                "value": "Don't Collapse",
                "hasvalue": True
            },
            {
                "hiddenUsername": False,
                "display": "XSOAR Indicator Page Size",
                "hiddenPassword": False,
                "hidden": False,
                "name": "page_size",
                "info": "Internal page size used when querying Cortex XSOAR for the EDL."
                        " By default, this value shouldn't be changed.",
                "defaultValue": "2000",
                "type": 0,
                "displayPassword": "",
                "options": None,
                "required": False,
                "value": "2000",
                "hasvalue": True
            },
            {
                "hiddenUsername": False,
                "display": "NGINX Global Directives",
                "hiddenPassword": False,
                "hidden": False,
                "name": "nginx_global_directives",
                "info": "NGINX global directives to be passed on the command line using the -g option."
                        " Each directive should end with `;`. For example: `worker_processes 4; timer_resolution 100ms;`"
                        ". Advanced configuration to be used only if instructed by Cortex XSOAR Support.",
                "defaultValue": "",
                "type": 0,
                "displayPassword": "",
                "options": None,
                "required": False
            },
            {
                "hiddenUsername": False,
                "display": "NGINX Server Conf",
                "hiddenPassword": False,
                "hidden": False,
                "name": "nginx_server_conf",
                "info": "NGINX server configuration. To be used instead of the default NGINX_SERVER_CONF used"
                        " in the integration code. Advanced configuration to be used only if instructed by Cortex"
                        " XSOAR Support.",
                "defaultValue": "",
                "type": 12,
                "displayPassword": "",
                "options": None,
                "required": False
            },
            {
                "hiddenUsername": False,
                "display": "Advanced: Use Legacy Queries",
                "hiddenPassword": False,
                "hidden": False,
                "name": "use_legacy_query",
                "info": "Legacy Queries: When enabled, the integration will query the Server using full queries."
                        " Enable this query mode, if you've been instructed by Support,"
                        " or you've encountered in the log errors of the form: msgpack: invalid code.",
                "defaultValue": "",
                "type": 8,
                "displayPassword": "",
                "options": None,
                "required": False
            },
            {
                "hiddenUsername": False,
                "display": "Incident type",
                "hiddenPassword": False,
                "hidden": False,
                "name": "incidentType",
                "info": "",
                "defaultValue": "",
                "type": 13,
                "displayPassword": "",
                "options": None,
                "required": False
            }
        ],
        "version": 1,
        "icon": "",
        "toServerVersion": "",
        "id": "EDL",
        "description": "This integration provides External Dynamic List (EDL) as a service for"
                       " the system indicators (Outbound feed).",
        "category": "Data Enrichment & Threat Intelligence",
        "prevName": "EDL",
        "integrationScript": {
            "resetContext": False,
            "isRemoteSyncOut": False,
            "longRunning": True,
            "commands": [
                {
                    "timeout": 0,
                    "important": None,
                    "polling": False,
                    "indicatorAction": False,
                    "docsHidden": False,
                    "cartesian": False,
                    "hidden": False,
                    "name": "edl-update",
                    "outputs": None,
                    "deprecated": False,
                    "arguments": [
                        {
                            "default": False,
                            "deprecated": False,
                            "description": "The query used to retrieve indicators from the system.",
                            "name": "query",
                            "required": True,
                            "secret": False
                        },
                        {
                            "default": False,
                            "deprecated": False,
                            "description": "The maximum number of entries in the EDL. If no value is provided,"
                                           " will use the value specified in the \"EDL Size\" parameter configured"
                                           " in the instance configuration.",
                            "name": "edl_size",
                            "required": False,
                            "secret": False
                        },
                        {
                            "default": False,
                            "predefined": [
                                "False",
                                "True"
                            ],
                            "name": "drop_invalids",
                            "auto": "PREDEFINED",
                            "secret": False,
                            "defaultValue": "false",
                            "deprecated": False,
                            "description": "If True, any URL entry that is not compliant with PAN-OS EDL URL"
                                           " format is dropped instead of being rewritten.",
                            "required": False
                        },
                        {
                            "default": False,
                            "predefined": [
                                "False",
                                "True"
                            ],
                            "name": "url_port_stripping",
                            "auto": "PREDEFINED",
                            "secret": False,
                            "defaultValue": "false",
                            "deprecated": False,
                            "description": "If set to True, a URL that includes a port number will be reformatted to"
                                           " remove the port. For example, 'www.example.com:9999/path' would become"
                                           " 'www.example.com/path'.",
                            "required": False
                        },
                        {
                            "default": False,
                            "predefined": [
                                "False",
                                "True"
                            ],
                            "name": "add_comment_if_empty",
                            "auto": "PREDEFINED",
                            "secret": False,
                            "defaultValue": "false",
                            "deprecated": False,
                            "description": "If selected, add to an empty EDL the comment \"# Empty EDL\".",
                            "required": False
                        },
                        {
                            "default": False,
                            "predefined": [
                                "Don't Collapse",
                                "To CIDRS",
                                "To Ranges"
                            ],
                            "name": "collapse_ips",
                            "auto": "PREDEFINED",
                            "secret": False,
                            "defaultValue": "Don't Collapse",
                            "deprecated": False,
                            "description": "Whether to collapse IPs to ranges or CIDRs.",
                            "required": False
                        },
                        {
                            "default": False,
                            "defaultValue": "0",
                            "deprecated": False,
                            "description": "The starting entry index from which to export the indicators.",
                            "name": "offset",
                            "required": False,
                            "secret": False
                        }
                    ],
                    "sensitive": False,
                    "permitted": False,
                    "execution": False,
                    "description": "Updates values stored in the EDL (only available On-Demand)."
                }
            ],
            "longRunningPortMapping": True,
            "isFetchCredentials": False,
            "runOnce": False,
            "isRemoteSyncIn": False,
            "isFetch": False,
            "isMappable": False,
            "isFetchSamples": False,
            "subtype": "python3",
            "type": "python",
            "dockerImage": "demisto/flask-nginx:1.0.0.23674",
            "feed": False
        },
        "instances": []
    },
    "enabled": "true",
    "propagationLabels": [
        "all"
    ],
    "data": [
        {
            "name": "indicators_query",
            "value": edl_query,
            "hasvalue": True,
            "type": 0,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "edl_size",
            "value": "2500",
            "hasvalue": True,
            "type": 0,
            "defaultValue": "",
            "required": True,
            "options": None
        },
        {
            "name": "on_demand",
            "type": 8,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "cache_refresh_rate",
            "value": "5 minutes",
            "hasvalue": True,
            "type": 0,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "longRunning",
            "value": "true",
            "hasvalue": True,
            "type": 8,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "longRunningPort",
            "value": str(random_port),
            "hasvalue": True,
            "type": 0,
            "defaultValue": "",
            "required": True,
            "options": None
        },
        {
            "name": "certificate",
            "type": 12,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "key",
            "type": 14,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "credentials",
            "type": 9,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "url_port_stripping",
            "value": "true",
            "hasvalue": True,
            "type": 8,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "drop_invalids",
            "type": 8,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "add_comment_if_empty",
            "value": "true",
            "hasvalue": True,
            "type": 8,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "collapse_ips",
            "value": "Don't Collapse",
            "hasvalue": True,
            "type": 15,
            "defaultValue": "",
            "required": False,
            "options": [
                "Don't Collapse",
                "To CIDRS",
                "To Ranges"
            ]
        },
        {
            "name": "page_size",
            "value": "2000",
            "hasvalue": True,
            "type": 0,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "nginx_global_directives",
            "type": 0,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "nginx_server_conf",
            "type": 12,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "use_legacy_query",
            "type": 8,
            "defaultValue": "",
            "required": False,
            "options": None
        },
        {
            "name": "incidentType",
            "type": 13,
            "defaultValue": "",
            "required": False,
            "options": None
        }
    ],
    "brand": "EDL",
    "canSample": True,
    "category": "Data Enrichment & Threat Intelligence",
    "version": 0,
    "isIntegrationScript": True,
    "isLongRunning": True,
    "passwordProtected": False,
    "mappingId": "",
    "incomingMapperId": "",
    "outgoingMapperId": "",
    "resetContext": False,
    "integrationLogLevel": ""
}


def main():
    # Create EDL instance
    parameters = {'uri': '/settings/integration', 'body': body}

    try:
        results = demisto.executeCommand('demisto-api-put', parameters)
    except Exception as e:
        return_error(e)

    readable_output = f"EDL: {edl_instance_name} created on port: {random_port}"
    return_results(CommandResults(readable_output=readable_output, raw_response=results))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
