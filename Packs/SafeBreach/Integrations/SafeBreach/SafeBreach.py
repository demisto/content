from CommonServerPython import *

import demistomock as demisto
from copy import deepcopy
import json
import re
from ast import literal_eval
from typing import Any
from collections.abc import Iterable

DATE_FORMAT = "%Y-%m-%d %H:%M:%S UTC"  # ISO8601 format with UTC, default in XSOAR

CATEGORY_MAPPER = {
    "Network Access": [1, 2, 3, 4, 19, 20, 21, 22],
    "Network Inspection": [7, 10, 11, 12, 18],
    "Endpoint": [8, 9, 13, 14, 17],
    "Email": [15, 24],
    "Web": [5, 6],
    "Data Leak": [16],
}

INSIGHT_DATA_TYPE_MAPPER = {
    1: "Port",
    2: "Protocol",
    3: "Port",
    4: "Port",
    5: "Domain",
    6: "URI",
    7: "Hash",
    9: "Hash",
    10: "Protocol",
    14: "Command",
    15: "Hash",
    17: "CVE",  # Not Supported Yet.
    18: "CVE",  # Not Supported Yet.
    19: "Port",
    20: "Protocol",
    21: "Port",
    22: "Port",
    24: "Hash",
}

SAFE_BREACH_TYPES = [
    "Protocol",
    "FQDN/IP",
    "Port",
    "URI",
    "SHA256",
    "Attack",
    "Proxies",
    "Impersonated User",
    "Commands",
    "Drop Path",
    "Registry Path",
    "Outbound",
    "Inbound",
    "Server Header",
    "Client Header",
]

# mapper from SB data type to demisto data type that given when the integration was configured.
INDICATOR_TYPE_SB_TO_DEMISTO_MAPPER = {
    "SHA256": "Hash",
    "Port": "Port",
    "FQDN/IP": "Domain",
    "Command": "Command",
    "Protocol": "Protocol",
    "URI": "URI",
}

INDICATOR_TYPE_MAPPER = {
    "FQDN/IP": FeedIndicatorType.Domain,
    "SHA256": FeedIndicatorType.File,
    "Domain": FeedIndicatorType.Domain,
    "Port": "SafeBreach Port",
    "Protocol": "SafeBreach Protocol",
    "Process": "SafeBreach Process",
    "Registry": "SafeBreach Registry",
    "Command": "SafeBreach Command",
    "URI": FeedIndicatorType.URL,
    "IP": FeedIndicatorType.IP,
}

DEMISTO_INDICATOR_REPUTATION = {"None": 0, "Good": 1, "Suspicious": 2, "Bad": 3}

IP_REGEX = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

simulator_details_inputs = [
    InputArgument(
        name="hostname", description="if hostname to be included for search.", required=False, is_array=False
    ),
    InputArgument(
        name="external_ip",
        description="if external IP details to be included for search.",
        required=False,
        is_array=False,
    ),
    InputArgument(
        name="internal_ip", description="if Internal IP are to be included for search.", required=False, is_array=False
    ),
    InputArgument(
        name="os",
        description="operating system name to filter with, Eg: LINUX,WINDOWS etc, incase nothing "
        + "is selected then this will be set as empty which means all are retrieved",
        options=["", "LINUX", "MAC", "WINDOWS"],
        default="",
        required=False,
        is_array=False,
    ),
    InputArgument(
        name="is_enabled",
        description="if to search only enabled ones.",
        options=["true", "false"],
        required=False,
        is_array=False,
    ),
    InputArgument(
        name="is_connected",
        description="status of connection of simulators to search.",
        options=["true", "false"],
        required=False,
        is_array=False,
    ),
    InputArgument(
        name="is_critical",
        description="whether to search only for critical simulators or not.",
        options=["true", "false"],
        required=False,
        is_array=False,
    ),
    InputArgument(
        name="additional_details",
        description="Whether to show additional details or not.",
        options=["true", "false"],
        required=False,
        is_array=False,
    ),
    InputArgument(
        name="status",
        description="if simulator status are to be included for search.",
        options=["APPROVED", "PENDING", "ALL"],
        default="ALL",
        required=False,
        is_array=False,
    ),
]

simulators_output_fields = [
    OutputArgument(name="is_enabled", description="Whether the simulator is enabled or not.", output_type=str),
    OutputArgument(name="simulator_id", description="The Id of given simulator.", output_type=str),
    OutputArgument(name="name", description="name for given simulator.", output_type=str),
    OutputArgument(name="account_id", description="Account Id of account Hosting given simulator.", output_type=str),
    OutputArgument(name="is_critical", description="Whether the simulator is critical.", output_type=str),
    OutputArgument(name="is_exfiltration", description="If Simulator is exfiltration target.", output_type=str),
    OutputArgument(name="is_infiltration", description="If simulator is infiltration target.", output_type=str),
    OutputArgument(name="is_mail_target", description="If simulator is mail target.", output_type=str),
    OutputArgument(name="is_mail_attacker", description="If simulator is mail attacker.", output_type=str),
    OutputArgument(name="is_pre_executor", description="Whether the simulator is pre executor.", output_type=str),
    OutputArgument(name="is_aws_attacker", description="if the given simulator is aws attacker.", output_type=str),
    OutputArgument(name="is_azure_attacker", description="If the given simulator is azure attacker.", output_type=str),
    OutputArgument(name="external_ip", description="external ip of given simulator.", output_type=str),
    OutputArgument(name="internal_ip", description="internal ip of given simulator.", output_type=str),
    OutputArgument(
        name="is_web_application_attacker",
        description="Whether the simulator is Web application attacker.",
        output_type=str,
    ),
    OutputArgument(name="preferred_interface", description="Preferred simulator interface.", output_type=str),
    OutputArgument(name="preferred_ip", description="Preferred Ip of simulator.", output_type=str),
    OutputArgument(name="hostname", description="Hostname of given simulator.", output_type=str),
    OutputArgument(name="connection_type", description="connection_type of given simulator.", output_type=str),
    OutputArgument(name="simulator_status", description="status of the simulator.", output_type=str),
    OutputArgument(name="connection_status", description="connection status of simulator.", output_type=str),
    OutputArgument(name="simulator_framework_version", description="Framework version of simulator.", output_type=str),
    OutputArgument(
        name="operating_system_type", description="operating system type of given simulator.", output_type=str
    ),
    OutputArgument(name="operating_system", description="Operating system of given simulator.", output_type=str),
    OutputArgument(
        name="execution_hostname", description="Execution Hostname of the given simulator.", output_type=str
    ),
    OutputArgument(name="deployments", description="deployments simulator is part of.", output_type=str),
    OutputArgument(name="created_at", description="Creation datetime of simulator.", output_type=str),
    OutputArgument(name="updated_at", description="Update datetime of given simulator.", output_type=str),
    OutputArgument(name="deleted_at", description="deletion datetime of given simulator.", output_type=str),
    OutputArgument(name="assets", description="Assets of given simulator.", output_type=str),
    OutputArgument(name="simulation_users", description="simulator users list.", output_type=str),
    OutputArgument(name="proxies", description="Proxies of simulator.", output_type=str),
    OutputArgument(name="advanced_actions", description="Advanced simulator details.", output_type=str),
]

simulator_details_for_update_fields = [
    InputArgument(
        name="connection_url",
        required=False,
        is_array=False,
        description="The given value will be set as "
        + "connection string, meaning this can be used to connect to this URL.",
    ),
    InputArgument(
        name="cloud_proxy_url",
        description="the given value will be set as cloud proxy url.",
        required=False,
        is_array=False,
    ),
    InputArgument(
        name="name",
        required=False,
        is_array=False,
        description="The given value will be set as name of simulator. "
        + "This will be the name of simulator once the command runs.",
    ),
    InputArgument(
        name="preferred_interface",
        required=False,
        is_array=False,
        description="the given value will be set as preferred interface.",
    ),
    InputArgument(
        name="preferred_ip",
        required=False,
        is_array=False,
        description="the given value will be set as Preferred IP to connect to the simulator.",
    ),
    InputArgument(name="tunnel", required=False, is_array=False, description="the given value will be set as tunnel."),
]

test_summaries_output_fields = [
    OutputArgument(name="scenario_id", description="scenario ID of the test.", output_type=str),
    OutputArgument(name="simulation_name", description="Name of the simulation.", output_type=str),
    OutputArgument(
        name="security_action_per_control", description="Security Actions of the simulation.", output_type=str
    ),
    OutputArgument(name="test_id", description="Test id of the test.", output_type=str),
    OutputArgument(name="status", description="status of the test.", output_type=str),
    OutputArgument(
        name="planned_simulations_amount", description="Planned simulations count of the test.", output_type=str
    ),
    OutputArgument(name="simulator_executions", description="simulator executions of the test.", output_type=str),
    OutputArgument(
        name="attack_executions", description="list of attacks that are part of the simulation.", output_type=str
    ),
    OutputArgument(name="ran_by", description="user who started the simulation.", output_type=str),
    OutputArgument(name="simulator_count", description="simulators count per account.", output_type=str),
    OutputArgument(name="end_time", description="End Time of the test.", output_type=str),
    OutputArgument(name="start_time", description="start time of the test.", output_type=str),
    OutputArgument(name="finalStatus.stopped", description="stopped count of attacks.", output_type=str),
    OutputArgument(name="finalStatus.missed", description="missed count of attacks.", output_type=str),
    OutputArgument(name="finalStatus.logged", description="logged count of attacks.", output_type=str),
    OutputArgument(name="finalStatus.detected", description="detected count of attacks.", output_type=str),
    OutputArgument(name="finalStatus.prevented", description="prevented count of attacks.", output_type=str),
]

tests_outputs = [
    OutputArgument(name="id", description="Id of Actively running test.", output_type=int),
    OutputArgument(name="name", description="Name of the test being run.", output_type=str),
    OutputArgument(name="description", description="Details related to the test being run.", output_type=str),
    OutputArgument(name="success_criteria", description="success criterion for the test.", output_type=str),
    OutputArgument(
        name="original_scenario_id", description="Original scenario ID of the running test", output_type=str
    ),
    OutputArgument(name="actions_count", description="number of actions", output_type=str),
    OutputArgument(name="edges_count", description="number of edges.", output_type=str),
    OutputArgument(name="created_at", description="details related to when test is created.", output_type=str),
    OutputArgument(
        name="updated_at", description="details related to when test is last updated/changed", output_type=str
    ),
    OutputArgument(name="steps_count", description="number of steps in simulator.", output_type=str),
    OutputArgument(name="scenario_id", description="scenario_id of the test.", output_type=str),
    OutputArgument(name="original_scenario_id", description="scenario_id for reference.", output_type=str),
    OutputArgument(name="ran_by", description="User who ran the scenario.", output_type=str),
    OutputArgument(name="ran_from", description="Where the test ran from.", output_type=str),
    OutputArgument(name="test_id", description="test id of the test.", output_type=str),
    OutputArgument(name="priority", description="priority of tests.", output_type=str),
    OutputArgument(name="retry_simulations", description="Should simulations be retried", output_type=str),
    OutputArgument(name="pause_duration", description="is the test paused and if so till when", output_type=str),
    OutputArgument(name="paused_date", description="when the test is paused", output_type=str),
    OutputArgument(name="expected_simulations_amount", description="number of simulations expected", output_type=str),
    OutputArgument(
        name="dispatched_simulations_amount", description="the number of simulations dispatched", output_type=str
    ),
    OutputArgument(name="skipped_simulations_amount", description="The number of simulations skipped", output_type=str),
    OutputArgument(name="failed_simulations_amount", description="The number of simulations failed", output_type=str),
]

test_outputs_headers_list = [
    "id",
    "name",
    "description",
    "successCriteria",
    "originalScenarioId",
    "actions_count",
    "edges_count",
    "createdAt",
    "updatedAt",
    "steps_count",
    "planId",
    "original_scenario_id",
    "ranBy",
    "ranFrom",
    "planRunId",
    "priority",
    "retrySimulations",
    "pause_duration",
    "paused_ate",
    "expectedSimulationsAmount",
    "dispatchedSimulationsAmount",
    "skippedSimulationsAmount",
    "failedSimulationsAmount",
]


def test_outputs_headers_transform(header):
    return_map = {
        "id": "id",
        "name": "name",
        "description": "description",
        "successCriteria": "success_criteria",
        "originalScenarioId": "original_scenario_id",
        "actions_count": "actions_count",
        "edges_count": "edges_count",
        "createdAt": "created_at",
        "updatedAt": "updated_at",
        "steps_count": "steps_count",
        "planId": "scenario_id",
        "original_scenario_id": "original_scenario_id",
        "ranBy": "ran_by",
        "ranFrom": "ran_from",
        "planRunId": "test_id",
        "priority": "priority",
        "retrySimulations": "retry_simulations",
        "pauseDuration": "pause_duration",
        "pausedDate": "paused_date",
        "expectedSimulationsAmount": "expected_simulations_amount",
        "dispatchedSimulationsAmount": "dispatched_simulations_amount",
        "skippedSimulationsAmount": "skipped_simulations_amount",
        "failedSimulationsAmount": "failed_simulations_amount",
    }

    return return_map.get(header, header)


metadata_collector = YMLMetadataCollector(
    integration_name="Safebreach",
    description="For enterprises using SafeBreach and XSOAR, integrating this package streamlines"
    + "operations by allowing you to operate SafeBreach through XSOAR, making SafeBreach "
    + "an integral part of the enterprise workflows. This integration includes "
    + "commands for managing tests, insight indicators, simulators "
    + "and deployments, users, API keys, integration issues, and more.",
    display="Safebreach",
    category="Deception & Breach Simulation",
    docker_image="demisto/python3:3.10.13.88772",
    is_fetch=False,
    long_running=False,
    long_running_port=False,
    is_runonce=False,
    image="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAOYAAAAkCAYAAACdSkYEAAAJ+klEQV"
    + "R42u3dA5DkQBiG4bk927Zt27Zt27Zt27Zt27Zts+"
    + "/dqlxVriuDzCZze1v5q57DTnfXTDLfoNPJ2qyyyiqrrLLKKqusssoqq6yyyswKkDh7UZyBwGtMRAi"
    + "NdomwAd8UG5BIo10IZYzXEMrYRW1+sRJnD4cu2IdXEPiOJ9iJXghls8qv7O"
    + "+k6Iy5OI4TZoWyOISGPfCnahcdzzTaPUN0VTt/Sl"
    + "+hobgf20mF8ALCgR8IabPKT5TyIixULpsVzLMQdhRVtRvhoN0I6d1X2HHWBxvEP3KiIyZiDmZj"
    + "FFoiC7w8uIPS4TOEE2c8cF8CIS4yoQBKowyKIRcSI7DNqv8qmMKBbqp2OyG8BUSgv9vtULXr5mhM"
    + "NzaEF5rjAYQTTzAOcT2wg45CSN5hO1ZgPz5goon3oTru4ieEE99xCgMR32aVrw/mSwg76tuUqpogw/h"
    + "ZcVOf3hgn5fMtcVL+9Ob9b352xvs21Xj1HYz3UudGCIrNEDr1NnnnpIeQbEAoqV1gRDP9SaLfdwxDAJ"
    + "tVvjaYIyE0vEYEm1IEsSCEHQVV40XAGwgNI3VuhAUQOv1EHJN3TkcIlc8I5wueJHotsVnla4MZBGsgVF"
    + "4gn9yWALbHDwjFD7TXGDMfXkhjrkEQHRsgA4TkF1aiBvKhOOpjHK5DYIcHds4UCJV9vuRJ8hntUQ+1FG0"
    + "wFfcgNJS3WeWrgimHKSOaogJC22tHEOOgniKOg/FCo4IyZkY3NsBICElrJ31ye/PAzlkMobLUlzxJXjv5"
    + "rt4Ov6Q+G21WGRVMv1/KJIpQ+YSABs1gpkNVdEBv9EEbFEFwN4K5AmHsCORgHH/IjJboi+6oiTiGBVMugi"
    + "j1eeBCnyBIjwpoitbK36WQwIX+IVASndEXHVECoXTOyidHBbRDT2WsDiiN8G4+H7yQRXk8vRUtURhhXAom"
    + "7VAQjdEaDZEPwf1iMI9AqHwwYMz+Lhzi+IDRCOFyMB2rYyeQjXAbQsMv7EI6E4LZX+rzyk67mOiO/fgK4c"
    + "AWO2OExwR8gtDwCeMR2sl9boB3EA58wzxEcfG5EABtcc/JJNlyJ9v8m9JOaPiMKYjg7sfYiOiHjWUSZNzT"
    + "PH76bnY+xgZEY6xSNIbmu5j3GN5jeY+pjB1RZ4i2QUhK+TCYQyBcdBqhDA8mr6LY4GLfL6hscDDnSH0uGD"
    + "CxNNHOcd4HLva/hpgO7nNDCBfdR2wn2yCK9MLvyBoDJtxuI7beUMbHYwhvY+KlEYRN9IyXbrcUykDYBSHZh"
    + "UDqtj3ipdvjfRtjqSd/HiO+znc3IXmNMj4IZn0IHSYbGUzlnXILhA5fkN6IYHJ7SnyQ+gwzIJjyi098vIDQ"
    + "4TQC2rkvOXSOtd3BNgiFSzrGamXQTPhh+NMTzHXqhQObVKFrEj99WVUwW0LY0dKmlHefPz/fhIDK2Ip1OkI"
    + "U28HHzp0oDi83jj/OQxPkRTLEVX7eFe80QhHShWBewhA70qn6tYCQHEIRREcK9MM3qc1+F8PzBpFVYihjVs"
    + "A0jY+UDxDBxbHfKvetIgqjDDpgFZJIffdrHMKagLSIjlx2jk+3tHNfImIl2qAgkiMeUqM5HkFIktsZa7adhSn9UQw5URo9cQTJnGyXj5iK"
    + "+iiKMspYryEkxfUE8yuEtwiJsv0VuC7x0q1TBXMThB2bbEp591HfxpjqYH7VGaTmLnxs6Y"
    + "+YBn2vzQ8hKeJCMBe7OIHyTH5l13qXUCaAhCSFwccxryOZ0bOPygumkDSx8z17vdTuopv7LZHGi3grjXYpNFZJHUV"
    + "4o2dl+XkajRfYmX4imMoDbObChM03LEA8A8J5Xj5EY1AwK2ksbo/voP1FqX0Hg1f+dEFQE4K5Sup3xEHbFBCSmG7ut"
    + "9XSOOM12ozTmJyJbdrhEr6fSm3P+u6Psvo3ekLMwRcIBz6htg+DuVJe3mdQMKfLH2GdtB8vtV9gwsqfe8hsVDCVd8E"
    + "3Ur82jrpofIoo6eZ+GyaNM1+jzXWtbWpiMDvIXwd8PPnjPYFj2uSP+6GJhHY4A2HHL1Rz8uW/PubjBO7gPi5gLa6YFMxDGh8lZztwWmq/"
    + "x4UnySe0lnTGcGzGRwjJWyQwKJixNCdiHD9OOcjN7IwdGJUxA4dwAw9xGVtwwuE+YTZcY3FFfZODWRlCzZ3DJf1NPFzS39XD"
    + "JTqX7C2WN7biDcJr9KmNVxCOmBTMmxA+cMqAWdkwmAohmW9QMDNC+FBnO+e93tM5jhzMhBptipoczJIOgunHixUWdqbmWzk8"
    + "VOL5YD7wWDD1n7L2Hl4GBDOr0cFUJuS+QfgwmEk12uQ3OZhF/H4w9c8ELlHdHhpvNZ6Mo1AaWZANVXHOpGBelicCMEaHVgY"
    + "GsxeEJLoBwUwFIVmh83HmlL6zXtOY6JuJSsiqKI89ToIZE0JS0bcH0/xF7OaH85XdMz7YARrfQ7M5XDxgfDDlhQWbbDrL"
    + "wGB2hpAkMCCYYTS+WtTxweNLAyGp4eKqLjmY/jUmDwf42mAqp32t1jjtK6/Bp32tRhCPB1P7/MmbNsrDweynMVET4R8Fc"
    + "63GC1VIgw6XXJVPIPfB4yunsVAhgFvB1J6Auwwv3xRM33+iNCFGXhfbFoaQzFPd3k667Tn8eTiYGex8zPPyaDB5B8MvrQ"
    + "P7BgVzOISksqMueiZPENbtYGofXmrj+WAaf2mRM1xO5IV0aZHTplxahI/Bqu9iHZESATUuHdnYzkxrXVW70hCSFp4MptJvH4RkF7LDv8bpaVnQF"
    + "+F0LJuLiADSYYLEqI5NEBraGRjMOPiqdSkTzYP5BE0JYFuN25JBSEbDy81gRsB7jXfhoYiqcTpYWpQxMpimXowrkELVbqfhF"
    + "+NSVnJIfuAZ7uCFk9X8QVRjhZQnfxQXMBNjMAlL8MTEYKZ0sIrpPS7jHG5LpxLlcmOh+S8XL9J1EoGMCqbStweEHY9xHhfxFE"
    + "LxyJWPxoo7mIcxmIgFuO3SPmESzcH2uoszuKpaV3zOQ8H0/ZevVN4Jv0K44R0ya6+79fzhEo2+ZfAFQofGJl3z5wAi2yiDg+kP"
    + "cyB00T4xuSh++uxwifalYVz0BQE8EEzff8Fn5QTbKfig+9Qaxwuz2+CTx4OpfZbLcQgXDTE4mGdRD15mXkJDOYvnJYQLfiGdnXHK"
    + "44VhwVROvtZx35IaFUyzf0XCV4W5vyKBcVAeE3AQj/FN9d3gqfLzUcihY1lfKyzEMVzFdZzHEazCWDRBdjunfZVGF5XSbk5u5MU4"
    + "HMIDvMYzXMBq9EUeeDl4LBXQE1OwDJuwG3uVv7diMYaiFuK5eN+ySI+xoZuPMTjqYjHO4xle4wGOYC5aIL6TcUKiHmbhEK7gBi7iONZhElohH8K7"
    + "+PxqoGy3y3iOF7iDPRiDEgjgznZRTilU2imsssoqq6yyyiqrrLLKKqusssrk+g3rPqPix+2WlgAAAA90RVh0Q29tbWVudABjaW1hZ2"
    + "Vz5AUQeQAAAABJRU5ErkJggg==",
    integration_subtype="python3",
    integration_type="python",
    fromversion="6.6.0",
    conf=[
        ConfKey(
            name="base_url",
            display="Server URL",
            required=True,
            additional_info="This is base URL for your instance.",
            key_type=ParameterTypes.STRING,
        ),
        ConfKey(
            name="credentials",
            display="API Key",
            required=True,
            additional_info="This is API key for your instance, this can be created in Safe Breach User \
                Administration -> API keys, it must be saved as there is no way to view it again.",
            key_type=ParameterTypes.AUTH,
        ),
        ConfKey(
            name="account_id",
            display="Account ID",
            required=True,
            additional_info="This is account ID of account with which we want to get data from safebreach",
            key_type=ParameterTypes.NUMBER,
        ),
        ConfKey(
            name="verify",
            display="Verify SSL Certificate",
            required=False,
            default_value=False,
            additional_info="This Field is useful for checking if the certificate of SSL for HTTPS is valid or not",
            key_type=ParameterTypes.BOOLEAN,
        ),
        ConfKey(
            name="proxy",
            display="Use system proxy settings",
            required=False,
            default_value=False,
            additional_info="This Field is useful for asking integration to use default system proxy settings.",
            key_type=ParameterTypes.BOOLEAN,
        ),
    ],
)


def sb_error_string(error_data, sb_code):
    sbcode_error_dict = {
        700: f"{error_data} value is below permitted minimum",
        701: f"{error_data} value is above permitted maximum",
        702: f"{error_data} length is more than permitted length",
        703: f"{error_data} field is expected to be integer but received something else",
        704: f"{error_data} field cant be empty",
        705: f"{error_data} field cant permit this value",
        706: f"{error_data} field value is supposed to be unique, value is already taken",
        707: f"{error_data} Requested value not found",
        708: f"{error_data} expected UUID but found something else",
        709: f"{error_data} cannot be null",
        710: f"{error_data} is not a valid URL",
        711: f"{error_data} field should not be changed but has been changed",
        712: "license is invalid",
        713: f"{error_data} fields have opposite Attributes",
        714: f"{error_data} fields block association with each other",
        715: "weak password is set",
        716: "account name and account number dont match",
        718: "license expired",
        719: "Connection Refused",
        720: "passwords dont match",
        721: "gateway timeout",
    }
    return sbcode_error_dict.get(sb_code, "")


def format_sb_code_error(errors_data):
    """
    This function gets all errors for when we get a 400 status and formats the errors accordingly

    Args:
        errors_data (dict): This is all errors with sbcodes returned by safebreach API

    Returns:
        (str,optional): returns error codes which are formatted as string
    """
    error_data = ""

    try:
        errors = errors_data.get("errors")
        if errors_data.get("statusCode") == 400:
            if errors_data.get("message"):
                return json.dumps({"issue": errors_data.get("message"), "details": errors_data.get("additionalData")})
        else:
            issues = []
            for error in errors:
                if error.get("sbcode"):
                    sb_code = error.get("sbcode")
                    fields = error.get("data", {}).get("fields")
                    if not fields:
                        return sb_error_string(error_data, sb_code=sb_code)
                    for field in fields:
                        error_data = field
                        issue = sb_error_string(error_data=error_data, sb_code=sb_code)
                        issues.append(issue)
            return "; ".join(issues)
    except AttributeError:
        return errors_data

    final_error_string = ""
    # here we are formatting errors and then we are making them as a string
    for error in errors:
        error_data = error.get("data")
        error_code = error.get("sbcode")
        final_error_string = final_error_string + " " + sb_error_string(error_data=error_data, sb_code=int(error_code))

    return final_error_string


class Client(BaseClient):
    """
    Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, api_key: str, account_id: int, base_url: str, verify: bool):
        super().__init__(base_url=base_url, verify=verify)

        self.base_url = base_url
        self.api_key = api_key
        self.account_id = account_id
        self.proxies = handle_proxy()

    def validate_email(self, email):
        """
        This function is to validate email.

        Args:
            email (str): Email address which we need to validate.

        Returns:
            (boo): boolean value
        """
        # Regular expression for basic email validation
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    def get_response(self, url: str = "", method: str = "GET", request_params: dict = {}, body: dict = None):
        """
        This function calls API endpoint and handles the response

        Args:
            url (str, optional): endpoint url which follows base URL will be this input . Defaults to "". 
            method (str, optional): HTTP method to be used, Defaults to "GET".
            request_params (dict, optional): request parameters if any. Defaults to {}.
            body (dict, optional): request body for API call. Defaults to None.

        Returns:
            (dict,list,Exception): a dictionary or list with data based on API call OR Throws an error based on status code
        """  # noqa: W291
        # base_url = demisto.params().get("base_url", "").strip()

        base_url = self.base_url.strip()
        base_url = base_url if base_url[-1] != "/" else base_url[0:-1]

        url = url if url[0] != "/" else url[1:]
        # full_url = urljoin(self.base_url, url')

        request_url = f"{base_url}/api/{url}"
        api_key = self.api_key.strip()
        headers = {"accept": "application/json", "content-type": "application/json", "x-apitoken": api_key}
        response = self._http_request(
            method=method,
            full_url=request_url,
            json_data=body,
            headers=headers,
            params=request_params,
            ok_codes=[200, 201, 204, 400, 409, 404],
        )
        return (
            response
            if not ((type(response) == dict) and (response.get("error") and not response.get("errorCode")))  # noqa: E721
            else self.handle_sbcodes(response)
        )

    def handle_sbcodes(self, response: dict):
        """
            This function handles errors related to SBcodes if the endpoint gives sbcode in errors

        Args:
            response (dict): all errors given by 400 response code will be accepted as dictionary and are formatted based on
            the state of error

        Raises:
            Exception: all errors will be formatted and then thrown as exception string which will show as error_results in XSOAR
        """
        demisto.debug(f"error being sent to format_sb_code_error function is {response.get('error')}")
        exception_string = format_sb_code_error(response.get("error"))
        raise DemistoException(exception_string)

    def get_all_users_for_test(self):
        """
        This function is being used for testing connection with safebreach
        after API credentials re taken from user when creating instance

        Returns:
            str: This is just status string, if "ok" then it will show test as success else it throws error
        """
        try:
            account_id = self.account_id
            url = f"/config/v1/accounts/{account_id}/users"
            response = self.get_response(url=url)
            if response and response.get("data"):
                return "ok"
            elif response.get("data") == []:
                return "Please check the Account Id and try again"
            return "Could not verify the connection"
        except Exception as exc:
            if "Error in API call [404] - Not Found" in str(exc):
                raise DemistoException(f"Please check the URL configured and try again. Error:-{exc}")
            elif "Error in API call [401] - Unauthorized" in str(exc):
                raise DemistoException(f"Please check the API used and try again. Error:-{exc}")
            elif "SSL Certificate Verification Failed" in str(exc):
                raise DemistoException("Unable to verify SSL certificate. Please ensure that the SSL "
                                       + f"certificate is valid and properly configured. Error:-{exc}")
            else:
                raise DemistoException(exc)

    def get_users_list(self):
        """
            This function returns all users present based on modifiers

        Returns:
            list: this is list of users queried based on modifiers specified
        """
        account_id = self.account_id
        url = f"/config/v1/accounts/{account_id}/users"
        params = {"details": "true", "deleted": "false"}
        response = self.get_response(url=url, request_params=params)
        user_data = response["data"]
        return user_data

    def delete_user(self):
        """
            This function deletes a given user based on arguments of commands

        Returns:
            dict: user data related to the user who has been deleted
        """
        user_id = demisto.args().get("user_id")
        account_id = self.account_id
        method = "DELETE"
        url = f"/config/v1/accounts/{account_id}/users/{user_id}"

        deleted_user = self.get_response(url=url, method=method)
        return deleted_user

    def update_user_with_details(self, user_id: str, user_details: dict):
        """
            This function updates user with given details

        Args:
            user_id (str): this is ID of user to update
            user_details (dict): this is list of user details to update

        Returns:
            dict: user data post update
        """
        # we dont want to update details as empty if user is not giving data in inputs , hence remove false values
        for key in list(user_details.keys()):
            if not user_details[key]:
                user_details.pop(key)

        account_id = self.account_id
        method = "PUT"
        url = f"/config/v1/accounts/{account_id}/users/{int(user_id)}"
        updated_user = self.get_response(url=url, method=method, body=user_details)
        return updated_user

    def list_deployments(self):
        """
            This function lists all deployments we extracted from safebreach

        Returns:
            list: List of deployments data retrieved
        """
        account_id = self.account_id
        url = f"/config/v1/accounts/{account_id}/deployments"

        response = self.get_response(url=url)
        deployments = response["data"]
        return deployments

    def create_deployment_data(self):
        """
            This function creates a deployment based on data given by user, this will be called by an external function \
                which is triggered with a command for creating deployment

        Returns:
            dict: the data of deployment created
        """
        account_id = self.account_id
        name = demisto.args().get("name", "").strip()
        description = demisto.args().get("description", "").strip()
        simulators = demisto.args().get("simulators", [])
        if simulators:
            simulators = simulators.split()
        deployment_payload = {
            "nodes": simulators,
            "name": name,
            "description": description,
        }
        method = "POST"
        url = f"/config/v1/accounts/{account_id}/deployments"
        created_deployment = self.get_response(url=url, method=method, body=deployment_payload)
        return created_deployment

    def update_deployment(self):
        """
            This function is called when we want to update a deployment data

        Raises:
            Exception: This will raise an exception if a deployment with given name or id couldn't be found

        Returns:
            dict: updated deployment data
        """

        deployment_payload = None
        account_id = self.account_id
        deployment_id = int(demisto.args().get("deployment_id", ""))
        if not deployment_id:
            raise DemistoException("Inputs Error: Deployment ID is a required field which has to have a value as input")

        name = demisto.args().get("updated_deployment_name", "").strip()
        simulators = demisto.args().get("updated_simulators_for_deployment", [])
        if simulators:
            simulators = simulators.split()
        description = demisto.args().get("updated_deployment_description", "").strip()
        if name or simulators or description:
            deployment_payload = {"nodes": simulators, "name": name, "description": description}
        method = "PUT"
        url = f"/config/v1/accounts/{account_id}/deployments/{deployment_id}"
        updated_deployment = self.get_response(url=url, method=method, body=deployment_payload)
        return updated_deployment

    def delete_deployment(self):
        """
            This function deletes a deployment with given id or name

        Raises:
            Exception: raised when a deployment with given name or id could not be found

        Returns:
            dict: deleted deployment data
        """
        account_id = self.account_id
        deployment_id = demisto.args().get("deployment_id", None)

        method = "DELETE"
        url = f"/config/v1/accounts/{account_id}/deployments/{deployment_id}"
        deleted_deployment = self.get_response(url=url, method=method)
        return deleted_deployment

    def get_tests_with_args(self):
        """
            This function calls GET of testsummaries endpoint and returns data related to test
            The parameters are all optional

        parameters include:
        1. simulator_id : this is simulator ID

        Returns:
            List[Dict]: Returns test data as a list of dictionaries
        """

        test_summaries = []
        # sort_map = {
        #     "endTime": "endTime",
        #     "startTime": "startTime",
        #     "testID": "planRunId",
        #     "stepRunId": "stepRunId"
        # }

        account_id = self.account_id

        # include_archived = "false"
        # size = demisto.args().get("entries_per_page")
        # status = demisto.args().get("status","")
        scenario_id = demisto.args().get("scenario_id")
        simulation_id = demisto.args().get("simulation_id")
        # sort_by = sort_map.get(demisto.args().get("sort_by"), "endTime")

        parameters = {}
        method = "GET"
        if scenario_id:
            url = f"/data/v1/accounts/{account_id}/testsummaries/{scenario_id}"
        else:
            url = f"/data/v1/accounts/{account_id}/testsummaries"
            for param in [("simulationId", simulation_id)]:
                parameters.update({} if not param[1] else {param[0]: param[1]})
        test_summaries = self.get_response(url=url, method=method, request_params=parameters)
        return test_summaries

    def flatten_test_summaries(self, test_summaries):
        """
            This function flattens the test summaries related data for table view

        Args:
            test_summaries (dict): This returns a list of dictionaries of test summaries
            which are flattened versions of data retrieved for tests
        """
        for test_summary in test_summaries:
            for key in list(test_summary.keys()):
                if key == "moveExecutions":
                    test_summary["attack_executions"] = ", ".join(
                        [str(attack["moveId"]) for attack in test_summary.get("moveExecutions", [])]
                    )
                elif key == "securityActionPerControl":
                    test_summary["security_actions"] = ", ".join(
                        [str(control["product"]) for control in test_summary.get("securityActionPerControl", [])]
                    )
                elif key == "finalStatus":
                    data_dict = {
                        "stopped": test_summary[key].get("stopped", 0),
                        "missed": test_summary[key].get("missed", 0),
                        "logged": test_summary[key].get("logged", 0),
                        "detected": test_summary[key].get("detected", 0),
                        "prevented": test_summary[key].get("prevented", 0),
                    }
                    test_summary.update(data_dict)
                elif key in ["endTime", "startTime"] and isinstance(test_summary[key], int):
                    test_summary[key] = datetime.utcfromtimestamp((test_summary[key]) / 1000).strftime(DATE_FORMAT)
        return test_summaries

    def flatten_tests_data(self, tests):
        """
            this function flattens tests data which is used for formatting running and queued tests

        Args:
            tests (list[dict]): This is list of dictionary containing data for tests which are queued

        Returns:
            list[dict]: the same data will have other keys which will be of more use to show in table
        """
        return_list = []
        return_obj = {}
        for test in tests:
            for key in list(test.keys()):
                if key == "actions":
                    return_obj["actions_count"] = len(test[key])
                elif key == "edges":
                    return_obj["edges_count"] = len(test[key])
                elif key == "steps":
                    return_obj["steps count"] = len(test[key])
                elif key == "originalPlan":
                    return_obj["original_scenario_id"] = test[key].get("id")
                return_obj[key] = test[key]
            return_list.append(return_obj)
        return return_list

    def flatten_simulations_data(self, simulations):
        """
            This function flattens simulations data which is used for formatting running and queued simulations

        Args:
            simulations (dict[lists]): This is list of dictionary containing data for simulations which are queued

        Returns:
            list[dict]: the same data will have other keys which will be of more use to show in table
        """
        simulations_copy = deepcopy(simulations)
        if simulations_copy.get("QUEUED"):
            simulations_copy.pop("QUEUED")
        return_list = []
        for simulation in simulations_copy:
            return_obj = {}
            return_obj["status"] = simulation
            simulation_type = simulations[simulation]
            items = list(simulation_type.values())
            for data in items:
                for key in data:
                    if key == "metadata":
                        return_obj["moveId"] = data["metadata"]["moveId"]
                        # skipping params keys because it is full of ID's and useless for user
                    # elif key == "actions":
                    #     return_obj['simulator_ids_involved'] = ""
                    #     return_obj["simulator_names_involved"] = ""
                    #     for object in data["actions"]:
                    #         return_obj['simulator_ids_involved'] =
                    # f"{return_obj['simulator_ids_involved']} ; {object['nodeId']}"
                    #         return_obj['simulator_names_involved'] = f"{return_obj['simulator_names_involved']} \
                    #             ; {object.get('nodeNameInMove','') or object.get('nodeNameInMoveDescription','')}"
                    else:
                        return_obj[key] = data[key]
                return_list.append(return_obj)

        return return_list

    def delete_test_result_of_test(self):
        """
            This function deletes test results of a given test ID by calling related endpoint

        Returns:
            dict: Deleted test data results
        """
        account_id = self.account_id
        test_id = demisto.args().get("test_id")

        method = "DELETE"
        url = f"/data/v1/accounts/{account_id}/tests/{test_id}"
        request_parameters = {"softDelete": "false"}

        test_summaries = self.get_response(url=url, method=method, request_params=request_parameters)
        return test_summaries

    def get_all_integration_issues(self, error_logs, connector_map, connector):
        integration_log = {}
        if error_logs.get("lastTestConnection") is not None:
            integration_log.update(self.map_error_log_data(connector, connector_map))
        return integration_log

    def map_error_log_data(self, integration_id, connector_map):
        log = {}
        integration_data = connector_map.get("result").get("providers")
        if integration_data:
            for data in integration_data:
                if data.get("id", "") == integration_id:
                    log["integration_name"] = data.get("name", "")
                    log["connector"] = integration_id  # Assuming integration_id is the correct value
        return log

    def get_all_errors(self, error_log, log):
        errors = []
        error_list = error_log.get("errors", [])
        if error_list:
            for error in error_list:
                log.update({
                    "action": error.get("action", ""),
                    "success": error.get("success", ""),
                    "error": error.get("error", ""),
                    "timestamp": error.get("timestamp", "")
                })
                errors.append(log)
        return errors

    def flatten_error_logs_for_table_view(self, error_logs):
        """
            This function flattens error logs into a single leveled dictionary for table view

        Args:
            error_logs (dict): This is list of dictionaries which have multiple levels of data

        Returns:
            dict : flattened error logs which are easier to display on table
        """
        flattened_logs_list = []
        error_map = {"ERROR": "errors", "WARNING": "warnings"}
        log = {}
        preference = demisto.args().get("error_type") if demisto else None
        preference = error_map.get(preference, "")  # type: ignore[arg-type]
        connector_map = self.get_integration_details()
        for connector in error_logs:
            # if preference is empty means we need to fetch both the errors and warnings.
            if preference == "":
                log = self.get_all_integration_issues(error_logs[connector], connector_map, connector)
            elif error_logs[connector].get(preference):
                log = self.map_error_log_data(connector, connector_map)
            else:
                continue
            error_list = self.get_all_errors(error_logs[connector], log)
            for error in error_list:
                flattened_logs_list.append(error)
        return flattened_logs_list

    def get_all_integration_error_logs(self):
        """
            This function retrieves all error logs of a given account

        Returns:
            dict: This will be having dict containing results and status
        """
        account_id = self.account_id
        method = "GET"
        url = f"/siem/v1/accounts/{account_id}/config/providers/status"

        error_logs = self.get_response(url=url, method=method)
        return error_logs

    def get_integration_details(self):
        """
            This function retrieves all integrations of a given account and their configurations

        Returns:
            dict: This will be having dict containing results and status
        """
        account_id = self.account_id
        method = "GET"
        url = f"/siem/v1/accounts/{account_id}/config/providers"

        error_logs = self.get_response(url=url, method=method)
        return error_logs

    def delete_integration_error_logs(self):
        """
            This function accepts connector ID related to a connector and then returns a status

        Returns:
            dict: status stating whether its success and how many errors are remaining incase of failure to delete some
        """
        account_id = self.account_id
        connector_id = demisto.args().get("integration_id", "").strip()

        method = "DELETE"
        url = f"/siem/v1/accounts/{account_id}/config/providers/status/delete/{connector_id}"

        error_logs = self.get_response(url=url, method=method)
        return error_logs

    def generate_api_key(self):
        """
            This function calls generate API key endpoint

        Returns:
            dict: response of generate API key API call which contains generated \
                API key and name along with additional details
        """
        account_id = self.account_id
        name = demisto.args().get("name", "").strip()
        description = demisto.args().get("description", "").strip()
        method = "POST"
        url = f"/config/v1/accounts/{account_id}/apikeys"
        data = {}
        if name:
            data["name"] = name
        if description:
            data["description"] = description

        generated_api_key = self.get_response(method=method, url=url, body=data)
        return generated_api_key

    def get_all_active_api_keys_with_details(self):
        """
            This function retrieves all available API keys

        Returns:
            dict: This function retrieves API keys which are active for the given account
        """
        account_id = self.account_id
        method = "GET"
        url = f"config/v1/accounts/{account_id}/apikeys"
        request_params = {"details": "true"}
        keys_data = self.get_response(url=url, method=method, request_params=request_params)
        return keys_data

    def filter_api_key_with_key_name(self, key_name):
        """
            This function retrieves all active keys and then filters key based on given input name

        Args:
            key_name (str): The API key name for searching API key

        Raises:
            Exception: if it couldn't find API key with given name

        Returns:
            string: key ID for API key
        """
        active_keys = self.get_all_active_api_keys_with_details()
        demisto.debug(f"active api keys count is {len(active_keys.get('data'))}")
        required_key_object = list(
            filter(lambda key_obj: key_obj["name"].lower() == key_name.lower(), active_keys.get("data"))
        )
        if not required_key_object:
            raise DemistoException(f"couldn't find API key with given name: {key_name}")
        return required_key_object[0]["id"]

    def delete_api_key(self):
        """
            This function calls API key delete endpoint

        Returns:
            dict: Deleted API key data
        """
        key_name = demisto.args().get("key_name", "").strip()
        key_id = self.filter_api_key_with_key_name(key_name=key_name)
        account_id = self.account_id
        method = "DELETE"
        url = f"/config/v1/accounts/{account_id}/apikeys/{key_id}"
        deleted_api_key = self.get_response(method=method, url=url)
        return deleted_api_key

    def get_simulator_quota(self):
        """
            This function calls Account details end point which will return account details
            which has nodesQuota

        Returns:
            dict: user details related to the queried account
        """
        account_id = self.account_id
        method = "GET"
        url = f"/config/v1/accounts/{account_id}"
        simulator_details = self.get_response(method=method, url=url)
        return simulator_details

    def get_simulators_details(self, request_params):
        """
            This function queries for simulators along with modifiers which are request_params
            based on that we get simulator related details and this raises an exception if
            no simulator with given details are found

        Args:
            request_params (dict): filters when querying the data related to simulators

        Raises:
            Exception: Raised when no entries are found related to given filters

        Returns:
            list(dict): returns simulator related data which fulfils the given input parameters
        """
        account_id = self.account_id
        method = "GET"
        url = f"/config/v1/accounts/{account_id}/nodes/bulk"

        simulators_details = self.get_response(method=method, url=url, request_params=request_params)
        if not simulators_details.get("data", {}).get("count"):
            raise DemistoException(f"No Matching simulators found with details not found details are {request_params}")
        return simulators_details

    def get_simulators_details_with_id(self):
        """
            This function queries for simulators along with modifiers which are request_params
            based on that we get simulator related details and this raises an exception if
            no simulator with given details are found

        Args:
            request_params (dict): filters when querying the data related to simulators

        Raises:
            Exception: Raised when no entries are found related to given filters

        Returns:
            list(dict): returns simulator related data which fulfils the given input parameters
        """
        account_id = self.account_id
        simulator_id = demisto.args().get("simulator_id")
        method = "GET"
        url = f"/config/v1/accounts/{account_id}/nodes/{simulator_id}"

        simulators_details = self.get_response(method=method, url=url)
        return simulators_details

    def create_search_simulator_params(self):
        """
            This function creates parameters related to simulator as a dictionary

        Returns:
            dict: parameters dictionary
        """
        possible_inputs = {
            "hostname": "hostname",
            "external_ip": "externalIp",
            "internal_ip": "internalIp",
            "os": "os",
            "status": "status",
            "is_enabled": "isEnabled",
            "is_connected": "isConnected",
            "is_critical": "isCritical",
            "additional_details": "additionalDetails",
        }
        request_params = {
            "details": "true",
            "deleted": "false",
            "secret": "false",
        }
        for parameter in possible_inputs:
            if demisto.args().get(parameter):
                request_params[possible_inputs[parameter]] = (
                    argToBoolean(demisto.args().get(parameter))
                    if (
                        demisto.args().get(parameter) not in ["true", "false"]
                        and parameter
                        in ["details", "deleted", "is_enabled", "is_connected", "is_critical", "additional_details"]
                    )
                    else demisto.args().get(parameter).strip()
                )
        return request_params

    def flatten_simulator_details(self, simulators):
        """
            This function will flatten the nested simulator data
            into a flatter structure for table display

        Args:
            simulators List(dict): This is list of simulators which are to be flattened

        Returns:
            List(dict): This is list of simulators related data for table which is flattened
            List : This is list of keys which are present in the dict
        """
        keys = None
        flattened_simulators = []
        for simulator in simulators:
            simulator_details = {
                "is_enabled": simulator.get("isEnabled"),
                "simulator_id": simulator.get("id"),
                "simulator_name": simulator.get("name"),
                "account_id": simulator.get("accountId"),
                "is_critical": simulator.get("isCritical"),
                "is_exfiltration": simulator.get("isExfiltration"),
                "is_infiltration": simulator.get("isInfiltration"),
                "is_mail_target": simulator.get("isMailTarget"),
                "is_mail_attacker": simulator.get("isMailAttacker"),
                "is_pre_executor": simulator.get("isPreExecutor"),
                "is_aws_attacker": simulator.get("isAWSAttacker"),
                "is_azure_attacker": simulator.get("isAzureAttacker"),
                "is_web_application_attacker": simulator.get("isWebApplicationAttacker"),
                "external_ip": simulator.get("externalIp"),
                "internal_ip": simulator.get("internalIp"),
                "preferred_interface": simulator.get("preferredInterface"),
                "preferred_ip": simulator.get("preferredIp"),
                "hostname": simulator.get("hostname"),
                "connection_type": simulator.get("connectionType"),
                "simulator_status": simulator.get("status"),
                "connection_status": simulator.get("isConnected"),
                "simulator_framework_version": simulator.get("frameworkVersion"),
                "operating_system_type": simulator.get("nodeInfo", {}).get("MACHINE_INFO", {}).get("TYPE", ""),
                "operating_system": simulator.get("nodeInfo", {})
                .get("MACHINE_INFO", {})
                .get("PLATFORM", {})
                .get("PRETTY_NAME", ""),
                "execution_hostname": simulator.get("nodeInfo", {})
                .get("CURRENT_CONFIGURATION", {})
                .get("EXECUTION_HOSTNAME", ""),
                "deployments": simulator.get("group"),
                "created_at": simulator.get("createdAt"),
                "updated_at": simulator.get("updatedAt"),
                "deleted_at": simulator.get("deletedAt"),
                "assets": simulator.get("assets"),
                "simulation_users": simulator.get("simulationUsers"),
                "advanced_actions": simulator.get("advancedActions"),
                "proxies": simulator.get("proxies"),
            }

            if not keys:
                keys = list(simulator_details.keys())
            flattened_simulators.append(simulator_details)

        return flattened_simulators, keys

    def delete_simulator_with_given_id(self, simulator_id, force: str):
        """
            This function calls delete simulator on simulator with given ID

        Args:
            simulator_id (str): This is simulator ID to delete
            force (str): If the simulator is to be force deleted even if its not connected

        Returns:
            dict: Deleted simulator data
        """
        request_params = {"force": force}
        method = "DELETE"
        account_id = demisto.params().get("account_id")
        request_url = f"/config/v1/accounts/{account_id}/nodes/{simulator_id}"

        deleted_simulator = self.get_response(url=request_url, method=method, request_params=request_params)
        return deleted_simulator

    def delete_simulator_with_given_name(self):
        """
            This function deletes a simulator with given name,
            This achieves this by retrieving ID by querying all simulators
            and then retrieving ID of name if it matches.
            Then it calls a function which makes API call with this ID

        Returns:
            dict: deleted simulator related data
        """
        simulator_id = demisto.args().get("simulator_id")
        demisto.debug(f"simulator id of given simulator is {simulator_id}")

        force_delete = "false"
        result = self.delete_simulator_with_given_id(simulator_id=simulator_id, force=force_delete)
        return result

    def make_update_simulator_payload(self):
        # this is created under assumption that only these fields will be  chosen to be updated by user
        """
            This function returns a payload with update related data

        Returns:
            dict: Update simulators payload
        """
        data_dict = {
            "connectionUrl": demisto.args().get("connection_url", "").lower().strip(),
            "cloudProxyUrl": demisto.args().get("cloud_proxy_url", "").strip(),
            "name": demisto.args().get("name", "").strip(),
            "tunnel": demisto.args().get("tunnel", "").strip(),
            "preferredInterface": demisto.args().get("preferred_interface", "").strip(),
            "preferredIp": demisto.args().get("preferred_ip", "").strip(),
        }
        for key, value in tuple(data_dict.items()):
            if not value:
                data_dict.pop(key)
        return data_dict

    def update_simulator_api_call(self, simulator_id, simulator_data):
        """
            This function calls update simulators details API and returns updated data

        Args:
            simulator_id (str): ID of simulators to update
            simulator_data (dict): Payload for PUT call

        Returns:
            dict: Updated simulators details
        """
        method = "PUT"
        account_id = demisto.params().get("account_id")
        request_url = f"/config/v1/accounts/{account_id}/nodes/{simulator_id}"

        updated_simulator = self.get_response(url=request_url, method=method, body=simulator_data)
        return updated_simulator

    def update_simulator(self):
        """
            This function updates simulator with given name

        Returns:
            dict: this is updated simulators details for given simulators ID
        """
        simulator_id = demisto.args().get("simulator_id")

        payload = self.make_update_simulator_payload()

        updated_simulator = self.update_simulator_api_call(simulator_id=simulator_id, simulator_data=payload)
        return updated_simulator

    def approve_simulator(self):
        """
            This function updates simulator with given name

        Returns:
            dict: this is updated simulators details for given simulators ID
        """
        simulator_id = demisto.args().get("simulator_id")
        payload = {"status": "APPROVED"}

        approved_simulator = self.update_simulator_api_call(simulator_id=simulator_id, simulator_data=payload)
        return approved_simulator

    def rotate_verification_token(self):
        """
            This function rotates a verification token thus generating a new token

        Returns:
            dict: dict containing a new token
        """
        method = "POST"
        account_id = demisto.params().get("account_id")
        request_url = f"/config/v1/accounts/{account_id}/nodes/secret/rotate"

        new_token = self.get_response(url=request_url, method=method, body={})
        return new_token

    def create_user_data(self):
        """
            This function takes user inputs and then formats it and
            then calls create user endpoint.

        Returns:
            dict: created user data
        """
        account_id = self.account_id
        name = demisto.args().get("name", "").strip()
        email = demisto.args().get("email", "").strip()
        is_active = argToBoolean(demisto.args().get("is_active"))
        send_email_post_creation = argToBoolean(demisto.args().get("email_post_creation"))
        password = demisto.args().get("password")
        change_password = argToBoolean(demisto.args().get("change_password_on_create"))
        role = demisto.args().get("user_role", "").strip()
        deployment_list = demisto.args().get("deployments", None)
        try:
            deployment_list = list(map(int, deployment_list.split(","))) if deployment_list else []
        except ValueError:
            raise DemistoException(
                "Input Error: Deployments ids are numbers, please give deployments ids as comma separated values"
            )

        if not email:
            raise DemistoException(
                "Inputs Error: Email is necessary when creating user, please give a valid email which hasn't \
                been used before for user creation"
            )

        if not self.validate_email(email):
            raise DemistoException("Inputs Error: Please enter valid email")

        user_payload = {
            "name": name,
            "password": password,
            "email": email,
            "mustChangePassword": change_password,
            "sendMail": send_email_post_creation,
            "role": role,
            "isActive": is_active,
            "deployments": deployment_list,
        }

        method = "POST"
        url = f"/config/v1/accounts/{account_id}/users"
        created_user = self.get_response(url=url, method=method, body=user_payload)
        return created_user

    def update_user_data(self):
        """
            This function takes user inputs and then formats it and
            then makes a call to function that handles updating user.

        Returns:
            dict: updated user data
        """

        user_id = demisto.args().get("user_id")
        # user_email = demisto.args().get("email", "").strip()
        name = demisto.args().get("name", "")
        if name:
            name = name.strip()
        is_active = demisto.args().get("is_active")
        if is_active:
            is_active = argToBoolean(is_active)
        description = demisto.args().get("user_description", "")
        if description:
            description = description.strip()
        role = demisto.args().get("user_role", "")
        if role:
            role = role.strip()
        password = demisto.args().get("password")
        deployment_list = demisto.args().get("deployments", [])
        try:
            deployment_list = list(map(int, deployment_list.split(","))) if deployment_list else []
        except ValueError:
            raise DemistoException(
                "Input Error: deployments ids are numbers, please give deployments ids as comma separated values"
            )

        # formatting the update user payload, we remove false values after passing to function which calls endpoint
        details = {
            "name": name,
            "isActive": is_active,
            "deployments": deployment_list,
            "description": description,
            "role": role,
            "password": password,
        }
        user = self.update_user_with_details(user_id, details)
        return user

    def get_active_tests(self):
        """
            This function calls GET of active tests being run endpoint

        Returns:
            Dict: Returns test data as a dictionary per test which is array as value for "data" key
        """
        account_id = self.account_id

        method = "GET"
        url = f"/orch/v2/accounts/{account_id}/queue"
        tests = self.get_response(url=url, method=method)
        return tests

    def get_active_simulations(self):
        """
            This function calls GET of active tests being run endpoint

        Returns:
            Dict: Returns test data as a dictionary per test which is array as value for "data" key
        """
        method = "GET"
        url = "/execution/v2/tasks"
        simulations_details = self.get_response(url=url, method=method)
        return simulations_details

    def set_simulations_status(self):
        account_id = self.account_id

        method = "PUT"
        url = f"orch/v3/accounts/{account_id}/queue/state"
        data = {"status": demisto.args().get("simulation_or_test_state", "").strip()}
        simulations_details = self.get_response(url=url, method=method, body=data)
        return simulations_details

    def get_schedules(self):
        account_id = self.account_id

        method = "GET"
        url = f"/config/v1/accounts/{account_id}/schedules"
        request_params = {"details": "true", "deleted": "false"}
        schedule_data = self.get_response(url=url, method=method, request_params=request_params)
        return schedule_data

    def append_cron_to_schedule(self, schedules):
        for schedule in schedules:
            if schedule["cronString"]:
                schedule["user_schedule"] = CronString(schedule["cronString"], schedule["cronTimezone"]).to_string()
        return schedules

    def delete_schedule(self):
        account_id = self.account_id
        schedule_id = int(demisto.args().get("schedule_id"))

        method = "DELETE"
        url = f"/config/v2/accounts/{account_id}/plans/{schedule_id}"
        schedule_data = self.get_response(url=url, method=method)
        return schedule_data

    def extract_default_scenario_fields(self, scenarios):
        return_list = []
        for scenario in deepcopy(scenarios):
            return_obj = {"tags_list": "", "steps_order": ""}
            for key in scenario:
                if key == "tags" and scenario[key]:
                    return_obj["tags_list"] = ", ".join(scenario.get(key, []))
                elif key == "steps" and scenario[key]:
                    steps_involved = [step.get("name") for step in scenario[key]]
                    return_obj["steps_order"] = "; ".join(steps_involved)
                return_obj[key] = scenario[key]
            return_list.append(return_obj)
        return return_list

    def extract_custom_scenario_fields(self, scenarios):
        return_list = []
        for scenario in deepcopy(scenarios):
            return_obj = {"actions_list": "", "steps_order": "", "edges_count": 0}
            for key in scenario:
                if key == "actions" and scenario[key]:
                    actions_list = [
                        f"{action.get('type')} with identity: "
                        + f"{action.get('data',{}).get('uuid','') or action.get('data',{}).get('id','')}"
                        for action in scenario[key]
                    ]
                    return_obj["actions_list"] = "; ".join(actions_list)
                elif key == "steps" and scenario[key]:
                    steps_involved = [step.get("name") for step in scenario[key] if step.get("name") is not None]
                    return_obj["steps_order"] = "; ".join(steps_involved)
                return_obj[key] = scenario[key]
            return_obj["custom_data_object_for_rerun_simulation"] = json.dumps(
                {"name": return_obj.get("name"), "steps": return_obj.get("steps")}
            )
            return_list.append(return_obj)

        return return_list

    def extract_test_fields(self, test):
        return_obj = {"actions_list": "", "steps_order": "", "edges_count": 0}
        for key in test:
            if key == "actions" and test[key]:
                new_list = [f"{action.get('type')} with id:{action.get('id','')}" for action in test[key]]
                return_obj["actions_list"] = "; ".join(new_list)
            elif key == "steps" and test[key]:
                steps_involved = [
                    f"{step.get('name')}- with test ID {step.get('planRunId')}"
                    for step in test[key]
                    if step.get("name") is not None
                ]
                return_obj["steps_order"] = "; ".join(steps_involved)
            return_obj[key] = test[key]
        return return_obj

    def format_services_response(self, services):
        return_list = []
        for service in deepcopy(services):
            if isinstance(service, dict):
                # Now proceed with the formatting
                service[
                    "connection_status"
                ] = f"Service {service['name']} is {'running' if service['isUp'] else 'not running'} as on {service['lastCheck']}"
                return_list.append(service)
        return return_list

    def get_prebuilt_scenarios(self):
        method = "GET"
        url = "/content-manager/v18/scenarios"

        scenarios = self.get_response(url=url, method=method)
        return scenarios

    def get_custom_scenarios(self):
        account_id = self.account_id

        method = "GET"
        url = f"/config/v2/accounts/{account_id}/plans"
        request_params = {"details": demisto.args().get("schedule_details", "").strip()}
        scenarios = self.get_response(url=url, method=method, request_params=request_params)
        return scenarios

    def get_services_status(self):
        method = "GET"
        url = "/lighthouse/v1/services"
        services_data = self.get_response(url=url, method=method)
        return services_data

    def get_simulations(self):
        account_id = self.account_id
        method = "GET"
        url = f"/data/v1/accounts/{account_id}/executionsHistoryResults"

        request_params = {"runId": demisto.args().get("test_id")}

        simulations_data = self.get_response(url=url, method=method, request_params=request_params)
        return simulations_data

    def get_verification_token(self):
        account_id = self.account_id
        method = "GET"
        url = f"/config/v1/accounts/{account_id}/nodes/secret"
        verification_data = self.get_response(url=url, method=method)
        return verification_data

    def rerun_test_or_simulation(self):
        account_id = self.account_id
        test_data: dict
        if demisto.command() == "safebreach-rerun-test":
            test_data = {
                "testId": demisto.args().get("test_id"),
                "name": demisto.args().get("test_name", ""),
            }
        elif demisto.command() == "safebreach-rerun-simulation":
            simulation_ids = demisto.args().get("simulation_ids").strip()
            simulation_ids = simulation_ids.replace('"', "").split(",")
            simulations_list = []
            for simulation in simulation_ids:
                try:
                    simulations_list.append(int(simulation))
                except ValueError:
                    raise DemistoException(
                        "Input Error: simulation_ids are numbers and not strings, please \
                        enter valid simulation ids"
                    )
            test_data = {
                "name": demisto.args().get("test_name", "").strip(),
                "steps": [
                    {
                        "attacksFilter": {},
                        "attackerFilter": {},
                        "targetFilter": {},
                        "systemFilter": {"simulations": {"operator": "is", "values": simulations_list}},
                    }
                ],
            }
        method = "POST"
        url = f"/orch/v3/accounts/{account_id}/queue"
        tests_data = self.get_response(
            url=url, method=method, body={"plan": test_data}
        )  # , request_params=request_params)
        return tests_data

    def contains(self, list_a, list_b):
        return list(set(list_a) & set(list_b))

    def get_category_and_data_type_filters(self, insight_category, insight_data_type):
        # The User can provide the arguments as the following: insightCategory=`Web,Network Inspection`
        if isinstance(insight_category, str):
            insight_category = insight_category.split(",")
        if isinstance(insight_data_type, str):
            insight_data_type = insight_data_type.split(",")

        # if the user provide invalid category or data type raise an ValueError.
        if not self.contains(
            insight_category, ["Network Access", "Network Inspection", "Endpoint", "Email", "Web", "Data Leak"]
        ):
            raise ValueError(f"Category {insight_category} is not a valid category")
        if not self.contains(insight_data_type, ["Hash", "Domain", "URI", "Command", "Port", "Protocol"]):
            raise ValueError(f"Data type {insight_data_type} is not a valid data type")
        return insight_category, insight_data_type

    def get_insights_ids_by_category(self, insight_category):
        output = []
        for category in insight_category:
            if CATEGORY_MAPPER.get(category):
                output.append(CATEGORY_MAPPER.get(category))
        return list({y for x in output if x is not None for y in x})

    def get_insights(self, test_id):
        account_id = self.account_id
        url = f"/data/v1/accounts/{account_id}/insights?type=actionBased&planRunIds={test_id}"
        return self.get_response(url=url, method="GET")

    def get_remediation_data(self, insight_id, test_id):
        account_id = self.account_id
        url = f"/data/v1/accounts/{account_id}/insights/{insight_id}/remediation?planRunIds={test_id}"
        return self.get_response(url=url, method="GET")

    def get_insights_command(self, args, test_id):
        insight_ids = args.get("insightIds")
        insights = []
        if isinstance(insight_ids, str):
            insight_ids = literal_eval(insight_ids)
        if isinstance(insight_ids, int):
            insight_ids = [insight_ids]
        response = self.get_insights(test_id)

        try:
            insights = sorted(response, key=lambda i: i.get("ruleId"))
        except TypeError:
            demisto.debug("Failed to sort SafeBreach insights, skip")

        if insight_ids and len(insight_ids) > 0:
            # Verify that insight_ids holds List[int]
            if isinstance(insight_ids, list):
                insight_ids = list(map(int, insight_ids))
            insights = [item for item in insights if int(item.get("ruleId")) in insight_ids]

        return insights

    def extract_safebreach_error(self, response):
        errors = response.json().get("error") and response.json().get("error").get("errors")
        if not errors:
            return f'Failed to extract error!\n{response.json().get("error")}'
        return ",".join([e.get("data").get("message") for e in errors])

    def unescape_string(self, string):
        try:
            return string.encode("utf-8").decode("unicode_escape")
        except Exception as e:
            demisto.debug("Failed to unescape_string", e)

    def extract_data(self, data):
        output = []
        list_of_seen_items = []

        parent_key = list(data.keys())[0]
        first_level_data = list(data[parent_key].keys())
        list_of_seen_items.extend(first_level_data)
        if parent_key != "Attack":
            output.extend([{"type": parent_key, "value": o} for o in first_level_data])

        for indicator in data[parent_key]:
            if self.contains(SAFE_BREACH_TYPES, list(data[parent_key][indicator].keys())):
                for inner_type in data[parent_key][indicator]:
                    formated_inner_type = inner_type.replace(" ", "")
                    for item in data[parent_key][indicator][inner_type]:
                        if item == "N/A":
                            continue
                        if isinstance(item, str):
                            item = self.unescape_string(item)
                        if item not in list_of_seen_items:
                            list_of_seen_items.append(item)
                            output.append({"type": formated_inner_type, "value": item})
        return output

    def get_remediation_data_command(self, args, test_id):
        insight_id = args.get("insightId")
        response = self.get_remediation_data(insight_id, test_id)
        insight = self.get_insights_command({"insightIds": [insight_id]}, test_id)

        if insight:
            insight = insight[0]

        sb_remediation_data = response.get("remediationData")
        processed_data = self.extract_data(sb_remediation_data)
        return processed_data

    def is_ip(self, value):
        if isinstance(value, int):
            value = str(value)
        return re.match(IP_REGEX, value)

    def get_simulators_versions_list(self):
        url = "/updater/v2/updates/nodes"
        return self.get_response(url=url, method="GET")

    def get_installation_links(self):
        url = "/updater/v2/installationLinks"
        return self.get_response(url=url, method="GET")

    def update_simulator_with_id(self):
        nodeId = demisto.args().get("simulator_id", "")
        simulator_version = demisto.args().get("simulator_version", "")
        url = "/updater/v2/simulatorUpdate/"
        body_dict = {
            "enableUpdates": True,
            "nodeId": nodeId,
            "selectedVersion": simulator_version,
        }
        simulator_data = self.get_response(url=url, method="POST", body=body_dict)
        return simulator_data

    def get_indicators_command(self):
        indicators: list = []
        insights: Iterable[Any]
        count = 0
        limit = int(demisto.args().get("limit", 1000))
        insightCategory = demisto.args().get("insightCategory", "")
        insightDataType = demisto.args().get("insightDataType", "")
        test_id = demisto.args().get("test_id", 0)

        insight_category, insight_data_type = self.get_category_and_data_type_filters(insightCategory, insightDataType)

        # Convert category into insight id
        insights_ids = self.get_insights_ids_by_category(insight_category)
        raw_insights = self.get_insights(test_id)
        # Filter insight by category
        insights = [
            item for item in raw_insights if isinstance(item, dict) and int(item.get("ruleId", 0)) in insights_ids
        ]

        for insight in insights:
            # Fetch remediation data for each insight
            processed_data = self.get_remediation_data_command({"insightId": insight.get("ruleId")}, test_id)
            for item in processed_data:
                # if the data type is not in the filter data types continue,
                if INDICATOR_TYPE_SB_TO_DEMISTO_MAPPER.get(item["type"]) not in insight_data_type:
                    continue
                if not INDICATOR_TYPE_MAPPER.get(str(item["type"])) or item["value"] == "N/A":
                    continue
                if isinstance(item["type"], int):
                    demisto.debug("Data type is int", item["type"], insight["ruleId"])

                is_behavioral = item["type"] not in ["Domain", "FQDN/IP", "SHA256", "URI", "Hash"]
                raw_json = {
                    "value": str(item["value"]),
                    "dataType": item["type"],
                    "insightTime": insight.get("maxExecutionTime"),
                }
                attacks = filter(lambda x: x is not None, insight.get("attacks"))
                mapping = {
                    "description": "SafeBreach Insight - {}".format(insight["actionBasedTitle"]),
                    item["type"].lower(): item["value"],
                    "safebreachseverity": insight.get("severity"),
                    "safebreachseverityscore": str(insight.get("severityScore")),
                    "safebreachisbehavioral": is_behavioral,
                    "safebreachattackids": list(map(str, attacks)),
                    "tags": [
                        f"SafeBreachInsightId: {insight.get('ruleId')}",
                    ],
                }

                indicator = {
                    "value": str(item["value"]),
                    "type": INDICATOR_TYPE_MAPPER.get(str(item["type"])),
                    "rawJSON": raw_json,
                    "fields": mapping,
                }
                if self.is_ip(item["value"]):
                    indicator["type"] = FeedIndicatorType.IP

                count += 1
                if count > limit:
                    return indicators
                indicators.append(indicator)
        return indicators


def get_simulators_and_display_in_table(client: Client):
    """
        This function gets all simulators and displays in table

    Args:
        client (Client): Client class for API calls
        just_name (bool, optional): This will be used to know whether to search and return all
        simulators or only one. Defaults to False.

    Returns:
        CommandResults : table showing simulator details
        dict: simulator details
    """
    request_params = client.create_search_simulator_params()

    result = client.get_simulators_details(request_params=request_params)
    demisto.debug(f"Related simulations are: {result}")

    flattened_simulators, keys = client.flatten_simulator_details(result.get("data", {}).get("rows", {}))

    if flattened_simulators:
        human_readable = tableToMarkdown(name="Simulators Details", t=flattened_simulators, headers=keys)
    else:
        human_readable = f"No simulators found:- {flattened_simulators}"
    outputs = result.get("data", {}).get("rows")
    outputs_prefix = "SafeBreach.Simulator"
    result = CommandResults(outputs_prefix=outputs_prefix, outputs=outputs, readable_output=human_readable)
    return result


def format_simulations_data(simulations):
    return_list = []
    if simulations:
        for simulation in simulations:
            return_object = {}
            for key in simulation:
                if key in [
                    "id",
                    "targetNodeName",
                    "attackerNodeName",
                    "destNodeName",
                    "moveDesc",
                    "moveName",
                    "securityAction",
                    "resultDetails",
                ]:
                    return_object[key] = simulation.get(key)
                elif key == "Attack_Type":
                    return_object["attacks_involved"] = ", ".join([attack["displayName"] for attack in simulation[key]])
            return_list.append(return_object)
    return return_list


def get_specific_simulator_details(client: Client):
    """
        This function simulator details and displays in table

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults : table showing simulator details
        dict: simulator details
    """

    result = client.get_simulators_details_with_id()
    demisto.debug(f"Result of simulator details is: {result}")

    flattened_simulators, keys = client.flatten_simulator_details([result.get("data", {})])
    if flattened_simulators:
        human_readable = tableToMarkdown(name="Simulators Details", t=flattened_simulators, headers=keys)
    else:
        human_readable = f"No simulator details found: {flattened_simulators}"
    outputs = result.get("data", {})
    outputs_prefix = "SafeBreach.Simulator"
    result = CommandResults(outputs_prefix=outputs_prefix, outputs=outputs, readable_output=human_readable)
    return result


def tests_header_transformer(header):
    return_map = {
        "planId": "scenario_id",
        "planName": "scenario_name",
        "securityActionPerControl": "security_action_per_control",
        "planRunId": "test_id",
        "status": "status",
        "plannedSimulationsAmount": "planned_simulations_amount",
        "simulatorExecutions": "simulator_executions",
        "ranBy": "ran_by",
        "security_actions": "security_actions",
        "attack_executions": "attack_executions",
        "simulatorCount": "simulator_count",
        "endTime": "end_time",
        "startTime": "start_time",
        "stopped": "stopped",
        "missed": "missed",
        "logged": "logged",
        "detected": "detected",
        "prevented": "prevented",
    }
    return return_map.get(header, header)


def get_tests_summary(client: Client):
    """
        This function retrieves tests and then flattens them and shows them in  a table

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,dict: This returns a table view of data and a dictionary as output
    """
    test_summaries = client.get_tests_with_args()
    demisto.debug(f"Get tests summary is: {test_summaries}")
    client.flatten_test_summaries(test_summaries)
    if test_summaries:
        human_readable = tableToMarkdown(
            name="Test Results",
            t=test_summaries,
            headerTransform=tests_header_transformer,
            headers=[
                "planId",
                "planName",
                "planRunId",
                "status",
                "ranBy",
                "security_actions",
                "securityActionPerControl",
                "plannedSimulationsAmount",
                "simulatorExecutions",
                "simulatorCount",
                "attack_executions",
                "endTime",
                "startTime",
                "stopped",
                "missed",
                "logged",
                "detected",
                "prevented",
            ],
        )
    else:
        human_readable = f"No test summaries found: {test_summaries}"
    outputs = {"tests_data": test_summaries}
    result = CommandResults(outputs_prefix="SafeBreach.Test", outputs=outputs, readable_output=human_readable)

    return result


@metadata_collector.command(
    command_name="safebreach-get-all-users",
    inputs_list=None,
    outputs_prefix="SafeBreach.User",
    outputs_list=[
        OutputArgument(
            name="id",
            prefix="SafeBreach.User",
            output_type=int,
            description="The ID of User retrieved. this can be used to further link this user with\
                      user_id field of safebreach-update-user or safebreach-delete-user commands",
        ),
        OutputArgument(name="name", prefix="SafeBreach.User", output_type=str, description="The name of User retrieved."),
        OutputArgument(
            name="email",
            prefix="SafeBreach.User",
            output_type=str,
            description="The email of User retrieved. this can be used for updating user or\
                      deleting user for input email of commands safebreach-update-user or safebreach-delete-user ",
        ),
    ],
    description="This command gives all users who are not deleted.",
)
def get_all_users(client: Client):
    """
        This function is executed when 'safebreach-get-all-users' command is executed

    Args:
        client (Client): This is client class

    Returns:
        CommandResults,dict: This returns all user data retrieved based on given parameters,
        as a table and as a dictionary
    """
    user_data = client.get_users_list()
    demisto.debug(f"Get all users result is :{user_data}")

    if user_data:
        human_readable = tableToMarkdown(name="user data", t=user_data, headers=["id", "name", "email"])
    else:
        human_readable = f"No users found: {user_data}"
    result = CommandResults(outputs_prefix="SafeBreach.User", outputs=user_data, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-get-user-with-matching-name-or-email",
    inputs_list=[
        InputArgument(
            name="name", required=False, is_array=False, description="Name of the user. Partial match is supported"
        ),
        InputArgument(
            name="email", required=False, is_array=False, description="Email of the user. Exact match required"
        ),
    ],
    outputs_prefix="SafeBreach.User",
    outputs_list=[
        OutputArgument(
            name="id",
            prefix="SafeBreach.User",
            output_type=int,
            description="The ID of User retrieved. this can be used to further link this user with user_id field of \
                      safebreach-update-user or safebreach-delete-user commands",
        ),
        OutputArgument(name="name", prefix="SafeBreach.User", output_type=str, description="The name of User retrieved."),
        OutputArgument(
            name="email",
            prefix="SafeBreach.User",
            output_type=str,
            description="The email of User retrieved. this can be used for updating user or deleting user \
                      for input email of commands safebreach-update-user or safebreach-delete-user",
        ),
    ],
    description="The command retrieves users based on the provided inputs. "
    + "If an email is provided, it returns the user associated with that email, as email is a unique identifier"
    + "If a name is provided, exact name matching is required to ensure accurate retrieval of a single user;"
    + "otherwise, multiple users may be returned. It's essential to note that either a name or an email must be populated as input;"  # noqa: E501
    + "failure to provide either results in an error.",
)
def get_user_id_by_name_or_email(client: Client):
    """
        This Command Returns a user or their email by a given name or email.

    Args:
        client (Client): Client class for calling API

    Raises:
        Exception: Raised when no user with given name or email or found

    Returns:
        CommandResults,dict,Exception: We create a table showing all details related to users found and
        give JSON which has all data related to filtered users if any users match given criterion,
        else we raise an exception which is shown as error_result in XSOAR saying user is not found
    """

    name = demisto.args().get("name", "").strip()
    email = demisto.args().get("email", "").strip()
    if not (name or email):
        raise DemistoException("Incorrect inputs: either name or email are to be given.")
    user_list = client.get_users_list()
    demisto.debug(f"User list: {user_list}")

    filtered_user_list = list(
        filter(
            lambda user_data: (
                (name.lower() == user_data["name"].lower() if name else False)
                or (email.lower() == user_data["email"].lower())
            ),
            user_list,
        )
    )

    if filtered_user_list:
        human_readable = tableToMarkdown(name="user data", t=filtered_user_list, headers=["id", "name", "email"])
        outputs = filtered_user_list

        result = CommandResults(outputs_prefix="SafeBreach.User", outputs=outputs, readable_output=human_readable)

        return result
    raise DemistoException(f"User with name {name} was not found")


@metadata_collector.command(
    command_name="safebreach-create-user",
    inputs_list=[
        InputArgument(name="name", required=True, is_array=False, description="Name of the user to create."),
        InputArgument(name="email", required=True, is_array=False, description="Email of the user to Create."),
        InputArgument(
            name="is_active",
            description="If the user will be activated upon creation. Setting this parameter "
            + "to 'true' active as soon as this command succeeds. Setting to 'false', will require to activate the "
            + "user by an administrator. Possible values are: true, false. Default is true.",
            required=False,
            is_array=False,
            options=["true", "false"],
            default="true",
        ),
        InputArgument(
            name="email_post_creation",
            required=False,
            is_array=False,
            options=["true", "false"],
            default="true",
            description="Whether to send an email with login information to a newly crated user. Possible "
            + "values are: true, false. Default is false.",
        ),
        InputArgument(
            name="password",
            required=True,
            is_array=False,
            description="Enforce password change on user creation."
            + " Possible values are: true, false. Default is false.",
        ),
        InputArgument(
            name="change_password_on_create",
            required=False,
            is_array=False,
            options=["true", "false"],
            default="false",
            description="Should user change password on creation. when this is set to true then "
            + "user will have to reset password on the next login, this can be used if we want user to reset password "
            + "as soon as they login.",
        ),
        InputArgument(
            name="user_role",
            required=False,
            is_array=False,
            description="Role of the user being created. "
            + "Possible values are: viewer, administrator, contentDeveloper, operator. Default is viewer.",
            options=["viewer", "administrator", "contentDeveloper", "operator"],
            default="viewer",
        ),
        InputArgument(
            name="deployments",
            required=False,
            is_array=True,
            description="Comma separated ID of all deployments the user should be part of. The deployment IDs can "
            + "be retrieved from 'list-deployments' command or from UI directly but care should be noted that "
            + "only deployment ids of deployments which haven't been deleted will be shown here and after creation of "
            + "user. for example if 1,2,3 are deployment ids given while creation but if 2 is deleted then when user"
            + " is created , he will only have 1,3.",
        ),
    ],
    outputs_prefix="SafeBreach.User",
    outputs_list=[
        OutputArgument(name="id", description="The ID of User created.", prefix="SafeBreach.User", output_type=int),
        OutputArgument(
            name="name", description="The name of User created.", prefix="SafeBreach.User", output_type=str
        ),
        OutputArgument(
            name="email", description="The email of User created.", prefix="SafeBreach.User", output_type=str
        ),
        OutputArgument(
            name="createdAt", prefix="SafeBreach.User", output_type=str, description="The creation time of User."
        ),
        OutputArgument(
            name="roles",
            prefix="SafeBreach.User",
            output_type=str,
            description="The roles and permissions of User created.",
        ),
        OutputArgument(
            name="description",
            prefix="SafeBreach.User",
            output_type=str,
            description="The description of User if any is given at creation time, it will be populated here.",
        ),
        OutputArgument(
            name="role",
            prefix="SafeBreach.User",
            output_type=str,
            description="The role assigned to user during creation.",
        ),
        OutputArgument(
            name="deployments",
            prefix="SafeBreach.User",
            output_type=str,
            description="The deployments user is part of.",
        ),
    ],
    description="This command creates a user, including credentials and permissions.",
)
def create_user(client: Client):
    """
        This function is executed when 'safebreach-create-user' is called and this creates a user.
        This function calls another function which handles getting inputs and calling API,
        This function just handles creating table and returning table and json

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,dict: This will show a dictionary based on user data created
    """
    created_user = client.create_user_data()
    demisto.debug(f"Create user result is: {created_user}")
    if created_user:
        human_readable = tableToMarkdown(
            name="Created User Data",
            t=created_user.get("data", {}),
            headers=[
                "id",
                "name",
                "email",
                "mustChangePassword",
                "roles",
                "description",
                "role",
                "is_active",
                "deployments",
                "created_at",
            ],
        )
    else:
        human_readable = f"Unable to create user: {created_user}"
    outputs = created_user.get("data", {})
    result = CommandResults(
        outputs_prefix="SafeBreach.User",
        outputs=outputs,
        outputs_key_field="SafeBreach.User",
        readable_output=human_readable,
    )
    return result


@metadata_collector.command(
    command_name="safebreach-update-user",
    inputs_list=[
        InputArgument(
            name="user_id", required=True, is_array=False, description="user ID of user from safebreach to search."
        ),
        InputArgument(
            name="name",
            required=False,
            is_array=False,
            description="Update the user name to given value of " + "this field",
        ),
        InputArgument(
            name="user_description",
            required=False,
            is_array=False,
            description="Update the user Description to " + "given value in this field.",
        ),
        InputArgument(
            name="is_active",
            required=False,
            is_array=False,
            options=["true", "false", ""],
            default="",
            description=" Update the user Status based on the input, if this is set to false then user will be "
            + "deactivated. unless this field is left empty, whatever is present here will be updated to user details."
            + " user will be selected based on user_id field mentioned above.",
        ),
        InputArgument(
            name="password",
            required=False,
            is_array=False,
            description="Password of user to be updated with. "
            + "this will be used for changing password for user. unless this field is left empty, whatever is present "
            + "here will be updated to user details. user will be selected based on user_id field mentioned above.",
        ),
        InputArgument(
            name="user_role",
            required=False,
            is_array=False,
            options=["viewer", "administrator", "contentDeveloper", "operator"],
            default="",
            description=" Role of "
            + "the user to be changed to. unless you want to change the user role and permissions, dont select "
            + "anything in this field, user will be selected based on user_id field mentioned above.",
        ),
        InputArgument(
            name="deployments",
            required=False,
            is_array=True,
            description="Comma separated ID of all deployments the "
            + "user should be part of. unless this field is left empty, whatever is present here will be updated to"
            + " user details.incase there are old deployments assigned to user then please include them too, else "
            + "they will be replaced with new values.User will be selected based on user_id field mentioned above.",
        ),
    ],
    outputs_prefix="SafeBreach.User",
    outputs_list=[
        OutputArgument(
            name="id",
            prefix="SafeBreach.User",
            output_type=int,
            description="The ID of User whose data has been updated.",
        ),
        OutputArgument(
            name="name",
            prefix="SafeBreach.User",
            output_type=str,
            description="The name of User after running the update command according to safebreach records.",
        ),
        OutputArgument(
            name="email",
            prefix="SafeBreach.User",
            output_type=str,
            description="the email of the user whose data has been updated by the command.",
        ),
        OutputArgument(
            name="createdAt",
            prefix="SafeBreach.User",
            output_type=str,
            description="the time at which the user who has been selected has been created",
        ),
        OutputArgument(
            name="updatedAt",
            prefix="SafeBreach.User",
            output_type=str,
            description="The last updated time of User selected for update. \
                      this will be the execution time for the command or close to it.",
        ),
        OutputArgument(
            name="deletedAt",
            prefix="SafeBreach.User",
            output_type=str,
            description="The Deletion time of User selected to update. Generally this is empty unless\
                      user chosen to update is a deleted user",
        ),
        OutputArgument(
            name="roles",
            prefix="SafeBreach.User",
            output_type=str,
            description="The roles of User updated. these will change if role has been updated during\
                      updating user details else they will be same as pre update.",
        ),
        OutputArgument(
            name="description",
            prefix="SafeBreach.User",
            output_type=str,
            description="The description of User after updating user, if description field has been given any\
                      new value during update then its updated else this will be left unchanged from previous value.",
        ),
        OutputArgument(
            name="role",
            prefix="SafeBreach.User",
            output_type=str,
            description="The roles and permissions related to user who has been selected for update.unless this field\
                      has been given a value , this will not be updated and will stay the same as previous value.",
        ),
        OutputArgument(
            name="deployments",
            prefix="SafeBreach.User",
            output_type=str,
            description="The deployments related to user, this will be comma separated values of deployment IDs",
        ),
    ],
    description="This command updates a user with given data.",
)
def update_user_with_details(client: Client):
    """
        This function is executed when 'safebreach-update-user' command is being executed.
        This function will call another function which receives inputs from user and creates payload for upload user.

    Args:
        client (Client): Client class for API call

    Returns:
        CommandResults,dict: This function returns updated user in form of table and dictionary
    """
    updated_user = client.update_user_data()
    demisto.debug(f"Update user result is: {updated_user}")
    if updated_user.get("data", {}):
        human_readable = tableToMarkdown(
            name="Updated User Data",
            t=updated_user.get("data", {}),
            headers=[
                "id",
                "name",
                "email",
                "deletedAt",
                "roles",
                "description",
                "role",
                "deployments",
                "createdAt",
                "updatedAt",
            ],
        )
    else:
        human_readable = f"Unable to update user: {updated_user}"
    outputs = updated_user.get("data", {})
    result = CommandResults(outputs_prefix="SafeBreach.User", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-delete-user",
    inputs_list=[
        InputArgument(
            name="user_id",
            required=True,
            is_array=False,
            description="ID of user to be deleted. The Id can be retrieved by using get-all-users command.",
        ),
    ],
    outputs_prefix="SafeBreach.User",
    outputs_list=[
        OutputArgument(
            name="id",
            prefix="SafeBreach.User",
            output_type=int,
            description="The ID of User whose data has been deleted.",
        ),
        OutputArgument(
            name="name",
            prefix="SafeBreach.User",
            output_type=str,
            description="The name of User deleted.",
        ),
        OutputArgument(
            name="email", description="The email of User deleted.", prefix="SafeBreach.User", output_type=str
        ),
        OutputArgument(
            name="createdAt",
            prefix="SafeBreach.User",
            output_type=str,
            description="the time at which the user who has been selected has been created",
        ),
        OutputArgument(name="updatedAt", prefix="SafeBreach.User", output_type=str, description="last updated time."),
        OutputArgument(
            name="deletedAt", prefix="SafeBreach.User", output_type=str, description="Deletion time of user."
        ),
        OutputArgument(
            name="roles",
            description="The roles of User before they were deleted.",
            prefix="SafeBreach.User",
            output_type=str,
        ),
        OutputArgument(
            name="description",
            description="The description of User who has been deleted.",
            prefix="SafeBreach.User",
            output_type=str,
        ),
        OutputArgument(
            name="role",
            description="The roles and permissions of User who has been deleted.",
            prefix="SafeBreach.User",
            output_type=str,
        ),
        OutputArgument(
            name="deployments",
            description="The deployments related to user before he was deleted.",
            prefix="SafeBreach.User",
            output_type=str,
        ),
    ],
    description="This command deletes a user with given data.",
)
def delete_user_with_details(client: Client):
    """
        This function deletes user with given details, The inputs are being received in function which this function calls.
        It returns deleted user details

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,dict: This is details of user that has been deleted
    """
    deleted_user = client.delete_user()
    demisto.debug(f"Delete user result is: {deleted_user}")

    if deleted_user.get("data", {}):
        human_readable = tableToMarkdown(
            name="Deleted User Data",
            t=deleted_user.get("data", {}),
            headers=["id", "name", "email", "deletedAt", "roles", "description", "role", "deployments", "createdAt"],
        )
    else:
        human_readable = f"Unable to delete user: {deleted_user}"
    outputs = deleted_user.get("data", {})
    result = CommandResults(outputs_prefix="SafeBreach.User", outputs=outputs, readable_output=human_readable)
    return result


def deployment_transformer(header):
    return_map = {
        "id": "id",
        "accountId": "accountId",
        "name": "name",
        "createdAt": "createdAt",
        "description": "description",
        "nodes": "simulators",
        "updatedAt": "updatedAt",
    }

    return return_map.get(header, header)


@metadata_collector.command(
    command_name="safebreach-list-deployments",
    inputs_list=None,
    outputs_prefix="SafeBreach.Deployment",
    outputs_list=[
        OutputArgument(name="id", prefix="SafeBreach.Deployment", output_type=int, description="The ID of deployment"),
        OutputArgument(
            name="account_id",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The accountId of user who created the deployment.",
        ),
        OutputArgument(
            name="name",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The name of deployment.\
                        this will be the name shown in deployment name field of table in deployments page in safebreach UI",
        ),
        OutputArgument(
            name="created_at",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The creation date and time of deployment.",
        ),
        OutputArgument(
            name="updated_at",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The last updated date and time of deployment.",
        ),
        OutputArgument(
            name="description",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="This is description field of deployments table of safebreach UI",
        ),
        OutputArgument(
            name="simulators",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The simulators that are part of deployment.",
        ),
    ],
    description="This command gets all deployments present for this instance.",
)
def get_deployments(client: Client):
    """
        This function is executed on command "safebreach-list-deployments"

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,dict:Deployment data as a table and a dictionary
    """
    deployments = client.list_deployments()
    demisto.debug(f"Get deployment list result is: {deployments}")

    if deployments:
        human_readable = tableToMarkdown(
            name="Deployments",
            t=deployments,
            headerTransform=deployment_transformer,
            headers=["id", "accountId", "name", "createdAt", "description", "nodes", "updatedAt"],
        )
    else:
        human_readable = f"No deployments found: {deployments}"
    outputs = deployments
    result = CommandResults(outputs_prefix="SafeBreach.Deployment", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-create-deployment",
    inputs_list=[
        InputArgument(
            name="name",
            required=True,
            is_array=False,
            description="Name of the deployment to create. this will "
            + "be shown as name in deployments page of safebreach",
        ),
        InputArgument(
            name="description",
            required=False,
            is_array=False,
            description="Description of the deployment to create. This will show as description of the deployment "
            + "in your safebreach instance. It is generally preferable to give description while creating a deployment "
            + "for easier identification",
        ),
        InputArgument(
            name="simulators",
            required=False,
            is_array=True,
            description="Deployment manages multiple simulators as "
            + "single group. This parameter receives a comma separated list of IDs of all simulators that should be "
            + "part of this deployment Simulator ID can be retrieved from safebreach-get-all-simulator-details .",
        ),
    ],
    outputs_prefix="SafeBreach.Deployment",
    outputs_list=[
        OutputArgument(
            name="id",
            prefix="SafeBreach.Deployment",
            output_type=int,
            description="The ID of deployment created. this Id can be used to update ,delete deployment as\
                      deployment_id field of the deployment.",
        ),
        OutputArgument(
            name="account_id",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="This field shows account ID of user who has created the account.",
        ),
        OutputArgument(
            name="name",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The name of deployment created. this will be name which will be shown on deployments page\
                      of safebreach and name that is given as input to the command.",
        ),
        OutputArgument(
            name="created_at",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The creation date and time of deployment , this will be closer to\
                      command execution time if the deployment creation is successful.",
        ),
        OutputArgument(
            name="description",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The description of the deployment created will be shown in description \
                          part of the table in safebreach.",
        ),
        OutputArgument(
            name="simulators",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The simulators that are part of deployment.",
        ),
    ],
    description="This command creates a deployment, grouping the list of simulators provided with"
    + " a name and optionally a description.",
)
def create_deployment(client: Client):
    """
        This function is executed on command "safebreach-create-deployment"

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,dict: Created deployment data as a table and a dictionary
    """
    created_deployment = client.create_deployment_data()
    demisto.debug(f"Create deployment result is: {created_deployment}")

    if created_deployment:
        human_readable = tableToMarkdown(
            name="Created Deployment",
            t=created_deployment.get("data", {}),
            headerTransform=deployment_transformer,
            headers=["id", "accountId", "name", "createdAt", "description", "nodes"],
        )
    else:
        human_readable = f"Unable to create deployment: {created_deployment}"
    outputs = created_deployment.get("data", {})
    result = CommandResults(outputs_prefix="SafeBreach.Deployment", outputs=outputs, readable_output=human_readable)

    return result


@metadata_collector.command(
    command_name="safebreach-update-deployment",
    inputs_list=[
        InputArgument(
            name="deployment_id",
            required=True,
            is_array=False,
            description="ID of the deployment to update. " + "Can be searched with list-deployments command.",
        ),
        InputArgument(
            name="updated_simulators_for_deployment",
            required=False,
            is_array=False,
            description="Comma separated ID of all simulators to be part of the deployment Simulators can be "
            + " retrieved by calling get-all-available-simulator-details command",
        ),
        InputArgument(name="updated_deployment_name", required=False, is_array=False, description="Deployment name"),
        InputArgument(
            name="updated_deployment_description", required=False, is_array=False, description="Deployment description."
        ),
    ],
    outputs_prefix="SafeBreach.Deployment",
    outputs_list=[
        OutputArgument(
            name="id",
            prefix="SafeBreach.Deployment",
            output_type=int,
            description="The ID of deployment whose values have been updated.\
                          ID cant be changed so this wont be updated.",
        ),
        OutputArgument(
            name="account_id",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The accountId of user who created the deployment.",
        ),
        OutputArgument(
            name="name",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The name of deployment which has been updated to the name given in updated_deployment_name.\
                        this will be the name shown in deployment name field of table in deployments page in safebreach UI",
        ),
        OutputArgument(
            name="created_at",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The creation date and time of deployment whose data has been updated.",
        ),
        OutputArgument(
            name="updated_at",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The last updated date and time of deployment whose data has been updated.\
                      This will generally be closer to the update deployment command run time for reference",
        ),
        OutputArgument(
            name="description",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The updated description of deployment which is provided in updated_deployment_description\
                      field of input . This will now be the description which is shown in description field of deployments\
                      table of safebreach UI",
        ),
        OutputArgument(
            name="simulators",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The simulators that are part of deployment. unless any simulators are given as input this \
                          field won't be updated this field doesn't reflect changes if simulators given as input are deleted",
        ),
    ],
    description="This command updates a deployment with given data. The deployment_id field of this command can be retrieved "
    + "from 'safebreach-list-deployments' command. If the user wants to search with deployment ID then they can search it ",
)
def update_deployment(client: Client):
    """
        This function is executed on command "safebreach-update-deployment"

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,dict: updated deployment data as a table and a dictionary
    """
    updated_deployment = client.update_deployment()
    demisto.debug(f"Update deployment result is: {updated_deployment}")

    if updated_deployment:
        human_readable = tableToMarkdown(
            name="Updated Deployment",
            t=updated_deployment.get("data", {}),
            headerTransform=deployment_transformer,
            headers=["id", "accountId", "name", "createdAt", "description", "nodes", "updatedAt"],
        )
    else:
        human_readable = f"Unable to update deployment: {updated_deployment}"
    outputs = updated_deployment.get("data", {})
    result = CommandResults(outputs_prefix="SafeBreach.Deployment", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-delete-deployment",
    inputs_list=[
        InputArgument(
            name="deployment_id",
            required=True,
            is_array=False,
            description="ID of the deployment to delete. " + "The ID his can be searched with list-deployments command",
        )
    ],
    outputs_prefix="SafeBreach.Deployment",
    outputs_list=[
        OutputArgument(
            name="id",
            prefix="SafeBreach.Deployment",
            output_type=int,
            description="The ID of deployment which has been deleted.",
        ),
        OutputArgument(
            name="account_id",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The account Id of user who deleted the deployment.",
        ),
        OutputArgument(
            name="name",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The name of deployment before the deployment was deleted.",
        ),
        OutputArgument(
            name="created_at",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The creation date and time of deployment which has been deleted.",
        ),
        OutputArgument(
            name="description",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The description of deployment before it was deleted.",
        ),
        OutputArgument(
            name="simulators",
            prefix="SafeBreach.Deployment",
            output_type=str,
            description="The simulators that are part of deployment before it was deleted.",
        ),
    ],
    description="This command deletes a deployment with the deployment_id (retrieved using the get-all-deployments command).",
)
def delete_deployment(client: Client):
    """
        This function is executed on command "safebreach-delete-deployment"

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,dict: deleted deployment data as a table and a dictionary
    """
    deleted_deployment = client.delete_deployment()
    demisto.debug(f"Delete deployment result is: {deleted_deployment}")

    if deleted_deployment:
        human_readable = tableToMarkdown(
            name="Deleted Deployment",
            t=deleted_deployment.get("data", {}),
            headerTransform=deployment_transformer,
            headers=["id", "accountId", "name", "createdAt", "description", "nodes", "updatedAt"],
        )
    else:
        human_readable = f"Unable to delete deployment: {deleted_deployment}"
    outputs = deleted_deployment.get("data", {})
    result = CommandResults(outputs_prefix="SafeBreach.Deployment", outputs=outputs, readable_output=human_readable)
    return result


def apikey_transformer(header):
    return_map = {
        "name": "name",
        "description": "description",
        "createdAt": "created_at",
        "createdBy": "created_by",
        "deletedBy": "deleted_by",
        "updatedBy": "updated_by",
        "key": "key",
    }

    return return_map.get(header, header)


@metadata_collector.command(
    command_name="safebreach-generate-api-key",
    inputs_list=[
        InputArgument(
            name="name",
            required=True,
            is_array=False,
            description="""
                      Name of the API Key to create. This will be the name shown in UI for API key under API keys section
                      """,
        ),
        InputArgument(
            name="description",
            required=False,
            is_array=False,
            description="""
                      Description of the API Key to create. This is not a required field but it is recommended to store a
                      description for easier identification if your use case requires using multiple API keys for multiple tasks.
                      """,
        ),
    ],
    outputs_prefix="SafeBreach.API",
    outputs_list=[
        OutputArgument(
            name="name",
            prefix="SafeBreach.API",
            output_type=str,
            description="The Name of API Key generated through this command, \
                          This will match the input name of the command.",
        ),
        OutputArgument(
            name="description",
            prefix="SafeBreach.API",
            output_type=str,
            description="The Description of API Key created. \
                          this will be same as input description given for the command.",
        ),
        OutputArgument(
            name="created_by",
            prefix="SafeBreach.API",
            output_type=str,
            description="The id of user who generated this API key.",
        ),
        OutputArgument(
            name="created_bt",
            prefix="SafeBreach.API",
            output_type=str,
            description="The creation date and time of API key.",
        ),
        OutputArgument(
            name="key",
            prefix="SafeBreach.API",
            output_type=str,
            description="The value of API key generated. store this for further use as this will only be shown once",
        ),
    ],
    description="This command creates an API key with the name and optionally the description provided. The API key created "
    + "will be shown on the Settings > API Keys page of SafeBreach Management. Important: The API key generated can be seen "
    + "only once, so it is recommended to store/save it in a safe place for further use.",
)
def create_api_key(client: Client):
    """
        This function generates API key and returns API key, Executed for command 'safebreach-generate-api-key'

    Args:
        client (Client): Client class for API call

    Returns:
        CommandResults,dict: Command results for generated API key details table and dict containing data
    """
    generated_api_key = client.generate_api_key()
    demisto.debug(f"Generated API key is: {generated_api_key}")
    if generated_api_key:
        human_readable = tableToMarkdown(
            name="Generated API key Data",
            headerTransform=apikey_transformer,
            t=generated_api_key.get("data"),
            headers=["name", "description", "createdBy", "createdAt", "key"],
        )
    else:
        human_readable = f"Unable to generate API key: {generated_api_key}"
    outputs = generated_api_key.get("data")

    result = CommandResults(outputs_prefix="SafeBreach.API", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-delete-api-key",
    inputs_list=[
        InputArgument(
            name="key_name",
            required=True,
            is_array=False,
            description="Name of the API Key to Delete. This will be "
            + "used for searching key with given name and then once it matches, that API key will be deleted.",
        ),
    ],
    outputs_prefix="SafeBreach.API",
    outputs_list=[
        OutputArgument(
            name="name", description="The Name of API Key deleted.", prefix="SafeBreach.API", output_type=int
        ),
        OutputArgument(
            name="description", description="Description of API Key deleted.", prefix="SafeBreach.API", output_type=str
        ),
        OutputArgument(
            name="created_by",
            description="The id of user who generated this API key.",
            prefix="SafeBreach.API",
            output_type=str,
        ),
        OutputArgument(
            name="created_at",
            description="The creation time and date of API key.",
            prefix="SafeBreach.API",
            output_type=str,
        ),
        OutputArgument(
            name="deleted_at",
            prefix="SafeBreach.API",
            output_type=str,
            description="The deletion time and date of API key. The deletion date and time are generally\
                      close to the command execution time and date.",
        ),
    ],
    description="This command deletes the API key with the name as specified in SafeBreach Management. It is not case sensitive.",
)
def delete_api_key(client: Client):
    """
        This function deletes API key and returns API key, Executed for command 'safebreach-delete-api-key'

    Args:
        client (Client): Client class for API call

    Returns:
        CommandResults,dict: Command results for deleted API key details table and dict containing data
    """
    deleted_api_key = client.delete_api_key()
    demisto.debug(f"Delete API key is: {deleted_api_key}")
    if deleted_api_key.get("data"):
        human_readable = tableToMarkdown(
            name="Deleted API key Data",
            t=deleted_api_key.get("data"),
            headerTransform=apikey_transformer,
            headers=["name", "description", "createdBy", "createdAt", "deletedAt"],
        )
    else:
        human_readable = f"Unable to delete API key: {deleted_api_key}"
    outputs = deleted_api_key.get("data")
    result = CommandResults(outputs_prefix="SafeBreach.API", outputs=outputs, readable_output=human_readable)
    return result


def integration_issues_transformer(header):
    return_map = {
        "connector": "integration_id",
        "action": "action",
        "success": "success_state",
        "error": "error_description",
        "timestamp": "timestamp",
    }
    return return_map.get(header, header)


@metadata_collector.command(
    command_name="safebreach-get-integration-issues",
    inputs_list=[
        InputArgument(
            name="error_type",
            required=False,
            is_array=False,
            options=["", "ERROR", "WARNING"],
            description="this will help see issues which are either errors or warnings or both based on the input ",
        ),
    ],
    outputs_prefix="SafeBreach.Integration",
    outputs_list=[
        OutputArgument(
            name="integration_id",
            prefix="SafeBreach.Integration",
            output_type=int,
            description="The ID of Integration. A general notation that has been followed here is\
                      as follows, if the  id has _default at the end then its a default connector else its a custom connector",
        ),
        OutputArgument(
            name="integration_name",
            prefix="SafeBreach.Integration",
            output_type=str,
            description="Name of the integration",
        ),
        OutputArgument(
            name="action",
            prefix="SafeBreach.Integration",
            output_type=str,
            description="The action of Integration error. This describes where exactly did the error occur,\
                        if its search,then it implies error/warning happened when connector was trying that process",
        ),
        OutputArgument(
            name="success_state",
            prefix="SafeBreach.Integration",
            output_type=str,
            description="status of integration error. This implies whether the connector was able to \
                      successfully perform the operation or if it failed partway. \
                      So false implies it failed partway and true implies it was successfully completed",
        ),
        OutputArgument(
            name="error_description",
            prefix="SafeBreach.Integration",
            output_type=str,
            description="This is the exact error description shown on safebreach integration error/warning page.\
                        This description can be used for understanding of what exactly happened for the integration to fail.",
        ),
        OutputArgument(
            name="timestamp",
            prefix="SafeBreach.Integration",
            output_type=str,
            description="Time at which error/warning occurred. This can be used to pinpoint error which occurred\
                      across integrations if time of origin was remembered",
        ),
    ],
    description="This command gives all integrations related issues and warning. this will show the integrations error and"
    + " warnings which are generally displayed in installed integrations page.",
)
def get_all_integration_error_logs(client: Client):
    """
        This function retrieves all error logs and shows them in form of table

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,Dict: This function returns all errors along with integration details in a table and we get data as json
    """
    formatted_error_logs = []
    error_logs = client.get_all_integration_error_logs()
    if error_logs is None:
        raise ValueError("Failed to retrieve integration error logs")
    demisto.debug(f"Get all integration error logs result is: {error_logs}")

    formatted_error_logs = client.flatten_error_logs_for_table_view(error_logs.get("result"))
    if formatted_error_logs:
        human_readable = tableToMarkdown(
            name="Integration errors",
            headerTransform=integration_issues_transformer,
            t=formatted_error_logs,
            headers=["connector", "action", "success", "error", "timestamp", "integration_name"],
        )
    else:
        human_readable = f"No integration {demisto.args().get('error_type')} logs found: {formatted_error_logs}"
    outputs = error_logs.get("result")
    result = CommandResults(outputs_prefix="SafeBreach.Integration", outputs=outputs, readable_output=human_readable)
    return result


def get_integration_details(client: Client):
    connector_details = client.get_integration_details()
    demisto.debug(f"Get integration details result is: {connector_details}")

    installed_connectors = connector_details.get("result", {}).get("providers", [])
    connectors_map = {}
    for connector in installed_connectors:
        connectors_map[connector["id"]] = connector["name"]

    return connectors_map


@metadata_collector.command(
    command_name="safebreach-clear-integration-issues",
    inputs_list=[
        InputArgument(
            name="integration_id",
            required=True,
            is_array=False,
            description="The ID of Integration to have its errors/warnings deleted. "
            + "Both errors and warnings will be deleted.",
        ),
    ],
    outputs_prefix="SafeBreach.Integration",
    outputs_list=[
        OutputArgument(
            name="error",
            description="Error count after deletion of errors for the given Integration.",
            prefix="SafeBreach.Integration",
            output_type=int,
        ),
        OutputArgument(
            name="result",
            description="error deletion status whether true or false.",
            prefix="SafeBreach.Integration",
            output_type=str,
        ),
    ],
    description="This command deletes connector-related errors and warnings for the specified connector_id"
    + " (retrieved using the get-all-integration-issues command).",
)
def delete_integration_error_logs(client: Client):
    """
        This function deletes integration errors of a given integration

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,Dict: This returns a table of data showing deleted details and dict showing same in outputs
    """
    error_logs = client.delete_integration_error_logs()
    demisto.debug(f"Delete integration error logs result is: {error_logs}")
    headers = ["result", "error"]
    if error_logs.get("errorMessage"):
        headers = ["error", "errorMessage"]
    if error_logs:
        human_readable = tableToMarkdown(name="Integration errors status", t=error_logs, headers=headers)
    else:
        human_readable = f"Unable to delete integration error logs: {error_logs}"
    outputs = error_logs
    result = CommandResults(outputs_prefix="SafeBreach.Integration", outputs=outputs, readable_output=human_readable)
    return result


def simulator_count_transformer(header):
    return_map = {
        "contactName": "contact_name",
        "contactEmail": "contact_email",
        "userQuota": "user_quota",
        "nodesQuota": "simulator_quota",
        "registrationDate": "registration_date",
        "activationDate": "activation_date",
        "expirationDate": "expiration_date",
    }
    return return_map.get(header, header)


@metadata_collector.command(
    command_name="safebreach-get-available-simulator-count",
    inputs_list=None,
    outputs_prefix="SafeBreach.Account",
    outputs_list=[
        OutputArgument(
            name="id",
            prefix="SafeBreach.Account",
            output_type=int,
            description="The account ID which is being used by integration.",
        ),
        OutputArgument(
            name="name",
            description="The Account Name of account being queried.",
            prefix="SafeBreach.Account",
            output_type=str,
        ),
        OutputArgument(
            name="contact_name",
            description="Contact name for given account.",
            prefix="SafeBreach.Account",
            output_type=str,
        ),
        OutputArgument(
            name="contact_email", description="Email of the contact person.", prefix="SafeBreach.Account", output_type=str
        ),
        OutputArgument(
            name="user_quota",
            prefix="SafeBreach.Account",
            output_type=str,
            description="User Quota for the given account, maximum users which are allowed for the account.",
        ),
        OutputArgument(
            name="simulators_quota",
            prefix="SafeBreach.Account",
            output_type=int,
            description="The simulator quota for the given account. The maximum number of "
            + "simulators which are available for the account.",
        ),
        OutputArgument(
            name="registration_date",
            description="The registration date of given account.",
            prefix="SafeBreach.Account",
            output_type=int,
        ),
        OutputArgument(
            name="activation_date",
            description="The Activation date of given account.",
            prefix="SafeBreach.Account",
            output_type=str,
        ),
        OutputArgument(
            name="expiration_date", description="Account expiration date.", prefix="SafeBreach.Account", output_type=str
        ),
    ],
    description="This command gives all details related to account, we are using this to find assigned simulator quota.",
)
def get_simulator_quota_with_table(client: Client):
    """
        This will be used to show account simulator quota and details in table

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,dict: this shows a table with account details and a dict with account details
    """
    simulator_details = client.get_simulator_quota()
    demisto.debug(f"Simulator details result is: {simulator_details}")
    if simulator_details.get("data"):
        human_readable = tableToMarkdown(
            name="Account Details",
            t=simulator_details.get("data"),
            headerTransform=simulator_count_transformer,
            headers=[
                "id",
                "name",
                "contactName",
                "contactEmail",
                "userQuota",
                "nodesQuota",
                "registrationDate",
                "activationDate",
                "expirationDate",
            ],
        )
    else:
        human_readable = f"Unable to get simulator quota and details: {simulator_details}"
    outputs = {
        "account_details": simulator_details.get("data"),
        "simulator_quota": simulator_details.get("data").get("nodesQuota"),
    }
    simulator_details = CommandResults(
        outputs_prefix="SafeBreach.Account", outputs=outputs, readable_output=human_readable
    )
    return simulator_details


@metadata_collector.command(
    command_name="safebreach-get-available-simulator-details",
    inputs_list=simulator_details_inputs,
    outputs_prefix="SafeBreach.Simulator",
    outputs_list=simulators_output_fields,
    description="This command to get all available simulators. if details is set to true then it retrieves simulator details "
    + "like name, hostname, internal and external ips, types of targets and attacker configurations this simulator is associated "
    + "with etc. if its set to false then it retrieves just name, id, simulation users, proxies etc. if deleted is set to true "
    + "then it retrieves the data which has been deleted.",
)
def get_all_simulator_details(client: Client):
    """
        This function returns simulator details of all simulators

    Args:
        client (Client): Client class for API calls

    Returns:
        List(dict): This is list of all simulators data
    """
    return get_simulators_and_display_in_table(client=client)


@metadata_collector.command(
    command_name="safebreach-get-simulator-with-id",
    inputs_list=[InputArgument(name="simulator_id", required=True, is_array=False, description="simulator id")],
    outputs_prefix="SafeBreach.Simulator",
    outputs_list=simulators_output_fields,
    description="This command gives simulator with given id",
)
def get_simulator_with_name(client: Client):
    """
        this function returns simulator with given name as  table and dict

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,data: This is data of simulator with given name
    """
    return get_specific_simulator_details(client=client)


@metadata_collector.command(
    command_name="safebreach-delete-simulator",
    inputs_list=[
        InputArgument(
            name="simulator_id", required=True, is_array=False, description="Id of the simulator we want to delete"
        )
    ],
    outputs_prefix="SafeBreach.Simulator",
    outputs_list=simulators_output_fields,
    description="The provided command facilitates the deletion of a simulator identified by its unique ID."
    + "To obtain the respective simulator ID, execute the \"safebreach-get-all-simulators\" command."
)
def delete_simulator_with_given_name(client: Client):
    """
        This function deletes simulator with given id

    Args:
        client (Client): This is client class for API calls

    Returns:
        CommandResults,Dict: this is for table showing deleted simulator data and dict with data
    """
    deleted_simulator = client.delete_simulator_with_given_name()
    demisto.debug(f"Delete simulator with given name result is: {deleted_simulator}")
    flattened_simulators, keys = client.flatten_simulator_details([deleted_simulator.get("data", {})])
    if flattened_simulators:
        human_readable = tableToMarkdown(name="Deleted Simulators Details", t=flattened_simulators, headers=keys)
    else:
        human_readable = f"Unable to delete simulator with given ID: {flattened_simulators}"
    outputs = deleted_simulator.get("data", {})
    result = CommandResults(outputs_prefix="SafeBreach.Simulator", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-update-simulator",
    inputs_list=[InputArgument(name="simulator_id", required=True, is_array=False, description="Simulator ID.")]
    + simulator_details_for_update_fields,
    outputs_prefix="SafeBreach.Simulator",
    outputs_list=simulators_output_fields,
    description="This command updates simulator with given id. the given inputs for update fields will be "
    + "updated to the selected filed values will be updated to given value.",
)
def update_simulator(client: Client):
    """
        This function updates simulator with given data having name as given input

    Args:
        client (Client): This is client class for API calls

    Returns:
        CommandResults,Dict: This will return table and dict containing updated simulator data
    """
    updated_simulator = client.update_simulator()
    demisto.debug(f"Update simulator result is: {updated_simulator}")
    flattened_simulators, keys = client.flatten_simulator_details([updated_simulator.get("data", {})])
    if flattened_simulators:
        human_readable = tableToMarkdown(name="Updated Simulators Details", t=flattened_simulators, headers=keys)
    else:
        human_readable = f"Unable to update simulator: {flattened_simulators}"
    outputs = updated_simulator.get("data", {})
    result = CommandResults(outputs_prefix="SafeBreach.Simulator", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-approve-simulator",
    inputs_list=[
        InputArgument(
            name="simulator_id",
            required=True,
            is_array=False,
            description="ID of simulator to approve, in case "
            + "unsure then please call safebreach-get-all-simulators and search for simulator name.",
        )
    ],
    outputs_prefix="SafeBreach.Simulator",
    outputs_list=simulators_output_fields,
    description="This command approves the simulator with the specified simulator_id.",
)
def approve_simulator(client: Client):
    """
        This function approves simulator with given data having name as given input

    Args:
        client (Client): This is client class for API calls

    Returns:
        CommandResults,Dict: This will return table and dict containing approved simulator data
    """
    approved_simulator = client.approve_simulator()
    demisto.debug(f"Approve simulator result is: {approved_simulator}")
    flattened_simulators, keys = client.flatten_simulator_details([approved_simulator.get("data", {})])
    if flattened_simulators:
        human_readable = tableToMarkdown(name="Approved Simulators Details", t=flattened_simulators, headers=keys)
    else:
        human_readable = f"Unable to approve simulator: {flattened_simulators}"
    outputs = approved_simulator.get("data", {})
    result = CommandResults(
        outputs_prefix="SafeBreach.Simulator", outputs=outputs, readable_output=human_readable
    )
    return result


@metadata_collector.command(
    command_name="safebreach-rotate-verification-token",
    inputs_list=None,
    outputs_prefix="SafeBreach.Token",
    outputs_list=[
        OutputArgument(
            name="new_token", output_type=str, description="New token which has been generated due to the API call"
        ),
    ],
    description="This command rotates generated verification token meaning it creates a new token which will be used for "
    + "verification of simulator and adding the simulator.",
)
def return_rotated_verification_token(client: Client):
    """
        This function is called when rotate-verification-token command is called and will
        help with calling API of rotate verification token
    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,Dict: This returns a table showing new token and a dict as output stating same
    """
    new_token = client.rotate_verification_token()
    if new_token.get("data"):
        human_readable = tableToMarkdown(name="New Token Details", t=new_token.get("data"), headers=["secret"])
    else:
        human_readable = f"Unable to rotate verification token: {new_token}"
    outputs = new_token.get("data", {}).get("secret", "")
    result = CommandResults(outputs_prefix="SafeBreach.Token", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-get-tests",
    inputs_list=None,
    outputs_prefix="SafeBreach.Test",
    outputs_list=test_summaries_output_fields,
    description="This command gets tests with given modifiers.",
)
def get_all_tests_summary(client: Client):
    """
        This function gets all tests summary and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns all tests related summary as a table and gives a dictionary as outputs for the same
    """
    return get_tests_summary(client=client)


@metadata_collector.command(
    command_name="safebreach-get-tests-with-scenario-id",
    inputs_list=[
        InputArgument(
            name="scenario_id",
            required=True,
            is_array=False,
            description="Scenario Id for test which has to be filtered. this can be found on UI, if unsure about this "
            + "then please run safebreach-get-tests instead of this with same parameters as inputs.",
        )
    ],
    outputs_prefix="SafeBreach.Test",
    outputs_list=test_summaries_output_fields,
    description="This command gets tests with given scenario ID as part of it.",
)
def get_all_tests_summary_with_scenario_id(client: Client):
    """
        This function takes scenario ID and returns test summaries with that scenario ID

    Args:
        client (Client): Client class for API calls

    Returns:
        CommandResults,List(dict): This will return  a table with all details and
        a list of dictionaries with details related to tests with given scenario ID
    """
    return get_tests_summary(client=client)


@metadata_collector.command(
    command_name="safebreach-delete-test-with-id",
    inputs_list=[
        InputArgument(name="test_id", description="Id of test to be deleted.", required=True, is_array=False),
    ],
    outputs_prefix="SafeBreach.Test",
    outputs_list=test_summaries_output_fields,
    description="This command deletes tests with given test ID.",
)
def delete_test_result_of_test(client: Client):
    """
        This function deletes test with given Test ID

    Args:
        client (Client): Client class for API call

    Returns:
        CommandResults,Dict: A table showing deletion results and a dict of outputs showing the same
    """
    test_summaries = client.delete_test_result_of_test()
    demisto.debug(f"Delete test with ID result is: {test_summaries}")
    if test_summaries.get("data"):
        human_readable = tableToMarkdown(name="Deleted Test", t=test_summaries.get("data", {}), headers=["id"])
    else:
        human_readable = f"Unable to delete test result with given test Id: {test_summaries}"
    outputs = [test_summaries.get("data")]
    result = CommandResults(outputs_prefix="SafeBreach.Test", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-get-running-tests",
    inputs_list=None,
    outputs_prefix="SafeBreach.Test",
    outputs_list=tests_outputs,
    description="This command gets tests which are in running state.",
)
def get_all_running_tests_summary(client: Client):
    """
        This function gets all running tests summary and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns all tests related summary as a table and gives a dictionary as outputs for the same
    """
    running_tests = client.get_active_tests()
    demisto.debug(f"Get all running tests summary result is: {running_tests}")

    flattened_running_tests_for_table = client.flatten_tests_data(running_tests.get("data", {}))
    if flattened_running_tests_for_table:
        human_readable = tableToMarkdown(
            name="Running Tests",
            t=flattened_running_tests_for_table,
            headerTransform=test_outputs_headers_transform,
            headers=test_outputs_headers_list,
        )
    else:
        human_readable = f"No running tests summary found: {flattened_running_tests_for_table}"
    outputs = running_tests
    result = CommandResults(outputs_prefix="SafeBreach.Test", outputs=outputs, readable_output=human_readable)

    return result


def simulations_output_transform(header):
    return_map = {
        "jobId": "simulation_id",
        "moveId": "attack_id",
        "timestamp": "timestamp",
        "planRunId": "test_id",
        "simulator_ids_involved": "simulator_ids_involved",
        "simulator_names_involved": "simulator_names_involved",
    }
    return return_map.get(header, header)


@metadata_collector.command(
    command_name="safebreach-get-running-simulations",
    inputs_list=None,
    outputs_prefix="SafeBreach.Test",
    outputs_list=[
        OutputArgument(
            name="test id", description="this is test ID of the simulation.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="simulation_id",
            description="the simulation id of the simulation.",
            prefix="SafeBreach.Test",
            output_type=str,
        ),
        OutputArgument(
            name="attack_id", description="the attack ID of the simulation.", prefix="SafeBreach.Test", output_type=str
        ),
    ],
    description="This command gets simulations which are in running or queued state.",
)
def get_all_running_simulations_summary(client: Client):
    """
        This function gets all running simulations summary and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns all simulations related summary as table and gives a dictionary as outputs
    """
    running_simulations = client.get_active_simulations()
    flattened_simulations_data_for_table = client.flatten_simulations_data(running_simulations.get("data", {}))
    demisto.debug(f"Get all running simulations summary result is: {running_simulations}")
    if flattened_simulations_data_for_table:
        human_readable = tableToMarkdown(
            name="Running Simulations",
            t=flattened_simulations_data_for_table,
            headerTransform=simulations_output_transform,
            headers=[
                # "timestamp",
                "planRunId",
                "jobId",
                "moveId",
            ],
        )
    else:
        human_readable = f"No running simulations summary found: {flattened_simulations_data_for_table}"
    outputs = running_simulations
    result = CommandResults(outputs_prefix="SafeBreach.Test", outputs=outputs, readable_output=human_readable)

    return result


@metadata_collector.command(
    command_name="safebreach-pause/resume-simulations-tests",
    inputs_list=[
        InputArgument(
            name="simulation_or_test_state",
            options=["resume", "pause"],
            required=True,
            is_array=False,
            description="State of tests/simulators to set to:\n"
            + "1. pause will set all simulations/tests which are in queue/running to paused stated and resume all "
            + "will be the state of button in running simulations page. \n"
            + "2. resume will queue all simulations/tests and will set them to running/queued depending on priority. \n"
            + "Note that this doe not affect the schedules and scheduled tasks unless they are running or active at the"
            + " moment of execution of the command.",
        )
    ],
    outputs_prefix="SafeBreach.Test",
    outputs_list=[
        OutputArgument(
            name="status",
            prefix="SafeBreach.Test",
            output_type=str,
            description="the status of the simulations/tests.",
        )
    ],
    description="This command gets simulations/tests which are in running or queued state and pauses/resumes them based on "
    + "input selected. The state selected will be applied for all running/queued state tasks whether they are simulations/tests.",
)
def pause_resume_tests_and_simulations(client: Client):
    """
        This function gets all tests/simulations summary and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns all tests related summary as a table and gives a dictionary as outputs for the same
    """
    simulations_status = client.set_simulations_status()
    if simulations_status.get("data"):
        human_readable = tableToMarkdown(
            name="Simulations/tests status", t=simulations_status.get("data"), headers=["status"]
        )
    else:
        human_readable = f"No tests and simulations summary found: {simulations_status}"

    outputs = simulations_status
    result = CommandResults(
        outputs_prefix="SafeBreach.Test", outputs=outputs.get("data"), readable_output=human_readable
    )

    return result


def safebreach_schedules_transformer(header):
    return_map = {
        "id": "id",
        "isEnabled": "is_enabled",
        "name": "name",
        "user_schedule": "user_schedule",
        "runDate": "runDate",
        "cronTimezone": "cron_timezone",
        "taskId": "task_id",
        "description": "description",
        "planId": "scenario_id",
        "matrixId": "scenario_id",
        "createdAt": "created_at",
        "updatedAt": "updated_at",
        "deletedAt": "deleted_at",
    }

    return return_map.get(header, header)


def plan_id_name_map(test_summaries):
    plan_map = {}
    for summary in test_summaries:
        plan_map[str(summary["planId"])] = summary["planName"]

    return plan_map


@metadata_collector.command(
    command_name="safebreach-get-scheduled-scenarios",
    inputs_list=None,
    outputs_prefix="SafeBreach.Schedules",
    outputs_list=[
        OutputArgument(name="id", description="the Id of the schedule.", prefix="schedules", output_type=str),
        OutputArgument(
            name="is_enabled", description="if simulation is enabled.", prefix="schedules", output_type=bool
        ),
        OutputArgument(
            name="user_schedule",
            description="the user readable form of the schedule.",
            prefix="SafeBreach.Schedules",
            output_type=str,
        ),
        OutputArgument(
            name="run_date", description="the run date of the schedule.", prefix="SafeBreach.Schedules", output_type=str
        ),
        OutputArgument(
            name="cron_timezone", description="the time zone of the schedule.", prefix="SafeBreach.Schedules", output_type=str
        ),
        OutputArgument(
            name="description", description="the description of the schedule.", prefix="SafeBreach.Schedules", output_type=str
        ),
        OutputArgument(
            name="scenario_id", description="the matrix ID of the schedule.", prefix="SafeBreach.Schedules", output_type=str
        ),
        OutputArgument(
            name="created_at", description="the creation datetime of the schedule.", prefix="SafeBreach.Schedules", output_type=str  # noqa: E501
        ),
        OutputArgument(
            name="updated_at", description="the updated datetime of the schedule.", prefix="SafeBreach.Schedules", output_type=str
        ),
        OutputArgument(
            name="deleted_at", description="the deletion time of the schedule.", prefix="SafeBreach.Schedules", output_type=str
        ),
    ],
    description="This command retrieves schedules from safebreach which user has set and they will display it to user. By "
    + "default Name is not shown, to retrieve and see it, please run 'safebreach-get-custom-scenarios' command to find name of "
    + "scenario to which the schedule is associated with.",
)
def get_schedules(client: Client):
    """
        This function retrieves schedules and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns schedules as a table and gives a dictionary as outputs for the same
    """
    headers = [
        "id",
        "name",
        "isEnabled",
        "user_schedule",
        "runDate",
        "cronTimezone",
        "description",
        "planId",
        "createdAt",
        "updatedAt",
        "deletedAt",
    ]

    schedules_data = client.get_schedules()
    new_schedules_data = client.append_cron_to_schedule(deepcopy(schedules_data.get("data")))
    demisto.debug(f"Get schedules result is: {schedules_data}")
    if new_schedules_data:
        human_readable = tableToMarkdown(
            name="Schedules", headerTransform=safebreach_schedules_transformer, t=new_schedules_data, headers=headers
        )
    else:
        human_readable = f"No schedules found: {new_schedules_data}"
    outputs = schedules_data.get("data")
    result = CommandResults(outputs_prefix="SafeBreach.Schedules", outputs=outputs, readable_output=human_readable)

    return result


@metadata_collector.command(
    command_name="safebreach-delete-scheduled-scenarios",
    inputs_list=[
        InputArgument(
            name="schedule_id", description="schedule ID of scheduled scenario to delete", required=True, is_array=False
        )
    ],
    outputs_prefix="SafeBreach.Scenario",
    outputs_list=[
        OutputArgument(
            name="id",
            description="the Id of the scheduled scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="name",
            description="the name of the scheduled scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="accountId",
            description="the account ID of the scheduled scenario.",
            prefix="SafeBreach.Schedules",
            output_type=str,
        ),
        OutputArgument(
            name="description",
            description="the description of the scheduled scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="successCriteria",
            description="the success criteria of the scheduled scenario.",
            prefix="SafeBreach.Schedules",
            output_type=str,
        ),
        OutputArgument(
            name="originalScenarioId",
            description="the original test ID of the scheduled scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="systemFilter",
            description="the systemFilter of the scheduled scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="tags",
            description="the tags of the scheduled scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="createdAt",
            description="the creation datetime of the scheduled scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="updatedAt",
            description="the updated datetime of the scheduled scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        )
    ],
    description="This command deletes the scheduled scenario with the specified schedule_id.",
)
def delete_schedules(client: Client):
    """
        This function delete schedules and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns deleted schedules as a table and gives a dictionary as outputs for the same
    """

    schedules_data = client.delete_schedule()
    demisto.debug(f"Delete schedules result is: {schedules_data}")

    if schedules_data.get("data"):
        human_readable = tableToMarkdown("Deleted scheduled scenario:", schedules_data.get("data"))
    else:
        human_readable = f"Unable to delete schedules: {schedules_data.get('data')}"

    outputs = schedules_data.get("data")
    result = CommandResults(
        outputs_prefix="SafeBreach.Scenario", outputs=outputs, readable_output=human_readable
    )

    return result


@metadata_collector.command(
    command_name="safebreach-get-prebuilt-scenarios",
    inputs_list=None,
    outputs_prefix="SafeBreach.Scenario",
    outputs_list=[
        OutputArgument(name="id", description="the Id of scenario.", prefix="SafeBreach.Scenario", output_type=str),
        OutputArgument(
            name="name", description="he name of the scenario.", prefix="SafeBreach.Scenario", output_type=str
        ),
        OutputArgument(
            name="description",
            description="the description of the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="created_by",
            description="user id of user, who created the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="created_at",
            description="creation datetime of scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="updated_at",
            description="the update datetime of the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="recommended",
            prefix="SafeBreach.Scenario",
            output_type=str,
            description="the recommendation status of the scenario.",
        ),
        OutputArgument(
            name="tags_list",
            description="the tags related to the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="categories",
            description="the category ids of the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="steps_order",
            description="the order of steps involved in the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="order",
            description="the order of execution related to the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="min_api_ver",
            description="the minimum version of API required for scenario to be executed",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
    ],
    description="This command gets scenarios which are built by safebreach. They will be available by default even in new "
    + "instance of your safebreach instance. They can be modified and saved as custom scenarios or used as it is.",
)
def get_prebuilt_scenarios(client: Client):
    """
        This function gets prebuilt scenarios and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns all tests related summary as a table and gives a dictionary as outputs for the same
    """
    prebuilt_scenarios = client.get_prebuilt_scenarios()
    demisto.debug(f"Get prebuilt scenarios result is: {prebuilt_scenarios}")

    flattened_simulations_data_for_table = client.extract_default_scenario_fields(prebuilt_scenarios)
    if flattened_simulations_data_for_table:
        human_readable = tableToMarkdown(
            name="Scenarios",
            headerTransform=scenarios_transformer,
            t=flattened_simulations_data_for_table,
            headers=[
                "id",
                "name",
                "description",
                "createdBy",
                "createdAt",
                "updatedAt",
                "recommended",
                "tags_list",
                "categories",
                "steps_order",
                "order",
                "minApiVer",
            ],
        )
    else:
        human_readable = f"No prebuilt scenarios found: {flattened_simulations_data_for_table}"
    outputs = prebuilt_scenarios
    result = CommandResults(outputs_prefix="SafeBreach.Scenario", outputs=outputs, readable_output=human_readable)

    return result


def scenarios_transformer(header):
    return_map = {
        "id": "id",
        "name": "name",
        "description": "description",
        "successCriteria": "success_criteria",
        "originalScenarioId": "original_scenario_id",
        "actions_list": "actions_list",
        "steps_order": "steps_order",
        "createdAt": "created_at",
        "updatedAt": "updated_at",
        "createdBy": "created_by",
        "recommended": "recommended",
        "tags_list": "tags_list",
        "categories": "categories",
        "order": "order",
        "minApiVer": "min_api_ver",
    }
    return return_map.get(header, header)


@metadata_collector.command(
    command_name="safebreach-get-custom-scenarios",
    inputs_list=[
        InputArgument(
            name="schedule_details",
            default="true",
            options=["false", "true"],
            required=False,
            is_array=False,
            description="Details of custom scenarios (My scenarios)."
            + " Possible values are: false, true. Default is true.",
        ),
    ],
    outputs_prefix="SafeBreach.Scenario",
    outputs_list=[
        OutputArgument(name="id", description="the Id of scenario.", prefix="SafeBreach.Scenario", output_type=str),
        OutputArgument(
            name="name", description="the name of the scenario.", prefix="SafeBreach.Scenario", output_type=str
        ),
        OutputArgument(
            name="description",
            description="the description of the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="success_criteria",
            description="success criteria the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="original_scenario_id",
            description="original scenario id of scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="actions_list", description="actions list of the scenario.", prefix="SafeBreach.Scenario", output_type=str
        ),
        OutputArgument(
            name="edges_count", description="edges_count for the scenario.", prefix="SafeBreach.Scenario", output_type=str
        ),
        OutputArgument(
            name="steps_order",
            description="the order of steps of the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="created_at",
            description="the creation datetime of the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
        OutputArgument(
            name="updated_at",
            description="the last updated time the scenario.",
            prefix="SafeBreach.Scenario",
            output_type=str,
        ),
    ],
    description="This command  retrieves scenarios which are saved by user as custom scenarios. they generally have "
    + "configurations and everything set up and will be ready to run as tests",
)
def get_custom_scenarios(client: Client):
    """
        This function gets custom scenarios and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns custom scenarios as a table and gives a dictionary as outputs for the same
    """
    custom_scenarios = client.get_custom_scenarios()
    demisto.debug(f"Get custom scenarios result is: {custom_scenarios}")

    if demisto.args().get("schedule_details") == "true":
        flattened_simulations_data_for_table = client.extract_custom_scenario_fields(custom_scenarios.get("data", {}))
    else:
        flattened_simulations_data_for_table = custom_scenarios.get("data", {})

    if flattened_simulations_data_for_table:
        human_readable = tableToMarkdown(
            name="Scenarios",
            headerTransform=scenarios_transformer,
            t=flattened_simulations_data_for_table,
            headers=[
                "id",
                "name",
                "description",
                "successCriteria",
                "originalScenarioId",
                "actions_list",
                "steps_order",
                "createdAt",
                "updatedAt",
            ],
        )
    else:
        human_readable = f"No custom scenarios found: {flattened_simulations_data_for_table}"
    outputs = custom_scenarios
    result = CommandResults(outputs_prefix="SafeBreach.Scenario", outputs=outputs, readable_output=human_readable)

    return result


@metadata_collector.command(
    command_name="safebreach-get-services-status",
    inputs_list=None,
    outputs_prefix="SafeBreach.Service",
    outputs_list=[
        OutputArgument(name="name", description="the name of the service.", prefix="SafeBreach.Service", output_type=str),
        OutputArgument(
            name="version", description="version of the service.", prefix="SafeBreach.Service", output_type=str
        ),
        OutputArgument(
            name="connection status",
            description="connection status of service.",
            prefix="SafeBreach.Service",
            output_type=str,
        ),
        OutputArgument(name="error", description="error status of service.", prefix="SafeBreach.Service", output_type=str),
    ],
    description="This command facilitates the retrieval of service statuses from SafeBreach,"
    + "presenting them to the user in a tabular format. In the event that services are inactive,"
    + "pertinent details regarding their downtime or last operational status are also displayed.",
)
def get_services_status(client: Client):
    """
        This function get services status and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns services status as a table and gives a dictionary as outputs for the same
    """
    services = client.get_services_status()
    demisto.debug(f"Services API call is {services}")

    modified_services_data = client.format_services_response(services)
    if modified_services_data:
        human_readable = tableToMarkdown(
            name="Services", t=modified_services_data, headers=["name", "version", "connection_status"]
        )
    else:
        human_readable = f"Unable to retrieve status of services: {modified_services_data}"

    outputs = services
    result = CommandResults(outputs_prefix="SafeBreach.Service", outputs=outputs, readable_output=human_readable)
    return result


def simulations_transformer(header):
    return_map = {
        "attackerNodeName": "attacker_node_name",
        "id": "simulation_id",
        "targetNodeName": "target_node_name",
        "destNodeName": "dest_node_name",
        "moveDesc": "attack_description",
        "moveName": "attack_name",
        "attacks_involved": "attacks_involved",
        "resultDetails": "result_details",
        "securityAction": "security_action",
    }

    return return_map.get(header, header)


@metadata_collector.command(
    command_name="safebreach-get-simulations",
    inputs_list=[
        InputArgument(
            name="test_id",
            required=False,
            is_array=False,
            description="This is ID of the test whose simulations will be retrieved.",
        ),
    ],
    outputs_prefix="SafeBreach.Simulation",
    outputs_list=[
        OutputArgument(
            name="simulation_id", description="the id of the simulation.", prefix="SafeBreach.Simulation", output_type=str
        ),
        OutputArgument(
            name="attacker_node_name",
            description="Name of attacker node of simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="target_node_name",
            description="name of target of simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="dest_node_name",
            description="name of destination of simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(name="attack_name", description="name of attack", prefix="SafeBreach.Simulation", output_type=str),
        OutputArgument(
            name="attacks_involved",
            description="attack types involved in of simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="result_details", description="result of simulation.", prefix="SafeBreach.Simulation", output_type=str
        ),
        OutputArgument(
            name="security_action",
            description="security status as per the simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="attack_description", description="attack details.", prefix="SafeBreach.Simulation", output_type=str
        ),
    ],
    description="This command facilitates the retrieval of simulations and their associated data for a specified test. It can be used as a precursor command for the rerun-simulations command, streamlining the process of queuing simulations. It's important to note that this command currently lacks pagination limiters, potentially resulting in the retrieval of a large volume of data."  # noqa: E501
)
def get_simulations(client: Client):
    """
        This function gets simulations and shows in a table

    Args:
        client (Client): Client class object for API calls

    Returns:
        CommandResults,Dict: This returns simulations as a table and gives a dictionary as outputs for the same
    """

    headers = [
        "attackerNodeName",
        "id",
        "moveName",
        "resultDetails",
        "securityAction",
        "targetNodeName",
        "attacks_involved",
    ]
    simulations = client.get_simulations()
    demisto.debug(f"Result of simulations is: {simulations}")
    modified_simulations_data = format_simulations_data(simulations.get("simulations"))
    if modified_simulations_data:
        human_readable = tableToMarkdown(
            name="Simulations Details for test",
            t=modified_simulations_data,
            headerTransform=simulations_transformer,
            headers=headers,
        )
    else:
        human_readable = f"No simulations found: {modified_simulations_data}"
    outputs = simulations
    result = CommandResults(outputs_prefix="SafeBreach.Simulation", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-get-verification-token",
    inputs_list=None,
    outputs_prefix="SafeBreach.Token",
    outputs_list=[
        OutputArgument(
            name="token",
            description="the value of new verification token.",
            prefix="SafeBreach.Token",
            output_type=str,
        ),
    ],
    description="This command retrieves existing verification token needed for verification of the simulators.",
)
def get_verification_token(client):
    token_data = client.get_verification_token()
    demisto.debug(f"Get verification token result is: {token_data}")
    if token_data.get("data"):
        human_readable = tableToMarkdown(name="Verification Token", t=token_data.get("data"), headers=["secret"])
    else:
        human_readable = f"No verification token found: {token_data}"
    outputs = token_data
    result = CommandResults(outputs_prefix="SafeBreach.Token", outputs=outputs, readable_output=human_readable)

    return result


def tests_scenarios_transformer(header):
    return_map = {
        "name": "name",
        "originalScenarioId": "original_scenario_id",
        "actions_list": "actions_list",
        "steps_order": "steps_order",
        "planRunId": "test_id",
        "planId": "scenario_id",
        "ranBy": "ran_by",
        "ranFrom": "ran_from",
        "priority": "priority",
        "retrySimulations": "retry_simulations",
        "createdAt": "created_at",
        "updatedAt": "updated_at",
        "successCriteria": "success_criteria",
    }
    return return_map.get(header, header)


@metadata_collector.command(
    command_name="safebreach-rerun-test",
    inputs_list=[
        InputArgument(
            name="test_id",
            description="test id for the given test, \
            this is be test id field from get-all-tests-summary command",
            required=True,
            is_array=False,
        ),
        InputArgument(name="test_name", description="test name for the given test", required=True, is_array=False),
    ],
    outputs_prefix="SafeBreach.Test",
    outputs_list=[
        OutputArgument(name="id", description="the Id of test.", prefix="SafeBreach.Test", output_type=str),
        OutputArgument(name="name", description="the name of the test.", prefix="SafeBreach.Test", output_type=str),
        OutputArgument(
            name="description", description="the description of the test.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="success_criteria", description="success criteria the test.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="original_scenario_id",
            description="original scenario id of test.",
            prefix="SafeBreach.Test",
            output_type=str,
        ),
        OutputArgument(
            name="actions_list", description="actions list of the test.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="edges_count", description="edges_count for the test.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="steps_order", description="the order of steps of the test.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="created_at", description="the creation datetime of the test.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="updated_at", description="the last updated time the test.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="scenario_id", description="the test id of the test.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="ran_by",
            description="the user id of the user who ran the test.",
            prefix="SafeBreach.Test",
            output_type=str,
        ),
        OutputArgument(
            name="ran_from", description="where the user ran the test from.", prefix="SafeBreach.Test", output_type=str
        ),
        OutputArgument(
            name="enable_feedback_loop",
            description="feedback loop status of the test.",
            prefix="SafeBreach.Test",
            output_type=str,
        ),
        OutputArgument(name="test_id", description="test_id of the test.", prefix="SafeBreach.Test", output_type=str),
        OutputArgument(name="priority", description="priority of the test.", prefix="SafeBreach.Test", output_type=str),
        OutputArgument(
            name="retry_simulations", description="retry status of the test.", prefix="SafeBreach.Test", output_type=str
        ),
    ],
    description="This command puts given test data in queue for execution.",
)
def rerun_test(client):
    rerun_results = client.rerun_test_or_simulation()
    demisto.debug(f"Rerun test result is: {rerun_results}")

    flattened_simulations_data_for_table = client.extract_test_fields(rerun_results.get("data", {}))
    if flattened_simulations_data_for_table:
        human_readable = tableToMarkdown(
            name="test",
            headerTransform=tests_scenarios_transformer,
            t=flattened_simulations_data_for_table,
            headers=[
                "name",
                "originalScenarioId",
                "actions_list",
                "steps_order",
                "planId",
                "ranBy",
                "ranFrom",
                "planRunId",
                "priority",
                "retrySimulations",
            ],
        )
    else:
        human_readable = f"Unable to rerun test: {flattened_simulations_data_for_table}"
    outputs = rerun_results
    result = CommandResults(outputs_prefix="SafeBreach.Test", outputs=outputs, readable_output=human_readable)
    return result


@metadata_collector.command(
    command_name="safebreach-rerun-simulation",
    inputs_list=[
        InputArgument(
            name="simulation_ids",
            required=True,
            is_array=False,
            description="ids of simulation we want to queue,\
                          please give ids of simulations as comma separated numbers",
        ),
        InputArgument(
            name="test_name",
            required=True,
            is_array=False,
            description="test name for the given test",
        ),
    ],
    outputs_prefix="SafeBreach.Simulation",
    outputs_list=[
        OutputArgument(name="id", description="the Id of simulation.", prefix="SafeBreach.Simulation", output_type=str),
        OutputArgument(
            name="name", description="the name of the simulation.", prefix="SafeBreach.Simulation", output_type=str
        ),
        OutputArgument(
            name="description",
            description="the description of the simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="success_criteria",
            description="success criteria the simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="original_scenario_id",
            description="original simulation id of simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="actions_list",
            description="actions list of the simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="steps_order",
            description="the order of steps of the simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="createdAt",
            description="the creation datetime of the simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
        OutputArgument(
            name="updatedAt",
            description="the last updated time the simulation.",
            prefix="SafeBreach.Simulation",
            output_type=str,
        ),
    ],
    description="this commands puts given simulation ids into queue for running.",
)
def rerun_simulation(client):
    rerun_results = client.rerun_test_or_simulation()
    demisto.debug(f"Rerun Simulation result is: {rerun_results}")
    flattened_simulations_data_for_table = client.extract_custom_scenario_fields([rerun_results.get("data", {})])
    human_readable = tableToMarkdown(
        name="Scenarios",
        headerTransform=tests_scenarios_transformer,
        t=flattened_simulations_data_for_table,
        headers=[
            "name",
            "actions_list",
            "steps_order",
            "ranBy",
            "ranFrom",
            "planRunId",
            "priority",
            "retrySimulations",
        ],
    )
    outputs = rerun_results
    result = CommandResults(outputs_prefix="SafeBreach.Test", outputs=outputs, readable_output=human_readable)

    return result


@metadata_collector.command(
    command_name="safebreach-get-indicators",
    inputs_list=[
        InputArgument(name="test_id", required=True, is_array=False, description="Test ID of the insight"),
        InputArgument(
            name="limit",
            required=False,
            is_array=False,
            description="The maximum number of indicators to " + " generate. The default is 1000.",
        ),
        InputArgument(
            name="insightCategory",
            required=False,
            is_array=True,
            description="Multi-select option for the category of the insights to get remediation data "
            + " for:Network Access, Network Inspection, Endpoint, Email, Web, Data Leak",
        ),
        InputArgument(
            name="insightDataType",
            required=False,
            is_array=True,
            description="Multi-select option for the remediation data type to get: "
            + " Hash, Domain, URI, Command, Port, Protocol, Registry",
        ),
        InputArgument(
            name="behavioralReputation",
            required=False,
            is_array=False,
            description="Select option for the category of behavioral reputation",
        ),
        InputArgument(
            name="nonBehavioralReputation",
            required=False,
            is_array=False,
            description="Select option for the category of non-behavioral reputation",
        ),
    ],
    outputs_prefix="SafeBreach.Indicator",
    outputs_list=[
        OutputArgument(
            name="value", description="The value of the indicator", prefix="SafeBreach.Indicator", output_type=str
        ),
        OutputArgument(
            name="type", description="The type of the indicator", prefix="SafeBreach.Indicator", output_type=str
        ),
        OutputArgument(
            name="rawJSON.dataType",
            description="The data type of the indicator",
            prefix="SafeBreach.Indicator",
            output_type=str,
        ),
        OutputArgument(
            name="rawJSON.insightTime",
            description="The time of the insight",
            prefix="SafeBreach.Indicator",
            output_type=str,
        ),
        OutputArgument(
            name="rawJSON.value",
            description="The data type value of the indicator",
            prefix="SafeBreach.Indicator",
            output_type=str,
        ),
        OutputArgument(
            name="fields.description",
            description="The description of the indicator",
            prefix="SafeBreach.Indicator",
            output_type=str,
        ),
        OutputArgument(
            name="fields.safebreachseverity",
            description="The severity of the indicator",
            prefix="SafeBreach.Indicator",
            output_type=str,
        ),
        OutputArgument(
            name="fields.safebreachseverityscore",
            description="The severity score of the indicator",
            prefix="SafeBreach.Indicator",
            output_type=str,
        ),
        OutputArgument(
            name="fields.safebreachisbehavioral",
            description="The behavioral of the indicator",
            prefix="SafeBreach.Indicator",
            output_type=bool,
        ),
        OutputArgument(
            name="fields.safebreachattackids",
            description="The attack ids of the indicator",
            prefix="SafeBreach.Indicator",
            output_type=list,
        ),
        OutputArgument(
            name="fields.port", description="The port of the indicator", prefix="SafeBreach.Indicator", output_type=str
        ),
        OutputArgument(
            name="fields.tags", description="The tags of the indicator", prefix="SafeBreach.Indicator", output_type=str
        ),
        OutputArgument(
            name="score", description="The score of the indicator", prefix="SafeBreach.Indicator", output_type=int
        ),
    ],
    description="This command fetches SafeBreach Insights from which indicators are extracted, "
    + " creating new indicators or updating existing indicators.",
)
def get_indicators_command(client):
    indicator_results = client.get_indicators_command()
    demisto.debug(f"List of Indicators: {indicator_results}")
    outputs = indicator_results

    entry_result = camelize(outputs)
    if entry_result:
        hr = tableToMarkdown("Indicators:", entry_result)
    else:
        hr = f"No indicators found: {outputs}"
    result = CommandResults(outputs_prefix="SafeBreach.Indicator", outputs=outputs, readable_output=hr)
    return result


@metadata_collector.command(
    command_name="safebreach-get-simulators-versions-list",
    outputs_prefix="SafeBreach.Simulator",
    outputs_list=[
        OutputArgument(name="id", description="Simulator Id", prefix="SafeBreach.Simulator", output_type=str),
        OutputArgument(
            name="lastUpdateDate",
            description="Simulator last updated data",
            prefix="SafeBreach.Simulator",
            output_type=str,
        ),
        OutputArgument(
            name="lastUpdateStatus",
            description="Simulator last updated status",
            prefix="SafeBreach.Simulator",
            output_type=str,
        ),
        OutputArgument(
            name="currentStatus", description="Simulator current status", prefix="SafeBreach.Simulator", output_type=str
        ),
        OutputArgument(
            name="availableVersions",
            description="Simulator available versions",
            prefix="SafeBreach.Simulator",
            output_type=list,
        ),
    ],
    description="This command fetches the list of SafeBreach simulators",
)
def get_simulators_versions_list(client):
    simulator_results = client.get_simulators_versions_list()
    demisto.debug(f"List of simulators versions: {simulator_results}")
    outputs = simulator_results
    entry_result = camelize(outputs)
    if entry_result:
        hr = tableToMarkdown("Simulators:", entry_result)
    else:
        hr = f"No simulators versions found: {simulator_results}"
    result = CommandResults(outputs_prefix="SafeBreach.Simulator", outputs=outputs, readable_output=hr)
    return result


@metadata_collector.command(
    command_name="safebreach-upgrade-simulator",
    inputs_list=[
        InputArgument(name="simulator_id", required=True, is_array=False, description="Simulator ID"),
        InputArgument(
            name="simulator_version",
            required=True,
            is_array=False,
            description="The version should be in the format of the safebreach-get-simulators-versions-list "
            + " command and that 'latest' can be used. The default is the latest.",
        ),
    ],
    outputs_prefix="SafeBreach.Simulator",
    outputs_list=[
        OutputArgument(name="nodeId", description="Simulator ID", prefix="SafeBreach.Simulator", output_type=str),
        OutputArgument(
            name="status", description="Simulator status", prefix="SafeBreach.Simulator", output_type=str
        ),
    ],
    description="This command updates the simulator using the Simulator ID and available version.",
)
def update_simulator_with_id(client):
    results = client.update_simulator_with_id()
    demisto.debug(f"Updated simulator result is: {results}")
    outputs = results
    entry_result = camelize(outputs)
    if entry_result:
        hr = tableToMarkdown("Updated Simulator:", entry_result)
    else:
        hr = f"Unable to update simulator with ID: {outputs}"
    result = CommandResults(outputs_prefix="SafeBreach.Simulator", outputs=outputs, readable_output=hr)
    return result


@metadata_collector.command(
    command_name="safebreach-get-simulator-download-links",
    outputs_prefix="SafeBreach.Installation",
    outputs_list=[
        OutputArgument(
            name="md5",
            description="The MD5 generated from the contents of the file",
            prefix="SafeBreach.Installation",
            output_type=str,
        ),
        OutputArgument(
            name="os",
            description="The operating system for which the update is intended",
            prefix="SafeBreach.Installation",
            output_type=str,
        ),
        OutputArgument(
            name="sha1",
            description="The sha1 generated from the contents of the file.",
            prefix="SafeBreach.Installation",
            output_type=str,
        ),
        OutputArgument(
            name="sha256",
            description="The sha256 generated from the contents of the file.",
            prefix="SafeBreach.Installation",
            output_type=str,
        ),
        OutputArgument(
            name="sha512",
            description="The sha512 generated from the contents of the file.",
            prefix="SafeBreach.Installation",
            output_type=str,
        ),
        OutputArgument(
            name="sha512",
            description="The sha512 generated from the contents of the file.",
            prefix="SafeBreach.Installation",
            output_type=str,
        ),
        OutputArgument(
            name="url",
            description="The URL from which update can be downloaded.",
            prefix="SafeBreach.Installation",
            output_type=str,
        ),
        OutputArgument(
            name="version",
            description="This indicates the simulator version.",
            prefix="SafeBreach.Installation",
            output_type=str,
        ),
    ],
    description="This command gets a list of links for download (item per operating system) for the latest available version.",
)
def get_installation_links(client):
    results = client.get_installation_links()
    demisto.debug(f"Installation links result is: {results}")
    outputs = results
    entry_result = camelize(outputs)
    if entry_result:
        hr = tableToMarkdown("Installation Links:", entry_result)
    else:
        hr = f"No installation links found: {outputs}"
    result = CommandResults(outputs_prefix="SafeBreach.Installation", outputs=outputs, readable_output=hr)
    return result


class CronString:
    def __init__(self, cron_string, time_zone):
        self.cron_string = cron_string
        self.final_string = ""
        self.time_zone = time_zone or "UTC"
        self.parse()

    def parse(self):
        comp_array = self.cron_string.split(" ")
        self.parse_hours_and_minutes(comp_array[0], comp_array[1])
        if comp_array[2] != "*":
            self.parse_days_of_month(comp_array[2])
        elif comp_array[-1] != "*":
            self.parse_day_of_week(comp_array[-1])
        else:
            self.final_string += "every day"

    def parse_hours_and_minutes(self, minutes, hours):
        self.final_string += f"At {hours} hours and {minutes} minutes "

    def parse_days_of_month(self, days_of_month):
        days = days_of_month.split(",")
        days_list = []
        for days_range in days:
            if "-" in days_range:
                days_present = days_range.split("-")
                days_list += list(map(str, range(int(days_present[0]), int(days_present[1]))))
            else:
                days_list.append(days_range)
        if days_list:
            self.final_string += f"on days {', '.join(days_list)} every month"

    def parse_day_of_week(self, days_of_week):
        days = days_of_week.split(",")
        days_list = []
        for days_range in days:
            if "-" in days_range:
                days_present = days_range.split("-")
                days_list += list(map(str, range(int(days_present[0]), int(days_present[1]))))
            else:
                days_list.append(days_range)
        if days_list:
            self.final_string += f"on days {', '.join(days_list)} every week"

    def __str__(self):
        return self.final_string + "."

    def to_string(self):
        return f"{self.final_string} on timezone {self.time_zone}."


def main() -> None:
    """
    Execution starts here
    """
    client = Client(
        api_key=demisto.params().get("credentials", {}).get("password"),
        account_id=demisto.params().get("account_id"),
        base_url=demisto.params().get("base_url"),
        verify=demisto.params().get("verify"),
    )
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = client.get_all_users_for_test()
            return_results(result)

        elif demisto.command() == "safebreach-get-services-status":
            result = get_services_status(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-all-users":
            users = get_all_users(client=client)
            return_results(users)

        elif demisto.command() == "safebreach-get-user-with-matching-name-or-email":
            result = get_user_id_by_name_or_email(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-create-user":
            user = create_user(client=client)
            return_results(user)

        elif demisto.command() == "safebreach-delete-user":
            user = delete_user_with_details(client=client)
            return_results(user)

        elif demisto.command() == "safebreach-update-user":
            user = update_user_with_details(client=client)
            return_results(user)

        elif demisto.command() == "safebreach-list-deployments":
            deployment = get_deployments(client=client)
            return_results(deployment)

        elif demisto.command() == "safebreach-create-deployment":
            deployment = create_deployment(client=client)
            return_results(deployment)

        elif demisto.command() == "safebreach-update-deployment":
            deployment = update_deployment(client=client)
            return_results(deployment)

        elif demisto.command() == "safebreach-delete-deployment":
            deployment = delete_deployment(client=client)
            return_results(deployment)

        elif demisto.command() == "safebreach-generate-api-key":
            result = create_api_key(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-delete-api-key":
            result = delete_api_key(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-integration-issues":
            result = get_all_integration_error_logs(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-indicators":
            result = get_indicators_command(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-clear-integration-issues":
            result = delete_integration_error_logs(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-available-simulator-count":
            result = get_simulator_quota_with_table(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-available-simulator-details":
            result = get_all_simulator_details(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-simulator-with-id":
            result = get_simulator_with_name(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-delete-simulator":
            result = delete_simulator_with_given_name(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-update-simulator":
            result = update_simulator(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-verification-token":
            result = get_verification_token(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-rotate-verification-token":
            result = return_rotated_verification_token(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-tests":
            result = get_all_tests_summary(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-tests-with-scenario-id":
            result = get_all_tests_summary_with_scenario_id(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-delete-test-with-id":
            result = delete_test_result_of_test(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-running-tests":
            result = get_all_running_tests_summary(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-running-simulations":
            result = get_all_running_simulations_summary(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-pause/resume-simulations-tests":
            result = pause_resume_tests_and_simulations(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-scheduled-scenarios":
            result = get_schedules(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-delete-scheduled-scenarios":
            result = delete_schedules(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-prebuilt-scenarios":
            result = get_prebuilt_scenarios(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-custom-scenarios":
            result = get_custom_scenarios(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-approve-simulator":
            result = approve_simulator(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-rerun-test":
            result = rerun_test(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-rerun-simulation":
            result = rerun_simulation(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-simulations":
            result = get_simulations(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-simulators-versions-list":
            result = get_simulators_versions_list(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-upgrade-simulator":
            result = update_simulator_with_id(client=client)
            return_results(result)

        elif demisto.command() == "safebreach-get-simulator-download-links":
            result = get_installation_links(client=client)
            return_results(result)

    except Exception as error:
        return_error(f"Failed to execute {demisto.command()} command .\nError:\n{error}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
