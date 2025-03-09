"""
Tests module for Cisco Umbrella Reporting integration
"""

import pytest
import json
import os
from CommonServerPython import DemistoException, urljoin
from CiscoUmbrellaReporting import (
    Client,
    get_destinations_list_command,
    get_categories_list_command,
    get_identities_list_command,
    get_file_list_command,
    create_cisco_umbrella_args,
    get_threat_list_command,
    get_event_types_list_command,
    get_activity_list_command,
    get_activity_by_traffic_type_command,
    get_summary_list_command,
    pagination,
    check_valid_indicator_value,
    get_command_title_string,
    activity_build_data,
)

client = Client(base_url="http://test.com", secret_key="test_123", client_key="test@12345", proxy=False)


def util_load_json(path):
    with open(path) as f:
        return json.loads(f.read())


DESTINATION_LIST_RESPONSE = util_load_json("test_data/context_data_output/destination_data.json")
CATEGORY_LIST_RESPONSE = util_load_json("test_data/context_data_output/category_data.json")
IDENTITY_LIST_RESPONSE = util_load_json("test_data/context_data_output/identity_data.json")
FILE_LIST_RESPONSE = util_load_json("test_data/context_data_output/file_data.json")
THREAT_LIST_RESPONSE = util_load_json("test_data/context_data_output/threat_data.json")
EVENT_TYPE_LIST_RESPONSE = util_load_json("test_data/context_data_output/event_type_data.json")
ACTIVITY_LIST_RESPONSE = util_load_json("test_data/context_data_output/activity_data.json")
ACTIVITY_DNS_LIST_RESPONSE = util_load_json("test_data/context_data_output/activity_dns_data.json")
SUMMARY_LIST_RESPONSE = util_load_json("test_data/context_data_output/summary_data.json")
DESTINATION_SUMMARY_LIST_RESPONSE = util_load_json("test_data/context_data_output/destination_summary_data.json")
ACCESS_TOKEN_RESPONSE = util_load_json("test_data/context_data_output/access_token_data.json")
ACTIVITY_FIREWALL_LIST_RESPONSE = util_load_json("test_data/context_data_output/file_data.json")


@pytest.mark.parametrize("raw_response, expected", [(DESTINATION_LIST_RESPONSE, DESTINATION_LIST_RESPONSE)])
def test_get_destinations_list_command(mocker, raw_response, expected):
    """
    Tests get_destinations_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_destinations_list_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0}
    with open(os.path.join("test_data", "command_readable_output/destination_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_destinations_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize("raw_response, expected", [(CATEGORY_LIST_RESPONSE, CATEGORY_LIST_RESPONSE)])
def test_get_category_list_command(mocker, raw_response, expected):
    """
    Tests get_category_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_category_list_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """

    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0}
    with open(os.path.join("test_data", "command_readable_output/category_command_readable_output.md")) as f:
        readable_output = f.read()
    results_without_traffic = get_categories_list_command(client, args)
    args["traffic_type"] = "dns"
    results_with_traffic = get_categories_list_command(client, args)

    # results is CommandResults list
    detail_without_traffic = results_without_traffic.to_context()["Contents"]
    detail_with_traffic = results_with_traffic.to_context()["Contents"]
    assert detail_without_traffic == expected.get("data")
    assert results_without_traffic.readable_output == readable_output
    assert detail_with_traffic == expected.get("data")

    # Check that the expected err message is raised for invalid sha256:
    with pytest.raises(ValueError) as e:
        args["sha256"] = "4c5f650943b0ae6ae2c9864f3bf6"
        get_categories_list_command(client, args)
    assert e.value.args[0] == "SHA256 value 4c5f650943b0ae6ae2c9864f3bf6 is invalid"


@pytest.mark.parametrize("raw_response, expected", [(IDENTITY_LIST_RESPONSE, IDENTITY_LIST_RESPONSE)])
def test_get_identities_list_command(mocker, raw_response, expected):
    """
    Tests get_identities_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_identities_list_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0}
    with open(os.path.join("test_data", "command_readable_output/identity_command_readable_output.md")) as f:
        readable_output = f.read()
    results_without_traffic = get_identities_list_command(client, args)
    args["traffic_type"] = "dns"
    results_with_traffic = get_identities_list_command(client, args)

    # results is CommandResults list
    detail_without_traffic = results_without_traffic.to_context()["Contents"]
    detail_with_traffic = results_with_traffic.to_context()["Contents"]
    assert detail_without_traffic == expected.get("data")
    assert results_without_traffic.readable_output == readable_output
    assert detail_with_traffic == expected.get("data")

    # Check that the expected err message is raised for invalid sha256:
    with pytest.raises(ValueError) as e:
        args["sha256"] = "4c5f650943b0ae6ae2c9864f3bf6"
        get_identities_list_command(client, args)
    assert e.value.args[0] == "SHA256 value 4c5f650943b0ae6ae2c9864f3bf6 is invalid"


@pytest.mark.parametrize("raw_response, expected", [(FILE_LIST_RESPONSE, FILE_LIST_RESPONSE)])
def test_get_file_list_command(mocker, raw_response, expected):
    """
    Tests get_file_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_file_list_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0}
    with open(os.path.join("test_data", "command_readable_output/file_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_file_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize("raw_response, expected", [(THREAT_LIST_RESPONSE, THREAT_LIST_RESPONSE)])
def test_get_threat_list_command(mocker, raw_response, expected):
    """
    Tests get_threat_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_threat_list_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0}
    with open(os.path.join("test_data", "command_readable_output/threat_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_threat_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize("raw_response, expected", [(EVENT_TYPE_LIST_RESPONSE, EVENT_TYPE_LIST_RESPONSE)])
def test_get_event_types_list_command(mocker, raw_response, expected):
    """
    Tests get_event_types_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_event_types_list_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0}
    with open(os.path.join("test_data", "command_readable_output/event_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_event_types_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize("raw_response, expected", [(ACTIVITY_LIST_RESPONSE, ACTIVITY_LIST_RESPONSE)])
def test_get_activity_list_command(mocker, raw_response, expected):
    """
    Tests get_activity_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_list_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0}
    with open(os.path.join("test_data", "command_readable_output/activity_list_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_activity_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for invalid domain:
    with pytest.raises(ValueError) as e:
        args["domains"] = "1234"
        get_activity_list_command(client, args)
    assert e.value.args[0] == "Domain 1234 is invalid"


@pytest.mark.parametrize("raw_response, expected", [(ACTIVITY_DNS_LIST_RESPONSE, ACTIVITY_DNS_LIST_RESPONSE)])
def test_get_activity_by_dns_traffic_type_command(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0, "traffic_type": "dns"}
    with open(os.path.join("test_data", "command_readable_output/dns_get_activity_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for invalid domain:
    with pytest.raises(ValueError) as e:
        args["domains"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == "Domain 1234 is invalid"

    # Check that the expected err message is raised for using unsupported argument for dns traffic type:
    with pytest.raises(DemistoException) as e:
        args["ports"] = "443"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == (
        "Invalid optional parameter is selected for traffic type dns.\nSupported optional "
        "parameters for dns traffic type are: traffic_type, limit, from, to, offset,"
        " domains, ip, verdict, threats, threat_types, identity_types, page, page_size, categories."
    )


@pytest.mark.parametrize("raw_response, expected", [(ACTIVITY_DNS_LIST_RESPONSE, ACTIVITY_DNS_LIST_RESPONSE)])
def test_get_activity_proxy_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0, "traffic_type": "proxy"}
    with open(os.path.join("test_data", "command_readable_output/proxy_get_activity_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for invalid ip:
    with pytest.raises(ValueError) as e:
        args["ip"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == 'IP "1234" is invalid'

    # Check that the expected err message is raised for using unsupported argument for proxy traffic type:
    with pytest.raises(DemistoException) as e:
        args["signatures"] = "1-2,1-4"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == (
        "Invalid optional parameter is selected for traffic type proxy.\nSupported optional "
        "parameters for proxy traffic type are: traffic_type, limit, from, to, offset, domains,"
        " ip, verdict, threats, threat_types, urls, ports, identity_types, file_name,"
        " amp_disposition, page, page_size, categories."
    )


@pytest.mark.parametrize("raw_response, expected", [(ACTIVITY_DNS_LIST_RESPONSE, ACTIVITY_DNS_LIST_RESPONSE)])
def test_get_activity_ip_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0, "traffic_type": "ip"}
    with open(os.path.join("test_data", "command_readable_output/ip_get_activity_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for invalid ip:
    with pytest.raises(ValueError) as e:
        args["ip"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == 'IP "1234" is invalid'

    # Check that the expected err message is raised for using unsupported argument for ip traffic type:
    with pytest.raises(DemistoException) as e:
        args["signatures"] = "1-2,1-4"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == (
        "Invalid optional parameter is selected for traffic type ip.\nSupported optional"
        " parameters for ip traffic type are: traffic_type, limit, from, to, offset, ip, ports,"
        " identity_types, verdict, page, page_size, categories."
    )


@pytest.mark.parametrize("raw_response, expected", [(ACTIVITY_FIREWALL_LIST_RESPONSE, ACTIVITY_FIREWALL_LIST_RESPONSE)])
def test_get_activity_firewall_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0, "traffic_type": "firewall"}
    with open(os.path.join("test_data", "command_readable_output/firewall_get_activity_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for invalid ip:
    with pytest.raises(ValueError) as e:
        args["ip"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == 'IP "1234" is invalid'

    # Check that the expected err message is raised for using unsupported argument for firewall traffic type:
    with pytest.raises(DemistoException) as e:
        args["signatures"] = "1-2,1-4"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == (
        "Invalid optional parameter is selected for traffic type firewall.\nSupported optional"
        " parameters for firewall traffic type are: traffic_type, limit, from, to, offset, ip,"
        " ports, verdict, page, page_size."
    )


@pytest.mark.parametrize("raw_response, expected", [(ACTIVITY_FIREWALL_LIST_RESPONSE, ACTIVITY_FIREWALL_LIST_RESPONSE)])
def test_get_activity_amp_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0, "traffic_type": "amp"}
    with open(os.path.join("test_data", "command_readable_output/amp_get_activity_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for invalid sha256:
    with pytest.raises(ValueError) as e:
        args["sha256"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == "SHA256 value 1234 is invalid"

    # Check that the expected err message is raised for using unsupported argument for amp traffic type:
    with pytest.raises(DemistoException) as e:
        args["domains"] = "google.com"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == (
        "Invalid optional parameter is selected for traffic type amp.\nSupported optional "
        "parameters for amp traffic type are: traffic_type, limit, from, to, offset, "
        "amp_disposition, sha256, page, page_size."
    )


@pytest.mark.parametrize("raw_response, expected", [(ACTIVITY_FIREWALL_LIST_RESPONSE, ACTIVITY_FIREWALL_LIST_RESPONSE)])
def test_get_activity_intrusion_by_traffic_type(mocker, raw_response, expected):
    """
    Tests get_activity_by_traffic_type_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_activity_by_traffic_type_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0, "traffic_type": "intrusion"}
    with open(os.path.join("test_data", "command_readable_output/intrusion_get_activity_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_activity_by_traffic_type_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for invalid ip:
    with pytest.raises(ValueError) as e:
        args["ip"] = "1234"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == 'IP "1234" is invalid'

    # Check that the expected err message is raised for using unsupported argument for intrusion traffic type:
    with pytest.raises(DemistoException) as e:
        args["domains"] = "google.com"
        get_activity_by_traffic_type_command(client, args)
    assert e.value.args[0] == (
        "Invalid optional parameter is selected for traffic type intrusion.\nSupported"
        " optional parameters for intrusion traffic type are: traffic_type, limit, from,"
        " to, offset, ip, ports, signatures, intrusion_action, page, page_size."
    )


@pytest.mark.parametrize("raw_response, expected", [(SUMMARY_LIST_RESPONSE, SUMMARY_LIST_RESPONSE)])
def test_get_summary_list_command(mocker, raw_response, expected):
    """
    Tests get_summary_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_summary_list_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0}
    with open(os.path.join("test_data", "command_readable_output/summary_list_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_summary_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output


@pytest.mark.parametrize("raw_response, expected", [(DESTINATION_SUMMARY_LIST_RESPONSE, DESTINATION_SUMMARY_LIST_RESPONSE)])
def test_get_category_summary_list(mocker, raw_response, expected):
    """
    Tests get_summary_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_summary_list_command'.

        Then:
            - Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0, "summary_type": "category"}
    with open(os.path.join("test_data", "command_readable_output/category_summary_list_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_summary_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for using unsupported argument for category summary type:
    with pytest.raises(DemistoException) as e:
        args["signatures"] = 1
        get_summary_list_command(client, args)
    assert e.value.args[0] == (
        "Invalid optional parameter is selected for summary type category.\nSupported "
        "optional parameters for category summary type are: summary_type, limit, from, to,"
        " offset, domains, urls, ip, identity_types, verdict, file_name, threats, threat_types,"
        " amp_disposition, page, page_size, categories."
    )


@pytest.mark.parametrize("raw_response, expected", [(DESTINATION_SUMMARY_LIST_RESPONSE, DESTINATION_SUMMARY_LIST_RESPONSE)])
def test_get_destination_summary_list(mocker, raw_response, expected):
    """
    Tests get_summary_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_summary_list_command'.

        Then:
            -  Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0, "summary_type": "destination"}
    with open(os.path.join("test_data", "command_readable_output/destination_summary_list_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_summary_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for using unsupported argument for destination summary type:
    with pytest.raises(DemistoException) as e:
        args["signatures"] = 1
        get_summary_list_command(client, args)
    assert e.value.args[0] == (
        "Invalid optional parameter is selected for summary type destination.\nSupported"
        " optional parameters for destination summary type are: summary_type, limit, from,"
        " to, offset, domains, urls, ip, identity_types, verdict, file_name, threats,"
        " threat_types, amp_disposition, page, page_size, categories."
    )


@pytest.mark.parametrize("raw_response, expected", [(DESTINATION_SUMMARY_LIST_RESPONSE, DESTINATION_SUMMARY_LIST_RESPONSE)])
def test_get_intrusion_rule_summary_list(mocker, raw_response, expected):
    """
    Tests get_summary_list_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_summary_list_command'.

        Then:
            -  Checks that the context output and the readable output of the command function are as expected.
    """
    mocker.patch.object(client, "query_cisco_umbrella_api", side_effect=[raw_response] * 5)
    args = {"limit": 5, "from": 1662015255000, "to": 1662447255000, "offset": 0, "summary_type": "intrusion_rule"}
    with open(os.path.join("test_data", "command_readable_output/intrusion_rule_summary_list_command_readable_output.md")) as f:
        readable_output = f.read()
    command_results = get_summary_list_command(client, args)

    # results is CommandResults list
    context_detail = command_results.to_context()["Contents"]
    assert context_detail == expected.get("data")
    assert command_results.readable_output == readable_output

    # Check that the expected err message is raised for using unsupported argument for intrusion rule summary type:
    with pytest.raises(DemistoException) as e:
        args["domains"] = 345678
        get_summary_list_command(client, args)
    assert e.value.args[0] == (
        "Invalid optional parameter is selected for summary type intrusion_rule.\nSupported"
        " optional parameters for intrusion_rule summary type are: summary_type, limit, from,"
        " to, offset, signatures, ip, identity_types, intrusion_action, ports, page, page_size."
    )


@pytest.mark.parametrize(
    "page, page_size, expected_result",
    [
        (2, 5, (5, 5)),
        (1, 5, (5, 0)),
        (4, 2, (2, 6)),
        (None, 5, (5, 0)),
        (2, None, (50, 50)),
        (3, None, (50, 100)),
    ],
)
def test_pagination(page, page_size, expected_result):
    """
    Tests the pagination function.

        Given:
            - page and page size arguments.

        When:
            - Running the 'pagination function'.

        Then:
            - Checks that the limit and offset are calculated as expected.
    """
    actual_result = pagination(page, page_size)
    assert actual_result == expected_result


@pytest.mark.parametrize(
    "page, page_size, expected_err_msg",
    [
        (0, 5, "Invalid Input Error: page number should be greater than zero."),
        (1, 0, "Invalid Input Error: page size should be greater than zero."),
        (-1, 5, "Invalid Input Error: page number should be greater than zero."),
        (1, -2, "Invalid Input Error: page size should be greater than zero."),
    ],
)
def test_pagination_wrong_input(page, page_size, expected_err_msg):
    """
    Tests the pagination function.

        Given:
            1+2 -  page and page size arguments with 0 value.
            3+4 -  page and page size arguments with < 0 value.

        When:
            - Running the 'pagination function'.

        Then:
            - Checks that the expected err message is raised.
    """
    with pytest.raises(DemistoException) as e:
        pagination(page, page_size)
    assert e.value.args[0] == expected_err_msg


@pytest.mark.parametrize("raw_response", [DESTINATION_LIST_RESPONSE])
def test_test_module(requests_mock, raw_response):
    """
    Tests the test_module function.

        Given:
            - no argument required.

        When:
            - Running the 'test_module function'.

        Then:
            - Check weather the given credentials are correct or not.
    """
    from CiscoUmbrellaReporting import test_module

    token_url = urljoin(client._base_url, "/auth/v2/token")
    requests_mock.post(token_url, json={"access_token": "12345"})
    access_token = client.get_access_token()
    get_req_url = f"{client._base_url}/reports/v2/activity"
    headers = {"Authorization": f"Bearer {access_token}"}
    requests_mock.get(get_req_url, headers=headers, json=raw_response)
    output = test_module(client)
    assert output == "ok"
    with pytest.raises(DemistoException):
        error_output = {"meta": {}, "data": {"error": "unauthorized"}}
        requests_mock.get(get_req_url, headers=headers, status_code=401, json=error_output)
        test_module(client)


def test_access_token(requests_mock):
    """
    Tests the access_token function.

        Given:
            - requests_mock object.

        When:
            - Running the 'get_activity_list_command function'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    token_url = urljoin(client._base_url, "/auth/v2/token")

    requests_mock.post(token_url, json={"access_token": "12345"})

    response = client.get_access_token()
    assert response == "12345"

    with pytest.raises(DemistoException) as e:
        requests_mock.post(token_url, status_code=401)
        client.get_access_token()
    assert e.value.args[0] == (
        "Authorization Error: The provided credentials for Cisco Umbrella Reporting are invalid."
        " Please provide a valid Client ID and Client Secret."
    )

    with pytest.raises(DemistoException) as e:
        requests_mock.post(token_url, status_code=400)
        client.get_access_token()
    assert e.value.args[0] == "Error: something went wrong, please try again."


@pytest.mark.parametrize(
    "indicator_type, indicator_value, expected_result",
    [
        ("domains", "google.com", True),
        ("domains", "google.com, facebook.com", True),
        ("urls", "https://www.facebook.com/path", True),
        ("ip", "1.1.1.1", True),
        ("sha256", "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25", True),  # its a test value of SHA256
        ("intrusion_action", "would_block", True),
        ("intrusion_action", "would_block, blocked", True),
    ],
)
def test_check_valid_indicator_value(indicator_type, indicator_value, expected_result):
    """
    Tests the check_valid_indicator_value function.

        Given:
            indicator_type - type of indicator
            indicator_value - Value of indicator

        When:
            - Running the 'check_valid_indicator_value function'.

        Then:
            - Checks the output of the command function with the expected result.
    """
    actual_result = check_valid_indicator_value(indicator_type, indicator_value)
    assert actual_result == expected_result


@pytest.mark.parametrize(
    "indicator_type, indicator_value, expected_err_msg",
    [
        ("domains", "abcd123", "Domain abcd123 is invalid"),
        ("domains", "google.com, abcd1234", "Domain abcd1234 is invalid"),
        ("urls", "123245", "URL 123245 is invalid"),
        ("ip", "google.1234", 'IP "google.1234" is invalid'),
        ("sha256", "abcde34", "SHA256 value abcde34 is invalid"),
        (
            "intrusion_action",
            "block_would",
            "Invalid input Error: supported values for intrusion_action are: 'would_block', 'blocked' and 'detected'.",
        ),
        (
            "intrusion_action",
            "block_would, block",
            "Invalid input Error: supported values for intrusion_action are: 'would_block', 'blocked' and 'detected'.",
        ),
    ],
)
def test_check_valid_indicator_value_wrong_input(indicator_type, indicator_value, expected_err_msg):
    """
    Tests the check_valid_indicator_value function.

        Given:
            indicator_type - type of indicator.
            indicator_value - Value of indicator massage.

        When:
            - Running the 'check_valid_indicator_value function'.

        Then:
            - Checks the output of the command function with the expected error message.
    """
    with pytest.raises(ValueError) as e:
        check_valid_indicator_value(indicator_type, indicator_value)
    assert e.value.args[0] == expected_err_msg


@pytest.mark.parametrize(
    "sub_context, page, page_size, expected_title",
    [
        ("Activity", 1, 10, "Activity List\nCurrent page size: 10\nShowing page 1 out of others that may exist"),
        ("Activity", 0, 0, "Activity List"),
        ("Activity", None, 10, "Activity List"),
        ("Activity", 1, None, "Activity List"),
    ],
)
def test_get_command_title_string(sub_context, page, page_size, expected_title):
    """
    Tests the get_command_title_string function

        Given:
            1. a sub context, page and page size arguments.
            2. a sub context, and a 0 values for page and page size arguments.
            3. a sub context, page = None and  a page size.
            4. a sub context, page  and a page size = None.

        When:
            - Running the 'get_command_title_string function'.

        Then:
            - Checks the output of the command function with the expected output.
    """

    actual_title = get_command_title_string(sub_context, page, page_size)
    assert actual_title == expected_title


def test_activity_build_data():
    """
    Tests the activity_build_data function

        Given:
            - no argument required.

        When:
            - Running the 'activity_build_data function'.

        Then:
            - Checks the output of the command function with the expected output.
    """
    activity_data = ACTIVITY_LIST_RESPONSE["data"][0]
    expected_output = {
        "category": ["Infrastructure and Content Delivery Networks"],
        "identity": ["DESKTOP"],
        "all_application": [],
        "application_category": [],
        "timestamp_string": "2022-09-07T22:49:44Z",
        "signature_cve": [],
        "signature_lebel": "",
    }
    result = activity_build_data(activity_data)
    assert result == expected_output


def test_create_cisco_umbrella_args():
    """
    Tests the create_cisco_umbrella_args function

        Given:
            - no argument required.

        When:
            - Running the 'create_cisco_umbrella_args function'.

        Then:
            - Checks the output of the command function with the expected output.
    """
    args = {"domains": "google.com", "amp_disposition": "clean", "limit": "30"}
    expected_output = {
        "limit": 30,
        "offset": 1,
        "from": "-7days",
        "to": "now",
        "threattypes": None,
        "identitytypes": None,
        "ampdisposition": "clean",
        "filename": None,
        "intrusionaction": None,
        "domains": "google.com",
        "urls": None,
        "ip": None,
        "ports": None,
        "verdict": None,
        "threats": None,
        "signatures": None,
        "sha256": None,
        "categories": [],
    }
    result = create_cisco_umbrella_args(50, 1, args)
    assert result == expected_output

    with pytest.raises(ValueError) as e:
        args["intrusion_action"] = "abcd"
        create_cisco_umbrella_args(50, 1, args)
    assert e.value.args[0] == (
        "Invalid input Error: supported values for intrusion_action are:" " 'would_block', 'blocked' and 'detected'."
    )
