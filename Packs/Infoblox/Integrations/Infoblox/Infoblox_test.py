from pathlib import Path
from typing import Any, cast
import pytest
from Infoblox import (
    INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY,
    INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY,
    INTEGRATION_COMMON_NAME_CONTEXT_KEY,
    INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY,
    INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY,
    INTEGRATION_COMMON_REFERENCE_ID_CONTEXT_KEY,
    INTEGRATION_CONTEXT_NAME,
    INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY,
    INTEGRATION_HOST_RECORDS_CONTEXT_NAME,
    INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY,
    INTEGRATION_IPV4_CONTEXT_NAME,
    INTEGRATION_MAX_RESULTS_DEFAULT,
    INTEGRATION_NETWORK_INFO_CONTEXT_KEY,
    INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY,
    IP_MAPPING,
    IPv4AddressStatus,
    InfoBloxNIOSClient,
    get_extended_attributes_context,
    get_host_records_command,
    get_ip_command,
    get_network_info_command,
    transform_ext_attrs,
    transform_host_records_context,
    transform_ip_context,
    transform_ipv4_range,
    transform_network_info_context
)
import demistomock as demisto
import json

from CommonServerPython import DemistoException, assign_params

BASE_URL = 'https://example.com/v1/'

POST_NEW_ZONE_RESPONSE = {
    "result": {
        "_ref": "zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0:test.com/default",
        "disable": False,
        "fqdn": "test.com",
        "rpz_policy": "GIVEN",
        "rpz_severity": "WARNING",
        "rpz_type": "LOCAL",
        "view": "default"
    }
}

API_ERROR_OBJ = {
    "Error": "AdmConDataError: None (IBDataConflictError: IB.Data.Conflict:Duplicate object 'test123.com' of type zone "
             "exists in the database.)",
    "code": "Client.Ibap.Data.Conflict",
    "text": "Duplicate object 'test123.com' of type zone exists in the database."
}

# disable-secrets-detection-start
SSL_ERROR = "Failed to parse json object from response: b'<html>\r\n<head>\r\n<meta http-equiv=\"Content-Type\" " \
            "content=\"text/html; charset=utf-8\">\r\n<META HTTP-EQUIV=\"PRAGMA\" CONTENT=\"NO-CACHE\">\r\n<meta " \
            "name=\"viewport\" content=\"initial-scale=1.0\">\r\n<title>Certificate Error</title>\r\n<style>\r\n  " \
            "#content {\r\n    border:3px solid#aaa;\r\n    background-color:#fff;\r\n    margin:1.5em;\r\n    " \
            "padding:1.5em;\r\n    font-family:Tahoma,Helvetica,Arial,sans-serif;\r\n    font-size:1em;\r\n  }\r\n  " \
            "h1 {\r\n    font-size:1.3em;\r\n    font-weight:bold;\r\n    color:#196390;\r\n  }\r\n  b {\r\n    " \
            "color:#196390;\r\n  }\r\n</style>\r\n</head>\r\n<body " \
            "\">\r\n<div id=\"content\">\r\n<h1>Certificate Error</h1>\r\n<p>There is an issue with " \
            "the SSL certificate of the server you are trying to contact.</p>\r\n<p><b>Certificate Name:</b> " \
            "www.infoblox.com </p>\r\n<p><b>IP:</b> </p>\r\n<p><b>Category:</b> any </p>\r\n<p><b>Issuer:</b> " \
            "www.infoblox.com </p>\r\n<p><b>Status:</b> expired </p>\r\n<p><b>Reason:</b>  </p>\r\n<p><b>User:</b> " \
            "</p>\r\n</div>\r\n</body>\r\n</html>\r\n\r\n'"
#  disable-secrets-detection-end

GET_USER_LIST = {
    'account': [
        {'username': 'User1', 'name': 'DBot Demisto', 'isLocked': False},
        {'username': 'User2', 'name': 'Demisto DBot', 'isLocked': True}
    ]
}

REQUEST_PARAM_ZONE = f'?{InfoBloxNIOSClient.REQUEST_PARAMS_RETURN_AS_OBJECT_KEY}=1&_return_fields%2B=fqdn%2Crpz_policy%2Crpz_severity%2Crpz_type%2C' \
                     'substitute_name%2Ccomment%2Cdisable'  # noqa: E501

client = InfoBloxNIOSClient('https://example.com/v1/')


class TestHelperFunctions:

    def test_parse_demisto_exception_unauthorized_error(self):
        from Infoblox import parse_demisto_exception
        json_err = 'Expecting value: line 1 column 1 (char 0)'
        api_err = 'Error in API call [401] - Authorization Required'
        parsed_err = parse_demisto_exception(DemistoException(api_err, json_err))
        assert str(parsed_err) == str(
            DemistoException("Authorization error, check your credentials."))

    def test_parse_demisto_exception_json_parse_error(self):
        from Infoblox import parse_demisto_exception
        json_err = 'Expecting value: line 1 column 1 (char 0)'
        api_err = f'Failed to parse json object from response: {SSL_ERROR}'
        parsed_err = parse_demisto_exception(DemistoException(api_err, json_err))
        assert str(parsed_err) == str(
            DemistoException("Cannot connect to Infoblox server, check your proxy and connection."))

    def test_parse_demisto_exception_api_error(self):
        from Infoblox import parse_demisto_exception

        api_err = f'Error in API call [400] - Bad Request\n {json.dumps(API_ERROR_OBJ)}'
        parsed_err = parse_demisto_exception(DemistoException(api_err))
        assert str(parsed_err) == str(
            DemistoException("Duplicate object 'test123.com' of type zone exists in the database."))

    def test_transform_ext_attrs_2_attrs(self):
        """
        Test transform_ext_attrs with 2 comma-separated values.

        Given:
        - An input.

        When:
        - The input has 2 comma-separated key-value pairs.

        Then:
        - A list of 2 dictionaries is returned with the key-value pairs as expected.
        """

        input = "IB Discovery Owned=EMEA,Site=Tel-Aviv"

        actual = transform_ext_attrs(input)
        expected = [{'*IB Discovery Owned': 'EMEA'}, {'*Site': 'Tel-Aviv'}]
        assert actual == expected

    def test_transform_ext_attrs_2_attrs_whitespace(self):
        """
        Test transform_ext_attrs with 2 comma-separated values
        and whitespace in the key/value.

        Given:
        - An input.

        When:
        - The input has 2 comma-separated key-value pairs.
        - The input includes spaces in the key
        - The input includes spaces in the value

        Then:
        - A list of 2 dictionaries is returned with the key-value pairs as expected.
        """

        input = " IB Discovery Owned=EMEA,Site= Tel-Aviv"
        actual = transform_ext_attrs(input)
        expected = [{'*IB Discovery Owned': 'EMEA'}, {'*Site': 'Tel-Aviv'}]
        assert actual == expected

    def test_transform_ext_attrs_2_attrs_comma_attr_end(self):
        """
        Test transform_ext_attrs with 2 comma-separated values
        and comma in the end of value.

        Given:
        - An input.

        When:
        - The input has 2 comma-separated key-value pairs.
        - The input includes a comma in the value.

        Then:
        - A list of 2 dictionaries is returned with the key-value pairs as expected.
        """

        input = "IB Discovery Owned=EMEA,Site=Tel-Aviv, Yafo"

        with pytest.raises(
            DemistoException,
            match=f"Unable to parse provided ext_attrs='{input}'. Expected format is 'ExtKey1=ExtVal1,ExtKeyN=ExtValN'"
        ):
            transform_ext_attrs(input)

    def test_transform_ext_attrs_2_attrs_comma_attr_beginning(self):
        """
        Test transform_ext_attrs with 2 comma-separated values
        and comma in the beginning of value.

        Given:
        - An input.

        When:
        - The input has 2 comma-separated key-value pairs.
        - The input includes a comma in the value.

        Then:
        - A list of 2 dictionaries is returned with the key-value pairs as expected.
        """

        input = "IB Discovery Owned=EMEA,Site=,Tel-Aviv"

        with pytest.raises(
            DemistoException,
            match=f"Unable to parse provided ext_attrs='{input}'. Expected format is 'ExtKey1=ExtVal1,ExtKeyN=ExtValN'"
        ):
            transform_ext_attrs(input)

    def test_transform_ext_attrs_no_delimiter(self):
        """
        Test transform_ext_attrs when the input has no delimiter (comma).

        Given:
        - An input.

        When:
        - The input has no delimiter.

        Then:
        - Return a list with 1 entry.
        """

        input = "Site=Tel-Aviv"
        actual = transform_ext_attrs(input)
        expected = [{'*Site': 'Tel-Aviv'}]
        assert actual == expected

    def test_transform_ext_attrs_no_delimiter_no_equal_sign(self):
        """
        Test transform_ext_attrs when the input has no delimiter (comma)
        and no equal sign.

        Given:
        - An input.

        When:
        - The input has no delimiter and no equal sign.

        Then:
        - Return an empty list.
        """

        input = "SiteTel-Aviv"
        actual = transform_ext_attrs(input)
        assert not actual

    def test_transform_ipv4_range(self):

        from_address = "192.168.1.0"
        to_address = "192.168.1.254"

        actual = transform_ipv4_range(from_address, to_address)
        expected = {'ip_address>': '192.168.1.0', 'ip_address<': '192.168.1.254'}

        assert actual == expected

        assign_params(actual)

    def test_transform_network_info_context(self):
        """
        Test the output of the `transform_network_info_context` helper command
        when provided with only extattr
        """

        input = json.loads((Path(__file__).parent.resolve() / "test_data"
                            / "TestNetworkInfoOperations" / "get_network_return_fields_extattrs.json").read_text()).get("result")

        actual = transform_network_info_context(input)

        assert len(actual) == 1
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in actual[0]
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in actual[0]
        assert INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY in actual[0]
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in actual[0]
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY not in actual[0]

    def test_transform_network_info_context_additional_fields(self):
        """
        Test the output of the `transform_network_info_context` helper command
        when provided with additional fields specified
        """

        input = json.loads((Path(__file__).parent.resolve() / "test_data"
                            / "TestNetworkInfoOperations" / "get_networks_return_fields_options_extattrs.json").read_text()).get("result")  # noqa: E501

        actual = transform_network_info_context(input)

        assert len(actual) == 2
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in actual[1]
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in actual[1]
        assert INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY in actual[1]
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in actual[1]
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY in actual[1]

    def test_transform_host_records_context(self):
        """
        Test the output of the `transform_network_info_context` helper command
        when provided with additional fields specified
        """

        input = json.loads((Path(__file__).parent.resolve() / "test_data"
                            / "TestHostRecordsOperations" / "get_records.json").read_text()).get("result")  # noqa: E501

        actual = transform_host_records_context(input)

        assert len(actual) == 4
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in actual[0]
        assert INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY in actual[0]
        assert INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY in actual[0]
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in actual[0]

    def test_get_extended_attributes_context_valid_extattrs(self):
        """Test get_extended_attributes_context with valid extattrs"""

        input = json.loads((Path(__file__).parent.resolve() / "test_data"
                            / "TestHostRecordsOperations" / "get_record_extattrs.json").read_text()).get("result")[0].get("extattrs")  # noqa: E501

        actual = get_extended_attributes_context(input)
        expected = {"IB Discovery Owned": "EMEA", "Site": "Tel-Aviv"}

        assert actual == expected

    def test_get_extended_attributes_context_invalid_extattrs(self):
        """Test get_extended_attributes_context with invalid extattrs"""

        input = {"invalid": "attribute"}

        actual = get_extended_attributes_context(input)
        expected = {"invalid": "N/A"}

        assert actual == expected

    def test_get_extended_attributes_context_empty_extattrs(self):
        """Test get_extended_attributes_context with invalid extattrs"""

        actual = get_extended_attributes_context({})

        assert not actual


class TestZonesOperations:

    def test_create_response_policy_zone_command(self, mocker, requests_mock):
        from Infoblox import create_response_policy_zone_command
        mocker.patch.object(demisto, 'params', return_value={})
        requests_mock.post(
            f'{BASE_URL}zone_rp{REQUEST_PARAM_ZONE}',
            json=POST_NEW_ZONE_RESPONSE)
        args = {
            "FQDN": "test.com", "rpz_policy": "GIVEN", "rpz_severity": "WARNING", "substitute_name": "", "rpz_type": ""
        }
        human_readable, context, raw_response = create_response_policy_zone_command(client, args)
        assert human_readable == "### Infoblox Integration - Response Policy Zone: test.com has been created\n" \
                                 "|Disable|FQDN|Reference ID|Rpz Policy|Rpz Severity|Rpz Type|View|\n" \
                                 "|---|---|---|---|---|---|---|\n" \
                                 "| false | test.com | zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0:test.com/default " \
                                 "| GIVEN | WARNING | LOCAL | default |\n"
        assert context == {
            'Infoblox.ResponsePolicyZones(val.FQDN && val.FQDN === obj.FQDN)': {
                'ReferenceID': 'zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0:test.com/default',
                'Disable': False,
                'FQDN': 'test.com',
                'RpzPolicy': 'GIVEN',
                'RpzSeverity': 'WARNING',
                'RpzType': 'LOCAL',
                'View': 'default'
            }}
        assert raw_response == {
            'result': {
                '_ref': 'zone_rp/ZG5zLnpvbmUkLl9kZWZhdWx0LmNvbS50ZXN0:test.com/default',
                'disable': False,
                'fqdn': 'test.com',
                'rpz_policy': 'GIVEN',
                'rpz_severity': 'WARNING',
                'rpz_type': 'LOCAL',
                'view': 'default'
            }}


class TestIPOperations:

    CONTEXT_PATH = f'{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_IPV4_CONTEXT_NAME}'  # noqa: E501
    VALID_IP_ADDRESS = "192.168.1.1"
    VALID_NETMASK = "192.168.1.0/24"
    BASE_URL = f"{client._base_url}ipv4address?{InfoBloxNIOSClient.REQUEST_PARAMS_RETURN_AS_OBJECT_KEY}=1"  # noqa: E501

    def test_get_ip_command_too_many_arguments(self):
        """
        Test the command argument input when too many arguments are specified.

        Given:
            - The execution of the `get_ip_command`
        When:
            - The `ip`, `network`, `from_ip` and `to_ip` arguments are all provided.
        Then:
            - Ensure that a validation error is raised.
        """

        with pytest.raises(ValueError, match="Please specify only one of the `ip`, `network` or `from_ip`/`to_ip` arguments"):
            get_ip_command(
                client,
                {
                    "ip": self.VALID_IP_ADDRESS,
                    "network": self.VALID_NETMASK,
                    "from_ip": self.VALID_IP_ADDRESS,
                    "to_ip": self.VALID_IP_ADDRESS
                }
            )

    def test_get_ip_command_no_valid_argument_specified(self):
        """
        Test the command argument input when no valid argument is specified.

        Given:
            - The execution of the `get_ip_command`
        When:
            - The `ip` argument is not provided.
            - The `network` argument is not provided.
            - The `from_ip` argument is not provided.
            - The `to_ip` argument is not provided.
        Then:
            - Ensure that a validation error is raised.
        """

        with pytest.raises(ValueError, match=("Please specify either the `ip`, `network` or `from_ip`/`to_ip` argument")):
            get_ip_command(client, {"status": IPv4AddressStatus.ACTIVE.value, "extended_attrs": "attr1=val1,attr2=val2"})

    def test_get_ip_command_to_ip_defined_from_ip_not_defined(self):
        """
        Test the command argument input when the `to_ip` argument is specified
        without the `from_ip` argument.

        Given:
            - The execution of the `get_ip_command`
        When:
            - The `ip` argument is not provided.
            - The `network` argument is not provided.
            - The `from_ip` argument is not provided.
            - The `to_ip` argument is provided.
        Then:
            - Ensure that a validation error is raised.
        """

        with pytest.raises(ValueError, match=("Please specify either the `ip`, `network` or `from_ip`/`to_ip` argument")):
            get_ip_command(client, {"to_ip": self.VALID_IP_ADDRESS, "extended_attrs": "attr1=val1,attr2=val2"})

    def test_get_ip_command_from_ip_not_to_ip(self):
        """
        Test the command argument input when `from_ip` is specified but not `to_ip`.

        Given:
            - The execution of the `get_ip_command`
        When:
            - The `from_ip` argument is provided but `to_ip` is not.
        Then:
            - Ensure that a validation error is raised.
        """

        with pytest.raises(ValueError, match="Please specify either the `ip`, `network` or `from_ip`/`to_ip` argument"):
            get_ip_command(client, {"from_ip": "1.1.1.1"})

    def test_get_ip_command_from_ip_address_no_status_no_extattr(self, requests_mock):
        """
        Test retrieval of an IP address in case it's provided.

        Given:
        - A mock response.

        When:
        - The IP address is provided.
        - No status is specified.
        - No extended attributes are specified.

        Then:
        - The human readable includes the input IP address.
        - The context includes the IP address object with the input IP address.
        """

        ip = self.VALID_IP_ADDRESS
        mock_response = (Path(__file__).parent.resolve() / "test_data" / self.__class__.__name__
                         / "get_ipv4_address_from_ip_address.json").read_text()

        requests_mock.get(
            f"{client._base_url}ipv4address?{InfoBloxNIOSClient.REQUEST_PARAMS_RETURN_AS_OBJECT_KEY}=1&ip_address={self.VALID_IP_ADDRESS}",  # noqa: E501
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, actual_raw_response = get_ip_command(client, {"ip": ip})

        actual_hr_lines = actual_hr.splitlines()
        assert "Infoblox Integration" in actual_hr_lines[0]
        assert self.VALID_IP_ADDRESS in actual_hr_lines[3]

        actual_output = cast(list, actual_context.get(self.CONTEXT_PATH))
        assert len(actual_output) == 1
        assert actual_output[0].get("IpAddress") == self.VALID_IP_ADDRESS

        assert actual_raw_response == json.loads(mock_response)

    def test_get_ip_command_from_ip_address_status_defined_no_extattr(self, requests_mock):
        """
        Test retrieval of an IP address in case it's provided
        alongside the status.

        Given:
        - A mock response.

        When:
        - The IP address is provided.
        - The status is specified.
        - No extended attributes are specified.

        Then:
        - The human readable includes the input IP address.
        - The context includes the IP address object with the input IP address.
        """

        ip = self.VALID_IP_ADDRESS
        mock_response = (Path(__file__).parent.resolve() / "test_data" / self.__class__.__name__
                         / "get_ipv4_address_from_ip_address.json").read_text()

        requests_mock.get(
            f"{client._base_url}ipv4address?{InfoBloxNIOSClient.REQUEST_PARAMS_RETURN_AS_OBJECT_KEY}=1&ip_address={self.VALID_IP_ADDRESS}&status={IPv4AddressStatus.USED.value}",  # noqa: E501
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, actual_raw_response = get_ip_command(
            client, {"ip": ip, "status": IPv4AddressStatus.USED.value})

        actual_hr_lines = actual_hr.splitlines()
        assert "Infoblox Integration" in actual_hr_lines[0]
        assert self.VALID_IP_ADDRESS in actual_hr_lines[3]

        assert self.CONTEXT_PATH in actual_context
        actual_output = cast(list, actual_context.get(self.CONTEXT_PATH))
        assert len(actual_output) == 1
        assert actual_output[0].get("Status") == IPv4AddressStatus.USED.value

        assert actual_raw_response == json.loads(mock_response)

    def test_get_ip_command_ip_range(self, requests_mock):
        """
        Test the output of the `get_ip_command` when supplied a valid IP range.

        Given:
        - A mock response with a range of IPs.

        When:
        - The `from_ip` argument is set and valid.
        - The `to_ip` argument is set and valid.

        Then:
        - 10 IP addresses are returned.
        """

        from_ip = self.VALID_IP_ADDRESS
        to_ip = self.VALID_IP_ADDRESS[:-1] + "9"

        mock_response = (Path(__file__).parent.resolve() / "test_data" / self.__class__.__name__
                         / "get_ipv4_addresses_from_network.json").read_text()

        requests_mock.get(
            f"{self.BASE_URL}&ip_address>={from_ip}&ip_address<={to_ip}&_max_results={INTEGRATION_MAX_RESULTS_DEFAULT}",
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, actual_raw_response = get_ip_command(
            client, {"from_ip": from_ip, "to_ip": to_ip})

        assert "Infoblox Integration" in actual_hr.splitlines()[0]

        assert self.CONTEXT_PATH in actual_context
        actual_output = cast(list, actual_context.get(self.CONTEXT_PATH))

        assert len(actual_output) == 9
        assert from_ip == actual_output[0].get("IpAddress")
        assert to_ip == actual_output[-1].get("IpAddress")

        assert INTEGRATION_COMMON_REFERENCE_ID_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_REFERENCE_ID_CONTEXT_KEY in actual_output[0]

        assert actual_raw_response == json.loads(mock_response)

    # TODO
    def test_get_ip_command_from_ip_status_defined_extattr_defined(self):
        """
        Test retrieval of an IP address in case it's provided
        alongside the status and extended attributes.

        Given:
        - A mock response.

        When:
        - The IP address is provided.
        - The status is specified.
        - Extended attributes are specified.

        Then:
        - The human readable includes the input IP address.
        - The context includes the IP address object with the input IP address and specified status and extended attributes.
        """

    # TODO
    def test_get_ip_command_from_ip_invalid_extattr(self, requests_mock):
        """
        Test retrieval of an IP address with invalid extended attributes.

        Given:
        - A mock response.

        When:
        - The IP address is provided.
        - The status is not specified.
        - Invalid extended attributes are specified.

        Then:
        - Ensure a validation error is raised.
        """

    def test_get_ip_command_from_netmask(self, requests_mock):
        """
        Test retrieval of an IP address in case netmask is provided.

        Given:
        - A mock response.

        When:
        - The netmask is provided.
        - No status is specified.
        - No extended attributes are specified.

        Then:
        - The human readable includes the input netmask.
        - The context includes the IP address object with the input netmask.
        """

        network = self.VALID_NETMASK

        mock_response = (Path(__file__).parent.resolve() / "test_data" / self.__class__.__name__
                         / "get_ipv4_addresses_from_network.json").read_text()

        requests_mock.get(
            f"{client._base_url}ipv4address?{InfoBloxNIOSClient.REQUEST_PARAMS_RETURN_AS_OBJECT_KEY}=1&network={self.VALID_NETMASK}&status={IPv4AddressStatus.USED.value}",  # noqa: E501
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, actual_raw_response = get_ip_command(client, {"network": network})

        actual_hr_lines = actual_hr.splitlines()
        assert "Infoblox Integration" in actual_hr_lines[0]

        assert self.CONTEXT_PATH in actual_context
        actual_output = cast(list, actual_context.get(self.CONTEXT_PATH))
        assert len(actual_output) == 9

    def test_transform_ip_context_known_keys(self):
        """
        Test for a scenario when the `infoblox-get-ip` command returns
        a expected/known response keys/.

        Given:
        - A mock response from InfoBlox API.

        When:
        - The response has all expected attributes.

        Then:
        - The transformation keys are as expected.
        """

        mock_response = (Path(__file__).parent.resolve() / "test_data" / self.__class__.__name__
                         / "get_ipv4_address_from_ip_address.json").read_text()

        res: dict[str, list] = json.loads(mock_response)
        ip: list[dict[str, Any]] = res.get("result")

        actual_transformation = transform_ip_context(ip)
        assert len(actual_transformation) == 1
        for k, v in IP_MAPPING.items():
            assert actual_transformation[0].get(v) == ip[0].get(k)

    def test_transform_ip_context_unknown_key(self):
        """
        Test for a scenario when the `infoblox-get-ip` command returns
        an unexpected/unknown key and the program doesn't raise
        an exception. See https://jira-dc.paloaltonetworks.com/browse/XSUP-35724.

        Given:
        - A mock response from InfoBlox API.

        When:
        - The response has an attribute, lease_state="active" that is unknown.

        Then:
        - The context output includes the transformed unknown key "LeaseState".
        """

        mock_response = (Path(__file__).parent.resolve() / "test_data" / self.__class__.__name__
                         / "get_ipv4_address_from_ip_address.json").read_text()

        unknown_key = "lease_state"
        unknown_key_value = "active"

        res: dict[str, list] = json.loads(mock_response)
        res["result"][0][unknown_key] = unknown_key_value
        ip = res.get("result")

        actual_transformation = transform_ip_context(ip)
        assert len(actual_transformation) == 1
        for k, v in IP_MAPPING.items():
            assert actual_transformation[0].get(v) == ip[0].get(k)
        assert actual_transformation[0]["LeaseState"] == unknown_key_value


class TestHostRecordsOperations:

    CONTEXT_KEY = f"{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_HOST_RECORDS_CONTEXT_NAME}"
    GET_HOST_RECORDS_ENDPOINT = "record:host"

    def test_get_all_records(self, requests_mock):
        """
        Test to get all records.

        Given:
        - Mock response for get all host records API call.

        When:
        - Get all host records API call is made.

        Then:
        - Ensure records are returned as expected.
        """

        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "get_records.json").read_text()

        requests_mock.get(
            f"{client._base_url}{self.GET_HOST_RECORDS_ENDPOINT}?{InfoBloxNIOSClient.REQUEST_PARAMS_RETURN_AS_OBJECT_KEY}=1",
            json=json.loads(mock_response)
        )

        hr, records, _ = get_host_records_command(client, {})

        assert len(cast(list, records.get(self.CONTEXT_KEY))) == 4
        assert "Host records" in hr
        assert "extattrs" not in hr

    def test_get_records_from_hostname(self, requests_mock):
        """
        Test to get host records by hostname.

        Given:
        - Mock response for get host records by hostname API call.

        When:
        - Get host records by hostname API call is made with hostname "host1".

        Then:
        - Ensure only matching record is returned.
        """

        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "get_record_by_hostname.json").read_text()
        host_name = "ciac-3607.test"

        requests_mock.get(
            client._base_url + self.GET_HOST_RECORDS_ENDPOINT
            + f"?{InfoBloxNIOSClient.REQUEST_PARAMS_RETURN_AS_OBJECT_KEY}=1&name={host_name}",
            json=json.loads(mock_response)
        )

        hr, records, _ = get_host_records_command(client, {"host_name": host_name})

        assert len(cast(list, records.get(self.CONTEXT_KEY))) == 1
        assert "Host records" in hr
        assert "extattrs" not in hr

    def test_get_records_from_extattr(self, requests_mock):
        """
        Test to get host records by extension attribute.

        Given:
        - Mock response for get host records by hostname API call.

        When:
        - An extension attribute is specified.

        Then:
        - Ensure only matching record is returned.
        """

        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "get_record_extattrs.json").read_text()
        input = "Site=Tel-Aviv"

        requests_mock.get(
            client._base_url + self.GET_HOST_RECORDS_ENDPOINT + f"?_return_fields%2B=extattrs&*{input}",
            json=json.loads(mock_response)
        )

        hr, records, _ = get_host_records_command(client, {"extattrs": input})

        assert len(cast(list, records.get(self.CONTEXT_KEY))) == 1
        assert "Host records" in hr
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in hr

    def test_get_rerords_with_extattrs_aliases(self, requests_mock):
        """
        Test to get host records with extended attributes and additional fields.

        Given:
        - Mock response for get host records by.

        When:
        - We specify extattrs and aliases as additional fields.

        Then:
        - 4 records are returned.
        - The 3 records don't include an AdditionalFields key.
        - The last record includes an AdditionalFields key.
        """

        input = "extattrs,aliases"

        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "get_records_extattrs_aliases.json").read_text()

        requests_mock.get(
            client._base_url + self.GET_HOST_RECORDS_ENDPOINT + f"?_return_fields%2B={input}",
            json=json.loads(mock_response)
        )

        actual_hr, actual_records, actual_raw_response = get_host_records_command(client, {"additional_return_fields": input})

        assert "Host records" in actual_hr
        assert self.CONTEXT_KEY in actual_records
        actual_output = cast(list, actual_records.get(self.CONTEXT_KEY))
        assert len(actual_output) == 4

        first_record = actual_output[0]
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in first_record
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in first_record
        assert INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY in first_record
        assert first_record[INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY] == "192.168.10.10"
        assert INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY in first_record
        assert not first_record[INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY]
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in first_record
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY not in first_record

        second_record = actual_output[1]
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in second_record
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in second_record
        assert INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY in second_record
        assert second_record[INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY] == "192.168.100.100"
        assert INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY in second_record
        assert second_record[INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY]
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in second_record
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY not in second_record

        third_record = actual_output[2]
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in third_record
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in third_record
        assert INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY in third_record
        assert INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY in third_record
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in third_record
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY not in third_record

        fourth_record = actual_output[3]
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in fourth_record
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in fourth_record
        assert INTEGRATION_HOST_RECORDS_IPV4ADDRESS_CONTEXT_KEY in fourth_record
        assert INTEGRATION_HOST_RECORDS_CONFIGURE_FOR_DHCP_KEY_CONTEXT_KEY in fourth_record
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in fourth_record
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY in fourth_record

        assert actual_raw_response == json.loads(mock_response)

    def test_get_host_records_command_non_existing_additional_return_fields(self, requests_mock):
        """
        Test running `get_host_records_command` with a non-existing return field.

        Given:
        - An `additional_return_fields` is specified.

        When:
        - The `additional_return_fields` doesn't exist.

        Then:
        - A `DemistoException` is raised.
        """

        additional_return_fields = "none"
        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "unknown_argument.json").read_text()

        requests_mock.get(
            client._base_url + self.GET_HOST_RECORDS_ENDPOINT + f"?_return_fields%2B={additional_return_fields}",
            json=json.loads(mock_response)
        )

        with pytest.raises(DemistoException, match="Unknown argument/field: 'none'"):
            get_host_records_command(
                client,
                {
                    "additional_return_fields": additional_return_fields
                }
            )

    def test_get_host_records_command_no_additional_fields(self, requests_mock):
        """
        Given:
        - Running `get_host_records_command`.

        When:
        - No `additional_fields` are provided.

        Then:
        - The `extattrs` should appended and returned.
        """

        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "get_records_extattrs.json").read_text()

        requests_mock.get(
            client._base_url + self.GET_HOST_RECORDS_ENDPOINT + f"?_return_fields%2B={INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY}",  # noqa: E501
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, actual_raw_response = get_host_records_command(
            client,
            {}
        )

        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in actual_hr.splitlines()[1]

        assert self.CONTEXT_KEY in actual_context
        actual_output = actual_context.get(self.CONTEXT_KEY)

        for o in actual_output:
            assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in o

    def test_get_host_records_command_extattrs_set_additional_fields(self, requests_mock):
        """
        Given:
        - Running `get_host_records_command`.

        When:
        - `additional_fields` is set to `extattrs`.

        Then:
        - The `extattrs` should appended and returned.
        """

        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "get_records_extattrs.json").read_text()

        requests_mock.get(
            client._base_url + self.GET_HOST_RECORDS_ENDPOINT + f"?_return_fields%2B={INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY}&*Site=ciac-5843",  # noqa: E501
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, actual_raw_response = get_host_records_command(
            client,
            {
                "additional_return_fields": INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY,
                INTEGRATION_COMMON_RAW_RESULT_EXTENSION_ATTRIBUTES_KEY: "Site=ciac-5843"
            }
        )

        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in actual_hr.splitlines()[1]

        assert self.CONTEXT_KEY in actual_context
        actual_output = actual_context.get(self.CONTEXT_KEY)

        for o in actual_output:
            assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in o


class TestNetworkInfoOperations:

    CONTEXT_KEY = f"{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_NETWORK_INFO_CONTEXT_KEY}"
    BASE_URL = f"{client._base_url}network?{InfoBloxNIOSClient.REQUEST_PARAMS_RETURN_AS_OBJECT_KEY}=1"  # noqa: E501

    def test_get_network_info_command(self, requests_mock):
        """
        Test when no arguments are supplied to the `get_network_info_command` method.

        Given:
        - A mock response of 2 networks.

        When:
        - No arguments are provided.

        Then:
        - 50 limit is applied.
        - output has 2 networks.
        - raw response is equal to the mock response.
        - No additional fields context key is set.
        """

        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "get_networks.json").read_text()

        requests_mock.get(
            self.BASE_URL,
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, actual_raw_response = get_network_info_command(client, {})

        assert "Network information" in actual_hr
        assert self.CONTEXT_KEY in actual_context
        actual_output = cast(list, actual_context.get(self.CONTEXT_KEY))
        assert len(actual_output) == 2
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY not in actual_output[0]

        assert actual_raw_response == json.loads(mock_response)

    def test_get_network_pattern_specified_return_fields_extattrs(self, requests_mock):
        """
        Test when an argument is supplied to the `get_network_info_command` method.

        Given:
        - A mock response of 1 network.

        When:
        - The `pattern` argument is supplied.

        Then:
        - 50 limit is applied.
        - output has 1 networks.
        - raw response is equal to the mock response.
        - No additional fields context key is set.
        """

        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "get_network_return_fields_extattrs.json").read_text()

        pattern = "192.168."

        requests_mock.get(
            f"{self.BASE_URL}&_max_results=50&_return_fields%2B=extattrs&network~={pattern}",
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, actual_raw_response = get_network_info_command(client, {"pattern": pattern})

        assert "Network information" in actual_hr

        assert self.CONTEXT_KEY in actual_context
        actual_output = cast(list, actual_context.get(self.CONTEXT_KEY))
        assert len(actual_output) == 1
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY not in actual_output[0]

        assert actual_raw_response == json.loads(mock_response)

    def test_get_networks_return_fields_options_extattrs(self, requests_mock):
        """
        Test when an arguments is supplied to the `get_network_info_command` method.

        Given:
        - A mock response of 2 networks.

        When:
        - `additional_return_fields` argument is set.
        - `max_results` argument is set.


        Then:
        - 10 limit is applied.
        - output has 1 networks.
        - raw response is equal to the mock response.
        - The additional fields context key is set.
        """

        limit = 10

        mock_response = (Path(__file__).parent.resolve() / "test_data"
                         / self.__class__.__name__ / "get_networks_return_fields_options_extattrs.json").read_text()

        requests_mock.get(
            self.BASE_URL,
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, actual_raw_response = get_network_info_command(
            client,
            {
                "additional_return_fields": "extattrs,options",
                "max_results": limit
            }
        )

        assert "Network information" in actual_hr

        assert self.CONTEXT_KEY in actual_context
        actual_output = cast(list, actual_context.get(self.CONTEXT_KEY))
        assert len(actual_output) == 2
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_EXTENSION_ATTRIBUTES_CONTEXT_KEY in actual_output[1]
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_NAME_CONTEXT_KEY in actual_output[1]
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_REFERENCE_CONTEXT_KEY in actual_output[1]
        assert INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_NETWORKVIEW_CONTEXT_KEY in actual_output[1]
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY in actual_output[0]
        assert INTEGRATION_COMMON_ADDITIONAL_FIELDS_CONTEXT_KEY in actual_output[1]

        assert actual_raw_response == json.loads(mock_response)
