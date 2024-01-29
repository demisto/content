from pathlib import Path
import pytest
from Infoblox import (
    INTEGRATION_CONTEXT_NAME,
    INTEGRATION_HOST_RECORDS_CONTEXT_NAME,
    INTEGRATION_IPV4_CONTEXT_NAME,
    RESULTS_LIMIT_DEFAULT,
    IPv4AddressStatus,
    InfoBloxNIOSClient,
    InvalidIPAddress,
    InvalidIPRange,
    InvalidNetmask,
    get_host_records_command,
    get_ip_command,
    transform_ext_attrs,
    transform_ipv4_range,
    valid_ip,
    valid_ip_range,
    valid_netmask
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

REQUEST_PARAM_ZONE = '?_return_as_object=1&_return_fields%2B=fqdn%2Crpz_policy%2Crpz_severity%2Crpz_type%2C' \
                     'substitute_name%2Ccomment%2Cdisable'

client = InfoBloxNIOSClient('https://example.com/v1/', params={'_return_as_object': '1'})


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
        actual = transform_ext_attrs(input)
        expected = [{'*IB Discovery Owned': 'EMEA'}, {'*Site': 'Tel-Aviv'}]
        assert actual == expected

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
        actual = transform_ext_attrs(input)
        expected = [{'*IB Discovery Owned': 'EMEA'}]
        assert actual == expected

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

    def test_valid_ip_address(self):
        """
        Test valid IP address
        """

        valid_ip("192.168.1.1")

    def test_valid_ip_invalid_address(self):
        """
        Test invalid IP address
        """

        ip = "192.168.1.256"
        with pytest.raises(InvalidIPAddress, match=f"'{ip}' is not a valid IP address"):
            valid_ip(ip)

    def test_valid_netmask(self):
        """
        Test a valid netmask.
        """

        valid_netmask("1.1.1.1/24")

    def test_valid_netmask_invalid(self):

        address = "192.168.1.0/33"
        with pytest.raises(InvalidNetmask, match=f"'{address}' is not a valid netmask"):
            valid_netmask(address)

    def test_valid_ip_range(self):
        valid_ip_range("192.168.1.0", "192.168.1.255")

    def test_valid_ip_range_to_greater_than_from(self):

        from_address = "192.168.1.100"
        to_address = "192.168.1.50"

        with pytest.raises(InvalidIPRange, match=f"'{from_address}' to '{to_address}' is not a valid IP range: last IP address must be greater than first"):
            valid_ip_range(from_address, to_address)

    def test_valid_ip_range_invalid_ip(self):

        from_address = "192.168.1.254"
        to_address = "192.168.2.256"

        with pytest.raises(InvalidIPRange, match=f"'{from_address}' to '{to_address}' is not a valid IP range: '{to_address}' does not appear to be an IPv4 or IPv6 address"):
            valid_ip_range(from_address, to_address)

    def test_transform_ipv4_range(self):

        from_address = "192.168.1.0"
        to_address = "192.168.1.254"

        actual = transform_ipv4_range(from_address, to_address)
        expected = [{'ip_address>': '192.168.1.0'}, {'ip_address<': '192.168.1.254'}]

        assert actual == expected

        assign_params(actual)


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

    # def test_delete_response_policy_zone_command(self, mocker, requests_mock):


class TestIPOperations:

    CONTEXT_PATH = f'{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_IPV4_CONTEXT_NAME}(val.ReferenceID && val.ReferenceID === obj.ReferenceID)'
    VALID_IP_ADDRESS = "192.168.1.1"
    VALID_NETMASK = "192.168.1.0/24"

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

        mock_response = (Path(__file__).parent.resolve() / "test_files" / self.__class__.__name__
                         / "get_ipv4_address_from_ip_address.json").read_text()

        requests_mock.get(
            f"{client._base_url}{InfoBloxNIOSClient.IPV4ADDRESS_ENDPOINT}?_return_as_object=1&ip_address={self.VALID_IP_ADDRESS}",
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, _ = get_ip_command(client, {"ip": self.VALID_IP_ADDRESS})

        actual_hr_lines = actual_hr.splitlines()
        assert f"Infoblox Integration - IP: {self.VALID_IP_ADDRESS} info" in actual_hr_lines[0]
        assert self.VALID_IP_ADDRESS in actual_hr_lines[3]
        assert actual_context.get(self.CONTEXT_PATH).get("IpAddress") == self.VALID_IP_ADDRESS

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

        mock_response = (Path(__file__).parent.resolve() / "test_files" / self.__class__.__name__
                         / "get_ipv4_address_from_ip_address.json").read_text()

        requests_mock.get(
            f"{client._base_url}{InfoBloxNIOSClient.IPV4ADDRESS_ENDPOINT}?_return_as_object=1&ip_address={self.VALID_IP_ADDRESS}&status={IPv4AddressStatus.USED.value}",
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, _ = get_ip_command(
            client, {"ip": self.VALID_IP_ADDRESS, "status": IPv4AddressStatus.USED.value})

        actual_hr_lines = actual_hr.splitlines()
        assert f"Infoblox Integration - IP: {self.VALID_IP_ADDRESS} info" in actual_hr_lines[0]
        assert self.VALID_IP_ADDRESS in actual_hr_lines[3]
        assert actual_context.get(self.CONTEXT_PATH).get("Status") == IPv4AddressStatus.USED.value

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

    # TODO
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

        mock_response = (Path(__file__).parent.resolve() / "test_files" / self.__class__.__name__
                         / "get_ipv4_addresses_from_network.json").read_text()

        requests_mock.get(
            f"{client._base_url}{InfoBloxNIOSClient.IPV4ADDRESS_ENDPOINT}?_return_as_object=1&network={self.VALID_NETMASK}&status={IPv4AddressStatus.USED.value}",
            json=json.loads(mock_response)
        )

        actual_hr, actual_context, _ = get_ip_command(client, {"network": self.VALID_NETMASK})

        actual_hr_lines = actual_hr.splitlines()
        assert f"Infoblox Integration - Netmask: {self.VALID_NETMASK} info" in actual_hr_lines[0]

    # TODO
    def test_get_ip_command_no_response(self):
        pass

    # TODO
    def test_get_ip_command_invalid_ip(self):
        pass

    # TODO
    def test_get_ip_command_invalid_netmask(self):
        pass

    # TODO
    def test_get_ip_command_invalid_from_ip(self):
        pass

    # TODO
    def test_get_ip_command_invalid_range(self):
        pass


class TestHostRecordsOperations:

    CONTEXT_KEY = f"{INTEGRATION_CONTEXT_NAME}.{INTEGRATION_HOST_RECORDS_CONTEXT_NAME}(val._ref && val._ref === obj._ref)"

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

        mock_response = (Path(__file__).parent.resolve() / "test_files"
                         / self.__class__.__name__ / "get_records.json").read_text()

        requests_mock.get(
            f"{client._base_url}{InfoBloxNIOSClient.GET_HOST_RECORDS_ENDPOINT}?_return_as_object=1",
            json=json.loads(mock_response)
        )

        hr, records, _ = get_host_records_command(client, {})

        assert len(records.get(self.CONTEXT_KEY)) == 4
        assert f"Host records (first {RESULTS_LIMIT_DEFAULT})" in hr
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

        mock_response = (Path(__file__).parent.resolve() / "test_files"
                         / self.__class__.__name__ / "get_record_by_hostname.json").read_text()
        host_name = "ciac-3607.test"

        requests_mock.get(
            client._base_url + InfoBloxNIOSClient.GET_HOST_RECORDS_ENDPOINT + f"?_return_as_object=1&name={host_name}",
            json=json.loads(mock_response)
        )

        hr, records, _ = get_host_records_command(client, {"host_name": host_name})

        assert len(records.get(self.CONTEXT_KEY)) == 1
        assert "Host records for ciac-3607.test" in hr
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

        mock_response = (Path(__file__).parent.resolve() / "test_files"
                         / self.__class__.__name__ / "get_record_extattrs.json").read_text()
        input = "Site=Tel-Aviv"

        requests_mock.get(
            client._base_url + InfoBloxNIOSClient.GET_HOST_RECORDS_ENDPOINT + f"?_return_fields%2B=extattrs&*{input}",
            json=json.loads(mock_response)
        )

        hr, records, _ = get_host_records_command(client, {"extattrs": input})

        assert len(records.get(self.CONTEXT_KEY)) == 1
        assert "Host records" in hr
        assert "extattrs" in hr
