from Infoblox import Client
import demistomock as demisto
import json

from CommonServerPython import DemistoException

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

client = Client('https://example.com/v1/', params={'_return_as_object': '1'})


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
