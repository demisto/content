from Infoblox import Client
import demistomock as demisto

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

POST_NEW_ZONE_ERROR = {
    "Error": "AdmConDataError: None (IBDataConflictError: IB.Data.Conflict:Duplicate object 'test123.com' of type zone exists in the database.)",
    "code": "Client.Ibap.Data.Conflict",
    "text": "Duplicate object 'test123.com' of type zone exists in the database."
}

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

    def test_parse_demisto_exception(self, requests_mock, mocker):
        from Infoblox import parse_demisto_exception
        mocker.patch.object(demisto, 'params', return_value={})
        requests_mock.post(BASE_URL + 'vault/lock?vaultId=111', json=POST_NEW_ZONE_ERROR)
        with raises(DemistoException, match='Could not lock vault'):
            lock_vault_command(client, {'vault_id': '111'})


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
