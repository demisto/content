import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def getexternalservices_request(self, field, operator, value):
        data = {"request_data": {"filters": [{"field": field, "operator": operator, "value": value}]}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        headers['x-xdr-auth-id'] = '{{XSIAM_AUTH_ID}}'

        response = self._http_request('POST', 'public_api/v1/assets/get_external_services/',
                                      json_data=data, headers=headers)

        return response

    def getexternalservice_request(self, service_id_list):
        data = {"request_data": {"service_id_list": service_id_list}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        headers['x-xdr-auth-id'] = '{{XSIAM_AUTH_ID}}'

        response = self._http_request('POST', 'public_api/v1/assets/get_external_service',
                                      json_data=data, headers=headers)

        return response

    def getexternalipaddressranges_request(self):
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        headers['x-xdr-auth-id'] = '{{XSIAM_AUTH_ID}}'
        headers['accept'] = 'application/json'

        response = self._http_request('POST', 'public_api/v1/assets/get_external_ip_address_ranges/', headers=headers)

        return response

    def getexternalipaddressrange_request(self, range_id_list):
        data = {"request_data": {"range_id_list": range_id_list}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        headers['x-xdr-auth-id'] = '{{XSIAM_AUTH_ID}}'
        headers['accept'] = 'application/json'

        response = self._http_request(
            'POST', 'public_api/v1/assets/get_external_ip_address_range/', json_data=data, headers=headers)

        return response

    def getassetsinternetexposure_request(self):
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        headers['x-xdr-auth-id'] = '{{XSIAM_AUTH_ID}}'
        headers['accept'] = 'application/json'

        response = self._http_request('POST', 'public_api/v1/assets/get_assets_internet_exposure/', headers=headers)

        return response

    def getassetinternetexposure_request(self, asm_id_list):
        data = {"request_data": {"asm_id_list": asm_id_list}}
        headers = self._headers
        headers['Content-Type'] = 'application/json'
        headers['x-xdr-auth-id'] = '{{XSIAM_AUTH_ID}}'
        headers['accept'] = 'application/json'

        response = self._http_request(
            'POST', 'public_api/v1/assets/get_asset_internet_exposure/', json_data=data, headers=headers)

        return response


def getexternalservices_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    field = args.get('field')
    operator = args.get('operator')
    value = args.get('value')

    response = client.getexternalservices_request(field, operator, value)
    command_results = CommandResults(
        outputs_prefix='ASM.GetExternalServices',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getexternalservice_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    service_id_list = args.get('service_id_list')

    response = client.getexternalservice_request(service_id_list)
    command_results = CommandResults(
        outputs_prefix='ASM.GetExternalService',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getexternalipaddressranges_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.getexternalipaddressranges_request()
    command_results = CommandResults(
        outputs_prefix='ASM.GetExternalIpAddressRanges',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getexternalipaddressrange_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    range_id_list = args.get('range_id_list')

    response = client.getexternalipaddressrange_request(range_id_list)
    command_results = CommandResults(
        outputs_prefix='ASM.GetExternalIpAddressRange',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getassetsinternetexposure_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.getassetsinternetexposure_request()
    command_results = CommandResults(
        outputs_prefix='ASM.GetAssetsInternetExposure',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def getassetinternetexposure_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    asm_id_list = args.get('asm_id_list')

    response = client.getassetinternetexposure_request(asm_id_list)
    command_results = CommandResults(
        outputs_prefix='ASM.GetAssetInternetExposure',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {}
    headers['Authorization'] = f'{params["api_key"]}'

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'asm-getexternalservices': getexternalservices_command,
            'asm-getexternalservice': getexternalservice_command,
            'asm-getexternalipaddressranges': getexternalipaddressranges_command,
            'asm-getexternalipaddressrange': getexternalipaddressrange_command,
            'asm-getassetsinternetexposure': getassetsinternetexposure_command,
            'asm-getassetinternetexposure': getassetinternetexposure_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
