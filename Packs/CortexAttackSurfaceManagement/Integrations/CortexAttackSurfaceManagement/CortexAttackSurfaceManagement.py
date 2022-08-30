import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, base_url, verify, proxy, headers, auth):
        super().__init__(base_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def getexternalservices_request(self, field, operator, value):
        data = {"request_data": {}}
        headers = self._headers

        response = self._http_request('POST', '/assets/get_external_services/',
                                      json_data=data, headers=headers)

        return response

    def getexternalservice_request(self, service_id_list):
        data = {"request_data": {"service_id_list": service_id_list}}
        headers = self._headers

        response = self._http_request('POST', '/assets/get_external_service',
                                      json_data=data, headers=headers)

        return response

    def getexternalipaddressranges_request(self):
        data = {"request_data": {}}
        headers = self._headers

        response = self._http_request('POST', '/assets/get_external_ip_address_ranges/',
                                      json_data=data, headers=headers)

        return response

    def getexternalipaddressrange_request(self, range_id_list):
        data = {"request_data": {"range_id_list": range_id_list}}
        headers = self._headers

        response = self._http_request('POST', '/assets/get_external_ip_address_range/',
                                      json_data=data, headers=headers)

        return response

    def getassetsinternetexposure_request(self):
        data = {"request_data": {}}
        headers = self._headers

        response = self._http_request('POST', '/assets/get_assets_internet_exposure/',
                                      json_data=data, headers=headers)

        return response

    def getassetinternetexposure_request(self, asm_id_list):
        data = {"request_data": {"asm_id_list": asm_id_list}}
        headers = self._headers

        response = self._http_request('POST', '/assets/get_asset_internet_exposure/',
                                      json_data=data, headers=headers)

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
    service_id = args.get('service_id')
    service_id_list = service_id.split(",")
    if len(service_id_list) > 1:
        return_error("This command only supports one service_id at this time")

    response = client.getexternalservice_request(service_id_list)
    parsed = response['reply']['details']
    markdown = tableToMarkdown('External Service', parsed)
    command_results = CommandResults(
        outputs_prefix='ASM.GetExternalService',
        outputs_key_field='service_id',
        outputs=parsed,
        raw_response=parsed,
        readable_output=markdown
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
    range_id = args.get('range_id')
    range_id_list = range_id.split(",")
    if len(range_id_list) > 1:
        return_error("This command only supports one range_id at this time")

    response = client.getexternalipaddressrange_request(range_id_list)
    parsed = response['reply']['details']
    markdown = tableToMarkdown('External IP Address Range', parsed)
    command_results = CommandResults(
        outputs_prefix='ASM.GetExternalIpAddressRange',
        outputs_key_field='range_id',
        outputs=parsed,
        raw_response=parsed,
        readable_output=markdown
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
    asm_id = args.get('asm_id')
    asm_id_list = asm_id.split(",")
    if len(asm_id_list) > 1:
        return_error("This command only supports one asm_id at this time")

    response = client.getassetinternetexposure_request(asm_id_list)
    parsed = response['reply']['details']
    markdown = tableToMarkdown('Asset Internet Exposure', parsed)
    command_results = CommandResults(
        outputs_prefix='ASM.GetAssetInternetExposure',
        outputs_key_field='asm_ids',
        outputs=parsed,
        raw_response=parsed,
        readable_output=markdown
    )

    return command_results


def test_module(client: Client) -> None:
    try:
        response = client.getexternalservices_request(None, None, None)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    #url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    #headers = {}
    #headers['Authorization'] = f'{params["api_key"]}'

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        headers = {
            "HOST": demisto.getLicenseCustomField("Core.ApiHostName"),
            demisto.getLicenseCustomField("Core.ApiHeader"): demisto.getLicenseCustomField("Core.ApiKey"),
            "Content-Type": "application/json"
        }
        url_suffix = "/public_api/v1"
        url = "http://" + demisto.getLicenseCustomField("Core.ApiHost") + "/api/webapp/"
        add_sensitive_log_strs(demisto.getLicenseCustomField("Core.ApiKey"))
        base_url = urljoin(url, url_suffix)
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            auth=None)

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
