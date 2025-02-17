import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def osv_get_vuln_by_id_request(self, id_):
        headers = self._headers

        response = self._http_request('get', f'v1new/vulns/{id_}', headers=headers)

        return response

    def osv_query_affected_by_commit_request(self, v1query_commit):
        data = assign_params(commit=v1query_commit)
        headers = self._headers

        response = self._http_request('post', 'v1new/query', json_data=data, headers=headers)

        return response

    def osv_query_affected_by_package_request(self, v1query_version, v1query_package, v1query_ecosystem):
        data = assign_params(version=v1query_version, package={'name': v1query_package, 'ecosystem': v1query_ecosystem})
        headers = self._headers
        response = self._http_request('post', 'v1new/query', json_data=data, headers=headers)

        return response


def osv_get_vuln_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = str(args.get('id_', ''))

    response = client.osv_get_vuln_by_id_request(id_)
    command_results = CommandResults(
        outputs_prefix='OSV.Vulnerability',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def osv_query_affected_by_commit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    command_results = CommandResults()
    v1query_commit = str(args.get('commit', ''))

    response = client.osv_query_affected_by_commit_request(v1query_commit)
    if response:
        command_results = CommandResults(
            outputs_prefix='OSV.VulnerabilityList',
            outputs_key_field='',
            outputs=response['vulns'],
            raw_response=response
        )
    else:
        return_error("Please check if the value provided is correct")
    return command_results


def osv_query_affected_by_package_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    command_results = CommandResults()
    v1query_version = str(args.get('version', ''))
    v1query_package = str(args.get('packageName', ''))
    v1query_ecosystem = str(args.get('ecosystem', ''))

    response = client.osv_query_affected_by_package_request(v1query_version, v1query_package, v1query_ecosystem)
    if response:
        command_results = CommandResults(
            outputs_prefix='OSV.VulnerabilityList',
            outputs_key_field='',
            outputs=response['vulns'],
            raw_response=response
        )
    else:
        return_error("Please check if the value provided is correct")
    return command_results


def test_module(client: Client) -> None:
    try:
        client.osv_get_vuln_by_id_request("OSV-2020-111")
    except Exception as e:
        if 'Bug not found' in str(e):
            return_error("Please check if the vulnerability OSV-2020-111 still exists")
        else:
            raise e
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers: Dict[str, Any] = {}
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'osv-get-vuln-by-id': osv_get_vuln_by_id_command,
            'osv-query-affected-by-commit': osv_query_affected_by_commit_command,
            'osv-query-affected-by-package': osv_query_affected_by_package_command
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
