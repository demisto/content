import demistomock as demisto
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def mitigation_performed_request(self,
                                     mitigationstatus_external_ticket_id,
                                     mitigationstatus_external_ticket_url,
                                     mitigationstatus_id,
                                     mitigationstatus_state):
        data = assign_params(external_ticket_id=mitigationstatus_external_ticket_id,
                             external_ticket_url=mitigationstatus_external_ticket_url, id=mitigationstatus_id,
                             state=mitigationstatus_state)
        headers = self._headers

        response = self._http_request('post', 'mitigations/performed', json_data=data, headers=headers)

        return response

    def mitigations_export_request(self, filter_):
        params = assign_params(filter=filter_)
        headers = self._headers

        response = self._http_request('get', 'mitigations', params=params, headers=headers)

        return response

    def mitigations_performed_request(self, mitigationsstatus_mitigation_id,
                                      mitigationsstatus_mitigation_ids, mitigationsstatus_state):
        data = assign_params(mitigation_id=mitigationsstatus_mitigation_id,
                             mitigation_ids=mitigationsstatus_mitigation_ids, state=mitigationsstatus_state)
        headers = self._headers

        response = self._http_request('post', 'mitigations', json_data=data, headers=headers)

        return response


def mitigation_performed_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mitigationstatus_external_ticket_id = str(args.get('mitigationstatus_external_ticket_id', ''))
    mitigationstatus_external_ticket_url = str(args.get('mitigationstatus_external_ticket_url', ''))
    mitigationstatus_id = str(args.get('mitigationstatus_id', ''))
    mitigationstatus_state = str(args.get('mitigationstatus_state', ''))

    response = client.mitigation_performed_request(
        mitigationstatus_external_ticket_id, mitigationstatus_external_ticket_url,
        mitigationstatus_id, mitigationstatus_state)
    command_results = CommandResults(
        outputs_prefix='Zafran.MitigationsPerformedResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def mitigations_export_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    filter_ = str(args.get('filter_', ''))

    response = client.mitigations_export_request(filter_)
    command_results = CommandResults(
        outputs_prefix='Zafran.UpstreamMitigation',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def mitigations_performed_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    mitigationsstatus_mitigation_id = str(args.get('mitigationsstatus_mitigation_id', ''))
    mitigationsstatus_mitigation_ids = argToList(args.get('mitigationsstatus_mitigation_ids', []))
    mitigationsstatus_state = str(args.get('mitigationsstatus_state', ''))

    response = client.mitigations_performed_request(
        mitigationsstatus_mitigation_id, mitigationsstatus_mitigation_ids, mitigationsstatus_state)
    command_results = CommandResults(
        outputs_prefix='Zafran.MitigationsPerformedResponse',
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
    headers['Authorization'] = 'Bearer ' + params['api_key']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, '/api/v2/'), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'zafran-mitigation-performed': mitigation_performed_command,
            'zafran-mitigations-export': mitigations_export_command,
            'zafran-mitigations-performed': mitigations_performed_command,
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
