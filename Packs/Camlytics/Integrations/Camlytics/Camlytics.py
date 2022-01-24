import demistomock as demisto
from CommonServerPython import *


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)

    def channels_request(self):
        headers = self._headers

        response = self._http_request('GET', 'channels', headers=headers)

        return response

    def eventstotalsrule_request(self, channelid, sincetime, untiltime, origin):
        params = assign_params(channelId=channelid, sinceTime=sincetime, untilTime=untiltime, origin=origin)
        headers = self._headers

        response = self._http_request('GET', 'events/totals/rule', params=params, headers=headers)

        return response

    def eventstotalstype_request(self, channelid, sincetime, untiltime, origin):
        params = assign_params(channelId=channelid, sinceTime=sincetime, untilTime=untiltime, origin=origin)
        headers = self._headers

        response = self._http_request('GET', 'events/totals/type', params=params, headers=headers)

        return response

    def events_request(self, channelid, sinceid, sincetime, untilid, untiltime, limit, order, timeout):
        params = assign_params(channelId=channelid, sinceId=sinceid, sinceTime=sincetime,
                               untilId=untilid, untilTime=untiltime, limit=limit, order=order, timeout=timeout)
        headers = self._headers

        response = self._http_request('GET', 'events', params=params, headers=headers)

        return response


def get_channels_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    response = client.channels_request()
    command_results = CommandResults(
        outputs_prefix='Camlytics.Channels',
        outputs_key_field='channel_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_events_totals_by_rule_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    channelid = args.get('channelid')
    sincetime = args.get('sincetime')
    untiltime = args.get('untiltime')
    origin = args.get('origin')

    response = client.eventstotalsrule_request(channelid, sincetime, untiltime, origin)
    command_results = CommandResults(
        outputs_prefix='Camlytics.EventsTotalsRule',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_events_totals_by_type_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    channelid = args.get('channelid')
    sincetime = args.get('sincetime')
    untiltime = args.get('untiltime')
    origin = args.get('origin')

    response = client.eventstotalstype_request(channelid, sincetime, untiltime, origin)
    command_results = CommandResults(
        outputs_prefix='Camlytics.EventsTotalsType',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_events_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    channelid = args.get('channelid')
    sinceid = args.get('sinceid')
    sincetime = args.get('sincetime')
    untilid = args.get('untilid')
    untiltime = args.get('untiltime')
    limit = args.get('limit')
    order = args.get('order')
    timeout = args.get('timeout')

    response = client.events_request(channelid, sinceid, sincetime, untilid, untiltime, limit, order, timeout)
    command_results = CommandResults(
        outputs_prefix='Camlytics.Events',
        outputs_key_field='event_id',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    client.channels_request()
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = str(params.get('url')) + '/v1/json/'
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers={})
        commands = {
            'camlytics-get-channels': get_channels_command,
            'camlytics-get-events-totals-by-rule': get_events_totals_by_rule_command,
            'camlytics-get-events-totals-by-type': get_events_totals_by_type_command,
            'camlytics-get-events': get_events_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
