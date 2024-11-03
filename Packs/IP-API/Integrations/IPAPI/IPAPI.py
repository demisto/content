import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
from typing import Any

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def get_ip_reputation(self, ip: str) -> dict[str, Any]:
        params = demisto.params()
        if params.get('https'):
            return self._http_request(
                method='GET',
                url_suffix=ip,
                params={
                    'key': params.get('apikey'),
                    'fields': params.get('fields')
                }
            )
        else:
            return self._http_request(
                method='GET',
                url_suffix=ip,
                params={
                    'fields': params.get('fields')
                }
            )


def test_module(client: Client) -> str:
    try:
        client.get_ip_reputation('8.8.8.8')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is either empty - or correctly set'
        else:
            raise e
    return 'ok'


def ip_reputation_command(client: Client, args: dict[str, Any]) -> list[CommandResults]:
    # ip command: Returns IP details for a list of IPs

    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    command_results: list[CommandResults] = []

    ip_data = []
    for ip in ips:
        # documentation of json api - https://ip-api.com/docs/api:json.
        result = client.get_ip_reputation(ip)

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            score=0,
            reliability=demisto.params().get('integrationReliability')
        )

        common_ip = Common.IP(
            ip=ip,
            dbot_score=dbot_score,
            geo_country=result.get('country'),
            region=result.get('regionName'),
            geo_longitude=result.get('lon'),
            geo_latitude=result.get('lat'),
            organization_name=result.get('org')
        )

        command_res = CommandResults(indicator=common_ip)

        command_results.append(command_res)
        ip_data.append(result)

    readable_output = tableToMarkdown('IP-API', ip_data)

    command_results.append(CommandResults(
        readable_output=readable_output,
        outputs_prefix='IP-API',
        outputs_key_field='query',
        outputs=ip_data
    ))
    return command_results


def main() -> None:
    params = demisto.params()
    if params.get('https'):
        base_url = "https://pro.ip-api.com/json/"
    else:
        base_url = "http://ip-api.com/json/"

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'ip':
            return_results(ip_reputation_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
