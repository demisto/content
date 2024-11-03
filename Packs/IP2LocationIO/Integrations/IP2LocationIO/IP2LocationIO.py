import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import urllib3
from typing import Any

urllib3.disable_warnings()


class Client(BaseClient):
    def get_ip_geolocation(self, ip: str, api_key: str) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/',
            params={
                'ip': ip,
                'key': api_key
            }
        )


def test_module(client: Client) -> str:
    try:
        client._http_request(
            method='GET',
            url_suffix='/',
            params={
                'ip': '8.8.8.8'
            }
        )
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e

    return 'ok'


def ip_geolocation_command(client: Client, args: dict[str, Any], reliability: DBotScoreReliability,
                           api_key: str) -> list[CommandResults]:
    ips = argToList(args.get('ip'))
    if len(ips) == 0:
        raise ValueError('IP(s) not specified')

    command_results: list[CommandResults] = []

    for ip in ips:
        if not is_ip_valid(ip, accept_v6_ips=True):  # check IP's validity
            raise ValueError(f'IP "{ip}" is not valid')
        ip_data = client.get_ip_geolocation(ip, api_key)
        ip_data['ip'] = ip

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name='IP2LocationIO',
            score=Common.DBotScore.NONE,
            reliability=reliability
        )

        ip_standard_context = Common.IP(
            ip=ip,
            geo_country=ip_data.get('country_name'),
            geo_latitude=ip_data.get('latitude'),
            geo_longitude=ip_data.get('longitude'),
            geo_description=f"{ip_data.get('city_name')}, {ip_data.get('region_name')}, {ip_data.get('country_name')}",
            region=ip_data.get('region'),
            asn=f"AS{ip_data.get('asn')}",
            dbot_score=dbot_score
        )

        ip_context_excluded_fields = ['objects', 'nir']
        ip_data = {k: ip_data[k] for k in ip_data if k not in ip_context_excluded_fields}

        readable_output = tableToMarkdown('IP', ip_data)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='IP2LocationIO.IP',
            outputs_key_field='ip',
            outputs=ip_data,
            indicator=ip_standard_context
        ))
    return command_results


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('credentials', {}).get('password')

    base_url = urljoin(params.get('url').rstrip("/"), '')

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    reliability = params.get('integrationReliability', DBotScoreReliability.C)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'ip':
            return_results(ip_geolocation_command(client, args, reliability, api_key))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
