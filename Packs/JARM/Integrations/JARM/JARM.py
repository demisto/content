import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from urllib.parse import urlparse
from ipaddress import ip_address
from typing import Dict, Tuple, Any
from jarm.scanner.scanner import Scanner

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

DEFAULT_PORT = 443

""" CLIENT CLASS """


class Client:
    def jarm_fingerprint(self, host: str, port: int) -> Tuple[str, str, int]:
        return Scanner.scan(host, port)


""" HELPER FUNCTIONS """


def parse_hostname(hostname: str, port: Optional[int]) -> Dict[str, Any]:
    """
    Parses a target hostname. Supports multiple ipv4/fqdn with and without port formats.
    """
    target: Dict[str, Any] = {}
    if not hostname.startswith('https://'):
        hostname = 'https://' + hostname

    parsed_url = urlparse(hostname)
    if port:
        target['port'] = port
    elif parsed_url.port:
        target['port'] = parsed_url.port
    else:
        target['port'] = DEFAULT_PORT

    try:
        ip = ip_address(parsed_url.hostname)
        target['target_host'] = str(ip)
        target['target_type'] = 'ip'
    except ValueError:
        target['target_host'] = parsed_url.hostname
        target['target_type'] = 'fqdn'

    return target


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    return "ok"


def jarm_fingerprint_command(
    client: Client, args: Dict[str, Any]
) -> List[CommandResults]:
    class JARMDBotScore(Common.Indicator):
        def __init__(self, output: Dict[str, Any]):
            self._jarm = output.get('Fingerprint')
            self._ip = output.get('IP')
            self._port = output.get('Port')
            self._fqdn = output.get('FQDN')

        def to_context(self) -> Dict[str, Any]:
            return {
                "DBotScore": {
                    "Indicator": self._jarm,
                    "Type": "jarm",
                    "Vendor": "JARM",
                    "Score": Common.DBotScore.NONE,
                    "Host": {
                        'ip': self._ip,
                        'fqdn': self._fqdn,
                        'port': self._port
                    }
                }
            }

    host = args.get("host")
    if not host:
        raise ValueError("Host name (IP or domain) not specified")

    port = arg_to_number(args.get("port"))

    target = parse_hostname(host, port)

    target_type = target.get('target_type')
    if not target_type:
        raise ValueError('Cannot determine scan target')

    target_host = target.get('target_host')
    if not target_host:
        raise ValueError('Cannot determine scan target')

    port = target.get('port')
    if not port:
        raise ValueError('Invalid port provided')

    result = client.jarm_fingerprint(target_host, port)

    output = {}
    if target_type == 'ip':
        output = {"IP": target_host, "Port": port, "Fingerprint": result[0]}
    elif target_type == 'fqdn':
        output = {"FQDN": target_host, "Port": port, "Fingerprint": result[0]}

    return [
        CommandResults(
            outputs_prefix="JARM", outputs_key_field=['FQDN', 'IP', 'Port'], outputs=output
        ),
        CommandResults(
            readable_output=f"New JARM indicator was found: {result[0]}",
            indicator=JARMDBotScore(output=output)
        )
    ]


""" MAIN FUNCTION """


def main() -> None:

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        handle_proxy()
        client = Client()

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == "jarm-fingerprint":
            return_results(jarm_fingerprint_command(client, demisto.args()))
        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
