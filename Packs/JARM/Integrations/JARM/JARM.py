import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import asyncio
import urllib3
import traceback
from urllib.parse import urlparse
from ipaddress import ip_address
from typing import Any
from jarm.scanner.scanner import Scanner

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

DEFAULT_PORT = 443

""" CLIENT CLASS """


class Client:
    def jarm_fingerprint(self, host: str, port: int) -> tuple[str, str, int]:
        return asyncio.run(Scanner.scan_async(host, port, suppress=True))


""" HELPER FUNCTIONS """


def parse_hostname(hostname: str, port: Optional[int]) -> dict[str, Any]:
    """
    Parses a target hostname. Supports multiple ipv4/fqdn with and without port formats.
    """
    target: dict[str, Any] = {}
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
        ip = ip_address(parsed_url.hostname)  # type: ignore[arg-type]
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
    client: Client, args: dict[str, Any]
) -> CommandResults:
    class JARMDBotScore(Common.Indicator):
        def __init__(self, output: dict[str, Any]):
            self._jarm = output.get('Fingerprint')

        def to_context(self) -> dict[str, Any]:
            return {
                "DBotScore": {
                    "Indicator": self._jarm,
                    "Type": "jarm",
                    "Vendor": "JARM",
                    "Score": Common.DBotScore.NONE,
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
    output['Fingerprint'] = result[0]
    output['Target'] = f'{target_host}:{port}'
    output['Port'] = port
    if target_type == 'ip':
        output['IP'] = target_host
    elif target_type == 'fqdn':
        output['FQDN'] = target_host

    return CommandResults(
        outputs_prefix="JARM", outputs_key_field=['FQDN', 'IP', 'Port'], outputs=output,
        indicator=JARMDBotScore(output=output)
    )


""" MAIN FUNCTION """


def main() -> None:

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        handle_proxy()
        client = Client()

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

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
