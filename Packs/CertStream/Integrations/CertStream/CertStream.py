from CommonServerPython import *  # noqa: F401
import traceback
import certstream
from certstream.core import CertStreamClient
from datetime import datetime


VENDOR = "Kali Dog Security"
PRODUCT = "CertStream"


def fetch_certificates(message: dict, context: dict) -> None:
    """
    This function gets a single message containing an X.509 certificate.

    Args:
        message - The message received from the Certificate Transparency (JSON)

    Returns:
        None
    """

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]

        now = datetime.now()
        domains = ", ".join(message['data']['leaf_cert']['all_domains'][1:])
        demisto.info(f"[{now:%m/%d/%y %H:%M:%S}] {domain} (SAN: {domains})\n")


def test_module(host: str):
    def on_message(message, context):
        return

    try:
        c = CertStreamClient(on_message, url=host, skip_heartbeats=True, on_open=None, on_error=None)
        c.run_forever(ping_interval=5)
        c.close()
        return 'ok'

    except Exception as e:
        demisto.error(e)


def long_running_execution_command(host: str):
    demisto.info("Starting CertStream Listener")
    certstream.listen_for_events(fetch_certificates, url=host)


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    host = params["url"]
    params["list_name"]

    try:
        if command == "long-running-execution":
            return_results(long_running_execution_command(host))
        elif command == "test-module":
            return_results(test_module(host))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception:
        return_error(f'Failed to execute {command} command.\nError:\n{traceback.format_exc()}')


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
