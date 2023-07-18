import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import socket


def port_listen_check(port: int, host: str) -> CommandResults:
    """
    When given a port and host, this function will attempt to connect to the host on the given port and if successful,
    return a CommandResults object indicating success

    :type port: ``int``
    :param port: The port of which to connect on.

    :type host: ``str``
    :param host: The host to test the connection on.

    :rtype CommandResults: ``CommandResults``
    :return: CommandResults object with the result of the connection test.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port))
    open_port = False
    if result == 0:
        resp = f"Port {port} is open on host: {host}"
        open_port = True
    else:
        resp = f"Port {port} is not open on host: {host}"
    outputs = {"portOpen": open_port}
    return CommandResults(outputs=outputs, readable_output=resp)


def main():
    """
    Main entry point for the script.
    """
    port = int(demisto.args().get("port"))
    host = demisto.args().get("host")
    try:
        results = port_listen_check(port=port, host=host)
        return_results(results=results)
    except Exception as e:
        return_error(message=f"An error has occurred: {e}")


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
