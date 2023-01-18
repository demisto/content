from CommonServerPython import *  # noqa: F401


import ipaddress
import socket


def snmp_send(udp_socket, probe, host, port):
    """Return the Snmp response

        Parameters:
            udp_socket (object): Python object of socket.
            probe (str): String value of Snmp data payload.
            host (str): String value of IP address.
            port (int): Integer port number.

        Returns:
            Str: Returns the value of the Snmp response.
    """

    udp_socket.sendto(bytes.fromhex(probe), (host, port))
    udp_socket.settimeout(3)
    return udp_socket.recvfrom(1024)


def snmp_v1(udp_socket, probe, host, port):
    """Return the Snmp Version 1 response."""
    return snmp_send(udp_socket, probe, host, port)


def snmp_v2(udp_socket, probe, host, port):
    """Return the Snmp Version 2 response."""

    return snmp_send(udp_socket, probe, host, port)


def snmp_v3(udp_socket, probe, host, port):
    """Return the Snmp Version 3 response."""

    return snmp_send(udp_socket, probe, host, port)


def snmp_detect(host: str) -> dict:
    """Return the dict of snmp versions enabled

        Parameters:
            host (str): String value of Ip address.

        Returns:
            Dict: Returns the dict containing if Snmp is enabled or not and list of versions enabled.
    """

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Hex value of the Snmp probes for each version.
    long_hex_v3 = "303a020103300f02024a69020300ffe30401040201030410300e0"
    hex_data = {
        "v1": [
            "302902010004067075626c6963a01c0204565adc5d020100020100300e300c06082b060102010101000500"
        ],
        "v2": [
            "302602010104067075626c6963a1190204dc63c29a020100020100300b300906052b060102010500"
        ],
        "v3": [
            long_hex_v3 + "400020100020100040004000400301204000400a00c020237f00201000201003000"
        ],
    }
    port = 161  # default SNMP port
    ver = list()

    enabled = "False"

    for version, probes in hex_data.items():
        for probe in probes:
            try:
                if version == "v1":
                    snmp_v1(udp_socket, probe, host, port)
                elif version == "v2":
                    snmp_v2(udp_socket, probe, host, port)
                else:
                    snmp_v3(udp_socket, probe, host, port)
                enabled = "True"
                ver.append(version)
            except TimeoutError:
                pass
    results = {"enabled": enabled, "versions": ver}
    return results


def main():
    host = demisto.args().get("IP")
    try:
        ipaddress.ip_address(host)  # validate ip address
        results = snmp_detect(host)
        return_results(CommandResults(
            outputs_prefix='SnmpDetection',
            outputs=results,
            raw_response=results
        ))
    except ValueError:
        pass


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    """This is executed when run from the command line"""
    main()
