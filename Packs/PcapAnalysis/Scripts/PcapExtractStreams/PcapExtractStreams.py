import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import codecs
import os
import unicodedata
import logging
from tempfile import NamedTemporaryFile
from typing import Any
from collections.abc import Generator

import pyshark

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10

codecs.register_error('replace_with_space', lambda x: (' ', x.start + 1))  # type: ignore[attr-defined]


def from_bytes_to_text(mode: str, binary: bytes) -> str:
    """
    Make a text from a binary.

    :param mode: How to convert the binary to text.
    :return: A text converted from the binary.
    """
    if mode == 'text-based-protocol':
        # Keep all the characters used in text based protocols
        # * The unicodedata category names of control code start with C
        return ''.join(' '
                       if c == '\ufffd'
                       or (c not in ('\n', '\r', '\t') and unicodedata.category(c)[0] == 'C')
                       else c
                       for c in binary.decode('utf-8', errors='replace'))
    elif mode == 'human-readable':
        return binary.decode('utf-8', errors='replace_with_space')
    else:
        raise ValueError(f'Unknown text conversion mode: {mode}')


class Streams:
    def __init__(self, server_ports: list[tuple[int, int]]):
        self.__tcp_streams: dict[tuple, Any] = {}
        self.__udp_streams: dict[tuple, Any] = {}
        self.__server_ports = server_ports

    def __make_item(self,
                    bin2txt_mode: str,
                    filter_keys: list[str] | None,
                    protocol: str,
                    sender_ip: str,
                    sender_port: int,
                    recipient_ip: str,
                    recipient_port: int,
                    stream_bytes: bytes,
                    outgoing_bytes: bytes,
                    incoming_bytes: bytes) -> dict[str, Any]:

        return {k: v for k, v in {
                'protocol': protocol,
                'client_ip': sender_ip,
                'client_port': sender_port,
                'server_ip': recipient_ip,
                'server_port': recipient_port,
                'stream_size': len(stream_bytes),
                'stream_text': from_bytes_to_text(bin2txt_mode, stream_bytes),
                'stream_base64': base64.b64encode(stream_bytes).decode(),
                'outgoing_size': len(outgoing_bytes),
                'outgoing_text': from_bytes_to_text(bin2txt_mode, outgoing_bytes),
                'outgoing_base64': base64.b64encode(outgoing_bytes).decode(),
                'incoming_size': len(incoming_bytes),
                'incoming_text': from_bytes_to_text(bin2txt_mode, incoming_bytes),
                'incoming_base64': base64.b64encode(incoming_bytes).decode()
                }.items() if not filter_keys or (k in filter_keys)}

    def add_tcp(self,
                stream_index: int,
                tcp_flags: int,
                sender_ip: str,
                sender_port: int,
                recipient_ip: str,
                recipient_port: int,
                payload: bytes | None) -> None:
        """
        Add a tcp packet to the streams.

        :param stream_index: The index of TCP streams.
        :param tcp_flags: The TCP flags.
        :param sender_ip: The IP address of a sender.
        :param sender_port: The port number of a sender.
        :param recipient_ip: The IP address of a recipient.
        :param recipient_port: The port number of a recipient.
        :param payload: The payload transmitted.
        """
        key1 = (sender_ip, sender_port, recipient_ip, recipient_port, stream_index)
        key2 = (recipient_ip, recipient_port, sender_ip, sender_port, stream_index)

        if key1 in self.__tcp_streams:
            if payload:
                self.__tcp_streams[key1]['outgoing'] += payload
                self.__tcp_streams[key1]['stream'] += payload
        elif key2 in self.__tcp_streams:
            if payload:
                self.__tcp_streams[key2]['incoming'] += payload
                self.__tcp_streams[key2]['stream'] += payload
        else:
            mask = TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_ACK
            payload = payload if payload else b''
            outgoing = None
            if (tcp_flags & mask) == TCP_FLAG_SYN:
                outgoing = True
            elif (tcp_flags & mask) == (TCP_FLAG_SYN | TCP_FLAG_ACK):
                outgoing = False
            else:
                matchs = any(port_range[0] < sender_port < port_range[1] for port_range in self.__server_ports)
                matchr = any(port_range[0] < recipient_port < port_range[1] for port_range in self.__server_ports)
                if matchs and (not matchr or (sender_port < recipient_port)):
                    outgoing = False
                elif matchr and (not matchs or (recipient_port < sender_port)):
                    outgoing = True

            if outgoing is None or outgoing is True:
                self.__tcp_streams[key1] = {
                    'outgoing': payload,
                    'incoming': b'',
                    'stream': payload
                }
            else:
                self.__tcp_streams[key2] = {
                    'outgoing': b'',
                    'incoming': payload,
                    'stream': payload
                }

    def add_udp(self,
                sender_ip: str,
                sender_port: int,
                recipient_ip: str,
                recipient_port: int,
                payload: bytes | None) -> None:
        """
        Add a udp packet to the streams.

        :param sender_ip: The IP address of a sender.
        :param sender_port: The port number of a sender.
        :param recipient_ip: The IP address of a recipient.
        :param recipient_port: The port number of a recipient.
        :param payload: The payload transmitted.
        """
        key1 = (sender_ip, sender_port, recipient_ip, recipient_port)
        key2 = (recipient_ip, recipient_port, sender_ip, sender_port)

        if key1 in self.__udp_streams:
            if payload:
                self.__udp_streams[key1]['outgoing'] += payload
                self.__udp_streams[key1]['stream'] += payload
        elif key2 in self.__udp_streams:
            if payload:
                self.__udp_streams[key2]['incoming'] += payload
                self.__udp_streams[key2]['stream'] += payload
        else:
            payload = payload if payload else b''
            self.__udp_streams[key1] = {
                'outgoing': payload,
                'incoming': b'',
                'stream': payload
            }

    def build(self, bin2txt_mode: str, filter_keys: list[str] | None = None) -> list[dict[str, Any]]:
        """
        Build the streams

        :param bin2txt_mode: How to convert the binary to text.
        :param filter_keys: Keys of the values to filter the stream information.
        :return: List of the streams.
        """
        output = []
        for key, stream in self.__tcp_streams.items():
            sender_ip, sender_port, recipient_ip, recipient_port, stream_index = key
            output.append(self.__make_item(
                bin2txt_mode=bin2txt_mode,
                filter_keys=filter_keys,
                protocol='tcp',
                sender_ip=sender_ip,
                sender_port=sender_port,
                recipient_ip=recipient_ip,
                recipient_port=recipient_port,
                stream_bytes=stream.get('stream', b''),
                outgoing_bytes=stream.get('outgoing', b''),
                incoming_bytes=stream.get('incoming', b'')
            ))
        for key, stream in self.__udp_streams.items():
            sender_ip, sender_port, recipient_ip, recipient_port = key
            output.append(self.__make_item(
                bin2txt_mode=bin2txt_mode,
                filter_keys=filter_keys,
                protocol='udp',
                sender_ip=sender_ip,
                sender_port=sender_port,
                recipient_ip=recipient_ip,
                recipient_port=recipient_port,
                stream_bytes=stream.get('stream', b''),
                outgoing_bytes=stream.get('outgoing', b''),
                incoming_bytes=stream.get('incoming', b'')
            ))
        return output


class PcapParser:
    def __init__(self, server_ports: list[tuple[int, int]]):
        self.__server_ports = server_ports

    def __parse(self, pcap: pyshark.capture.capture.Capture) -> Streams:
        """
        Parse a pcap

        :param pcap: The packet capture instance.
        :return: The stream data extracted.
        """
        streams = Streams(server_ports=self.__server_ports)
        for packet in pcap:
            ip_layer = packet.get_multiple_layers('ip')
            if not ip_layer:
                continue

            sender_ip = ip_layer[0].get('src_host')
            recipient_ip = ip_layer[0].get('dst_host')

            if tcp_layer := packet.get_multiple_layers('tcp'):
                tcp = tcp_layer[0]

                payload = tcp.get('payload')
                streams.add_tcp(
                    stream_index=int(tcp.get('stream', 0)),
                    tcp_flags=int(tcp.flags, 0),
                    sender_ip=str(sender_ip),
                    sender_port=int(tcp.get('srcport')),
                    recipient_ip=str(recipient_ip),
                    recipient_port=int(tcp.get('dstport')),
                    payload=payload.binary_value if payload else None
                )

            if udp_layer := packet.get_multiple_layers('udp'):
                udp = udp_layer[0]

                payload = udp.get('payload')
                streams.add_udp(
                    sender_ip=str(sender_ip),
                    sender_port=int(udp.get('srcport')),
                    recipient_ip=str(recipient_ip),
                    recipient_port=int(udp.get('dstport')),
                    payload=payload.binary_value if payload else None
                )
        return streams

    def parse_file(self, pcap_file_path: str, wpa_password: str, rsa_key_file_path: str | None, pcap_filter: str) -> Streams:
        """
        Parse a pcap file

        :param pcap_file_path: The file of the pcap to parse.
        :param wpa_password: The wpa password for the decryption
        :param rsa_key_file_path: The file of the decryption key.
        :param pcap_filter: A filter to apply on the PCAP. Same filter syntax as in Wireshark
        :return: The stream data extracted.
        """
        # Create custom parameters
        custom_parameters = None
        if rsa_key_file_path:
            custom_parameters = {'-o': f'uat:rsa_keys:"{rsa_key_file_path}",""'}

        # Parse the pcap
        logging.getLogger('asyncio').setLevel(logging.ERROR)
        with open(os.devnull, 'w') as devnull:
            sys.stderr = devnull
            try:
                with pyshark.FileCapture(pcap_file_path,
                                         display_filter=pcap_filter,
                                         decryption_key=wpa_password,
                                         encryption_type='WPA-PWD',
                                         keep_packets=False,
                                         custom_parameters=custom_parameters) as cap:
                    return self.__parse(cap)
            except pyshark.capture.capture.TSharkCrashException:
                raise ValueError('Could not find packets. Make sure that the file is a .cap/.pcap/.pcapng file, '
                                 'the filter is of the correct syntax and that the rsa key is added correctly.')
            finally:
                sys.stderr = sys.__stderr__

    def parse_bytes(self, pcap: bytes, wpa_password: str, rsa_decrypt_key: bytes | None, pcap_filter: str) -> Streams:
        """
        Parse a pcap bytes

        :param pcap: The data of a PCAP
        :param wpa_password: The wpa password for the decryption
        :param rsa_decrypt_key: The decryption key.
        :param pcap_filter: A filter to apply on the PCAP. Same filter syntax as in Wireshark
        :return: The stream data extracted.
        """
        with NamedTemporaryFile(mode='wb') as pcap_file:
            pcap_file.write(pcap)
            pcap_file.flush()
            os.fsync(pcap_file.fileno())

            if rsa_decrypt_key:
                with NamedTemporaryFile(mode='wb') as rsa_key_file:
                    rsa_key_file.write(rsa_decrypt_key)
                    rsa_key_file.flush()
                    os.fsync(rsa_key_file.fileno())

                    return self.parse_file(pcap_file.name, wpa_password, rsa_key_file.name, pcap_filter)
            else:
                return self.parse_file(pcap_file.name, wpa_password, None, pcap_filter)


def make_pcap_by_type(pcap_type: str, pcap_bytes: bytes) -> bytes:
    """
    Build a pcap bytes by type

    :param pcap_type: The data type of the PCAP.
    :param pcap_bytes: The data of a PCAP.
    :return: The data of the PCAP which can be parsed by pyshark.
    """
    if pcap_type in ('auto', 'cdl-pcap'):
        while True:
            if pcap_bytes[0:1] not in (b'\x01', b'\x00') or pcap_bytes[1:2] not in (b'\x01', b'\x00'):
                break

            POS_FIRST_PACKET = 0x24
            packet_time_be32 = pcap_bytes[16:16 + 4]
            packet_size_be16 = pcap_bytes[2:2 + 2]
            packet_size = int.from_bytes(packet_size_be16, byteorder='big')
            if len(pcap_bytes) < packet_size + POS_FIRST_PACKET:
                break

            # pcap header
            pcap = b'\xa1\xb2\xc3\xd4'      # .magic
            pcap += b'\x00\x02'             # .major
            pcap += b'\x00\x04'             # .minor
            pcap += b'\x00\x00\x00\x00'     # .thiszone
            pcap += b'\x00\x00\x00\x00'     # .sigfigs
            pcap += b'\x00\x00\xff\xff'     # .snaplen
            pcap += b'\x00\x00\x00\x01'     # .linktype

            # packet header
            pcap += packet_time_be32                # .ts.tv_sec
            pcap += b'\x00\x00\x00\x00'             # .ts.tv_usec
            pcap += b'\x00\x00' + packet_size_be16  # .caplen: length of portion present
            pcap += b'\x00\x00' + packet_size_be16  # .len: length this packet (off wire)

            # packet payload
            pcap += pcap_bytes[POS_FIRST_PACKET:POS_FIRST_PACKET + packet_size]
            return pcap

        if pcap_type != 'auto':
            raise ValueError('Invalid packet in CDL format')

    if pcap_type in ('auto', 'libpcap'):
        return pcap_bytes

    else:
        raise ValueError(f'Unknown pcap type: {pcap_type}')


def split_context_path(path: str) -> tuple[list[str], str]:
    """
    Split a context path separated by a dot with a replacement name
    following a comma into the key tree the replacement name.

    :param path: The context path (with an optional replacement name)
    :return: The key tree and the replacement name.
    """
    key_tree = []
    key = []
    itr = iter(path)
    for c in itr:
        if c == '\\':
            try:
                key.append(next(itr))
            except StopIteration:
                key.append('\\')
        elif c == '.':
            key_tree.append(''.join(key))
            key = []
        else:
            key.append(c)

    names = ''.join(key).rsplit(',', 1)
    if len(names) == 2:
        key_tree.append(names[0])
        return key_tree, names[1]
    elif len(names) == 1:
        key_tree.append(names[0])
        return key_tree, names[0]
    else:
        raise ValueError(f'Invalid path: {path}')


class MainProcess:
    def __init__(self,
                 pcap_type: str,
                 rsa_decrypt_key: bytes | None,
                 wpa_password: str,
                 pcap_filter: str,
                 bin2txt_mode: str,
                 filter_keys: list[str],
                 error_action: str,
                 server_ports: list[tuple[int, int]]):
        self.__pcap_type = pcap_type
        self.__rsa_decrypt_key = rsa_decrypt_key
        self.__wpa_password = wpa_password
        self.__pcap_filter = pcap_filter
        self.__bin2txt_mode = bin2txt_mode
        self.__filter_keys = filter_keys
        self.__error_action = error_action
        self.__server_ports = server_ports

    def __make_streams(self, node: Any) -> Generator[Any, None, None]:
        """
        Create stream instances from a pcap node.

        :param node: The pcap node.
        :return: The streams extracted from pcaps in the node.
        """
        if isinstance(node, list):
            for v in node:
                yield from self.__make_streams(v)
        else:
            try:
                if not isinstance((pcap_value := node), str):
                    raise ValueError(f'A pcap value is not str: {type(pcap_value)}')

                if pcap_bytes := base64.b64decode(pcap_value.encode()):
                    parser = PcapParser(server_ports=self.__server_ports)
                    streams = parser.parse_bytes(
                        pcap=make_pcap_by_type(self.__pcap_type, pcap_bytes),
                        wpa_password=self.__wpa_password,
                        rsa_decrypt_key=self.__rsa_decrypt_key,
                        pcap_filter=self.__pcap_filter
                    ).build(
                        bin2txt_mode=self.__bin2txt_mode,
                        filter_keys=self.__filter_keys)
                    yield from streams
            except Exception:
                if self.__error_action == 'abort':
                    raise
                elif self.__error_action == 'keep':
                    yield node
                elif self.__error_action == 'ignore':
                    pass
                else:
                    raise ValueError(f'Invalid error action: {self.__error_action}')

    def extract_and_replace(self, node: Any, key_tree: list[str], repl_name: str) -> None:
        """
        Extract streams from pcaps specified with 'node' and 'key_tree',
        and set them into the node specified with 'repl_name'

        :param node: The node
        :param key_tree: The list of the keys to the node where the pcap exists.
        :param repl_name: The name of the key to set the streams.
        """
        for i, key in enumerate(key_tree):
            if isinstance(node, list):
                for v in node:
                    self.extract_and_replace(v, key_tree[i:], repl_name)
                return

            if not isinstance(node, dict) or key not in node:
                # The key is not found in the node
                return

            if i != len(key_tree) - 1:
                node = node[key]
            else:
                # Extract pcap streams and set them into the node
                node[repl_name] = self.make_streams(node[key])

    def make_streams(self, node: Any) -> Any:
        """
        Create streams from the pcap node.

        :param node: The pcap node.
        :return: The streams extracted from pcaps in the node.
        """
        streams = list(self.__make_streams(node))
        if isinstance(node, list) or len(streams) != 1:
            return streams
        else:
            return streams[0]


'''MAIN'''


def main():
    args = demisto.args()
    value = args.get('value', '')
    path = args.get('path')
    error_action = args.get('error_action') or 'abort'
    pcap_type = args.get('pcap_type') or 'auto'
    rsa_decrypt_key_base64 = args.get('rsa_decrypt_key') or ''
    wpa_password = args.get('wpa_password') or ''
    pcap_filter = args.get('pcap_filter') or ''
    bin2txt_mode = args.get('bin2txt_mode') or 'text-based-protocol'
    filter_keys = argToList(args.get('filter_keys'))

    server_ports: list[tuple[int, int]] = []
    for range_str in argToList(args.get('server_ports') or '1-49151'):
        port_range = range_str.split('-')
        if len(port_range) == 1:
            server_ports.append(((int(port_range[0].strip())), (int(port_range[0].strip()))))
        elif len(port_range) == 2:
            server_ports.append(((int(port_range[0].strip())), (int(port_range[1].strip()))))
        else:
            raise ValueError(f'Invalid port range: {range_str}')

    proc = MainProcess(pcap_type=pcap_type,
                       rsa_decrypt_key=base64.b64decode(rsa_decrypt_key_base64.encode()),
                       wpa_password=wpa_password,
                       pcap_filter=pcap_filter,
                       bin2txt_mode=bin2txt_mode,
                       filter_keys=filter_keys,
                       error_action=error_action,
                       server_ports=server_ports)

    if path:
        key_tree, repl_name = split_context_path(path)
        proc.extract_and_replace(value, key_tree, repl_name)
    else:
        value = proc.make_streams(value)

    return_results(value)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
