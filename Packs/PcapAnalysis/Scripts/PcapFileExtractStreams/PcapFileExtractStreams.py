import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
import codecs
import unicodedata
import logging
from typing import Any, Dict, List, Optional, Tuple

import pyshark

TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10

codecs.register_error('replace_with_space', lambda x: (u' ', x.start + 1))  # type: ignore[attr-defined]


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
                       if c == u'\ufffd'
                       or (c not in ('\n', '\r', '\t') and unicodedata.category(c)[0] == 'C')
                       else c
                       for c in binary.decode('utf-8', errors='replace'))
    elif mode == 'human-readable':
        return binary.decode('utf-8', errors='replace_with_space')
    else:
        raise ValueError(f'Unknown text conversion mode: {mode}')


class Streams:
    def __init__(self, server_ports: List[Tuple[int, int]]):
        self.__tcp_streams: Dict[tuple, Any] = {}
        self.__udp_streams: Dict[tuple, Any] = {}
        self.__server_ports = server_ports

    def __make_item(self,
                    bin2txt_mode: str,
                    filter_keys: Optional[List[str]],
                    protocol: str,
                    sender_ip: str,
                    sender_port: int,
                    recipient_ip: str,
                    recipient_port: int,
                    stream_bytes: bytes,
                    outgoing_bytes: bytes,
                    incoming_bytes: bytes) -> Dict[str, Any]:

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
                payload: Optional[bytes]) -> None:
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

        if key1 in self.__tcp_streams.keys():
            if payload:
                self.__tcp_streams[key1]['outgoing'] += payload
                self.__tcp_streams[key1]['stream'] += payload
        elif key2 in self.__tcp_streams.keys():
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
                matchs = any([port_range[0] < sender_port < port_range[1] for port_range in self.__server_ports])
                matchr = any([port_range[0] < recipient_port < port_range[1] for port_range in self.__server_ports])
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
                payload: Optional[bytes]) -> None:
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

        if key1 in self.__udp_streams.keys():
            if payload:
                self.__udp_streams[key1]['outgoing'] += payload
                self.__udp_streams[key1]['stream'] += payload
        elif key2 in self.__udp_streams.keys():
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

    def build(self, bin2txt_mode: str, filter_keys: Optional[List[str]] = None) -> List[Dict[str, Any]]:
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
    def __init__(self, server_ports: List[Tuple[int, int]]):
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

    def parse_file(self, pcap_file_path: str, wpa_password: str, rsa_key_file_path: Optional[str], pcap_filter: str) -> Streams:
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


def main():
    args = demisto.args()
    try:
        pcap_entry_id = args.get('entry_id', '')
        bin2txt_mode = args.get('bin2txt_mode') or 'text-based-protocol'
        rsa_decrypt_key_entry_id = args.get('rsa_decrypt_key_entry_id', '')
        wpa_password = args.get('wpa_password', '')
        pcap_filter = args.get('pcap_filter', '')
        filter_keys = argToList(args.get('filter_keys', ''))
        verbose = argToBoolean(args.get('verbose') or False)

        server_ports: List[Tuple[int, int]] = []
        for range_str in argToList(args.get('server_ports') or '1-49151'):
            port_range = range_str.split('-')
            if len(port_range) == 1:
                server_ports.append(((int(port_range[0].strip())), (int(port_range[0].strip()))))
            elif len(port_range) == 2:
                server_ports.append(((int(port_range[0].strip())), (int(port_range[1].strip()))))
            else:
                raise ValueError(f'Invalid port range: {range_str}')

        rsa_key_file_path = None
        if rsa_decrypt_key_entry_id:
            rsa_key_file_path = demisto.getFilePath(rsa_decrypt_key_entry_id).get('path')

        parser = PcapParser(server_ports=server_ports)
        streams = parser.parse_file(
            pcap_file_path=demisto.getFilePath(pcap_entry_id).get('path'),
            wpa_password=wpa_password,
            rsa_key_file_path=rsa_key_file_path,
            pcap_filter=pcap_filter
        )
        contents = streams.build(bin2txt_mode=bin2txt_mode, filter_keys=filter_keys)

        # Create a summary entry
        table_headers = ['protocol', 'client_ip', 'client_port', 'server_ip', 'server_port',
                         'stream_size', 'outgoing_size', 'incoming_size']
        if filter_keys:
            table_headers = [k for k in table_headers if k in filter_keys]

        if not table_headers:
            readable_output = 'No summary'
        else:
            readable_output = tableToMarkdown(
                'PCAP Stream Summary',
                [{k: stringEscapeMD(str(ent[k]), True, True) for k in ent.keys() & table_headers} for ent in contents],
                headers=table_headers,
                headerTransform=lambda s: stringEscapeMD(string_to_table_header(s), True, True))
        return_results(CommandResults(outputs_prefix='PCAPStream',
                                      outputs=contents,
                                      readable_output=readable_output,
                                      raw_response=contents))

        # Create stream entries
        if verbose and\
           contents and\
           (not filter_keys or ({'stream_text', 'outgoing_text', 'incoming_text'}.intersection(filter_keys))):
            table_headers = ['protocol', 'client_ip', 'client_port', 'server_ip', 'server_port',
                             'stream_size', 'outgoing_size', 'incoming_size',
                             'stream_text', 'outgoing_text', 'incoming_text']
            if filter_keys:
                table_headers = [k for k in table_headers if k in filter_keys]

            for ent in contents:
                readable_output = tableToMarkdown(
                    'PCAP Stream',
                    {k: stringEscapeMD(str(ent[k]), True, True) for k in ent.keys() & table_headers},
                    headers=table_headers,
                    headerTransform=lambda s: stringEscapeMD(string_to_table_header(s), True, True))
                return_results(CommandResults(readable_output=readable_output))

    except Exception as e:
        return_error(f'Failed to extract streams. Error: {str(e)}')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
