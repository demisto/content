import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import base64
from typing import Any
from collections.abc import Generator


def convert_pcap(pcap_type: str, pcap_bytes: bytes) -> bytes | None:
    """
    Convert a CDL pcap to a standard PCAP.

    :param pcap_type: The data type of the PCAP.
    :param pcap_bytes: The data of a PCAP.
    :return: The data of the PCAP which can be parsed by pyshark.
    """
    if pcap_type in ('auto', 'cdl-pcap'):
        while True:
            if pcap_bytes[0:1] not in (b'\x01', b'\x00') or pcap_bytes[1:2] not in (b'\x01', b'\x00'):
                if pcap_type != 'auto':
                    raise ValueError('Invalid packet in CDL format')
                break

            POS_FIRST_PACKET = 0x24
            packet_time_be32 = pcap_bytes[16:16 + 4]
            packet_size_be16 = pcap_bytes[2:2 + 2]
            packet_size = int.from_bytes(packet_size_be16, byteorder='big')
            if len(pcap_bytes) < packet_size + POS_FIRST_PACKET:
                if pcap_type != 'auto':
                    raise ValueError('Invalid packet in CDL format')
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
    else:
        raise ValueError(f'Unknown pcap type: {pcap_type}')

    return None


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
                 error_action: str):
        self.__pcap_type = pcap_type
        self.__error_action = error_action

    def __convert_pcap(self, node: Any) -> Generator[Any, None, None]:
        """
        Convert pcap(s) in the node.

        :param node: The pcap(s) node.
        :return: The pcap(s) converted.
        """
        if isinstance(node, list):
            for v in node:
                yield from self.__convert_pcap(v)
        else:
            try:
                if not isinstance((pcap_value := node), str):
                    raise ValueError(f'A pcap value is not str: {type(pcap_value)}')

                if pcap_bytes := base64.b64decode(pcap_value.encode()):
                    if (pcap := convert_pcap(self.__pcap_type, pcap_bytes)) is None:
                        raise ValueError('Invalid pcap')

                    yield base64.b64encode(pcap).decode()
            except Exception:
                if self.__error_action == 'abort':
                    raise
                elif self.__error_action == 'keep':
                    yield node
                elif self.__error_action == 'ignore':
                    pass
                else:
                    raise ValueError(f'Invalid error action: {self.__error_action}')

    def convert_and_replace(self, node: Any, key_tree: list[str], repl_name: str) -> None:
        """
        Convert from pcaps specified with 'node' and 'key_tree',
        and set them into the node specified with 'repl_name'

        :param node: The node
        :param key_tree: The list of the keys to the node where the pcap exists.
        :param repl_name: The name of the key to set the standard pcap.
        """
        for i, key in enumerate(key_tree):
            if isinstance(node, list):
                for v in node:
                    self.convert_and_replace(v, key_tree[i:], repl_name)
                return

            if not isinstance(node, dict) or key not in node:
                # The key is not found in the node
                return

            if i != len(key_tree) - 1:
                node = node[key]
            else:
                node[repl_name] = self.convert_pcap(node[key])

    def convert_pcap(self, node: Any) -> Any:
        """
        Convert pcap(s) in the node.

        :param node: The pcap(s) node.
        :return: The pcap(s) converted.
        """
        pcaps = [v for v in self.__convert_pcap(node)]
        if isinstance(node, list) or len(pcaps) != 1:
            return pcaps
        else:
            return pcaps[0]


'''MAIN'''


def main():
    args = demisto.args()
    value = args.get('value', '')
    path = args.get('path')
    pcap_type = args.get('pcap_type') or 'auto'
    error_action = args.get('error_action') or 'abort'

    proc = MainProcess(pcap_type=pcap_type,
                       error_action=error_action)

    if path:
        key_tree, repl_name = split_context_path(path)
        proc.convert_and_replace(value, key_tree, repl_name)
    else:
        value = proc.convert_pcap(value)

    return_results(value)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
