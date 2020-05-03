import demistomock as demisto
from CommonServerPython import *

import pyshark
import re
from typing import Dict, Any
import traceback

'''GLOBAL VARS'''
BAD_CHARS = ['[', ']', '>', '<', "'", ' Layer', ' ', '{', '}']
EMAIL_REGEX = r'\b[A-Za-z0-9._%=+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
IP_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.)' \
           r'{3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'
URL_REGEX = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
PRAGMA_REGEX = r'Pragma: ([^\\]+)'
TYPE_REGEX = r'Type: (.+)'
CLASS_REGEX = r'Class: (.+)'
COMMAND_REGEX = r'Command: (.+)'
SNAME_REGEX = r'SNameString: (.+)'


class PCAP():
    def __init__(self, is_reg_extract, extracted_protocols, homemade_regex):
        # setup data structures
        self.hierarchy = {}  # type: Dict[str, int]
        self.num_of_packets = 0
        self.tcp_streams = 0
        self.udp_streams = 0
        self.bytes_transmitted = 0
        self.min_time = float('inf')
        self.max_time = -float('inf')
        self.conversations = {}  # type: Dict[tuple, Any]
        self.flows = {}  # type: Dict[tuple, Any]
        self.unique_source_ip = set([])
        self.unique_dest_ip = set([])
        self.ips_extracted = set([])
        self.urls_extracted = set([])
        self.emails_extracted = set([])
        self.homemade_extracted = set([])
        self.last_layer = set([])
        self.kerb_data = set()
        self.syslogs = []
        self.protocol_data: Dict[str, Any] = dict()
        self.extracted_protocols = extracted_protocols
        self.homemade_regex = homemade_regex
        for protocol in extracted_protocols:
            self.protocol_data[protocol] = dict()

        # Regex compilation
        if 'LLMNR' in extracted_protocols:
            self.llmnr_type = re.compile('Type: (.*)\n')
            self.llmnr_class = re.compile('Class: (.*)\n')
            self.llmnr_dict = {}

        if is_reg_extract:
            self.reg_ip = re.compile(IP_REGEX)
            self.reg_email = re.compile(EMAIL_REGEX)
            self.reg_url = re.compile(URL_REGEX)

        if 'HTTP' in extracted_protocols:
            self.reg_pragma = re.compile(PRAGMA_REGEX)

        if 'ICMP' in extracted_protocols:
            self.icmp_data = set()
        if 'DNS' in extracted_protocols or 'NETBIOS' in extracted_protocols or 'ICMP' in extracted_protocols:
            self.reg_type = re.compile(TYPE_REGEX)
        if 'NETBIOS' in extracted_protocols:
            self.reg_class = re.compile(CLASS_REGEX)
        if 'SMB2' in extracted_protocols:
            self.reg_cmd = re.compile(COMMAND_REGEX)
        if 'KERBEROS':
            self.reg_sname = re.compile(SNAME_REGEX)
        if homemade_regex:
            self.reg_homemade = re.compile(self.homemade_regex)

    def extract_context_from_packet(self, packet, is_reg_extract=False):
        if 'KERBEROS' in self.extracted_protocols:
            kerb_layer = packet.get_multiple_layers('KERBEROS')
            if kerb_layer:
                sname_results = self.reg_sname.findall(str(kerb_layer))
                self.kerb_data.update({
                    'Realm': kerb_layer[0].get('realm'),
                    'CName': kerb_layer[0].get('CNameString'),
                    'SName': sname_results[0] if sname_results else None,
                })

        if 'TELNET' in self.extracted_protocols:
            telnet_layer = packet.get_multiple_layers('TELNET')
            if telnet_layer:
                pass
            # TODO finish this

        if 'LLMNR' in self.extracted_protocols:
            llmnr_layer = packet.get_multiple_layers('llmnr')
            if llmnr_layer:
                llmnr_layer_string = str(llmnr_layer[0])
                llmnr_data = {
                    'ID': llmnr_layer[0].get('dns_id'),
                    'QueryType': None if len(self.llmnr_type.findall(llmnr_layer_string)) == 0 else
                    self.llmnr_type.findall(llmnr_layer_string)[0],
                    'QueryClass': None if len(self.llmnr_class.findall(llmnr_layer_string)) == 0 else
                    self.llmnr_class.findall(llmnr_layer_string)[0],
                    'QueryName': str(llmnr_layer[0].get('dns_qry_name')),
                    'Questions': int(llmnr_layer[0].get('dns_count_queries'))
                }
                add_to_data(self.protocol_data['LLMNR'], llmnr_data)

        if 'SYSLOG' in self.extracted_protocols:
            syslog_layer = packet.get_multiple_layers('syslog')
            if syslog_layer:
                self.syslogs.append(syslog_layer[0].get('msg'))

        if 'SMTP' in self.extracted_protocols:
            imf_layer = packet.get_multiple_layers('imf')
            if imf_layer:
                imf_data = {
                    'ID': imf_layer[0].get('Message-ID', -1),
                    'To': imf_layer[0].get('to'),
                    'From': imf_layer[0].get('from'),
                    'Subject': imf_layer[0].get('subject'),
                    'MimeVersion': imf_layer[0].get('mime-version')
                }
                add_to_data(self.protocol_data['SMTP'], imf_data)

        if 'SMB2' in self.extracted_protocols:
            smb_layer = packet.get_multiple_layers('smb2')
            if smb_layer:
                command_results = self.reg_cmd.findall(str(smb_layer))
                smb_data = {
                    'ID': smb_layer[0].get('sesid', -1),
                    'UserName': smb_layer[0].get('ntlmssp_auth_username'),
                    'Domain': smb_layer[0].get('ntlmssp_auth_domain'),
                    'HostName': smb_layer[0].get('ntlmssp_auth_hostname'),
                    'Command': command_results[0] if command_results else None,
                    'FileName': smb_layer[0].get('smb2.filename'),
                    'Tree': smb_layer[0].get('tree')
                }
                add_to_data(self.protocol_data['SMB2'], smb_data)

        if 'NETBIOS' in self.extracted_protocols:
            netbios_layer = packet.get_multiple_layers('nbns')
            if netbios_layer:
                type_results = self.reg_type.findall(str(netbios_layer[0]))
                class_results = self.reg_class.findall(str(netbios_layer[0]))
                netbios_data = {
                    'ID': netbios_layer[0].get('id', -1),
                    'Name': netbios_layer[0].get('name'),
                    'Type': type_results[0] if type_results else None,
                    'Class': class_results[0] if class_results else None
                }
                add_to_data(self.protocol_data['NETBIOS'], netbios_data)

        if 'ICMP' in self.extracted_protocols:
            icmp_layer = packet.get_multiple_layers('icmp')
            if icmp_layer:
                type_results = self.reg_type.findall(str(icmp_layer[0]))
                if type_results:
                    self.icmp_data.add(type_results[0])

        if is_reg_extract:
            self.ips_extracted.update(self.reg_ip.findall(str(packet)))
            self.emails_extracted.update(self.reg_email.findall(str(packet)))
            self.urls_extracted.update(self.reg_url.findall(str(packet)))

        if self.homemade_regex:
            self.homemade_extracted.update(self.reg_homemade.findall((str(packet))))

    def get_outputs(self, entry_id, conversation_number_to_display=15, is_flows=False, is_reg_extract=False):
        md = f'## PCAP Info:\n' \
            f'Between {formatEpochDate(self.min_time)} and {formatEpochDate(self.max_time)} ' \
            f'there were {self.num_of_packets} ' \
            f'packets transmitted in {self.tcp_streams + self.udp_streams} streams.\n'
        md += '#### Protocol Breakdown\n'
        md += hierarchy_to_md(self.hierarchy)
        md += f'#### Top {conversation_number_to_display} Conversations\n'
        md += conversations_to_md(self.conversations, conversation_number_to_display)
        if is_flows:
            md += f'#### Top {conversation_number_to_display} Flows\n'
            md += flows_to_md(self.flows, conversation_number_to_display)

        # Entry Context
        general_context = {
            'EntryID': entry_id,
            'Bytes': self.bytes_transmitted,
            'Packets': self.num_of_packets,
            'StreamCount': self.tcp_streams + self.udp_streams,
            'UniqueSourceIP': len(self.unique_source_ip),
            'UniqueDestIP': len(self.unique_dest_ip),
            'StartTime': formatEpochDate(self.min_time),
            'EndTime': formatEpochDate(self.max_time),
            'Protocols': list(self.last_layer)
        }
        for protocol in self.extracted_protocols:
            general_context[protocol] = list(self.protocol_data[protocol].values())
        if 'ICMP' in self.extracted_protocols:
            general_context['ICMP'] = list(self.icmp_data)
        if 'KERBEROS' in self.extracted_protocols:
            general_context['KERBEROS'] = list(self.kerb_data)
        if is_flows:
            general_context['Flow'] = flows_to_ec(self.flows)
        if is_reg_extract:
            general_context['IP'] = list(self.ips_extracted)
            general_context['URL'] = list(self.urls_extracted)
            general_context['Email'] = list(self.emails_extracted)
        if self.homemade_regex:
            general_context['Regex'] = list(self.homemade_extracted)
        ec = {'PcapResults(val.EntryID == obj.EntryID)': general_context}
        return (md, ec, general_context)

    def mine(self, file_path, decrypt_key, is_flows, is_reg_extract, pcap_filter, pcap_filter_new_file_path):
        try:
            cap = pyshark.FileCapture(file_path, display_filter=pcap_filter, output_file=pcap_filter_new_file_path,
                                      decryption_key=decrypt_key, encryption_type='WPA-PWD')
            j = 0
            for packet in cap:
                # j += 1
                # if (j % 100 == 0):
                #     print(j)
                self.last_layer.add(packet.layers[-1].layer_name)

                layers = str(packet.layers)
                # remove duplicate layer names such as [ETH,DATA,DATA] -> # [ETH, DATA]
                layers = list(dict.fromkeys(layers.split(',')))  # type: ignore
                layers = strip(str(layers))
                self.hierarchy[layers] = self.hierarchy.get(layers, 0) + 1  # type: ignore

                # update times
                packet_epoch_time = float(packet.frame_info.get('time_epoch'))
                self.max_time = max(self.max_time, packet_epoch_time)
                self.min_time = min(self.min_time, packet_epoch_time)

                # count packets
                self.num_of_packets += 1

                # count bytes
                self.bytes_transmitted += int(packet.length)

                # count num of streams + get src/dest ports
                tcp = packet.get_multiple_layers('tcp')

                if tcp:
                    tcp_streams = max(int(tcp[0].get('stream', 0)), self.tcp_streams)
                    src_port = int(tcp[0].get('srcport', 0))
                    dest_port = int(tcp[0].get('dstport', 0))

                udp = packet.get_multiple_layers('udp')
                if udp:
                    udp_streams = max(int(udp[0].get('stream', 0)), self.udp_streams)
                    src_port = int(udp[0].get('srcport', 0))
                    dest_port = int(udp[0].get('dstport', 0))

                # extract DNS layer
                if 'DNS' in self.extracted_protocols:
                    dns_layer = packet.get_multiple_layers('dns')
                    if dns_layer:
                        temp_dns = {
                            'ID': dns_layer[0].get('id'),
                            'Request': dns_layer[0].get('qry_name'),
                            'Response': dns_layer[0].get('a'),
                            'Type': self.reg_type.findall(str(dns_layer[0]))[0] if self.reg_type.findall(
                                str(dns_layer[0])) else None
                        }
                        add_to_data(self.protocol_data['DNS'], temp_dns)

                # add conversations
                ip_layer = packet.get_multiple_layers('ip')
                if ip_layer:
                    a = ip_layer[0].get('src_host', '')
                    b = ip_layer[0].get('dst_host')
                    self.unique_source_ip.add(a)
                    self.unique_dest_ip.add(b)

                    # generate flow data
                    if is_flows:
                        if "src_port" not in locals():
                            continue
                        if (b, dest_port, a, src_port) in self.flows.keys():
                            b, a, src_port, dest_port = a, b, dest_port, src_port
                        flow = (a, src_port, b, dest_port)
                        flow_data = self.flows.get(flow, {'min_time': float('inf'),
                                                          'max_time': -float('inf'),
                                                          'bytes': 0,
                                                          'counter': 0})
                        flow_data['min_time'] = min(flow_data['min_time'], packet_epoch_time)
                        flow_data['max_time'] = max(flow_data['min_time'], packet_epoch_time)
                        flow_data['bytes'] += int(packet.length)
                        flow_data['counter'] += 1
                        self.flows[flow] = flow_data

                    # gather http data
                    if 'HTTP' in self.extracted_protocols:
                        http_layer = packet.get_multiple_layers('http')
                        if http_layer:
                            all_fields = http_layer[0]._all_fields
                            temp_http = {
                                "ID": http_layer[0].get('request_in', packet.number),
                                'RequestAgent': all_fields.get("http.user_agent"),
                                'RequestHost': all_fields.get('http.host'),
                                'RequestSourceIP': a,
                                'RequestURI': http_layer[0].get('request_full_uri'),
                                'RequestMethod': http_layer[0].get('request_method'),
                                'RequestVersion': http_layer[0].get('request_version'),
                                'RequestAcceptEncoding': http_layer[0].get('accept_encoding'),
                                'RequestPragma': self.reg_pragma.findall(str(http_layer[0]))[0]
                                if self.reg_pragma.findall(str(http_layer[0])) else None,
                                'RequestAcceptLanguage': http_layer[0].get('accept_language'),
                                'RequestCacheControl': http_layer[0].get('cache_control')

                            }
                            # if the packet is a response
                            if all_fields.get('http.response'):
                                temp_http.update({
                                    'ResponseStatusCode': http_layer[0].get('response_code'),
                                    'ResponseVersion': all_fields.get('http.response.version'),
                                    'ResponseCodeDesc': http_layer[0].get('response_code_desc'),
                                    'ResponseContentLength': http_layer[0].get('content_length'),
                                    'ResponseContentType': http_layer[0].get('content_type'),
                                    'ResponseDate': formatEpochDate(packet_epoch_time)
                                })
                            add_to_data(self.protocol_data['HTTP'], temp_http)
                    if (b, a) in self.conversations.keys():
                        a, b = b, a
                    hosts = (a, b)
                    self.conversations[hosts] = self.conversations.get(hosts, 0) + 1

                self.extract_context_from_packet(packet, is_reg_extract)

            self.tcp_streams += 1
            self.udp_streams += 1

        except pyshark.capture.capture.TSharkCrashException:
            raise ValueError("Filter could not be applied to file. Please make sure it is of correct syntax.")

        except Exception as error:
            print(str(error))
            traceback.print_exc()


'''HELPER FUNCTIONS'''


def strip(s: str, bad_chars=None):
    """

    Args:
        s: string to strip
        bad_chars: all characters to remove from string.

    Returns:
        The input s without the bac_chars
    """
    if bad_chars is None:
        bad_chars = BAD_CHARS
    temp = s
    for char in bad_chars:
        temp = temp.replace(char, '')
    return temp


def hierarchy_to_md(hierarchy: dict) -> str:
    """

    Args:
        hierarchy: a dictionary of layer hierarchy for all packets

    Returns:
        A markdown string for displaying the hierarchy in a nice view. The script also counts the number of occurrences
        each hierarchy.
    """
    final_dict = {}  # type: Dict[str, Any]
    num_of_all_packets = 0
    for k in hierarchy.keys():
        layer_heir = ''
        for layer in k.split(','):
            layer_heir += ' -> ' + layer
            final_dict[layer_heir] = final_dict.get(layer_heir, 0) + hierarchy[k]
        num_of_all_packets += hierarchy[k]
    md = '|Layer| # of Packets|% of Packets|\n|---|----|---|\n'
    for key in sorted(final_dict):
        md += f'|{key}|{final_dict[key]}|{round(final_dict[key] / num_of_all_packets, 3) * 100}%|\n'
    return md


def conversations_to_md(conversations: dict, disp_num: int) -> str:
    """

    Args:
        conversations: a raw dictionary of conversations.
        disp_num: The limit of conversations to display.

    Returns:
        A mardkown of <=disp_num of conversations, ordered in descending order.
    """
    md = '|A|B|# of Packets\n|---|---|---|\n'
    ordered_conv_list = sorted(conversations.items(), key=lambda x: x[1], reverse=True)
    disp_num = min(disp_num, len(ordered_conv_list))
    for i in range(disp_num):
        md += f'|{ordered_conv_list[i][0][0]}|{ordered_conv_list[i][0][1]}|{ordered_conv_list[i][1]}|\n'
    return md


def flows_to_md(flows: dict, disp_num: int) -> str:
    """

    Args:
        flows: a raw dictionary of flows.
        disp_num: The limit of flows to display.

    Returns:
        A mardkown of <=disp_num of flows, ordered in descending order.

    """
    md = '|A|port|B|port|# of Packets\n|---|---|---|---|---|\n'
    ordered_flow_list = sorted(flows.items(), key=lambda x: x[1].get('counter'), reverse=True)
    disp_num = min(disp_num, len(ordered_flow_list))
    for i in range(disp_num):
        md += f'|{ordered_flow_list[i][0][0]}|{ordered_flow_list[i][0][1]}|{ordered_flow_list[i][0][2]}|' \
            f'{ordered_flow_list[i][0][3]}|{ordered_flow_list[i][1].get("counter", 0)}|\n'
    return md


def flows_to_ec(flows: dict) -> list:
    """

    Args:
        flows: A dictionary that hold the flows data

    Returns:
        flows data in ec format.
    """
    flows_ec = []
    for flow in flows.keys():
        flow_data = flows[flow]
        flow_ec = {
            'SourceIP': flow[0],
            'SourcePort': flow[1],
            'DestIP': flow[2],
            'DestPort': flow[3],
            'Duration': round(flow_data.get('max_time', 0) - flow_data.get('min_time', 0)),
            'StartTime': formatEpochDate(flow_data.get('min_time', 0)),
            'EndTime': formatEpochDate(flow_data.get('max_time', 0)),
            'Bytes': flow_data.get('bytes', 0)
        }
        flows_ec.append(flow_ec)
    return flows_ec


def remove_nones(d: dict) -> dict:
    """

    Args:
        d: a dictionary

    Returns: A new dictionary that does not contain keys with None values.

    """
    return {k: v for k, v in d.items() if v is not None}


def add_to_data(d: dict, data: dict) -> None:
    """
    updates dictionary d to include/update the data. Also removes None values.
    Args:
        d: a Dictionary of ID: data to which we want to update the data according to ID
        data: the data to update. data must have an "ID" field.

    Returns:
        updates dictionary d to include/update the data. Also removes None values.
    """
    data_id = data.get('ID')
    if not data_id:
        return
    else:
        if not d.get(data_id):
            d[data_id] = remove_nones(data)
        else:
            d[data_id].update(remove_nones(data))


'''MAIN'''


def main():
    entry_id = demisto.args().get('entry_id', '')
    file_path = demisto.executeCommand('getFilePath', {'id': entry_id})
    if is_error(file_path):
        return_error(get_error(file_path))

    file_path = file_path[0]["Contents"]["path"]

    decrypt_key = demisto.args().get('wpa_password', '')

    decrypt_key_entry_id = demisto.args().get('decrypt_key_entry_id', '')
    if decrypt_key_entry_id and not decrypt_key:
        decrypt_key_file_path = demisto.executeCommand('getFilePath', {'id': decrypt_key_entry_id})
        if is_error(decrypt_key_file_path):
            return_error(get_error(decrypt_key_file_path))
        decrypt_key = file_path = decrypt_key_file_path[0]["Contents"]["path"]

    conversation_number_to_display = int(demisto.args().get('convs_to_display', '15'))
    extracted_protocols = argToList(demisto.args().get('context_output', ''))
    is_flows = True
    is_reg_extract = demisto.args().get('extract_strings', 'False') == 'True'
    pcap_filter = demisto.args().get('pcap_filter', '')
    homemade_regex = demisto.args().get('custom_regex', '')  # 'Layer (.+):'
    pcap_filter_new_file_path = ''
    pcap_filter_new_file_name = demisto.args().get('filtered_file_name', '')

    if pcap_filter_new_file_name:
        temp = demisto.uniqueFile()
        pcap_filter_new_file_path = demisto.investigation()['id'] + '_' + temp

    pcap = PCAP(is_reg_extract, extracted_protocols, homemade_regex)
    pcap.mine(file_path, decrypt_key, is_flows, is_reg_extract, pcap_filter, pcap_filter_new_file_path)
    hr, ec, raw = pcap.get_outputs(entry_id, conversation_number_to_display, is_flows, is_reg_extract)
    return_outputs(hr, ec, raw)

    if pcap_filter_new_file_name:
        demisto.results({'Contents': '', 'ContentsFormat': formats['text'], 'Type': 3,
                         'File': pcap_filter_new_file_name, 'FileID': temp})


def local_main():  # TODO remove this function
    # Variables from demisto
    # file_path = "/Users/olichter/Downloads/chargen-udp.pcap"
    # file_path = "/Users/olichter/Downloads/http-site.pcap"                 # HTTP
    # file_path = "/Users/olichter/Downloads/dns.cap"                        # DNS
    # file_path = "/Users/olichter/Downloads/tftp_rrq.pcap"                 # tftp
    # file_path = "/Users/olichter/Downloads/rsasnakeoil2.cap"              # encrypted SSL
    # file_path = "/Users/olichter/Downloads/smb-legacy-implementation.pcapng"  # llmnr/netbios/smb
    # file_path = "/Users/olichter/Downloads/smtp.pcap"                      # SMTP#
    # file_path = "/Users/olichter/Downloads/nb6-hotspot.pcap"                #syslog
    # file_path = "/Users/olichter/Downloads/wpa-Induction.pcap"               #wpa - Password is Induction
    # file_path = "/Users/olichter/Downloads/iseries.cap"
    # file_path = "/Users/olichter/Downloads/2019-12-03-traffic-analysis-exercise.pcap"  # 1 min
    file_path = "/Users/olichter/Downloads/smb-on-windows-10.pcapng"  # ran for 2.906 secs
    # file_path = "/Users/olichter/Downloads/telnet-cooked.pcap"

    # PC Script
    entry_id = ''

    decrypt_key = "Induction"  # "/Users/olichter/Downloads/rsasnakeoil2.key"
    conversation_number_to_display = 15
    is_flows = True
    is_reg_extract = True
    extracted_protocols = ['SMTP', 'DNS', 'HTTP', 'SMB2', 'NETBIOS', 'ICMP', 'KERBEROS', 'SYSLOG', 'TELNET']

    pcap_filter = 'smb2'
    # pcap_filter_new_file_name = ''  # '/Users/olichter/Downloads/try.pcap'
    homemade_regex = ''  # 'Layer (.+):'
    pcap_filter_new_file_path = ''

    pcap = PCAP(is_reg_extract, extracted_protocols, homemade_regex)
    pcap.mine(file_path, decrypt_key, is_flows, is_reg_extract, pcap_filter, pcap_filter_new_file_path)
    hr, ec, raw = pcap.get_outputs(entry_id, conversation_number_to_display, is_flows, is_reg_extract)
    return_outputs(hr, ec, raw)


if __name__ in ['__main__', 'builtin', 'builtins']:
    # from datetime import datetime

    # startTime = datetime.now()
    local_main()
    # print(datetime.now() - startTime)
    # print(timeit.timeit(local_main), number=1)

# TODO: fix todos
