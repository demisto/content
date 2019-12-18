import pyshark
import demistomock as demisto
from CommonServerPython import *

'''GLOBAL VARS'''
BAD_CHARS = ['[', ']', '>', '<', "'"]

'''HELPER FUNCTIONS'''


def strip(s: str, bad_chars=BAD_CHARS):
    temp = s
    for char in bad_chars:
        temp = temp.replace(char, '')
    return temp


def hierarchy_to_md(hierarchy: dict) -> str:
    final_dict = {}
    num_of_all_packets = 0
    for k in hierarchy.keys():
        layer_heir = ''
        for layer in k.split(','):
            layer_heir += ' -> '+layer
            final_dict[layer_heir] = final_dict.get(layer_heir, 0) + hierarchy[k]
        num_of_all_packets += hierarchy[k]
    md = '|Layer| # of Packets|% of Packets|\n|---|----|---|\n'
    for key in sorted(final_dict):
        md += f'|{key}|{final_dict[key]}|{round(final_dict[key]/num_of_all_packets,3)*100}%|\n'
    return md


def conversations_to_md(conversation: dict, disp_num: int) -> str:
    md = '|A|B|# of Packets\n|---|---|---|\n'
    ordered_conv_list = sorted(conversations.items(), key=lambda x: x[1], reverse=True)
    for i in range(disp_num):
        hosts = strip(ordered_conv_list[i][0]).split(',')
        md += f'|{hosts[0]}|{hosts[1]}|{ordered_conv_list[i][1]}|\n'
    return md


'''MAIN'''

# Variables from demisto
# filePath = "/Users/olichter/Downloads/chargen-udp.pcap"
filePath = "/Users/olichter/Downloads/http-site.pcap"
conversation_number_to_display = 15
is_flows = True
# Variables for the script
hierarchy = {}
num_of_packets = 0
tcp_streams = 0
udp_streams = 0
min_time = float('inf')
max_time = -float('inf')
conversations = {}
flows = {}

cap = pyshark.FileCapture(filePath, use_json=True)
# cap = pyshark.FileCapture(filePath) #, use_json=True
for packet in cap:

    # Set hierarchy for layers
    layers = str(packet.layers)
    layers = strip(layers)
    hierarchy[layers] = hierarchy.get(layers, 0) + 1

    # update times
    packet_epoch_time = float(packet.frame_info.get('time_epoch'))
    max_time = max(max_time, packet_epoch_time)
    min_time = min(min_time, packet_epoch_time)

    # count packets
    num_of_packets += 1

    # count num of streams + get src/dest ports
    tcp = packet.get_multiple_layers('tcp')

    if tcp:
        tcp_streams = max(int(tcp[0].get('stream', 0)), tcp_streams)
        src_port = int(tcp[0].get('srcport', 0))
        dest_port = int(tcp[0].get('dstport', 0))

    udp = packet.get_multiple_layers('udp')
    if udp:
        udp_streams = max(int(udp[0].get('stream', 0)),udp_streams)
        src_port = int(udp[0].get('srcport', 0))
        dest_port = int(udp[0].get('dstport', 0))

    # add conversations
    ip_layer = packet.get_multiple_layers('ip')
    if ip_layer:
        a = ip_layer[0].get('src_host', '')
        b = ip_layer[0].get('dst_host')
        if is_flows:
            if str([b, dest_port, a, src_port]) in flows.keys():
                b, a, src_port, dest_port = a, b, dest_port, src_port
            flow = str([a, src_port, b, dest_port])
            flows[flow] = flows.get(flow, 0) + 1

        if str([b, a]) in conversations.keys():
            a, b = b, a
        hosts = str([a, b])
        conversations[hosts] = conversations.get(hosts, 0) + 1

tcp_streams += 1
udp_streams += 1
md = f'## PCAP Info:\n' \
    f'Between {formatEpochDate(min_time)} and {formatEpochDate(max_time)} there were {num_of_packets} ' \
    f'packets transmitted in {tcp_streams + udp_streams} streams.\n'
md += f'#### Top {conversation_number_to_display} Conversations\n'
md += conversations_to_md(conversations, conversation_number_to_display)
md += '#### Protocol Breakdown\n'
md += hierarchy_to_md(hierarchy)
print(md)

for k in flows.keys():
    print(k, flows[k])



# TIPS:
# cap.load_packets() - Loads packets to cap. Then we can use len(cap)
