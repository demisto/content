
# pip files needed:
# * regex
# * dpkt
import dpkt
import math
import datetime

def basic_info(pcap):
    counter = 0
    min_time = float("inf")
    max_time = float("-inf")
    for ts, buf in pcap:
        min_time = min(min_time, ts)
        max_time = max(max_time, ts)
        counter += 1
    print(counter, min_time, max_time)
    return counter, min_time, max_time


filePath = "/Users/olichter/Downloads/http-site.pcap" #demisto.executeCommand('getFilePath', {'id': demisto.args()['entryId']})
f = open(filePath)
pcap = dpkt.pcap.Reader(f)
_, _, time =basic_info(pcap)
print(str(datetime.datetime.utcfromtimestamp(time)))

f.close()
