import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
#!/usr/bin/env python2.7
# -*- coding: utf8 -*-

import os
import dpkt
import cymruwhois
import simplejson as json
import glob
import os

path = "/app/pcapminey/"
if path not in sys.path:
    sys.path.append(path)

from core.Dispatcher import Dispatcher
from minepcaps import pcap_miner
from shutil import copyfile

os.popen('rm -f ./output/*')
filePath = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryId'] })
readyPath = filePath[0]["Contents"]["path"]
ret = []
filename = filePath[0]["Contents"]["name"]
miner = pcap_miner(readyPath)
jsonResults = miner.summary2json()
pyResults = json.loads(jsonResults)
dispatcher = Dispatcher(readyPath, 'output', entropy=True,verifyChecksums=True,udpTimeout=500,)
results = dispatcher.run()
pyResults['files_found'] = results.filenamelist
listdir = os.listdir('./output')
ouputPath = './output/*'
files=glob.glob(ouputPath)

if(pyResults["counts"]):
    displayData = tableToMarkdown('PCAP Data Frequency Counts', pyResults["counts"])
if(pyResults["destination_ip_details"]):
    displayData += tableToMarkdown('Destination IP Details', pyResults["destination_ip_details"])
if(pyResults["dns_data"]):
    displayData += tableToMarkdown('DNS Details', pyResults["dns_data"])
if(pyResults["http_requests"]):
    displayData += tableToMarkdown('Http Requests', pyResults["http_requests"])
if(pyResults["flows"]):
    displayData += tableToMarkdown('Flow Data', pyResults["flows"])
if(pyResults["files_found"]):
    mdTableList = []
    for fileFound in pyResults["files_found"]:
        mdTableList.append({'Files Found': fileFound})

    displayData += tableToMarkdown('Files Add', mdTableList)

for file in files:
    filename = file.replace("./output/","")
    demisto.results(file_result_existing_file(file, filename))

demisto.results({'Type': entryTypes['note'], 'Contents': pyResults, 'EntryContext': {'pcap_results': pyResults}, 'ContentsFormat': formats['json'], 'HumanReadable': displayData})
