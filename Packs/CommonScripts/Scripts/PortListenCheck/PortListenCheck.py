import socket

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = int(demisto.args()["port"])
host = demisto.args()["host"]
result = sock.connect_ex((host, port))
openPort = False
if result == 0:
    resp = "Port " + str(port) + " is open on host:" + host
    openPort = True
else:
    resp = "Port " + str(port) + " is not open on host:" + host

demisto.results({'Type': entryTypes['note'],
                 'Contents': resp,
                 'ContentsFormat': formats['json'],
                 'HumanReadable': resp,
                 'ReadableContentsFormat': formats['markdown'],
                 'EntryContext': {"portOpen": openPort}})
