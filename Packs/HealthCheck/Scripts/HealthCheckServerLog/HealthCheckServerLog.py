import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# noqa: F401
# noqa: F401
import re


def findOldestDate(incidentDate, newDate):
    incidentDate = datetime.strptime(incidentDate, "%Y-%m-%d %H:%M:%S")
    newDate = datetime.strptime(newDate, "%Y-%m-%d %H:%M:%S")
    return min([incidentDate, newDate])


def findNewestDate(incidentDate, newDate):
    incidentDate = datetime.strptime(incidentDate, "%Y-%m-%d %H:%M:%S")
    newDate = datetime.strptime(newDate, "%Y-%m-%d %H:%M:%S")
    return max([incidentDate, newDate])


context = demisto.context()

suggestions = []
knownerrors = [
    {
        "Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get": [
            "Error Found: `Got permission denied while trying to connect to the Docker daemon socket at unix`",
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4oCAG"
        ]
    },
    {
        '[Errno 13] Permission denied:': [
            'Error Found: `[Errno 13] Permission denied`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4ZCAW"
        ]
    },
    {
        'config.json: permission denied': [
            'Error Found: `config.json: permission denied`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4tCAG"
        ]
    },
    {
        'Error response from daemon: OCI runtime create failed:': [
            'Error Found: `Error response from daemon: OCI runtime create failed`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4eCAG"
        ]
    },
    {
        'proxyconnect tcp: tls: oversized record received with length 20527': [
            'Error Found: `proxyconnect tcp: tls: oversized record received with length 20527`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNhpCAG"
        ]
    },
    {
        "error: websocket: not a websocket handshake: 'upgrade' token not found in 'Connection' header": [
            'Error Found: `websocket: not a websocket handshake: upgrade token not found in Connection header`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNiOCAW"
        ]
    },
    {
        "Create more free space in thin pool or use dm.min_free_space": [
            'Error Found: `Create more free space in thin pool or use dm.min_free_space`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNhQCAW"
        ]
    },
    {
        "in pool reached high watermark": [
            "Error Found: `amount of active containers in pool reached high watermark`",
            "Check and increase high watermark for docker: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
            "cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server"
        ]
    },
    {
        "no space left on device": [
            "Error Found: `no space left on device`",
            "Free up Disk Space with Data Archiving: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/"
            "Cortex-XSOAR-Administrator-Guide/Free-up-Disk-Space-with-Data-Archiving"
        ]
    },
    {
        "ImportError: No module named": [
            "Error Found: `ImportError: No module named`",
            "Python environment missing dependency or docker image outdated."
        ]
    },
    {
        "(error: websocket: close 1006 (abnormal closure): unexpected EOF)": [
            " Error Found: `error: websocket: close 1006 (abnormal closure): unexpected EOF`",
            "WebSocket Configuration:  https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/"
            "Cortex-XSOAR-Administrator-Guide/WebSocket-Configuration"
        ]
    },
    {
        "fatal error: runtime: out of memory": [
            "Error Found: `fatal error: runtime: out of memory.`",
            "Performance Tuning of Cortex XSOAR Server: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
            "cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server"
        ]
    },
    {
        "error Wrong schedule format": [
            "Error Found: `error Wrong schedule format`",
            "Change jobs.serverSiemIncidents.schedule=<time in minutes> to Xm. for example 5 minuets should be 5m"
        ]
    },
    {
        "error Failed on ensure function for": [
            "Error Found: `error Failed on ensure function for`",
            "Reindex the Entire Database: "
            "https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.10/"
            "Cortex-XSOAR-Administrator-Guide/Reindex-the-Entire-Database"
        ]
    },
    {
        "Version didnt change": [
            "Error Found: `Version didnt change`",
            "Upgrade used an older version, Re-run the upgrade with the latest version."
        ]
    },
    {
        "layout-edit-.json: invalid argument": [
            "Error Found: `layout-edit-.json: invalid argument`",
            "Please contact customer support"
        ]
    },
    {
        "error: unsupported mode": [
            "Error Found: `error: unsupported mode`",
            "Remove old index files under /usr/local/demisto/dist. and do a hard refresh in the browser. "
            "No service restart needed"
        ]
    }
]

res = []
context_since = context.get('LogServer', {}).get('since')
since = log_until = restartcount = None
context_log_until = context.get('LogServer', {}).get('logUntil')
context_restartcount = context.get('LogServer', {}).get('restartCount')
path = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})

if path[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')
else:
    try:
        with open(path[0]['Contents']['path']) as f:
            data_line = f.readlines()
            # find Since and find knownErrors
            for line in data_line:
                if 'good luck' in line:
                    if (context_restartcount is None) and (restartcount is None):
                        restartcount = 1
                    elif (context_restartcount is not None) and (restartcount is None):
                        restartcount = int(context_restartcount)
                        restartcount += 1
                    elif (context_restartcount is not None) and (restartcount is not None):
                        restartcount += 1
                for item in knownerrors:
                    for (err, suggest) in item.items():
                        if err in line:
                            if suggest not in suggestions:
                                suggestions.append(suggest)
                if (context_since is None) and (since is None):
                    since = re.findall('(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    oldestDate = since[0]
                    continue
                elif (context_since is not None) and (since is None):
                    since = re.findall('(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    oldestDate = findOldestDate(since[0], context_since)
                    continue
                else:
                    continue
            # find Last Log
            for line in reversed(data_line):
                if (context_log_until is None) and (log_until is None):
                    log_until = re.findall('(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    if not log_until:
                        log_until = None
                        continue
                    newestDate = log_until[0]
                    break
                elif (context_since is not None) and (log_until is None):
                    log_until = re.findall('(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    if not log_until:
                        continue
                    newestDate = log_until[0]
                    newestDate = findNewestDate(log_until[0], context_log_until)
                    break
                else:
                    oldestDate = context_since
                    newestDate = context_log_until
                    break

        demisto.setContext("LogServer.since", str(oldestDate))
        demisto.setContext("LogServer.logUntil", str(newestDate))
        demisto.setContext("LogServer.restartCount", restartcount)
        demisto.executeCommand("setIncident", {"healthcheckrestartcount": restartcount,
                                               "healthchecklogsince": str(oldestDate),
                                               "healthcheckloguntil": str(newestDate)})

        if suggestions:
            for entry in suggestions:
                res.append({"category": "Log Analysis", "severity": "High", "description": entry[0], "resolution": entry[1]})

        results = CommandResults(
            readable_output="HealthCheckServerLog Done",
            outputs_prefix="HealthCheck.ActionableItems",
            outputs=res)

        return_results(results)

    except UnicodeDecodeError:
        demisto.results("Could not read file")
