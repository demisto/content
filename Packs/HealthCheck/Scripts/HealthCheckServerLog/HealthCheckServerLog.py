import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

restartcount = 0
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
            "Free up Disk Space with Data Archiving: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
            "cortex-xsoar-admin/manage-data/free-up-disc-space-with-data-archiving"
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
            "WebSocket Configuration: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-1/cortex-xsoar-admin/installation/"
            "post-installation-checklist/websocket-configuration.html#idee004eaa-34d9-41a1-a8d0-aba3bf9f91bb"
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
            "https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/manage-data/reindex-the-database"
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
last_line: List
since: List
path = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})
if path[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')
else:
    try:
        with open(path[0]['Contents']['path'], 'r') as f:
            data_line = f.readlines()

            for line in data_line:
                if 'good luck' in line:
                    restartcount += 1

                for item in knownerrors:
                    for (err, suggest) in item.items():
                        if err in line:
                            if suggest not in suggestions:
                                suggestions.append(suggest)
                if since:
                    pass
                else:
                    since = re.findall('(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                last_line = re.findall('(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)

        demisto.executeCommand("setIncident", {"restartcount": restartcount, "logsince": since[0], "loguntil": last_line[0]})

        if suggestions:
            for entry in suggestions:
                res.append({"category": "Log Analysis", "severity": "High", "description": entry[0], "resolution": entry[1]})

        results = CommandResults(
            readable_output="HealthCheckServerLog Done",
            outputs_prefix="actionableitems",
            outputs=res)

        return_results(results)

    except UnicodeDecodeError:
        demisto.results("Could not read file")
