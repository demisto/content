import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

restartcount = 0
suggestions = []

# knownerrors = [
#     {"Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get": ["*Found Error:* `Got permission denied while trying to connect to the Docker daemon socket at unix`","Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4oCAG"]},
#     {'[Errno 13] Permission denied:':['*Found Error:* `[Errno 13] Permission denied`',"Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4ZCAW"]},
#     {'config.json: permission denied':['*Found Error:* `config.json: permission denied`',"Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4tCAG"]},
#     {'Error response from daemon: OCI runtime create failed:':['*Found Error:* `Error response from daemon: OCI runtime create failed`',"Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4eCAG"]},
#     {'proxyconnect tcp: tls: oversized record received with length 20527':['*Found Error:* `proxyconnect tcp: tls: oversized record received with length 20527`',"Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNhpCAG"]},
#     {"error: websocket: not a websocket handshake: 'upgrade' token not found in 'Connection' header": ['*Found Error:* `websocket: not a websocket handshake: upgrade token not found in Connection header`',"Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNiOCAW"]},
#     {"Create more free space in thin pool or use dm.min_free_space":['*Found Error:* `Create more free space in thin pool or use dm.min_free_space`',"Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNhQCAW"]},
#     {"in pool reached high watermark": ["*Found Error:* `amount of active containers in pool reached high watermark`","Check and increase high watermark for docker"]},
#     {"no space left on device": ["*Found Error:* `no space left on device`","Disk space full, need to check and clear space."]},
#     {"ImportError: No module named": ["*Found Error:* `ImportError: No module named`","Python environment missing dependency or docker image outdated."]},
#     {"(error: websocket: close 1006 (abnormal closure): unexpected EOF)":[" *Found Error:* `error: websocket: close 1006 (abnormal closure): unexpected EOF`","https://support.demisto.com/hc/en-us/articles/115004463233-Websocket-configuration"]},
#     {"fatal error: runtime: out of memory" : ["*Found Error:* `fatal error: runtime: out of memory.`"," Server is out of Memory please check Specs/Architecture."]},
#     {"error Wrong schedule format":["*Found Error:* `error Wrong schedule format`","change jobs.serverSiemIncidents.schedule=<time in minutes> to Xm. for example 5 minuets should be 5m"]},
#     {"error Failed on ensure function for":["*Found Error:* `error Failed on ensure function for`","One or more of the indexes is corrupted, please refer to https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/manage-data/reindex-the-database"]},
#     {"Version didnt change":["*Found Error:* `Version didnt change`","Upgrade used older version","Re-run the upgrade with latest version."]},
#     {"layout-edit-.json: invalid argument":["*Found Error:* `layout-edit-.json: invalid argument`","There is a corrupted layout file. need to run dbDeleteInvalidLayouts.sh"]},
#     {"error: unsupported mode":["*Found Error:* `error: unsupported mode`","Remove old index files under /usr/local/demisto/dist. and do a hard refresh in the browser. No service restart needed"]}]

knownerrors = [
    {
        "Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get": [
            "*Found Error:* `Got permission denied while trying to connect to the Docker daemon socket at unix`",
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4oCAG"
        ]
    },
    {
        '[Errno 13] Permission denied:': [
            '*Found Error:* `[Errno 13] Permission denied`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4ZCAW"
        ]
    },
    {
        'config.json: permission denied': [
            '*Found Error:* `config.json: permission denied`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4tCAG"
        ]
    },
    {
        'Error response from daemon: OCI runtime create failed:': [
            '*Found Error:* `Error response from daemon: OCI runtime create failed`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u000000HB4eCAG"
        ]
    },
    {
        'proxyconnect tcp: tls: oversized record received with length 20527': [
            '*Found Error:* `proxyconnect tcp: tls: oversized record received with length 20527`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNhpCAG"
        ]
    },
    {
        "error: websocket: not a websocket handshake: 'upgrade' token not found in 'Connection' header": [
            '*Found Error:* `websocket: not a websocket handshake: upgrade token not found in Connection header`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNiOCAW"
        ]
    },
    {
        "Create more free space in thin pool or use dm.min_free_space": [
            '*Found Error:* `Create more free space in thin pool or use dm.min_free_space`',
            "Please refer to https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000PNhQCAW"
        ]
    },
    {
        "in pool reached high watermark": [
            "*Found Error:* `amount of active containers in pool reached high watermark`",
            "Check and increase high watermark for docker: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server"
        ]
    },
    {
        "no space left on device": [
            "*Found Error:* `no space left on device`",
            "Free up Disk Space with Data Archiving: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/manage-data/free-up-disc-space-with-data-archiving"
        ]
    },
    {
        "ImportError: No module named": [
            "*Found Error:* `ImportError: No module named`",
            "Python environment missing dependency or docker image outdated."
        ]
    },
    {
        "(error: websocket: close 1006 (abnormal closure): unexpected EOF)": [
            " *Found Error:* `error: websocket: close 1006 (abnormal closure): unexpected EOF`",
            "WebSocket Configuration: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-1/cortex-xsoar-admin/installation/post-installation-checklist/websocket-configuration.html#idee004eaa-34d9-41a1-a8d0-aba3bf9f91bb"
        ]
    },
    {
        "fatal error: runtime: out of memory": [
            "*Found Error:* `fatal error: runtime: out of memory.`",
            "Performance Tuning of Cortex XSOAR Server: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server"
        ]
    },
    {
        "error Wrong schedule format": [
            "*Found Error:* `error Wrong schedule format`",
            "Change jobs.serverSiemIncidents.schedule=<time in minutes> to Xm. for example 5 minuets should be 5m"
        ]
    },
    {
        "error Failed on ensure function for": [
            "*Found Error:* `error Failed on ensure function for`",
            "Reindex the Entire Database: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/manage-data/reindex-the-database"
        ]
    },
    {
        "Version didnt change": [
            "*Found Error:* `Version didnt change`",
            "Upgrade used an older version, Re-run the upgrade with the latest version."
        ]
    },
    {
        "layout-edit-.json: invalid argument": [
            "*Found Error:* `layout-edit-.json: invalid argument`",
            "Please contact customer support"
        ]
    },
    {
        "error: unsupported mode": [
            "*Found Error:* `error: unsupported mode`",
            "Remove old index files under /usr/local/demisto/dist. and do a hard refresh in the browser. No service restart needed"
        ]
    }
]

res = []
last_line = None
since = None
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
