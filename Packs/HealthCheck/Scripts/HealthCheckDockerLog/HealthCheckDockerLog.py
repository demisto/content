import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re

DESCRIPTION = [
    "Container {0} was last updated {1}, consider updating it",
    "Container {0} version {1} was last updated {2}, consider updating it",
    "There are {} containers that are running with over 10% CPU Usage - Please check docker.log",
    "There are {} containers that are running with over 10% RAM Usage - Please check docker.log"
]

RESOLUTION = ["Docker containers overloaded: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
              "cortex-xsoar-admin/cortex-xsoar-overview/performance-tuning-of-cortex-xsoar-server"]


def containerAnalytics(containers):
    lres: List
    for container in containers:
        if float(container['cpu_usage']) > 80.0:
            res.append({"category": "Docker", "severity": "High",
                        "description": "Container {} uses more then 80% of the CPU".format(container['containerid']),
                        "resolution": f"{RESOLUTION[0]}"
                        })
    return lres


def imageAnalytics(images):
    lres = []
    for image in images:
        if "month" in image['last_update']:
            lres.append({"category": "Docker", "severity": "Medium",
                         "description": f"{DESCRIPTION[0]}".format(image['image'], image['last_update']),
                         "resolution": f"{RESOLUTION[0]}"
                         })
        elif "years" in image['last_update']:
            lres.append({"category": "Docker", "severity": "High",
                         "description": f"{DESCRIPTION[0]}".format(image['image'], image['version'], image['last_update']),
                         "resolution": f"{RESOLUTION[0]}"
                         })
    return lres


args = demisto.args()
Thresholds = {
    "DockerContainerCPUUsage": 10,
    "DockerContainerRAMUsage": 10
}
thresholds = args.get('Thresholds', Thresholds)

# get the file path from the given entry ID
path = demisto.executeCommand('getFilePath', {'id': args['entryID']})

# if no file, return error
if path[0]['Type'] == entryTypes['error']:
    return_results('File not found')
else:
    getimages = re.compile(
        r'(?P<repository>[\w*\/\.\-\<\>]*)\s+(?P<tag>\d[\.|\d]*|\blatest\b|\b\<none\>\b|\b1\.[0-9]\-alpine\b)'
        r'\s+(?P<ImageID>\w+)\s+(?P<Created>\d{0,2}\s(?:\byears\b|\bmonths\b|weeks\b) ago)\s+(?P<size>\d+.*B)', re.MULTILINE)
    getcontainers = re.compile(
        r'^(?P<container>[\w]+)\s+(?P<name>[\w\d\-\.]+)\s+(?P<cpu>[\d\.]+)\%\s+(?P<memusage>[\d\.]+(?:MiB|GiB))\s+\/\s+'
        r'(?P<memlimit>[\d\.]+(?:MiB|GiB))\s+(?P<mempercent>[\d\.]+)%\s+(?P<netI>[\d\.]+(?:B|kB|MB))\s+\/\s+'
        r'(?P<netO>[\d\.]+(?:B|kB|MB))\s+(?P<blockI>[\d\.]+(?:B|kB|MB))\s+\/\s+(?P<blockO>[\d\.]+(?:B|kB|MB))\s+(?P<pids>\d+)',
        re.MULTILINE)
    usage = re.compile(r'(\d+[.]\d+)%', re.MULTILINE)
    config = re.compile(r'([ \w]+)[:] ([-., \d\w]+)', re.MULTILINE)
    image_array = []
    res = []
    container_array = []
    dataset = {}
    try:
        with open(path[0]['Contents']['path'], 'r') as f:
            ALL_LINES = f.read()
            # fetch all data items and create a dataset

            ALL_IMAGES = [m.groups() for m in getimages.finditer(ALL_LINES)]
            for item in ALL_IMAGES:
                image_array.append({"image": item[0], "version": item[1], 'imageid': item[2],
                                    'last_update': item[3], 'size': item[4]})

            ALL_CONTAINERS = [m.groups() for m in getcontainers.finditer(ALL_LINES)]
            for item in ALL_CONTAINERS:
                if len(item) == 11:
                    container_array.append({"containerid": item[0], "name": item[1], 'cpu_usage': item[2],
                                            'mem_used': item[3], 'mem_limit': item[4],
                                            'mem_percent': item[5], 'net_in': item[6],
                                            'net_out': item[7], 'block_in': item[8],
                                            'block_out': item[9], 'pids': item[10],
                                            })

            return_outputs(readable_output=tableToMarkdown("Containers", container_array,
                                                           ['containerid', 'name', 'cpu_usage', 'mem_percent']))
            return_outputs(readable_output=tableToMarkdown("Images", image_array, [
                'imageid', 'image', 'version', 'last_update', 'size']))

            getconfig = [m.groups() for m in config.finditer(ALL_LINES)]
            for m in getconfig:
                dataset.update({m[0].lstrip(): m[1].strip()})

            usage_all = [m.groups() for m in usage.finditer(ALL_LINES)]
            countCPU = 0
            countMEM = 0
            count = 0
            for m in usage_all:
                if float(m[0]) > 10.0:
                    if (count % 2) == 0:
                        countCPU += 1
                    elif (count % 2) != 0:
                        countMEM += 1
                count += 1

            if countCPU:
                res.append({"category": "Docker", "severity": "Medium",
                            "description": DESCRIPTION[2].format(countCPU)})
            if countMEM:
                res.append({"category": "Docker", "severity": "Medium",
                            "description": DESCRIPTION[3].format(countMEM)})

        res = res + imageAnalytics(image_array)
        res = res + containerAnalytics(container_array)

        results = CommandResults(
            readable_output="HealthCheckDockerLog Done",
            outputs_prefix="actionableitems",
            outputs=res)

        return_results(results)

        demisto.executeCommand("setIncident", {'DockerStatsSettings': dataset})

        if 'Operating System' in dataset:
            demisto.executeCommand("setIncident", {
                'xsoarcpu': dataset['CPUs'],
                'xsoaros': dataset['Operating System'],
                'xsoarmemory': dataset['Total Memory'],
                'dockercontainers': dataset['Containers'],
                'dockerrunning': dataset['Running'],
                'dockerpaused': dataset['Paused'],
                'dockerstop': dataset['Stopped'],
                'dockerversion': dataset['Server Version']
            })

    except UnicodeDecodeError:
        return_results("Could not read file")
