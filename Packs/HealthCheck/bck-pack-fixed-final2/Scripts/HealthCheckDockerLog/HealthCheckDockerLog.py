import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
count_lines = 0
countCPU = 0
countRAM = 0
human_readable = []
contstat = []
CPUs = []
res = []

# get the file path from the given entry ID
path = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})

# if no file, return error
if path[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')
else:
    try:
        with open(path[0]['Contents']['path'], 'r') as f:
            data_line = f.readlines()

            for line in data_line:
                count_lines += 1
                contstat.append(re.findall(r"\d+[.]\d+%", line))

                if 'CPUs' in line:
                    # get numbers after white space
                    result = re.search("\d+", line)
                    if result:
                        CPUs = result.group(0)

                # (?<=:).*
                if 'Operating' in line:
                    result = re.search("(?<=:).*", line)
                    if result:
                        Operating = result.group(0)

                if 'Memory' in line:
                    result = re.search("\d+.*", line)
                    if result:
                        Memory = result.group(0)

                if 'Containers' in line:
                    result = re.search("\d+", line)
                    if result:
                        Containers = result.group(0)

                if 'Running:' in line:
                    result = re.search("\d+", line)
                    if result:
                        Running = result.group(0)

                if 'Paused' in line:
                    result = re.search("\d+", line)
                    if result:
                        Paused = result.group(0)

                if 'Stopped' in line:
                    result = re.search("\d+", line)
                    if result:
                        Stopped = result.group(0)

            for line in contstat:
                if len(line) == 2:
                    line[0] = line[0][:-1]
                    line[1] = line[1][:-1]
                    if float(line[0]) > 10.0:
                        countCPU += 1
                    if float(line[1]) > 10.0:
                        countRAM += 1
            if countCPU:
                res.append({"category": "Docker", "severity": "Medium",
                            "description": "There are {} containers that are running with over 10% CPU Usage - Please check docker.log".format(countCPU)})
            if countRAM:
                res.append({"category": "Docker", "severity": "Medium",
                            "description": "There are {} containers that are running with over 10% RAM Usage - Please check docker.log".format(countRAM)})

        results = CommandResults(
            readable_output="HealthCheckDockerLog Done",
            outputs_prefix="actionableitems",
            outputs=res)

        return_results(results)

        if CPUs:
            demisto.executeCommand("setIncident", {
                'xsoarcpu': CPUs,
                'xsoaros': Operating,
                'xsoarmemory': Memory,
                'dockercontainers': Containers,
                'dockerrunning': Running,
                'dockerpaused': Paused,
                'dockerstop': Stopped
            })

    except UnicodeDecodeError:
        demisto.results("Could not read file")
