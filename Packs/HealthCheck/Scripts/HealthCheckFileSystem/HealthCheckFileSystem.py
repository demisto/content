import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import os
import sys
import re

LS_RE = br'(?P<type>^[d-])(?P<u>...)(?P<g>...)(?P<o>...)(?P<S>[.\s]+)(?P<hlinks>\d+)\s+(?P<uid>\S+)\s+(?P<gid>\S+)\s+' \
        br'(?P<size>[\w\d.]+)\s+(?P<modified>\w+\s+\d+\s+\d+:?\d+)\s+(?P<name>.*)'
UNITS = {'B': 1, 'K': 10**3, 'M': 10**6, 'G': 10**9, 'T': 10**12}


def count_partitions(filesystem):
    if filesystem:
        for path in filesystem:
            if '/lib/demisto/data/partitionsData' in path:
                return len(filesystem[path]) - 2


def parse_size(size):
    m = re.match(br'^(?P<number>[0-9.]+)(?P<unit>\w*)$', size)
    if not m:
        sys.exit(0)
    number, unit = m.group('number'), str(m.group('unit'), 'utf-8')
    if not unit:
        unit = 'B'
    return int(float(number) * UNITS[unit])


# Large File Threshold
LARGE_FILE = parse_size(demisto.getArg('minFileSize').strip().encode())


def read_section(section):
    path = ""
    files = []
    large_files = []
    for line in section.split(os.linesep.encode()):
        if line.endswith(b':'):
            path = line[:-1].decode("utf-8")
        else:
            m = re.match(LS_RE, line)
            if not m:
                continue
            f = {
                'path': path,
                'type': m.group('type').decode("utf-8"),
                'u': m.group('u').decode("utf-8"),
                'g': m.group('g').decode("utf-8"),
                'o': m.group('o').decode("utf-8"),
                'S': m.group('S').decode("utf-8"),
                'hlinks': m.group('hlinks').decode("utf-8"),
                'uid': m.group('uid').decode("utf-8"),
                'gid': m.group('gid').decode("utf-8"),
                'size': m.group('size'),
                'modified': m.group('modified').decode("utf-8"),
                'name': m.group('name').decode("utf-8"),
            }
            if parse_size(f['size']) >= LARGE_FILE:
                large_files.append(f)

            # decode size key
            f['size'] = m.group('size').decode("utf-8")
            files.append(f)
    if isinstance(path, bytes):
        path = path.decode("utf-8")
    return path, files, large_files


RESOLUTION = ["Free up Disk Space with Data Archiving: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
              "cortex-xsoar-admin/manage-data/free-up-disc-space-with-data-archiving"]

res = []
largeFilesTable = []
path = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})


if is_error(path):
    demisto.results('File not found')
    sys.exit(0)

with open(path[0]['Contents']['path'], 'rb') as fh:
    fs = fh.read()
    fs = fs.split(2 * os.linesep.encode())
    large = []
    filesystem = {}
    for section in fs:
        path, files, large_files = read_section(section)
        filesystem[path] = files
        if large_files:
            large += large_files
    numberOfPartitions = count_partitions(filesystem)
    demisto.executeCommand('setIncident', {"numberofdbpartitions": numberOfPartitions})
    for file in large:
        res.append({'category': 'File system', 'severity': 'Medium',
                    'description': f"The file: {file['path']}/{file['name']} has a size of: {file['size']}\n",
                    'resolution': RESOLUTION[0]
                    })
        largeFilesTable.append({"file": f"{file['path']}/{file['name']}", "size": f"{file['size']}"})
    if numberOfPartitions > 12:
        res.append({'category': 'File system', 'severity': 'Medium',
                    'description': f"You have {numberOfPartitions} months data, consider to archive old data",
                    'resolution': RESOLUTION[0]
                    })
    elif numberOfPartitions > 6:
        res.append({'category': 'File system', 'severity': 'Low',
                    'description': f"You have {numberOfPartitions} months data, consider to archive old data",
                    'resolution': RESOLUTION[0]
                    })

print(largeFilesTable)

aa = demisto.executeCommand('setIncident', {"largefiles": largeFilesTable})

print(aa)

results = CommandResults(
    readable_output="HealthCheckFileSysLog Done",
    outputs_prefix="actionableitems",
    outputs=res)

return_results(results)
