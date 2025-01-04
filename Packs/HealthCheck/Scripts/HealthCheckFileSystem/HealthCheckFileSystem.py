import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# noqa: F401
# noqa: F401
import os
import sys
import re


LS_RE = (
    rb"(?P<type>^[d-])(?P<u>.{3})(?P<g>.{3})(?P<o>.{3})(?P<S>[.\s]+)(?P<hlinks>\d+)\s+(?P<uid>\S+)\s+"
    rb"(?P<gid>\S+)\s+(?P<size>[\w\d.]+)\s+(?P<modified>\w+\s+\d+\s+\d+:?\d+)\s+(?P<name>.*)"
)
UNITS = {"B": 1, "K": 10**3, "M": 10**6, "G": 10**9, "T": 10**12}


def count_partitions(filesystem):
    partitionscounter = 0
    if filesystem:
        for path in filesystem:
            if "/data/partitionsData" in path:
                for file in filesystem[path]:
                    name = file.get("name")
                    regx = re.search("demisto_\d{6}\.db", name)
                    if regx:
                        partitionscounter += 1
        return partitionscounter
    return None


def parse_size(size):
    m = re.match(rb"^(?P<number>[\d.]+)(?P<unit>\w*)$", size)
    if not m:
        sys.exit(0)
    number, unit = m.group("number"), str(m.group("unit"), "utf-8")
    if not unit:
        unit = "B"
    return int(float(number) * UNITS[unit])


# Large File Threshold
LARGE_FILE = parse_size(demisto.getArg("minFileSize").strip().encode())


def read_section(section):
    path = ""
    total = ""
    files = []
    large_files = []
    for line in section.split(os.linesep.encode()):
        if line.endswith(b":"):
            path = line[:-1].decode("utf-8")
        if line.startswith(b"total "):
            total = line.decode("utf-8")
        else:
            m = re.match(LS_RE, line)
            if not m:
                continue
            f = {
                "path": path,
                "type": m.group("type").decode("utf-8"),
                "u": m.group("u").decode("utf-8"),
                "g": m.group("g").decode("utf-8"),
                "o": m.group("o").decode("utf-8"),
                "S": m.group("S").decode("utf-8"),
                "hlinks": m.group("hlinks").decode("utf-8"),
                "uid": m.group("uid").decode("utf-8"),
                "gid": m.group("gid").decode("utf-8"),
                "size": m.group("size"),
                "modified": m.group("modified").decode("utf-8"),
                "name": m.group("name").decode("utf-8"),
            }
            if parse_size(f["size"]) >= LARGE_FILE:
                large_files.append(f)

            # decode size key
            f["size"] = m.group("size").decode("utf-8")
            files.append(f)
    if isinstance(path, bytes):
        path = path.decode("utf-8")
    return path, files, large_files, total


RESOLUTION = [
    "Free up Disk Space with Data Archiving: https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/"
    "cortex-xsoar-admin/manage-data/free-up-disc-space-with-data-archiving"
]


def main(args):
    if is_demisto_version_ge("8.0.0"):
        return_error("Not Available for XSOAR v8")
    entry_id = args.get("entryID")
    path = demisto.getFilePath(entry_id)["path"]
    with open(path, "rb") as file_:
        fs = file_.read()

    res = []
    large_files_table = []

    file_content = fs.split(2 * os.linesep.encode())
    large = []
    filesystem = {}
    importantPathTable = []
    for section in file_content:
        path, files, large_files, total = read_section(section)
        filesystem[path] = files

        if large_files:
            large += large_files

        if re.match(".*_(?:0[1-9]|1[0-2])[0-9]{4}\/store", path) and re.match(
            "total\s(?:[1-9]\d*[MG]$|\d*.\d*[MG])", total
        ):  # bigger than M and G
            entry = {"path": path, "size": total[6:]}
            importantPathTable.append(entry)
    number_of_partitions = count_partitions(filesystem)
    demisto.executeCommand(
        "setIncident", {"xsoarnumberofdbpartitions": number_of_partitions, "healthcheckfilesystemdirectories": importantPathTable}
    )

    for file in large:
        res.append(
            {
                "category": "File system",
                "severity": "Medium",
                "description": f"The file: {file['path']}/{file['name']} has a size of: {file['size']}\n",
                "resolution": RESOLUTION[0],
            }
        )
        large_files_table.append({"file": f"{file['path']}/{file['name']}", "size": f"{file['size']}"})
    if number_of_partitions > 12:
        res.append(
            {
                "category": "File system",
                "severity": "Medium",
                "description": f"You have {number_of_partitions} months data, consider to archive old data",
                "resolution": RESOLUTION[0],
            }
        )
    elif number_of_partitions > 6:
        res.append(
            {
                "category": "File system",
                "severity": "Low",
                "description": f"You have {number_of_partitions} months data, consider to archive old data",
                "resolution": RESOLUTION[0],
            }
        )
    resCommand = demisto.executeCommand("setIncident", {"healthchecklargefiles": large_files_table})
    if is_error(resCommand):
        return_results(resCommand)
        return_error("Failed to execute setIncident. See additional error details in the above entries.")

    results = CommandResults(
        readable_output="HealthCheckFileSysLog Done",
        outputs_prefix="HealthCheck.ActionableItems",
        outputs=res,
    )

    return results


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    return_results(main(demisto.args()))
