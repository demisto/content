import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Copyright © Seth Piezas

1. Hunt for any and all assets that have ever reached out to the known IoC (manygoodnews.com)
2. Collect and attach evidence of related telemetry [10 mins of all network and endpoint data] around the time of first access by the first asset in the environment that ever reached out to the IoC in question
3. Uncover any other alerts that occurred on the same asset in the preceding and following 30 mins after the initial outreach to the malicious domain

"""

testdata = {"GoogleChronicleBackstory": {"Asset": [{"AccessedDomain": "manygoodnews.com", "FirstAccessedTime": "2020-01-10T07:08:39.930255Z", "LastAccessedTime": "2020-01-11T07:51:25.083668Z", "ProductId": "B17"}, {"AccessedDomain": "manygoodnews.com", "FirstAccessedTime": "", "IpAddress": "10.0.9.117",
                                                                                                                                                                                                                       "LastAccessedTime": ""}, {"AccessedDomain": "manygoodnews.com", "FirstAccessedTime": "2020-01-12T07:08:39.930255Z", "LastAccessedTime": "2020-01-14T07:51:25.083668Z", "MACAddress": "00:1B:44:11:3A:B7"}]}, "Host": [{"IP": "10.0.9.117"}, {"MACAddress": "00:1B:44:11:3A:B7"}, {"ID": "B17"}]}


def getDateTime(first, format):
    date_time_str = first[:-1]
    date_time_obj = datetime.datetime.strptime(date_time_str, format)
    return date_time_obj


def getTimeWithOffset(timestring, offset):
    time = getDateTime(timestring, '%Y-%m-%dT%H:%M:%S.%f')
    time = time - datetime.timedelta(hours=0, minutes=offset)
    return time.strftime('%Y-%m-%dT%H:%M:%SZ')

# good time format 2002-10-02T15:00:00Z


def getFirstIOCAccess(iocs):
    idx = 0
    ls = []
    lowesttime = "2080-01-10T07:08:39.930255Z"
    asset = None
    for ioc in iocs:
        firsttime = ioc["FirstAccessedTime"]
        if len(firsttime) > 3:
            if firsttime < lowesttime:
                lowesttime = firsttime
                asset = ioc
    return asset


def GetFirst(pkg):
    assets = pkg["GoogleChronicleBackstory"]["Asset"]
    first = getFirstIOCAccess(assets)
    return first


netevent = {
    "UdpDestination": "8.8.8.8",
    "UdpPort": 53,
    "UdpSource": "192.168.2.4"
}


def AddRelatedTelemetry(ioc):
    network = []
    for i in range(0, 1024):
        network.append(netevent)
    return network


def Generate(ctx):
    if ctx == None:
        ctx = testdata
    asset = GetFirst(ctx)
    # print(asset)
    rangestart = getTimeWithOffset(asset["FirstAccessedTime"], -30)
    rangeend = getTimeWithOffset(asset["FirstAccessedTime"], 30)
    # print(rangestart, rangeend)
    response_from_api = {
        "Asset": asset,
        "Related": AddRelatedTelemetry(asset),
        "RangeAccessStart": rangestart,
        "RangeAccessEnd": rangeend
    }
    ipname = "10.0.9.117"
    if "IpAddress" in asset:
        ipname = asset["IpAddress"]
    if "MACAddress" in asset:
        ipname = asset["MACAddress"]
    readable = "## Related network traffic within half hour of incident\n"
    for r in response_from_api["Related"]:
        readable += f'dest: {r["UdpDestination"]}, port: {r["UdpPort"]}, source: {ipname}\n'
    command_results = CommandResults(
        outputs_prefix='SecureHealth.Assets',
        outputs_key_field='Asset',
        outputs=response_from_api,
        readable_output=readable,
    )
    return command_results


if __name__ == "__main__":
    print(Generate(None))
else:
    ans = Generate(demisto.context())
    obj = {'id': "first", 'description': "related events within 30 minutes"}
    return_results(ans)
