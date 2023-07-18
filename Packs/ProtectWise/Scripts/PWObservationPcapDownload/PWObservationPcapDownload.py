import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from time import sleep


res = []
dArgs = demisto.args()
burstSize = demisto.get(dArgs, 'burstsize')
burstSize = int(burstSize) if burstSize else 10
remaining = burstSize
waitSeconds = demisto.get(dArgs, 'waitms')
waitSeconds = float(waitSeconds) / 1000.0 if waitSeconds else 1.0
dArgs["using-brand"] = "ProtectWise"
obIDs = argToList(demisto.get(dArgs, 'id'))
sensorIDs = demisto.get(dArgs, 'sensorId')
sensorList = [sensorIDs] if isinstance(sensorIDs, int) else argToList(sensorIDs)
for sensorId in sensorList:
    dArgs['sensorId'] = sensorId
    for oid in obIDs:
        dArgs['id'] = oid
        dArgs['filename'] = oid + '.pcap'
        if remaining:
            remaining -= 1
        else:
            sleep(waitSeconds)  # pylint: disable=sleep-exists
            remaining = burstSize
        resCmd = demisto.executeCommand("protectwise-observation-pcap-download", dArgs)
        try:
            res += resCmd
        except Exception as ex:
            res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                        "Contents": "Error occurred while parsing output from command. Exception info:\n"
                        + str(ex) + "\n\nInvalid output:\n" + str(resCmd)})
demisto.results(res)
