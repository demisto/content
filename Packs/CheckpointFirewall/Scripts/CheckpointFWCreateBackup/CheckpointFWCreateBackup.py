import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


CLI_ADD = "add backup local"
BASH_ADD = '/etc/cli.sh -c "' + CLI_ADD + '"'


def main():
    res = []
    tbl = []
    devices = demisto.get(demisto.args(), 'devices')
    devicesBackupStarted = []
    devicesBackupError = []
    if not devices:
        res.append(
            {"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": "Received empty device list!"})
    else:
        devices = ','.join(devices) if isinstance(devices, list) else devices
        sshArgs = {"using": devices,
                   "cmd": BASH_ADD
                   }
        resSSH = demisto.executeCommand("ssh", sshArgs)
        try:
            for entry in resSSH:
                if isError(entry) and not demisto.get(entry, 'Contents.command'):
                    res += resSSH
                    break
                else:
                    device = entry['ModuleName']
                    if demisto.get(entry, 'Contents.success'):
                        output = demisto.get(entry, 'Contents.output')
                        backFileLoc = output.find("Backup file location")
                        result = 'Answer returned'
                        devicesBackupStarted.append({
                            'DeviceName': device,
                            'System': demisto.get(entry, 'Contents.system'),
                            'Status': ("Done" if output.find("local backup succeeded.") > -1 else "Pending"),
                            'Path': (output[backFileLoc, :] if backFileLoc > -1 else None)
                        })
                    else:
                        devicesBackupError.append(device)
                        output = "Output:\n" + str(demisto.get(entry, 'Contents.output')) + \
                                 "Error:\n" + str(demisto.get(entry, 'Contents.error'))
                        result = 'Failed to query'

                    tbl.append({'DeviceName': device, 'System': demisto.get(
                        entry, 'Contents.system'), 'Query result': result, 'Output': output})
        except Exception as ex:
            res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                        "Contents": "Error occurred while parsing output from command. "
                                    "Exception info:\n" + str(ex) + "\n\nInvalid output:\n" + str(resSSH)})
        demisto.setContext('CheckpointBackup', devicesBackupStarted)
        res.append({"Type": entryTypes["note"], "ContentsFormat": formats["table"], "Contents": tbl})
    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
