import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import sys
from time import sleep
import re
import json

device = demisto.get(demisto.args(), 'device')
res = []

if not device:
    res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                "Contents": "Received empty device list!"})
    demisto.results(res)

try:
    demisto.info("Starting backup")
    creation_status = demisto.executeCommand('CheckpointFWCreateBackup', {'devices': device})
    creation_content = creation_status[0].get('Contents')

    if not isinstance(creation_content[0], dict):
        res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "Error before starting backup: " + creation_content + "\nHint: make"
                                " sure the device selected exists and is correctly configured"})
        demisto.results(res)
        sys.exit()

    output = str(creation_content[0].get('Output'))
    if 'Error' in output:
        res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "Failed creating the backup!" + output})
        demisto.results(res)
        sys.exit()

    current_status = ''
    while current_status.find('Local backup succeeded') == -1:

        status_entries = demisto.executeCommand('CheckpointFWBackupStatus',
                                                {'devices': device})

        content = status_entries[0]
        if content:
            content = json.dumps(content.get('Contents'))

        for entry in status_entries:
            current_status = str(demisto.get(entry, 'Contents'))

        if 'Progress' in current_status:
            percent_completed = re.findall(r'\d+%', current_status)[0]
            demisto.results('Current progress: ' + percent_completed)

        process_good = False
        for good_status in ['Progress', 'succeeded', 'Creating']:
            if good_status in current_status:
                process_good = True

        if not process_good:
            res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                        "Contents": "Failed while checking the backup status! " + current_status})
            demisto.results(res)
            sys.exit()
        sleep(30)

    demisto.info("Backup completed. Starting to download backup file to war room.")
    time_taken = re.findall(r'\d+:\d+', current_status)[0]
    demisto.results('Time taken to create backup: ' + time_taken)

    file_path = re.findall(r'/.*\.tgz', current_status)[0]

    file_status = demisto.executeCommand('copy-from', {'file': file_path,
                                                       'using': device,
                                                       'timeout': 60})
    demisto.info("File was downloaded to war room. File status:", file_status)
    demisto.results(file_status)

except Exception as exception:
    demisto.results(exception)
