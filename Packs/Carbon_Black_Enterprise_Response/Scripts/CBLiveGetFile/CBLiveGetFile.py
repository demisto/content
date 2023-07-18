import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import time


secTimeout = 120

# find sensor ID
if not demisto.get(demisto.args(), 'ip') and not demisto.get(demisto.args(), 'hostname'):
    demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                     'Contents': 'You must provide ip or hostname for Cb sensor.'})
    sys.exit()
else:
    dArgs = {'ip': demisto.args()['ip']} if demisto.get(demisto.args(), 'ip') else {
        'hostname': demisto.args()['hostname']}
    resFind = demisto.executeCommand('cb-sensor-info', dArgs)
    if isError(resFind[0]):
        demisto.results(resFind)
        sys.exit()
    else:
        matches = resFind[0]['Contents']
        if matches:
            if len(matches) == 1:
                sensorId = str(matches[0]['id'])
            else:
                demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                                 'Contents': 'More than one sensor returned.\nResult:\n' + str(matches)})
                sys.exit()
        else:
            demisto.results(
                {'Type': entryTypes['error'], 'ContentsFormat': formats['text'], 'Contents': 'Sensor not found.'})
            sys.exit()
demisto.debug('[*] Located sensor ID ' + sensorId)
# Get a live session to the endpoint
resSessions = demisto.executeCommand('cb-list-sessions', {})
if isError(resSessions[0]):
    demisto.results(resSessions)
    sys.exit()
else:
    existingSessions = [s for s in resSessions[0]['Contents'] if str(
        s['sensor_id']) == sensorId and s['status'] in ['pending', 'active']]
    if not existingSessions:
        resSessionCreate = demisto.executeCommand('cb-session-create', {'sensor': sensorId})
        if isError(resSessionCreate[0]):
            demisto.results(resSessionCreate + [{'Type': entryTypes['error'],
                                                 'ContentsFormat': formats['text'],
                                                 'Contents': 'Error while trying to create session.'}])
            sys.exit()
        else:
            sessionId = str(resSessionCreate[0]['Contents']['id'])
            demisto.debug('[*] Created session ' + sessionId + ' for sensor '
                          + sensorId + '. Waiting for session to become active.')
    else:
        es = existingSessions[0]
        demisto.debug('[*] Found existing %s session %d..' % (es['status'], es['id']))
        sessionId = str(es['id'])

    session = {'status': 'pending'}
    resSessionInfo = []
    while session['status'] == 'pending':
        resSessionInfo = demisto.executeCommand('cb-session-info', {'session': sessionId})
        if isError(resSessionInfo[0]):
            demisto.results(resSessionInfo + [{'Type': entryTypes['error'],
                                               'ContentsFormat': formats['text'],
                                               'Contents': 'Error while polling for session status.'}])
            sys.exit()
        else:
            session = resSessionInfo[0]['Contents']
        time.sleep(3)
    if not session['status'] == 'active':
        demisto.results(resSessionInfo + [{'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                                           'Contents': 'Finished polling but session is not in active state.'}])
        sys.exit()
    else:
        demisto.debug('[*] Session ' + sessionId + ' active.')

# Create async command
resCreate = demisto.executeCommand(
    'cb-command-create', {'session': sessionId, 'name': 'get file', 'object': demisto.args()['path']})

if not isError(resCreate[0]):
    if len(resCreate) == 1:
        # Get command id from response
        cmdID = demisto.get(resCreate[0], 'Contents.id')
    else:
        demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                         'Contents': 'Unexpected output returned from command-create.'})
        sys.exit(0)
else:
    demisto.results(resCreate)
    sys.exit(0)

# Poll for command completion
secRemaining = secTimeout
while secRemaining:
    resInfo = demisto.executeCommand('cb-command-info', {'session': sessionId, 'command': str(cmdID)})
    if not isError(resInfo[0]):
        if len(resInfo) == 1:
            status = demisto.get(resInfo[0], 'Contents.status')
            # If still working
            if 'pending' == status:
                secRemaining -= 1
                time.sleep(1)
            elif 'error' == status:
                content = 'Command "get file" returned error: [Type:' + \
                          str(demisto.get(resInfo[0], 'Contents.result_type')) + \
                          ' , Code:' + \
                          str(int(demisto.get(resInfo[0], 'Contents.result_code'))) + \
                          ' , Desc:' + \
                          str(demisto.get(resInfo[0], 'Contents.result_desc')) + \
                          ' ]'
                demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                                 'Contents': content})
                sys.exit(0)
            elif 'complete' == status:
                # Get FileID from command info response
                fileID = demisto.get(resInfo[0], 'Contents.file_id')
                resFileGet = demisto.executeCommand('cb-file-get', {'session': sessionId, 'file-id': str(fileID)})
                if not isError(resFileGet[0]):
                    if len(resFileGet) == 1:
                        demisto.results(resFileGet)
                        sys.exit(0)
                    else:
                        demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                                         'Contents': 'Unexpected output returned from file-get command.'})
                        sys.exit(0)
                else:
                    demisto.results(resFileGet)
                    sys.exit(0)
            else:
                demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                                 'Contents': 'Unexpected status "' + status + '" returned from command-info.'})
                sys.exit(0)
        else:
            demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                             'Contents': 'Unexpected output returned from command-create command.'})
            sys.exit(0)
    else:
        demisto.results(resInfo)
        sys.exit(0)

else:
    demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'],
                     'Contents': 'Command timed out after %d seconds' % secTimeout})
    sys.exit(0)
