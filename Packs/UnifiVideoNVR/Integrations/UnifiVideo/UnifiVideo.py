from datetime import datetime, timedelta

import cv2
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from unifi_video import UnifiVideoAPI

params = demisto.params()
args = demisto.args()
api_key = params.get('api_key')
address = params.get('addr')
port = params.get('port')
schema = params.get('schema')
verify_cert = params.get('verify_cert')

if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    demisto.results('ok')

if demisto.command() == 'unifivideo-get-camera-list':
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    output = ''
    for camera in uva.cameras:
        output = output + ' - ' + camera.name + '\n'
    demisto.results({"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": output})

if demisto.command() == 'unifivideo-get-snapshot':
    camera_name = args['camera_name']
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    uva.get_camera(camera_name).snapshot("/tmp/snapshot.png")
    f = open("/tmp/snapshot.png", "r")
    output = f.read()
    filename = "snapshot.png"
    file = fileResult(filename=filename, data=output)
    file['Type'] = entryTypes['image']
    demisto.results(file)

if demisto.command() == 'unifivideo-set-recording-settings':
    camera_name = args['camera_name']
    rec_set = args['rec_set']
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    uva.get_camera(camera_name).set_recording_settings(rec_set)

if demisto.command() == 'unifivideo-ir-leds':
    camera_name = args['camera_name']
    ir_leds = args['ir_leds']
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    uva.get_camera(camera_name).ir_leds(ir_leds)

if demisto.command() == 'unifivideo-get-recording':
    recording_id = args['recording_id']
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    uva.recordings[recording_id].download('/tmp/recording.mp4')
    f = open("/tmp/recording.mp4", "r")
    output = f.read()
    filename = "recording.mp4"
    file = fileResult(filename=filename, data=output)
    file['Type'] = entryTypes['video']
    demisto.results(file)
    if "frame" in demisto.args():
        vc = cv2.VideoCapture('/tmp/recording.mp4')
        c = 1

        if vc.isOpened():
            rval, frame = vc.read()
        else:
            rval = False

        while rval:
            rval, frame = vc.read()
            c = c + 1
            if c == int(demisto.args()['frame']):
                cv2.imwrite('/tmp/snapshot.jpg', frame)
                break
        vc.release()
        f = open("/tmp/snapshot.jpg", "r")
        output = f.read()
        filename = "snapshot.jpg"
        file = fileResult(filename=filename, data=output)
        file['Type'] = entryTypes['image']
        demisto.results(file)

if demisto.command() == 'unifivideo-get-recording-snapshot':
    recording_id = args['recording_id']
    snapshot_file_name = 'snapshot-' + recording_id + '-' + args['frame'] + '.jpg'
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    uva.recordings[recording_id].download('/tmp/recording.mp4')
    if "frame" in args:
        vc = cv2.VideoCapture('/tmp/recording.mp4')
        c = 1

        if vc.isOpened():
            rval, frame = vc.read()
        else:
            rval = False

        while rval:
            rval, frame = vc.read()
            c = c + 1
            if c == int(args['frame']):
                cv2.imwrite("/tmp/" + snapshot_file_name, frame)
                break
        vc.release()
        f = open("/tmp/" + snapshot_file_name, "r")
        output = f.read()
        filename = snapshot_file_name
        file = fileResult(filename=filename, data=output)
        file['Type'] = entryTypes['image']
        demisto.results(file)

if demisto.command() == 'unifivideo-get-recording-list':
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    for rec in uva.recordings:
        demisto.results(rec)

if demisto.command() == 'unifivideo-get-snapshot-at-frame':
    vc = cv2.VideoCapture('recording.mp4')
    c = 1

    if vc.isOpened():
        rval, frame = vc.read()
    else:
        rval = False

    while rval:
        rval, frame = vc.read()
        c = c + 1
        if c == 500:
            cv2.imwrite(str(c) + '.jpg', frame)
            break
    vc.release()

if demisto.command() == 'fetch-incidents':
    start_time_of_int = str(datetime.now())
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)

    # And retrieve it for use later:
    last_run = demisto.getLastRun()
    # lastRun is a dictionary, with value "now" for key "time".
    # JSON of the incident type created by this integration
    inc = []
    day_ago = datetime.now() - timedelta(days=1)
    start_time = day_ago
    if last_run and last_run.has_key('start_time'):
        start_time = last_run.get('start_time')
    if not isinstance(start_time, datetime):
        start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S.%f')
    for rec in uva.recordings:
        incident = {}
        datetime_object = datetime.strptime(str(rec.start_time), '%Y-%m-%d %H:%M:%S')
        for camera in uva.cameras:
            cam_id = uva.get_camera(camera.name)
            if cam_id._id in rec.cameras:
                camera_name = camera.name
        try:
            if datetime_object > start_time:
                incident = {
                    'name': rec.rec_type,
                    'occurred': datetime_object.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'rawJSON': json.dumps({"event": rec.rec_type, "ubnt_id": rec._id, "camera_name": camera_name,
                                           "integration_lastrun": str(start_time), "start_time": str(rec.start_time),
                                           "stop_time": str(rec.end_time)})
                }
                inc.append(incident)
        except Exception as e:
            raise Exception("Problem comparing: " + str(datetime_object) + ' ' + str(start_time) + " Exception: " + str(e))
    demisto.incidents(inc)
    demisto.setLastRun({'start_time': start_time_of_int})