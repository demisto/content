from datetime import datetime, timedelta

import cv2
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from unifi_video import UnifiVideoAPI
import json

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
    context_output = []
    for camera in uva.cameras:
        context_output.append(camera.name)
    results = [
        CommandResults(
            outputs_prefix='UnifiVideo.Cameras',
            readable_output=tableToMarkdown("Camera list", context_output, headers=["Camera name"], removeNull=False),
            outputs=context_output
        )]
    return_results(results)

if demisto.command() == 'unifivideo-get-snapshot':
    camera_name = args.get('camera_name')
    output = bytes()
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    uva.get_camera(camera_name).snapshot("/tmp/snapshot.png")
    f = open("/tmp/snapshot.png", "rb")
    output = f.read()
    filename = "snapshot.png"
    file = fileResult(filename=filename, data=output)
    file['Type'] = entryTypes['image']
    demisto.results(file)

if demisto.command() == 'unifivideo-set-recording-settings':
    camera_name = args.get('camera_name')
    rec_set = args.get('rec_set')
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    uva.get_camera(camera_name).set_recording_settings(rec_set)
    demisto.results(camera_name + ": " + rec_set)

if demisto.command() == 'unifivideo-ir-leds':
    camera_name = args.get('camera_name')
    ir_leds = args.get('ir_leds')
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    uva.get_camera(camera_name).ir_leds(ir_leds)
    demisto.results(camera_name + ": " + ir_leds)

if demisto.command() == 'unifivideo-get-recording':
    recording_id = args.get('recording_id')
    recording_file_name = 'recording-' + recording_id + '.mp4'
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    for rec in uva.get_recordings():
        if rec._id == recording_id:
            rec.download('/tmp/recording.mp4')
    f = open("/tmp/recording.mp4", "rb")
    output = f.read()
    filename = recording_file_name
    file = fileResult(filename=filename, data=output)
    file['Type'] = entryTypes['file']
    demisto.results(file)

if demisto.command() == 'unifivideo-get-recording-snapshot':
    recording_id = args.get('recording_id')
    snapshot_file_name = 'snapshot-' + recording_id + '-' + args.get('frame') + '.jpg'
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    for rec in uva.get_recordings():
        if rec._id == recording_id:
            rec.download('/tmp/recording.mp4')
    if "frame" in args:
        vc = cv2.VideoCapture('/tmp/recording.mp4')  # pylint: disable=E1101
        c = 1

        if vc.isOpened():
            rval, frame = vc.read()
        else:
            rval = False

        while rval:
            rval, frame = vc.read()
            c = c + 1
            if c == int(args.get('frame')):
                cv2.imwrite("/tmp/" + snapshot_file_name, frame)  # pylint: disable=E1101
                break
        vc.release()
        f = open("/tmp/" + snapshot_file_name, "rb")
        output = f.read()
        filename = snapshot_file_name
        file = fileResult(filename=filename, data=output)
        file['Type'] = entryTypes['image']
        demisto.results(file)

if demisto.command() == 'unifivideo-get-recording-list':
    uva = UnifiVideoAPI(api_key=api_key, addr=address, port=port, schema=schema, verify_cert=verify_cert)
    recordings = []
    for rec in uva.get_recordings():
        rec_tmp = {}
        rec_tmp['id'] = rec._id
        rec_tmp['rec_type'] = rec.rec_type
        rec_tmp['start_time'] = rec.start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        rec_tmp['end_time'] = rec.start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        recordings.append(rec_tmp)
    results = [
        CommandResults(
            outputs_prefix='UnifiVideo.Recordings',
            readable_output=tableToMarkdown("Recording list", recordings, headers=["id", "rec_type", "start_time", "end_time"]),
            outputs_key_field=['id'],
            outputs=recordings
        )]
    return_results(results)

if demisto.command() == 'unifivideo-get-snapshot-at-frame':  # TOFIX
    vc = cv2.VideoCapture('recording.mp4')  # pylint: disable=E1101
    c = 1

    if vc.isOpened():
        rval, frame = vc.read()
    else:
        rval = False

    while rval:
        rval, frame = vc.read()
        c = c + 1
        if c == 500:
            cv2.imwrite(str(c) + '.jpg', frame)  # pylint: disable=E1101
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
    if last_run:
        start_time = last_run.get('start_time')
    if not isinstance(start_time, datetime):
        start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S.%f')
    for rec in uva.get_recordings():
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
