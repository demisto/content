from datetime import datetime, timedelta

import cv2
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from unifi_video import UnifiVideoAPI

#import dateutil.parser
# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    uva = UnifiVideoAPI(api_key=demisto.params()["api_key"], addr=demisto.params()["addr"], port=demisto.params()[
                        "port"], schema=demisto.params()["schema"], verify_cert=demisto.params()["verify_cert"])
    demisto.results('ok')
    sys.exit(0)

if demisto.command() == 'get_camera_list':
    uva = UnifiVideoAPI(api_key=demisto.params()["api_key"], addr=demisto.params()["addr"], port=demisto.params()[
                        "port"], schema=demisto.params()["schema"], verify_cert=demisto.params()["verify_cert"])
    output = ''
    for camera in uva.cameras:
        output = output + ' - ' + camera.name + '\n'
    demisto.results({"ContentsFormat": formats["markdown"], "Type": entryTypes["note"], "Contents": output})
    sys.exit(0)

if demisto.command() == 'get_snapshot':
    uva = UnifiVideoAPI(api_key=demisto.params()["api_key"], addr=demisto.params()["addr"], port=demisto.params()[
                        "port"], schema=demisto.params()["schema"], verify_cert=demisto.params()["verify_cert"])
    uva.get_camera(demisto.args()["camera_name"]).snapshot("/tmp/snapshot.png")
    r_type = demisto.args().get('type', 'png')
    f = open("/tmp/snapshot.png", "r")
    output = f.read()
    filename = "snapshot.png"
    file = fileResult(filename=filename, data=output)
    if r_type == 'png':
        file['Type'] = entryTypes['image']
    demisto.results(file)
    sys.exit(0)

if demisto.command() == 'set_recording_settings':
    uva = UnifiVideoAPI(api_key=demisto.params()["api_key"], addr=demisto.params()["addr"], port=demisto.params()[
                        "port"], schema=demisto.params()["schema"], verify_cert=demisto.params()["verify_cert"])
    uva.get_camera(demisto.args()["camera_name"]).set_recording_settings(demisto.args()["rec_set"])
    sys.exit(0)

if demisto.command() == 'ir_leds':
    uva = UnifiVideoAPI(api_key=demisto.params()["api_key"], addr=demisto.params()["addr"], port=demisto.params()[
                        "port"], schema=demisto.params()["schema"], verify_cert=demisto.params()["verify_cert"])
    uva.get_camera(demisto.args()["camera_name"]).ir_leds(demisto.args()["ir_leds"])
    sys.exit(0)

if demisto.command() == 'get_recording':
    uva = UnifiVideoAPI(api_key=demisto.params()["api_key"], addr=demisto.params()["addr"],
                        port=demisto.params()["port"], schema=demisto.params()["schema"],
                        verify_cert=demisto.params()["verify_cert"])
    uva.recordings[demisto.args()["recording_id"]].download('/tmp/recording.mp4')
    r_type = demisto.args().get('type', 'png')
    f = open("/tmp/recording.mp4", "r")
    output = f.read()
    filename = "recording.mp4"
    file = fileResult(filename=filename, data=output)
    if r_type == 'mp4':
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
        if r_type == 'jpg':
            file['Type'] = entryTypes['image']
        demisto.results(file)
    sys.exit(0)

if demisto.command() == 'get_recording_snapshot':
    uva = UnifiVideoAPI(api_key=demisto.params()["api_key"], addr=demisto.params()["addr"],
                        port=demisto.params()["port"], schema=demisto.params()["schema"],
                        verify_cert=demisto.params()["verify_cert"])
    uva.recordings[demisto.args()["recording_id"]].download('/tmp/recording.mp4')
    r_type = demisto.args().get('type', 'png')
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
        if r_type == 'jpg':
            file['Type'] = entryTypes['image']
        demisto.results(file)
    sys.exit(0)

if demisto.command() == 'get_recording_list':
    uva = UnifiVideoAPI(api_key=demisto.params()["api_key"], addr=demisto.params()["addr"],
                        port=demisto.params()["port"], schema=demisto.params()["schema"],
                        verify_cert=demisto.params()["verify_cert"])
    for rec in uva.recordings:
        print(rec)
    sys.exit(0)

if demisto.command() == 'create_inc':
    lastRun = demisto.getLastRun()
    print(lastRun)
    sys.exit(0)

if demisto.command() == 'get_snapshot_at_frame':
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
    sys.exit(0)

if demisto.command() == 'fetch-incidents':
    start_time_of_int = str(datetime.now())
    uva = UnifiVideoAPI(api_key=demisto.params()["api_key"], addr=demisto.params()["addr"], port=demisto.params()[
                        "port"], schema=demisto.params()["schema"], verify_cert=demisto.params()["verify_cert"])

    # And retrieve it for use later:
    last_run = demisto.getLastRun()
    # lastRun is a dictionary, with value "now" for key "time".
    # JSON of the incident type created by this integration
    inc = []
    day_ago = datetime.now() - timedelta(days=1)
    start_time = day_ago
    if last_run and last_run.has_key('start_time'):
        start_time = last_run.get('start_time')
    for rec in uva.recordings:
        incident = {}
        datetime_object = datetime.strptime(str(rec.start_time), '%Y-%m-%d %H:%M:%S')
        for camera in uva.cameras:
            cam_id = uva.get_camera(camera.name)
            if cam_id._id in rec.cameras:
                camera_name = camera.name

        incident = {
            'name': rec.rec_type,
            'occurred': datetime_object.isoformat() + "Z",
            'rawJSON': json.dumps({"event": rec.rec_type, "ubnt_id": rec._id, "camera_name": camera_name, "integration_lastrun": str(start_time), "start_time": str(rec.start_time), "stop_time": str(rec.end_time)})
        }
        try:
            if not isinstance(start_time, datetime):
                start_time = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S.%f')
            if datetime_object > start_time:
                inc.append(incident)
        except Exception as e:
            raise Exception("Problem comparing: " + str(datetime_object) + ' ' + str(start_time) + " Exception: " + str(e))
    demisto.incidents(inc)
    demisto.setLastRun({'start_time': start_time_of_int})
    sys.exit(0)
# You can use demisto.args()[argName] to get a specific arg. args are strings.
# You can use demisto.params()[paramName] to get a specific params.
# Params are of the type given in the integration page creation.

# if demisto.command() == 'long-running-execution':
#  # Should have here an endless loop
