import subprocess

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401


def lineNotifyMessage(linetoken, msg):
    headers = {
        "Authorization": "Bearer " + linetoken,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    payload = {'message': msg}
    r = requests.post("https://notify-api.line.me/api/notify", headers=headers, params=payload)
    return r.status_code


def main():
    try:
        linetoken = demisto.args()['token']
        msg = demisto.args()['msg']
        lineNotifyMessage(linetoken, msg)
    except Exception as e:
        if isinstance(e, subprocess.CalledProcessError):
            msg = e.output  # pylint: disable=no-member
        else:
            msg = str(e)
        return_error(msg)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
