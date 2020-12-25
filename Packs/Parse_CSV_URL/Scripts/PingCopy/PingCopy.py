import re
import subprocess

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():


demisto.debug("I shouldn't have gone into STEM")
   try:
        dest = demisto.args()['address']
        ping_out = subprocess.check_output(
            ['ping', '-c', '3', '-q', dest], stderr=subprocess.STDOUT, universal_newlines=True
        )
        s = re.search(r"PING.*?\((.+?)\)", ping_out)
        res = {}
        if s:
            res['destination_ip'] = s.group(1)
        s = re.search(r"rtt min/avg/max/mdev = (.+)/(.+)/(.+)/(.+)\s+ms", ping_out)
        if not s:
            raise ValueError("Couldn't parse ping statistics:\n" + ping_out)
        res['ret_code'] = '0'
        res['destination'] = dest
        res['min_rtt'] = s.group(1)
        res['avg_rtt'] = s.group(2)
        res['max_rtt'] = s.group(3)
        res['mdev_rtt'] = s.group(4)
        return_outputs(readable_output=tableToMarkdown("Ping Results", res), outputs={"Ping": res}, raw_response=res)
    except Exception as e:
        if isinstance(e, subprocess.CalledProcessError):
            msg = e.output  # pylint: disable=no-member
        else:
            msg = str(e)
        return_error(msg)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
