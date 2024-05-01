import demistomock as demisto
from CommonServerPython import *
import subprocess
import re


def main():
    try:
        # context = demisto.context()
        # version = demisto.demistoVersion()
        # calling_context = demisto.callingContext
        # urls = demisto.demistoUrls()
        # demisto.log(f'{context.get("context")=}')
        # demisto.log(f'{version=}')
        # demisto.log(f'{calling_context=}')
        # demisto.log(f'{urls=}')
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
        demisto.debug(f'{msg=}')
        if not is_xsoar_on_prem() and "ping: socket: Operation not permitted" in msg:
            msg = "The Ping script can be executed only on custom engines"
        return_error(msg)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
