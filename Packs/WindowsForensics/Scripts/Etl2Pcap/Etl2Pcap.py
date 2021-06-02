import subprocess
import uuid

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def etl_to_pcap(etl_file_path, output_file_path):
    etl_file_path = os.path.abspath("./" + etl_file_path)
    output_file_path = os.path.abspath("./" + output_file_path)
    cmd = ["python", "/var/opt/etl/etl2pcap.py", etl_file_path, output_file_path]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.communicate()


def get_file_name(entry_id):
    ctx = demisto.context()
    res = demisto.dt(ctx, "File(val['EntryID'] == '%s')" % entry_id)
    if res:
        if type(res) is list:
            res = res[0]
        return os.path.splitext(res.get('Name', ''))[0]


def main():
    entry_id = demisto.args()['EntryID']
    res = demisto.getFilePath(entry_id)
    if not res or res.get('path') is None:
        return_error("Cannot find file path for entry ID: " + entry_id)
    etl_file_path = res.get('path')
    output_file_name = get_file_name(entry_id)
    if output_file_name is None:
        output_file_name = str(uuid.uuid4())
    output_file_path = output_file_name + '.pcap'
    etl_to_pcap(etl_file_path, output_file_path)
    with open(output_file_path, 'rb') as f:
        entry = fileResult(output_file_path, f.read())
        entry['EntryContext'] = {
            'EtlToPcap': {
                'NewFileName': output_file_path,
            }
        }
        demisto.results(entry)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
