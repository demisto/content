import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import shutil

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

URL = "http://api.qrserver.com/"

''' FUNCTION '''


def read_qr_code(verify=True):
    entry_id = demisto.args().get("entry_id")
    file_path = demisto.getFilePath(entry_id)['path']
    file_name = demisto.getFilePath(entry_id)['name']

    try:
        shutil.copy(file_path, file_name)
    except Exception:
        raise Exception('Failed to prepare file for upload.')

    try:
        multipart_file = {'file': open(file_name, 'rb')}
        data = {'outputformat': 'json'}
        res = requests.post(URL + '/v1/read-qr-code/', data=data, files=multipart_file, verify=verify)
        if str(res.status_code) == "200":
            return res
        else:
            return_error(str(res.text))

    finally:
        shutil.rmtree(file_name, ignore_errors=True)


def test_qr_api(verify=True):
    res = requests.get(URL + "/v1/create-qr-code/?data=HelloWorld", verify)
    if str(res.status_code) == "200":
        return 'ok'
    else:
        return str(res.text)


''' MAIN FUNCTION '''


def main() -> None:

    verify_certificate = not demisto.params().get('insecure', False)

    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration Test button.
        result = test_qr_api(verify=verify_certificate)
        demisto.results(result)

    elif demisto.command() == 'goqr-read-qr-code-from-file':
        res = read_qr_code(verify=verify_certificate)
        demisto.results({
            "Contents": json.loads(res.text),
            "ContentsFormat": formats["markdown"],
            "Type": entryTypes["note"],
            "HumanReadable": tableToMarkdown("QR Reader", json.loads(res.text)[0]['symbol']),
            "EntryContext": {"GoQRCodeData": json.loads(res.text)[0]['symbol']}
        })


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
