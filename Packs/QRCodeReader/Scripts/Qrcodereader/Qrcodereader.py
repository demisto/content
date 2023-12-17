import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import cv2


def detect_qrcode_image(path):

    img = cv2.imread(path)  # pylint: disable=no-member
    detect = cv2.QRCodeDetector()  # pylint: disable=no-member
    c, v = detect.detectAndDecodeMulti(img)[0:2]

    if c:
        result = {"Detected": True, "Value": str(v)}
    else:
        result = {"Detected": False}

    return CommandResults(
        outputs_prefix="QR.Data",
        outputs=result
    )


def main():
    try:
        entry_id = demisto.args().get('entry_id')
        file_path = demisto.executeCommand("getFilePath", {
            "id": entry_id
        })[0].get('Contents').get('path')
        return_results(detect_qrcode_image(file_path))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute qrcodereader. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
