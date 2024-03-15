import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa
from pyzbar import pyzbar
import cv2
from wurlitzer import pipes
# pylint: disable=E1101  # disable pylint not recognizing cv2's attributes.


def read_qr_code(filename: str) -> list:

    debug_messages = []  # don't use demisto.debug under the context manager.
    with pipes() as (out, _):
        img = cv2.imread(filename)
        text = [d.data.decode() for d in pyzbar.decode(img)]

        if not text:
            debug_messages.append("Couldn't extract text with pyzbar, retrying with cv2.")
            detect = cv2.QRCodeDetector()
            text, *_ = detect.detectAndDecode(img)

        debug_messages.append(f'stdout: {out.read()}')

    demisto.debug('\n'.join(debug_messages))
    return text if isinstance(text, list) else [text]


def extract_indicators_from_text(text: list) -> dict:
    return json.loads(demisto.executeCommand(
        'extractIndicators', {'text': text}
    )[0]['Contents'])  # type: ignore


def extract_info_from_qr_code(entry_id: str) -> CommandResults:

    try:
        filename = demisto.getFilePath(entry_id)['path']
        text = read_qr_code(filename)
        if not any(text):
            return CommandResults(readable_output='No QR code was found in the image.')
        indicators = extract_indicators_from_text(text)
    except (cv2.error, TypeError) as e:  # generic error raised by cv2
        raise DemistoException('Error parsing file. Please make sure it is a valid image file.') from e
    except ValueError:  # raised by demisto.getFilePath when the entry_id is not found
        raise DemistoException(f'Invalid entry ID: {entry_id=}')

    return CommandResults(
        outputs_prefix='QRCodeReader',
        outputs=({'Text': text} | indicators),
        readable_output=tableToMarkdown(
            'QR Code Read', {'Text': text}
        ),
    )


def main():
    try:
        return_results(extract_info_from_qr_code(demisto.args()['entry_id']))
    except Exception as e:
        return_error(f'Failed to execute ReadQRCode. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
