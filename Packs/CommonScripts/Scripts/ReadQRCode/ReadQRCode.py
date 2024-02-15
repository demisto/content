import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa
import cv2

# pylint: disable=E1101  # disable pylint not recognizing cv2's attributes.


def read_qr_code(filename: str) -> str:

    detect = cv2.QRCodeDetector()
    img = cv2.imread(filename)
    text, *rest = detect.detectAndDecode(img)
    demisto.debug(f'QR code matrices: {rest}')
    return text


def extract_indicators_from_text(text: str) -> dict:

    return json.loads(demisto.executeCommand(
        'extractIndicators',
        {'text': text}
    )[0]['Contents'])


def extract_info_from_qr_code(entry_id: str, **_) -> CommandResults:

    try:
        filename = demisto.getFilePath(entry_id)['path']
        text = read_qr_code(filename)
        if not text:
            return CommandResults(readable_output='No QR code was found in the image.')
        indicators = extract_indicators_from_text(text)
    except cv2.error as e:  # generic error raised by cv2
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
        return_results(extract_info_from_qr_code(**demisto.args()))
    except Exception as e:
        return_error(f'Failed to execute ReadQRCode. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
