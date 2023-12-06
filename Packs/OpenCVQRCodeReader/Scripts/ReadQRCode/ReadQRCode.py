import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa
import cv2


def read_qr_code(filename: str) -> str:

    detect = cv2.QRCodeDetector()
    img = cv2.imread(filename)
    text, *_ = detect.detectAndDecode(img)
    if not text:
        raise DemistoException('Could not extract text from file. Make sure the file contains a valid QR code.')
    return text


def extract_indicators_from_text(text: str) -> dict:

    return json.loads(demisto.executeCommand(
        'extractIndicators',
        {'text': text}
    )[0]['Contents'])


def extract_info_from_qr_code(entry_id: str) -> CommandResults:

    try:
        filename = demisto.getFilePath(entry_id)['path']
        text = read_qr_code(filename)
        indicators = extract_indicators_from_text(text)
    except cv2.error as e:  # generic error raised by cv2
        raise DemistoException('Error parsing file. Please make sure it is a valid image file') from e
    except ValueError:  # raised by demisto.getFilePath when the entry_id is not found
        raise DemistoException(f'Invalid entry ID: {entry_id=}')

    return CommandResults(
        outputs_prefix='OpenCVQRCodeReader',
        outputs=({'text': text} | indicators),
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
