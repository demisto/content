import demistomock as demisto  # noqa
from CommonServerPython import *  # noqa
from typing import IO
from pyzbar import pyzbar
import cv2
import tempfile
# pylint: disable=E1101  # disable pylint not recognizing cv2's attributes.


class StderrRedirect:
    '''Context manager to redirect stderr.'''
    temp_stderr: IO
    old_stderr: int

    def __enter__(self):
        demisto.debug('entering StderrRedirect')
        self.temp_stderr = tempfile.TemporaryFile()
        self.old_stderr = os.dup(sys.stderr.fileno())  # make a copy of stderr
        os.dup2(self.temp_stderr.fileno(), sys.stderr.fileno())  # redirect stderr to the temporary file

    def __exit__(self, exc_type, exc_value, exc_traceback):
        demisto.debug(f'exiting StderrRedirect: {exc_type=}, {exc_value=}, {exc_traceback=}')
        self.temp_stderr.seek(0)
        demisto.debug(f'stderr: {self.temp_stderr.read()}')
        os.dup2(self.old_stderr, sys.stderr.fileno())  # restore stderr
        os.close(self.old_stderr)
        self.temp_stderr.close()


def read_qr_code(filename: str) -> list:

    with StderrRedirect():  # redirect stderr to catch cv2 warnings which are sent directly to stderr

        img = cv2.imread(filename)
        demisto.debug(f'loaded file: {filename}')
        text = [d.data.decode() for d in pyzbar.decode(img, symbols=[pyzbar.ZBarSymbol.QRCODE])]
        demisto.debug(f'pybar decode: {text}')

        if not text:
            demisto.debug("Couldn't extract text with pyzbar, retrying with cv2.")
            text = [cv2.QRCodeDetector().detectAndDecode(img)[0]]

    return text


def extract_indicators_from_text(text: list) -> dict:
    res = demisto.executeCommand('extractIndicators', {'text': text})
    if is_error(res):
        demisto.debug(f'Error in "extractIndicators": {get_error(res)}')
        return {}
    return json.loads(res[0]['Contents'])  # type: ignore


def extract_info_from_qr_code(entry_id: str) -> CommandResults:

    try:
        filename = demisto.getFilePath(entry_id)['path']
        text = read_qr_code(filename)
        if not any(text):
            return CommandResults(readable_output='No QR code was found in the image.')
        indicators = extract_indicators_from_text(text)
    except (cv2.error, TypeError) as e:  # generic error raised by cv2
        raise DemistoException('Error parsing file. Please make sure it is a valid image file.') from e
    except ValueError as e:  # raised by demisto.getFilePath when the entry_id is not found
        demisto.debug(f'ValueError: {e}, {e.args}')
        raise DemistoException(f'Invalid entry ID: {entry_id=}') from e
    return CommandResults(
        outputs_prefix='QRCodeReader',
        outputs=({'Text': text} | indicators),
        readable_output=tableToMarkdown(
            'QR Code Read', {'Text': text}
        )
    )


def main():
    try:
        return_results(extract_info_from_qr_code(demisto.args()['entry_id']))
    except Exception as e:
        return_error(f'Failed to execute ReadQRCode. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
