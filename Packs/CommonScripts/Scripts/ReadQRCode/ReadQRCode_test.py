import pytest
import demistomock as demisto
from CommonServerPython import *
from pytest_mock import MockerFixture


def test_extract_info_from_qr_code(mocker: MockerFixture):
    """
    Given:
        A QR code image file.

    When:
        - Calling the ReadQRCode script.

    Then:
        Extract the text of the QR code and get indicators from it.
    """
    from ReadQRCode import extract_info_from_qr_code

    mocker.patch.object(
        demisto, 'getFilePath', return_value={'path': 'test_data/qr_code.png'},
    )
    mocker.patch.object(
        demisto, 'executeCommand', return_value=[{"Contents": '{"Domain": "xsoar.pan.dev"}'}],
    )

    result = extract_info_from_qr_code('entry_id')

    assert result.outputs_prefix == 'QRCodeReader'
    assert result.outputs == {'Text': 'https://xsoar.pan.dev/', 'Domain': 'xsoar.pan.dev'}
    assert result.readable_output == '### QR Code Read\n|Text|\n|---|\n| https://xsoar.pan.dev/ |\n'


def test_with_non_qr_code_file(mocker: MockerFixture):
    """
    Given:
        An image file that does not contain a QR code.

    When:
        - Calling the ReadQRCode script.

    Then:
        Return a message that no QR code was found.
    """
    from ReadQRCode import extract_info_from_qr_code

    mocker.patch.object(
        demisto, 'getFilePath', return_value={'path': 'test_data/not_a_qr_code.png'},
    )

    result = extract_info_from_qr_code('entry_id')

    assert result.readable_output == 'No QR code was found in the image.'


def test_with_non_image_file(mocker: MockerFixture):
    """
    Given:
        A file that is not an image.

    When:
        - Calling the ReadQRCode script.

    Then:
        Return an informative error.
    """
    from ReadQRCode import extract_info_from_qr_code

    mocker.patch.object(
        demisto, 'getFilePath', return_value={'path': 'test_data/text.txt'},
    )

    with pytest.raises(DemistoException, match='Error parsing file. Please make sure it is a valid image file.'):
        extract_info_from_qr_code('entry_id')


def test_read_qr_code_with_pyzbar(mocker: MockerFixture):
    """
    Given:
        A file that cannot be decoded with cv2.

    When:
        - Calling the ReadQRCode script.

    Then:
        Decode the image with pyzbar.
    """
    from ReadQRCode import read_qr_code

    debug = mocker.patch.object(demisto, 'debug')

    # result = read_qr_code('test_data/pyzbar_code_1.png')
    result = read_qr_code('test_data/multiple_codes.png')

    # debug.assert_called_with("Couldn't extract text with cv2, retrying with pyzbar.")
    assert result == 'https://xsoar.pan.dev/'
