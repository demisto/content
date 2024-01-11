import pytest
import demistomock as demisto
from CommonServerPython import *


def test_extract_info_from_qr_code(mocker):
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


def test_with_non_qr_code_file(mocker):
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


def test_with_non_image_file(mocker):
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
