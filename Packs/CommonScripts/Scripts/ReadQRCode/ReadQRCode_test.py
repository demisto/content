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
        demisto, 'executeCommand', return_value=[{
            'Contents': '{"Domain": "xsoar.pan.dev"}',
            'Type': EntryType.NOTE
        }],
    )

    result = extract_info_from_qr_code('entry_id')

    assert result.outputs_prefix == 'QRCodeReader'
    assert result.outputs == {'Text': ['https://xsoar.pan.dev/'], 'Domain': 'xsoar.pan.dev'}
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


def test_read_qr_code_multiple_codes():
    """
    Given:
        An image that has multiple QR codes.

    When:
        - Calling the ReadQRCode script.

    Then:
        Return the result of all images.
    """
    from ReadQRCode import read_qr_code

    result = read_qr_code('test_data/multiple_codes.png')

    assert result == [
        'http://itunes.apple.com/us/app/encyclopaedia-britannica/id447919187?mt=8',
        'http://searchmobilecomputing.techtarget.com/definition/2D-barcode',
        'https://www.linkedin.com/company/1334758?trk=NUS_CMPY_TWIT',
        'http://en.m.wikipedia.org'
    ]


def test_extract_indicators_from_text(mocker: MockerFixture):
    """
    Given:
        The extractIndicators script returns an error.

    When:
        - Calling the extractIndicators script on the extracted text.

    Then:
        Debug the error and continue.
    """
    from ReadQRCode import extract_indicators_from_text

    debug_func = mocker.patch.object(demisto, 'debug')
    mocker.patch.object(
        demisto, 'executeCommand', return_value=[{
            'Contents': 'Error message',
            'Type': EntryType.ERROR
        }],
    )

    res = extract_indicators_from_text(['a', 'b'])

    assert res == {}
    debug_func.assert_called_once_with('Error in "extractIndicators": Error message')
