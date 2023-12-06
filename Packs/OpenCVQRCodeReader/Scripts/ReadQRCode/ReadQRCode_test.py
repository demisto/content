import pytest
import demistomock as demisto
from CommonServerPython import *


def test_extract_info_from_qr_code(mocker):

    from ReadQRCode import extract_info_from_qr_code

    mocker.patch.object(
        demisto, 'getFilePath', return_value={'path': 'test_data/qr_code.png'},
    )
    mocker.patch.object(
        demisto, 'executeCommand', return_value=[{'Content': {'Domain': 'xsoar.pan.dev'}}],
    )

    result = extract_info_from_qr_code('entry_id')

    assert result.outputs_prefix == 'OpenCVQRCodeReader'
    assert result.outputs == {'text': 'https://xsoar.pan.dev/', 'Domain': 'xsoar.pan.dev'}
    assert result.readable_output == '### QR Code Read\n|Text|\n|---|\n| https://xsoar.pan.dev/ |\n'


def test_with_non_qr_code_file(mocker):

    from ReadQRCode import extract_info_from_qr_code

    mocker.patch.object(
        demisto, 'getFilePath', return_value={'path': 'test_data/not_a_qr_code.png'},
    )

    with pytest.raises(DemistoException, match='Could not extract text from file. Make sure the file contains a valid QR code.'):
        extract_info_from_qr_code('entry_id')


def test_with_non_image_file(mocker):

    from ReadQRCode import extract_info_from_qr_code

    mocker.patch.object(
        demisto, 'getFilePath', return_value={'path': 'test_data/text.txt'},
    )

    with pytest.raises(DemistoException, match='Error parsing file. Please make sure it is a valid image file'):
        extract_info_from_qr_code('entry_id')
