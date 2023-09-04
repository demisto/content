import json

from DetectAndDecodeBarcode import detect_and_decode_barcode

CWD = "./test_data"


def read_file(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def util_load(path):
    return json.loads(read_file(path))


def test_not_image_file():
    """
    Given:
        - a file that is not an image
    When:
        - running the script on the file
    Then:
        - script will report file is not an image
    """
    result = detect_and_decode_barcode(f"{CWD}/test_not_image_file.png")

    assert result == util_load(f"{CWD}/test_not_image_file.json")


def test_triple_qrcode():
    """
    Given:
        - a file with three QR codes
    When:
        - running the script on the file
    Then:
        - script will decode the three QR codes
    """
    result = detect_and_decode_barcode(f"{CWD}/test_triple_qrcode.png")

    assert result == util_load(f"{CWD}/test_triple_qrcode.json")


def test_url_qrcode():
    """
    Given:
        - a file with a URL in the QR code
    When:
        - running the script on the file
    Then:
        - script will decode the QR code
    """
    result = detect_and_decode_barcode(f"{CWD}/test_url_qrcode.png")

    assert result == util_load(f"{CWD}/test_url_qrcode.json")


def test_code128():
    """
    Given:
        - a file with barcodes
    When:
        - running the script on the file
    Then:
        - script will decode the barcodes
    """
    result = detect_and_decode_barcode(f"{CWD}/test_code128.png")

    assert result == util_load(f"{CWD}/test_code128.json")
