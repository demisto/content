import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import pytest
from BMCTool import BMCContainer


@pytest.mark.parametrize("container, expected_size",
                         [
                             (BMCContainer.BMC_CONTAINER, 0x14),
                             (BMCContainer.BIN_CONTAINER, 0xC)
                         ]
                         )
def test_tile_header_size(container, expected_size):
    """
    Given:
        - BMCContainer object
    When:
        - Calling the TILE_HEADER_SIZE property
    Then:
        - Ensure that the TILE_HEADER_SIZE is set as expected
    """
    assert BMCContainer.TILE_HEADER_SIZE[container] == expected_size


def test_palette_length():
    assert len(BMCContainer.PALETTE) == 1024


def test_palette_colors():
    """
    Given:
        - BMCContainer object
    When:
        - Calling the PALETTE property
    Then:
        - Ensure that the PALETTE is as expected
    """
    assert bytes(bytearray((
        0, 0, 0, 0, 0, 0, 128, 0, 0, 128, 0, 0, 0, 128, 128, 0, 128, 0, 0, 0, 128, 0, 128, 0, 128,
        128, 0, 0, 192, 192, 192, 0, 192, 220, 192, 0, 240, 202, 166, 0, 0, 32, 64, 0, 0, 32, 96,
        0, 0, 32, 128, 0, 0, 32, 160, 0, 0, 32, 192, 0, 0, 32, 224, 0, 0, 64, 0, 0, 0, 64, 32, 0,
        0, 64, 64, 0, 0, 64, 96, 0, 0, 64, 128, 0, 0, 64, 160, 0, 0, 64, 192, 0, 0, 64, 224, 0, 0,
        96, 0, 0, 0, 96, 32, 0, 0, 96, 64, 0, 0, 96, 96, 0, 0, 96, 128, 0, 0, 96, 160, 0, 0, 96,
        192, 0, 0, 96, 224, 0, 0, 128, 0, 0, 0, 128, 32, 0, 0, 128, 64, 0, 0, 128, 96, 0, 0, 128,
        128, 0, 0, 128, 160, 0, 0, 128, 192, 0, 0, 128, 224, 0, 0, 160, 0, 0, 0, 160, 32, 0, 0,
        160, 64, 0, 0, 160, 96, 0, 0, 160, 128, 0, 0, 160, 160, 0, 0, 160, 192, 0, 0, 160, 224, 0,
        0, 192, 0, 0, 0, 192, 32, 0, 0, 192, 64, 0, 0, 192, 96, 0, 0, 192, 128, 0, 0, 192, 160, 0,
        0, 192, 192, 0, 0, 192, 224, 0, 0, 224, 0, 0, 0, 224, 32, 0, 0, 224, 64, 0, 0, 224, 96, 0,
        0, 224, 128, 0, 0, 224, 160, 0, 0, 224, 192, 0, 0, 224, 224, 0, 64, 0, 0, 0, 64, 0, 32, 0,
        64, 0, 64, 0, 64, 0, 96, 0, 64, 0, 128, 0, 64, 0, 160, 0, 64, 0, 192, 0, 64, 0, 224, 0,
        64, 32, 0, 0, 64, 32, 32, 0, 64, 32, 64, 0, 64, 32, 96, 0, 64, 32, 128, 0, 64, 32, 160, 0,
        64, 32, 192, 0, 64, 32, 224, 0, 64, 64, 0, 0, 64, 64, 32, 0, 64, 64, 64, 0, 64, 64, 96, 0,
        64, 64, 128, 0, 64, 64, 160, 0, 64, 64, 192, 0, 64, 64, 224, 0, 64, 96, 0, 0, 64, 96, 32,
        0, 64, 96, 64, 0, 64, 96, 96, 0, 64, 96, 128, 0, 64, 96, 160, 0, 64, 96, 192, 0, 64, 96,
        224, 0, 64, 128, 0, 0, 64, 128, 32, 0, 64, 128, 64, 0, 64, 128, 96, 0, 64, 128, 128, 0,
        64, 128, 160, 0, 64, 128, 192, 0, 64, 128, 224, 0, 64, 160, 0, 0, 64, 160, 32, 0, 64, 160,
        64, 0, 64, 160, 96, 0, 64, 160, 128, 0, 64, 160, 160, 0, 64, 160, 192, 0, 64, 160, 224, 0,
        64, 192, 0, 0, 64, 192, 32, 0, 64, 192, 64, 0, 64, 192, 96, 0, 64, 192, 128, 0, 64, 192,
        160, 0, 64, 192, 192, 0, 64, 192, 224, 0, 64, 224, 0, 0, 64, 224, 32, 0, 64, 224, 64, 0,
        64, 224, 96, 0, 64, 224, 128, 0, 64, 224, 160, 0, 64, 224, 192, 0, 64, 224, 224, 0, 128,
        0, 0, 0, 128, 0, 32, 0, 128, 0, 64, 0, 128, 0, 96, 0, 128, 0, 128, 0, 128, 0, 160, 0, 128,
        0, 192, 0, 128, 0, 224, 0, 128, 32, 0, 0, 128, 32, 32, 0, 128, 32, 64, 0, 128, 32, 96, 0,
        128, 32, 128, 0, 128, 32, 160, 0, 128, 32, 192, 0, 128, 32, 224, 0, 128, 64, 0, 0, 128,
        64, 32, 0, 128, 64, 64, 0, 128, 64, 96, 0, 128, 64, 128, 0, 128, 64, 160, 0, 128, 64, 192,
        0, 128, 64, 224, 0, 128, 96, 0, 0, 128, 96, 32, 0, 128, 96, 64, 0, 128, 96, 96, 0, 128,
        96, 128, 0, 128, 96, 160, 0, 128, 96, 192, 0, 128, 96, 224, 0, 128, 128, 0, 0, 128, 128,
        32, 0, 128, 128, 64, 0, 128, 128, 96, 0, 128, 128, 128, 0, 128, 128, 160, 0, 128, 128,
        192, 0, 128, 128, 224, 0, 128, 160, 0, 0, 128, 160, 32, 0, 128, 160, 64, 0, 128, 160, 96,
        0, 128, 160, 128, 0, 128, 160, 160, 0, 128, 160, 192, 0, 128, 160, 224, 0, 128, 192, 0, 0,
        128, 192, 32, 0, 128, 192, 64, 0, 128, 192, 96, 0, 128, 192, 128, 0, 128, 192, 160, 0,
        128, 192, 192, 0, 128, 192, 224, 0, 128, 224, 0, 0, 128, 224, 32, 0, 128, 224, 64, 0, 128,
        224, 96, 0, 128, 224, 128, 0, 128, 224, 160, 0, 128, 224, 192, 0, 128, 224, 224, 0, 192,
        0, 0, 0, 192, 0, 32, 0, 192, 0, 64, 0, 192, 0, 96, 0, 192, 0, 128, 0, 192, 0, 160, 0, 192,
        0, 192, 0, 192, 0, 224, 0, 192, 32, 0, 0, 192, 32, 32, 0, 192, 32, 64, 0, 192, 32, 96, 0,
        192, 32, 128, 0, 192, 32, 160, 0, 192, 32, 192, 0, 192, 32, 224, 0, 192, 64, 0, 0, 192,
        64, 32, 0, 192, 64, 64, 0, 192, 64, 96, 0, 192, 64, 128, 0, 192, 64, 160, 0, 192, 64, 192,
        0, 192, 64, 224, 0, 192, 96, 0, 0, 192, 96, 32, 0, 192, 96, 64, 0, 192, 96, 96, 0, 192,
        96, 128, 0, 192, 96, 160, 0, 192, 96, 192, 0, 192, 96, 224, 0, 192, 128, 0, 0, 192, 128,
        32, 0, 192, 128, 64, 0, 192, 128, 96, 0, 192, 128, 128, 0, 192, 128, 160, 0, 192, 128,
        192, 0, 192, 128, 224, 0, 192, 160, 0, 0, 192, 160, 32, 0, 192, 160, 64, 0, 192, 160, 96,
        0, 192, 160, 128, 0, 192, 160, 160, 0, 192, 160, 192, 0, 192, 160, 224, 0, 192, 192, 0, 0,
        192, 192, 32, 0, 192, 192, 64, 0, 192, 192, 96, 0, 192, 192, 128, 0, 192, 192, 160, 0,
        240, 251, 255, 0, 164, 160, 160, 0, 128, 128, 128, 0, 0, 0, 255, 0, 0, 255, 0, 0, 0, 255,
        255, 0, 255, 0, 0, 0, 255, 0, 255, 0, 255, 255, 0, 0, 255, 255, 255, 0
    ))) == BMCContainer.PALETTE


def test_color_black():
    """    
    Given:
        - BMCContainer object
    When:
        - Calling the COLOR_BLACK property
    Then:
        - Ensure that the COLOR_BLACK is set correctly
    """
    assert BMCContainer.COLOR_BLACK == b"\x00"


def test_b_process():
    """    
    Given:
        - BMCContainer object
    When:
        - Calling the b_process function
    Then:
        - Ensure that the return value is not None and returned properly
    """
    container = BMCContainer()
    container.b_process()
    assert container.bdat is not None


@pytest.mark.parametrize("data, expected_output", [
    (b"\xFF\xE0\x07\x1F\xF8\x00", b"\xff\x1c\xe7\xff9\xe3\x18\xff\xc6\x1c\x00\xff"),
    (b"\x00\x00\x00\x00", b"\x00\x00\x00\xff\x00\x00\x00\xff"),
])
def test_b_parse_rgb565(data, expected_output):
    """    
    Given:
        - BMCContainer object
    When:
        - Calling the b_process function
    Then:
        - Ensure that the return value is not None and returned properly
    """
    container = BMCContainer()
    result = container.b_parse_rgb565(data)

    # Compare the result with the expected output
    assert result == expected_output


@pytest.mark.parametrize("data, expected_output, btype", [
    (b"\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00", b"", BMCContainer.BIN_CONTAINER),
    (b"\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00", b"\xff\x00\x00\xff\x00\x00\xff\xff\x00\xff\x00\xff",
     BMCContainer.BMC_CONTAINER),
    (b"\xFF\x00\x00", b"", BMCContainer.BIN_CONTAINER),
    (b"\xFF\x00\x00", b"\xFF\x00\x00\xFF", BMCContainer.BMC_CONTAINER),
])
def test_b_parse_rgb32b(data, expected_output, btype):
    container = BMCContainer()

    container.btype = btype

    result = container.b_parse_rgb32b(data)

    # Compare the result with the expected output
    assert result == expected_output


@pytest.mark.parametrize("data, expected_output, btype", [
    (b"\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00", b"", BMCContainer.BIN_CONTAINER),
    (b"\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00",
     b"\xff\x00\x00\xff\xff\x00\x00\xff\xff\x00\x00\xff\xff\x00\x00\xff", BMCContainer.BMC_CONTAINER),
    (b"\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00", b"", BMCContainer.BIN_CONTAINER),
    (b"\xFF\x00\x00\xFF\x00\x00\xFF\x00\x00", b"\xff\x00\x00\xff\xff\x00\x00\xff\xff\x00\x00\xff", BMCContainer.BMC_CONTAINER),
])
def test_b_parse_rgb24b(data, expected_output, btype):
    container = BMCContainer()

    container.btype = btype

    result = container.b_parse_rgb24b(data)

    # Compare the result with the expected output
    assert result == expected_output


@pytest.mark.parametrize("data, expected_output", [
    (b"", (-1, 1, 0)),
    (b"\xF5", (-1, 2, 0xF5)),
    (b"\xFD", (0xFD, 0, 1)),
    (b"\xF9", (0xF9, 8, 1)),
    (b"\xF0\x00\x01", (0xF0, 256, 3)),
    (b"\xA0", (-1, 2, 0xA0)),
    (b"\x80", (-1, 1, 0x00)),
    (b"\x00", (-1, 1, 0x00)),
    (b"\x10", (0x00, 16, 1)),
    (b"\x40", (-1, 1, 0x00)),
    (b"\xD0", (-1, 1, 0x00)),
])
def test_b_unrle(data, expected_output):
    container = BMCContainer()
    result = container.b_unrle(data)

    # Compare the result with the expected output
    assert result == expected_output


@pytest.mark.parametrize("data, bbp, expected_output", [
    (b"", 3, b""),
    (b"\xF5", 3, b""),
    (b"\xFD", 3, b"\xFF\xFF\xFF"),
    (b"\xA0", 3, b""),
    (b"\x80", 3, b""),
    (b"\x00", 3, b""),
    (b"\x40", 3, b""),
    (b"\xD0", 3, b""),
])
def test_b_uncompress(data, bbp, expected_output):
    container = BMCContainer()
    result = container.b_uncompress(data, bbp)

    # Compare the result with the expected output
    assert result == expected_output


@pytest.mark.parametrize("width, height, data, pal, expected_output", [
    (10, 10, b"\x00" * 100, False,
     b'BM\xde\x00\x00\x00\x00z\x00\x00\x00l\x00\x00\x00\x0a\x00\x00\x00\x0a\x00\x00\x00\x01\x00 \x00\x03\x00\x00\x00d\x00\x00\x00\x13\x0b\x00\x00\x13\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\xff\x00\x00\xff\x00\x00\x00\x00\x00\x00\xff niW\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')])  # noqa: E501
def test_b_export_bmp(width, height, data, pal, expected_output):
    container = BMCContainer()
    container.pal = pal
    result = container.b_export_bmp(width, height, data)

    # Compare the result with the expected output
    assert result == expected_output
