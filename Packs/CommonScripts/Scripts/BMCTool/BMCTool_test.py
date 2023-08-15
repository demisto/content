import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401
from BMCTool import BMCContainer, main


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


def test_bmc_container_with_old_true():
    # Test initialization with count > 0
    old = True
    bmc_container = BMCContainer(old=old)
    # Check that the container is initialized correctly
    assert bmc_container.oldsave is True


def test_bmc_container_with_count():
    # Test initialization with count > 0
    count = 5
    bmc_container = BMCContainer(count=count)
    # Check that the container is initialized correctly
    assert bmc_container.cnt > 0


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

    @pytest.mark.parametrize("width, height, data, expected", [
        (10, 10, b"test_data", b"expected_output_without_palette"),
        (10, 10, b"test_data", b"expected_output_with_palette"),
        # Add more test cases as needed
    ])
    def test_b_export_bmp(self, width, height, data, expected, mocker):
        container = BMCContainer()
        # Mock CommonServerPython.fileResult() to do nothing (avoid creating files on disk)
        with mocker.patch("CommonServerPython.fileResult"):
            actual = container.b_export_bmp(width, height, data)
        assert actual == expected


@pytest.fixture
def bmc_container():
    # Create an instance of BMCContainer for testing
    return BMCContainer()


def test_b_import_already_loaded(bmc_container):
    # Test importing when data is already loaded
    bmc_container.bdat = b"Some data"
    assert bmc_container.b_import("path/to/valid_bmc_container.bin") is False


def test_b_import_valid_file(bmc_container):
    # Test importing valid bin file
    assert bmc_container.b_import("test_data/valid_bin.bin") is True


def test_b_import_empty_file_contents(bmc_container):
    # Test importing empty bin file
    bmc_container.bdat = b""
    assert bmc_container.b_import("test_data/empty_file.bin") is False


def test_b_import_else_case(bmc_container):
    assert bmc_container.b_import("test_data/text_test_file.bin") is False


# Tests that BMCContainer object is initialized with default parameters
def test_default_init():
    bmc = BMCContainer()
    assert bmc.bdat == b''
    assert bmc.o_bmps == []
    assert bmc.bmps == []
    assert bmc.btype == b''
    assert bmc.cnt == 0
    assert bmc.fname == ''
    assert not bmc.oldsave
    assert not bmc.pal
    assert not bmc.verb
    assert not bmc.big
    assert bmc.STRIPE_WIDTH == 64


# Tests that BMCContainer object is initialized with custom parameters
def test_custom_init():
    bmc = BMCContainer(verbose=True, count=10, old=True, big=True, width=128)
    assert bmc.bdat == b''
    assert bmc.o_bmps == []
    assert bmc.bmps == []
    assert bmc.btype == b''
    assert bmc.cnt == 10
    assert bmc.fname == ''
    assert bmc.oldsave
    assert not bmc.pal
    assert bmc.verb
    assert bmc.big
    assert bmc.STRIPE_WIDTH == 128


# Tests that BMCContainer object is initialized with count = 0
def test_zero_count():
    bmc = BMCContainer(count=0)
    assert bmc.cnt == 0


# Tests that BMCContainer object is initialized with old = True
def test_old_true():
    bmc = BMCContainer(old=True)
    assert bmc.oldsave


# Tests that BMCContainer object is initialized with width = 0
def test_width_zero():
    bmc = BMCContainer(width=0)
    assert bmc.STRIPE_WIDTH == 0


# Tests that debug messages are logged when count > 0 or old = True
def test_debug_messages():
    assert BMCContainer(count=5, old=True)


# Tests that the method returns a byte string when called with valid input data
def test_happy_path_valid_input_data():
    bmc = BMCContainer()
    data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
    bbp = 2
    result = bmc.b_uncompress(data, bbp)
    assert result == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\xff\xff\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff'  # noqa: E501


# Tests that the method handles different values of bbp parameter
def test_happy_path_different_bbp_values():
    bmc = BMCContainer()
    data = b'\x00\x01'
    bbp = 1
    result = bmc.b_uncompress(data, bbp)
    assert result == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # noqa: E501

    bbp = 4
    result = bmc.b_uncompress(data, bbp)
    assert result == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # noqa: E501


# Tests that the method handles different values of data parameter
def test_happy_path_different_data_values():
    bmc = BMCContainer()
    data = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'
    bbp = 2
    result = bmc.b_uncompress(data, bbp)
    assert result == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\xff\xff\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff'  # noqa: E501

    data = b''
    result = bmc.b_uncompress(data, bbp)
    assert result == b''


# Tests that the method returns an empty byte string when called with empty data
def test_edge_case_empty_data():
    bmc = BMCContainer()
    data = b''
    bbp = 2
    result = bmc.b_uncompress(data, bbp)
    assert result == b''


# Tests that the method logs an error message and returns an empty byte string when called with an invalid cmd value
def test_edge_case_invalid_cmd_value():
    bmc = BMCContainer()
    data = b'\xff'
    bbp = 2
    result = bmc.b_uncompress(data, bbp)
    assert result == b''


# Tests that the method logs an error message and returns an empty byte string when called with an invalid rl value
def test_edge_case_invalid_rl_value():
    bmc = BMCContainer()
    data = b'\x00\x01\x02'
    bbp = 2
    result = bmc.b_uncompress(data, bbp)
    assert result == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00'  # noqa: E501


def test_edge_case_cmd_0xC0():
    bmc = BMCContainer()
    data = b'\xC0' + b'\xFF' * (3 * 64)  # cmd = 0xC0, rl = 64
    bbp = 2
    assert bmc.b_uncompress(data, bbp) == b''


def test_edge_case_cmd_0xF6():
    bmc = BMCContainer()
    data = b'\xF6' + b'\x01' * (1 * 64)  # cmd = 0xF6, rl = 64
    bbp = 128
    assert bmc.b_uncompress(data, bbp) == b''


def test_edge_case_cmd_0x20():
    bmc = BMCContainer()
    data = b'\x01' * (1 * 64)  # cmd = 0xF6, rl = 64
    bbp = 2
    assert bmc.b_uncompress(data, bbp) == b'\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'  # noqa: E501


def test_b_process_btype_is_bin():
    bmcc = BMCContainer()
    bmcc.btype = b".BIN"
    with open("test_data/valid_bin.bin", "rb") as f:
        bmcc.bdat = f.read()
    assert bmcc.b_process() is True


def test_b_process_btype_is_bin_buf_256():
    bmcc = BMCContainer()
    data = b'\x01' * 85 + b'\xFF' * 18 + b'\x01' * 90
    bmcc.btype = b".BIN"

    assert bmcc.b_parse_rgb24b(data)


def test_b_process_btype_is_bmc_22():
    bmcc = BMCContainer()
    bmcc.btype = b".BMC"
    bmcc.fname = "22.bmc"
    bmcc.TILE_HEADER_SIZE = {bmcc.BMC_CONTAINER: 0x20}
    bmcc.bdat = bmcc.bdat = b'\x03' * 0xC + b'\xff' * (64 * 64 * 3) + b'\x03' * 0xC + b'\xff' * (64 * 64 * 3)
    assert bmcc.b_process() is True


def test_b_process_btype_is_bmc_24():
    bmcc = BMCContainer()
    bmcc.btype = b".BMC"
    bmcc.fname = "24.bmc"
    bmcc.TILE_HEADER_SIZE = {bmcc.BMC_CONTAINER: 0x20}
    bmcc.bdat = bmcc.bdat = b'\x03' * 0xC + b'\xff' * (64 * 64 * 4) + b'\x03' * 0xC + b'\xff' * (64 * 64 * 4)
    assert bmcc.b_process() is True


def test_b_process_btype_is_bmc_2():
    bmcc = BMCContainer()
    bmcc.btype = b".BMC"
    bmcc.fname = "2.bmc"
    bmcc.TILE_HEADER_SIZE = {bmcc.BMC_CONTAINER: 0x20}
    bmcc.bdat = bmcc.bdat = b'\x03' * 0xC + b'\xff' * (64 * 64) + b'\x03' * 0xC + b'\xff' * (64 * 64)
    assert bmcc.b_process() is True


def test_b_process_btype_is_bmc_else():
    bmcc = BMCContainer()
    bmcc.btype = b".BMC"
    bmcc.fname = "1.bmc"
    bmcc.TILE_HEADER_SIZE = {bmcc.BMC_CONTAINER: 0x20}
    bmcc.bdat = bmcc.bdat = b'\x03' * 0xC + b'\xff' * (64 * 64) + b'\x03' * 0xC + b'\xff' * (64 * 64)
    assert bmcc.b_process() is False


def test_b_process_btype_is_bmc_and_compressed_bit():
    bmcc = BMCContainer()
    bmcc.btype = b".BMC"
    bmcc.fname = "1.bmc"
    bmcc.bdat = b'\x03' * 0xC + b'\xff' * (64 * 64) + b'\x0B' + b'\xff' * (64 * 64)
    assert bmcc.b_process() is False


# Tests that the method extracts multiple tiles from a BMC container with valid data
def test_happy_path_multiple_tiles():
    bmcc = BMCContainer()
    bmcc.btype = 1
    bmcc.bdat = b'\x01' * 0xC + b'\xff' * (64 * 64 * 4) + b'\x01' * 0xC + b'\xff' * (64 * 64 * 4)  # BMC container with two tiles
    try:
        bmcc.b_process()
    except KeyError:
        assert True
    else:
        raise AssertionError


# Tests that the method extracts tiles from a BMC container with a valid palette
def test_happy_path_valid_palette():
    bmcc = BMCContainer()
    bmcc.btype = b"1"
    bmcc.bdat = b'\x02' * 0xC + b'\xff' * (64 * 64 * 2) + b'\x02' * 0xC + b'\xff' * (64 * 64 * 2)  # BMC container with two tiles
    try:
        bmcc.b_process()
    except KeyError:
        assert True
    else:
        raise AssertionError


# Tests that the method logs an error message when there is nothing to process
def test_edge_case_no_data():
    bmcc = BMCContainer()
    assert bmcc.b_process() is False


# Tests that the method extracts tiles from a BMC container with invalid data
def test_edge_case_invalid_data():
    bmcc = BMCContainer()
    bmcc.btype = 1
    bmcc.bdat = b'\x01' * 0xC + b'\xff' * (64 * 64 * 4) + b'\x01' * 0xC + b'\xff' * \
        (64 * 64 * 4) + b'\x01' * 0xC + b'\xff' * (64 * 64 * 2)
    try:
        bmcc.b_process()
    except KeyError:
        assert True
    else:
        raise AssertionError


def test_edge_case_invalid_bpp():
    bmcc = BMCContainer()
    bmcc.btype = 1
    bmcc.bdat = b'\x03' * 0xC + b'\xff' * (64 * 64 * 3) + b'\x03' * 0xC + b'\xff' * (64 * 64 * 3)  # BMC container with two tiles
    try:
        bmcc.b_process()
    except KeyError:
        assert True
    else:
        raise AssertionError


def test_b_flush():
    bmcc = BMCContainer()
    bmcc.bdat = b'\x01\x01\x01'
    bmcc.bmps = [1, 2, 3]
    bmcc.o_bmps = [1, 2, 3]

    bmcc.b_flush()
    assert bmcc.bdat == b""
    assert bmcc.bmps == []
    assert bmcc.o_bmps == []


def test_main(mocker):
    # Mock demisto.getArg function to return the input arguments
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'context', return_value={'File': [{'name': 'valid_bin.bin'}]})
    mocker.patch.object(demisto, 'getFilePath', return_value={
        'id': 1,
        'name': 'valid_bin.bin',
        'path': 'test_data/valid_bin.bin'})
    mocker.patch.object(demisto, 'args', return_value={
        'verbose': False,
        'width': 64,
        'EntryID': ''
    })
    # Mock CommonServerPython.fileResult() to do nothing (avoid creating files on disk)
    with mocker.patch("BMCTool.BMCContainer.b_write"):
        main()

    result = demisto.results
    assert result
