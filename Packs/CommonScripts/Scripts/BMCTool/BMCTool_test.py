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


def test_bmc_container_with_old_true():
    # Test initialization with count > 0
    old = True
    bmc_container = BMCContainer(old)

    # Check that the container is initialized correctly
    assert bmc_container


def test_bmc_container_with_count():
    # Test initialization with count > 0
    count = 5
    bmc_container = BMCContainer(count)

    # Check that the container is initialized correctly
    assert bmc_container


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
    def test_b_export_bmp(self, width, height, data, expected):
        container = BMCContainer()
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


class Test__Init__:
    # Tests that BMCContainer object is initialized with default parameters
    def test_default_init(self):
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
    def test_custom_init(self):
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
    def test_zero_count(self):
        bmc = BMCContainer(count=0)
        assert bmc.cnt == 0

    # Tests that BMCContainer object is initialized with old = True
    def test_old_true(self):
        bmc = BMCContainer(old=True)
        assert bmc.oldsave

    # Tests that BMCContainer object is initialized with width = 0
    def test_width_zero(self):
        bmc = BMCContainer(width=0)
        assert bmc.STRIPE_WIDTH == 0

    # Tests that debug messages are logged when count > 0 or old = True
    def test_debug_messages(self):
        assert BMCContainer(count=5, old=True)
