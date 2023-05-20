import demistomock as demisto
import pytest
from BMCTool import BMCContainer

# Import the module or class to be tested
from BMCTool import BMCContainer


@pytest.fixture
def bmc_container():
    return BMCContainer()


def test_bmc_container_file_header(bmc_container):
    assert bmc_container.BIN_FILE_HEADER == b"RDP8bmp\x00"


def test_bmc_container_tile_header_size(bmc_container):
    assert bmc_container.TILE_HEADER_SIZE == {
        bmc_container.BMC_CONTAINER: 0x14,
        bmc_container.BIN_CONTAINER: 0xC,
    }


def test_bmc_container_stripe_width(bmc_container):
    assert bmc_container.STRIPE_WIDTH == 64


def test_bmc_container_log_types(bmc_container):
    assert bmc_container.LOG_TYPES == ["[===]", "[+++]", "[---]", "[!!!]"]


def test_bmc_container_palette(bmc_container):
    assert len(bmc_container.PALETTE) == 1024


def test_bmc_container_import(bmc_container, capfd):    
    with capfd.disabled():
        assert bmc_container.b_import("test_data/empty_file") is False