from os import getcwd, chdir

import pytest
from demisto_sdk.commands.common.constants import MarketplaceVersions
from pathlib import Path

from collect_tests import BranchTestCollector, XSOARNightlyTestCollector, XSIAMNightlyTestCollector, TestCollector

TEST_DATA = Path(__file__).parent / 'test_data'
CASE_1 = TEST_DATA / 'case1'
CASE_EMPTY = TEST_DATA / 'case_empty'


class ChangeCWD:
    def __init__(self, directory: Path):
        self.current = getcwd()
        self.directory = str(directory.resolve())

    def __enter__(self):
        chdir(self.directory)

    def __exit__(self, *args):
        chdir(self.current)


@pytest.mark.parametrize('collector,expected_tests', (
        (BranchTestCollector('master', MarketplaceVersions.XSOAR), ()),
        (BranchTestCollector('master', MarketplaceVersions.MarketplaceV2), ()),
        (XSOARNightlyTestCollector(), ()),
        (XSIAMNightlyTestCollector(), ())
))
def test_sanity(collector: TestCollector, expected_tests: tuple):
    with ChangeCWD(CASE_1):
        assert not collector.collect()
