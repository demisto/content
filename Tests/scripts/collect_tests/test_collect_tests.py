from os import chdir, getcwd
from pathlib import Path

import pytest
from collect_tests import (BranchTestCollector, TestCollector,
                           XSIAMNightlyTestCollector,
                           XSOARNightlyTestCollector)
from demisto_sdk.commands.common.constants import MarketplaceVersions

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


@pytest.mark.parametrize('run_master', (True, False))
@pytest.mark.parametrize('run_nightly', (True, False))
@pytest.mark.parametrize('collector,expected_tests', (
        (XSOARNightlyTestCollector(), ()),
        (XSIAMNightlyTestCollector(), ())
))
def test_sanity_nightly(mocker, collector: TestCollector, expected_tests: tuple, run_nightly: bool, run_master: bool):
    import collect_tests
    mocker.patch.object(collect_tests, 'CONTENT_PATH', CASE_1)
    assert not collector.collect(run_nightly, run_master)


@pytest.mark.parametrize('run_master', (True, False))
@pytest.mark.parametrize('run_nightly', (True, False))
@pytest.mark.parametrize('collector,expected_tests', (
        (BranchTestCollector('master', MarketplaceVersions.XSOAR, service_account=None), ()),
        (BranchTestCollector('master', MarketplaceVersions.MarketplaceV2, service_account=None), ()),
))
def test_sanity_branch(mocker, run_master: bool, run_nightly: bool, collector: TestCollector, expected_tests: tuple):
    import collect_tests
    mocker.patch.object(collect_tests, 'CONTENT_PATH', CASE_1)
    # mocker.patch('demisto_sdk.commands.common.tools.run_command', return_value=())
    with ChangeCWD(CASE_1):
        collected = collector.collect(run_nightly, run_master)
        assert not collected
