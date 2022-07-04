from os import chdir, getcwd
from pathlib import Path
from typing import Callable, NamedTuple, Optional

import collect_tests
import pytest
from collect_tests import (BranchTestCollector, CollectedTests, TestCollector,
                           XSIAMNightlyTestCollector,
                           XSOARNightlyTestCollector)
from demisto_sdk.commands.common.constants import MarketplaceVersions

from Tests.scripts.collect_tests.constants import XSOAR_SANITY_TEST_NAMES
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.utils import PackManager, Machine

TEST_DATA = Path(__file__).parent / 'test_data'
CASE_1 = TEST_DATA / 'case1'
CASE_EMPTY = TEST_DATA / 'case_empty'


class CollectTestsMocker:
    """
    Allows testing Test Collection, by "mocking" (changing reference in memory) collect_tests.
    """

    def __init__(self, content_path: Path):
        self.path_manager = PathManager(content_path)
        self.previous_path_manager = None

    def __enter__(self):
        self.previous_path_manager = collect_tests.PATHS
        self._mock(self.path_manager)

    def __exit__(self, *args):
        self._mock(self.previous_path_manager)
        self.previous_path_manager = None

    @staticmethod
    def _mock(path_manager: PathManager):
        collect_tests.PATHS = path_manager
        collect_tests.PACK_MANAGER = PackManager(path_manager)


MOCKER__CASE_ONE = CollectTestsMocker(Path('test_data/case1'))
MOCKER__CASE_EMPTY = CollectTestsMocker(Path('test_data/case_empty'))


@pytest.mark.parametrize('collector_class,expected_tests', ((XSOARNightlyTestCollector, XSOAR_SANITY_TEST_NAMES),
                                                            (XSIAMNightlyTestCollector, ())))
@pytest.mark.parametrize('run_master', (True, False))
@pytest.mark.parametrize('run_nightly', (True, False))
def test_nightly_empty(run_master: bool, run_nightly: bool, collector_class: Callable, expected_tests: tuple[str]):
    with MOCKER__CASE_EMPTY:
        collector = collector_class()
        collected = collector.collect(run_nightly, run_master)

        if expected_tests:
            assert collected.tests == set(expected_tests)
        else:
            assert not collected


# @pytest.mark.parametrize('run_master', (True, False))
# @pytest.mark.parametrize('run_nightly', (True, False))
# @pytest.mark.parametrize('collector_class', (XSOARNightlyTestCollector, XSIAMNightlyTestCollector))
# @pytest.mark.parametrize('mocker,expected', ((MOCKER__CASE_EMPTY, ExpectedResult(0, 0, 0)),
#                                              (MOCKER__CASE_ONE, ExpectedResult(0, 1, 1))))
# def test_sanity_nightly(mocker: CollectTestsMocker, collector_class: Callable,
#                         expected: ExpectedResult, run_nightly: bool, run_master: bool):
#     with mocker:
#         collector = collector_class()
#         collected = collector.collect(run_nightly, run_master)
#         validate_result(collected, expected)

#
# @pytest.mark.parametrize('run_master', (True, False))
# @pytest.mark.parametrize('run_nightly', (True, False))
# @pytest.mark.parametrize('collector,expected_tests', (
#         (BranchTestCollector('master', MarketplaceVersions.XSOAR, service_account=None), ()),
#         (BranchTestCollector('master', MarketplaceVersions.MarketplaceV2, service_account=None), ()),
# ))
# def test_sanity_branch(mocker, run_master: bool, run_nightly: bool, collector: TestCollector, expected_tests: tuple):
#     import collect_tests
#     mocker.patch.object(collect_tests, 'CONTENT_PATH', CASE_1)
#     # mocker.patch('demisto_sdk.commands.common.tools.run_command', return_value=())
#     with MOCKER__CASE_EMPTY:
#
#     with ChangeCWD(CASE_1):
#         collected = collector.collect(run_nightly, run_master)
#         assert not collected
