from pathlib import Path
from typing import Callable, Iterable, Optional

import collect_tests
import pytest
# importing Machine from collect_tests (rather than utils) to compare class member values
from collect_tests import (Machine, XSIAMNightlyTestCollector,
                           XSOARNightlyTestCollector)

from Tests.scripts.collect_tests.constants import XSOAR_SANITY_TEST_NAMES
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.utils import PackManager

# todo empty_xsiam
"""
Test Collection Unit-Test cases 
- `empty` has no packs
- `empty_xsiam` has no packs, and only a test that is taken from conf.json (it is not saved elsewhere)
- `A` has a single pack with an integration and two test playbooks.
- `B` has a single pack, with only test playbooks. (they should be collected)
- `C` has a pack supported by both marketplaces, and one only for marketplacev2 and one only for XSOAR.
"""


class CollectTestsMocker:
    """
    Allows testing Test Collection, by "mocking" (changing reference in memory) collect_tests.
    """

    def __init__(self, content_path: Path):
        self.path_manager = PathManager(content_path)
        self.previous_path_manager = None

    def __enter__(self):
        print(f'mocking content root={self.path_manager.content_path}')
        self.previous_path_manager = collect_tests.PATHS
        self._mock(self.path_manager)

    def __exit__(self, *args):
        self._mock(self.previous_path_manager)
        self.previous_path_manager = None

    @staticmethod
    def _mock(path_manager: PathManager):
        collect_tests.PATHS = path_manager
        collect_tests.PACK_MANAGER = PackManager(path_manager)

    def __repr__(self):
        return str(self.path_manager.content_path)


class MockerCases:
    empty = CollectTestsMocker(Path('test_data/empty'))
    empty_xsiam = CollectTestsMocker(Path('test_data/empty_xsiam'))
    A_xsoar = CollectTestsMocker(Path('test_data/A_xsoar'))
    A_xsiam = CollectTestsMocker(Path('test_data/A_xsiam'))
    B_xsiam = CollectTestsMocker(Path('test_data/B_xsiam'))
    B_xsoar = CollectTestsMocker(Path('test_data/B_xsoar'))
    C = CollectTestsMocker(Path('test_data/C'))


def _test(mocker: CollectTestsMocker, run_nightly: bool, run_master: bool, collector_class: Callable,
          expected_tests: Iterable[str], expected_packs: Iterable[str],
          expected_machines: Optional[Iterable[Machine]], collector_class_args: tuple[str] = ()):
    """
    Instantiates the given collector class, calls collect with (run_nightly, run_master) and asserts
    that the result packs and tests are expected ones.

    :param mocker: with which to run the test
    :param run_nightly: whether to ask, and check for, a nightly machine.
    :param run_master: whether to ask and check for a master machine.
    :param collector_class: the collector class to test.
    :param expected_tests: the expected test names. (pass None to not check)
    :param expected_packs: the expected pack names. (pass None to not check)
    :param expected_machines: the expected machines. (pass None to not check)
    :param collector_class_args: with which to instantiate the collector class.
    :return: Nothing: only calls assert.
    """
    with mocker:
        collected = collector_class(*collector_class_args).collect(run_nightly, run_master)

        if not any((expected_tests, expected_packs, expected_machines)):
            assert not collected, f'should not have collected packs {collected.packs}, tests {collected.tests}'

        if expected_tests is not None:
            assert collected.tests == set(expected_tests)
        if expected_packs is not None:
            assert collected.packs == set(expected_packs)
        if expected_machines is not None:
            assert set(collected.machines) == set(expected_machines)

        assert run_nightly == (Machine.NIGHTLY in collected.machines)
        assert run_master == (Machine.MASTER in collected.machines)

    for test in collected.tests:
        print(f'collected test {test}')
    for machine in collected.machines:
        print(f'machine {machine}')
    for pack in collected.packs:
        print(f'collected pack {pack}')


@pytest.mark.parametrize('mocker,collector_class,expected_tests,expected_packs', (
        (MockerCases.empty, XSOARNightlyTestCollector, XSOAR_SANITY_TEST_NAMES, ()),
        (MockerCases.empty, XSIAMNightlyTestCollector, (), ()),
        (MockerCases.empty_xsiam, XSIAMNightlyTestCollector, ('some_xsiam_test_only_mentioned_in_conf_json',), ()),
        (MockerCases.C, XSOARNightlyTestCollector,
         ('myXSOAROnlyTestPlaybook', 'myTestPlaybook'), ('myXSOAROnlyPack', 'bothMarketplacesPack')),
        (MockerCases.C, XSIAMNightlyTestCollector,
         ('myXSIAMOnlyTestPlaybook',), ('bothMarketplacesPack', 'myXSIAMOnlyPack')),
))
@pytest.mark.parametrize('run_master', (True, False))
def test_nightly_empty(mocker, run_master: bool, collector_class: Callable,
                       expected_tests: tuple[str], expected_packs: tuple[str]):
    """
    given:  a content folder
    when:   collecting tests with a NightlyTestCollector
    then:   make sure sanity tests are collected for XSOAR, and that XSIAM tests are collected from conf.json
    """
    _test(mocker, run_nightly=True, run_master=run_master, collector_class=collector_class,
          expected_tests=expected_tests, expected_packs=expected_packs, expected_machines=None)


NIGHTLY_EXPECTED_TESTS = {'myTestPlaybook', 'myOtherTestPlaybook'}


@pytest.mark.parametrize('mocker,collector_class,expected_tests,expected_packs,', (
        (MockerCases.A_xsoar, XSOARNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSOAROnlyPack',)),
        (MockerCases.A_xsiam, XSIAMNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSIAMOnlyPack',)),
        (MockerCases.B_xsoar, XSOARNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSOAROnlyPack',)),
        (MockerCases.B_xsiam, XSIAMNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSIAMOnlyPack',)),
        (MockerCases.C, XSOARNightlyTestCollector,
         {'myXSOAROnlyTestPlaybook', 'myTestPlaybook'}, {'bothMarketplacesPack', 'myXSOAROnlyPack'}),  # todo packs
        (MockerCases.C, XSIAMNightlyTestCollector,
         {'myXSIAMOnlyTestPlaybook'}, {'bothMarketplacesPack', 'myXSIAMOnlyPack'})  # todo packs
))
def test_nightly(mocker, collector_class: Callable, expected_tests: set[str], expected_packs: tuple[str]):
    """
    given:  a content folder
    when:   collecting tests with a NightlyTestCollector
    then:   make sure tests are collected from integration and id_set
    """
    # noinspection PyTypeChecker

    _test(mocker, run_nightly=True, run_master=True, collector_class=collector_class, expected_tests=expected_tests,
          expected_packs=expected_packs, expected_machines=None)
