from pathlib import Path
from typing import Callable, Iterable, Optional

import collect_tests
import pytest
# importing Machine,FileType from collect_tests (rather than utils) to compare class member values
from collect_tests import (BranchTestCollector, FileType, Machine,
                           XSIAMNightlyTestCollector,
                           XSOARNightlyTestCollector)
from demisto_sdk.commands.common.constants import MarketplaceVersions

from Tests.scripts.collect_tests.constants import XSOAR_SANITY_TEST_NAMES
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.utils import PackManager

"""
Test Collection Unit-Test cases
- `empty` has no packs
- `empty_xsiam` has no packs, and only a test that is taken from conf.json (it is not saved elsewhere)
- `A` has a single pack with an integration and two test playbooks.
- `B` has a single pack, with only test playbooks. (they should be collected)
- `C` has a pack supported by both marketplaces, and one only for marketplacev2 and one only for XSOAR.
- `D` has a single pack with from_version == to_version == 6.5, for testing the version range.
- `E` has a single pack with a script tested using myTestPlaybook, and a Playbook used in myOtherTestPlaybook.
- `F` has a single pack with a script set up as `no tests`, and a conf where myTestPlaybook is set as the script's test.
- `G` has objects that trigger collection of the pack (without tests)
- `H` has a single file, that is not a content item, and find_type is mocked to test ONLY_INSTALL_PACK.
"""


class CollectTestsMocker:
    """
    Allows testing Test Collection, by injecting a custom PathManager into the imported collect_tests module in memory
    """

    def __init__(self, content_path: Path):
        self.path_manager = PathManager(Path(__file__).parent / content_path)
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

    def __repr__(self):
        return str(self.path_manager.content_path)


TEST_DATA = Path('test_data')


class MockerCases:
    empty = CollectTestsMocker(TEST_DATA / 'empty')
    empty_xsiam = CollectTestsMocker(TEST_DATA / 'empty_xsiam')
    A_xsoar = CollectTestsMocker(TEST_DATA / 'A_xsoar')
    A_xsiam = CollectTestsMocker(TEST_DATA / 'A_xsiam')
    B_xsoar = CollectTestsMocker(TEST_DATA / 'B_xsoar')
    B_xsiam = CollectTestsMocker(TEST_DATA / 'B_xsiam')
    C = CollectTestsMocker(TEST_DATA / 'C')
    D = CollectTestsMocker(TEST_DATA / 'D')
    E = CollectTestsMocker(TEST_DATA / 'E')
    F = CollectTestsMocker(TEST_DATA / 'F')
    G = CollectTestsMocker(TEST_DATA / 'G')
    H = CollectTestsMocker(TEST_DATA / 'H')


def _test(monkeypatch, case_mocker: CollectTestsMocker, run_nightly: bool, collector_class: Callable,
          expected_tests: Iterable[str], expected_packs: Iterable[str], expected_machines: Optional[Iterable[Machine]],
          collector_class_args: tuple[str] = ()):
    """
    Instantiates the given collector class, calls collect with run_nightly and asserts
    that the result packs and tests are expected ones.

    :param case_mocker: with which to run the test
    :param run_nightly: whether to ask, and check for, a nightly machine.
    :param collector_class: the collector class to test.
    :param expected_tests: the expected test names. (pass None to not check)
    :param expected_packs: the expected pack names. (pass None to not check)
    :param expected_machines: the expected machines. (pass None to not check)
    :param collector_class_args: with which to instantiate the collector class.
    :return: Nothing: only calls assert.
    """
    monkeypatch.chdir(case_mocker.path_manager.content_path)
    with case_mocker:
        collector = collector_class(*collector_class_args)
        collected = collector.collect(run_nightly)

    if not any((expected_tests, expected_packs, expected_machines)):
        if not collected:
            # matches expectation
            return
        description = 'should NOT have collected '
        if collected.packs:
            description += f'packs {collected.packs} '
        if collected.tests:
            description += f'tests {collected.tests}'

        assert False, description

    if collected is None:
        assert False, 'should have collected something'

    if expected_tests is not None:
        assert collected.tests == set(expected_tests)
    if expected_packs is not None:
        assert collected.packs == set(expected_packs)
    if expected_machines is not None:
        assert set(collected.machines) == set(expected_machines)

    assert Machine.MASTER in collected.machines
    assert (Machine.NIGHTLY in collected.machines) == run_nightly

    for test in collected.tests:
        print(f'collected test {test}')
    for machine in collected.machines:
        print(f'machine {machine}')
    for pack in collected.packs:
        print(f'collected pack {pack}')


NIGHTLY_EMPTY_TESTS = (
    (MockerCases.empty, XSOARNightlyTestCollector, XSOAR_SANITY_TEST_NAMES, ()),
    (MockerCases.empty, XSIAMNightlyTestCollector, (), ()),
    (MockerCases.empty_xsiam, XSIAMNightlyTestCollector,
     ('some_xsiam_test_only_mentioned_in_conf_json',), ())
)


@pytest.mark.parametrize('case_mocker,collector_class,expected_tests,expected_packs', NIGHTLY_EMPTY_TESTS)
def test_nightly_empty(monkeypatch, case_mocker, collector_class: Callable, expected_tests: tuple[str],
                       expected_packs: tuple[str]):
    """
    given:  a content folder
    when:   collecting tests with a NightlyTestCollector
    then:   make sure sanity tests are collected for XSOAR, and that XSIAM tests are collected from conf.json
            make sure master machine is used
    """
    _test(monkeypatch, case_mocker, run_nightly=True, collector_class=collector_class, expected_tests=expected_tests,
          expected_packs=expected_packs, expected_machines=None)


NIGHTLY_EXPECTED_TESTS = {'myTestPlaybook', 'myOtherTestPlaybook'}
NIGHTLY_TESTS = ((MockerCases.A_xsoar, XSOARNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSOAROnlyPack',), None),
                 (MockerCases.B_xsoar, XSOARNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSOAROnlyPack',), None),
                 (MockerCases.A_xsiam, XSIAMNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSIAMOnlyPack',), None),
                 (MockerCases.B_xsiam, XSIAMNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSIAMOnlyPack',), None),

                 (MockerCases.C, XSOARNightlyTestCollector, {'myXSOAROnlyTestPlaybook', 'myTestPlaybook'},
                  {'bothMarketplacesPack', 'bothMarketplacesPackOnlyXSIAMIntegration', 'myXSOAROnlyPack'}, None),

                 (MockerCases.C, XSIAMNightlyTestCollector, {'myXSIAMOnlyTestPlaybook'},
                  {'myXSIAMOnlyPack', 'bothMarketplacesPackOnlyXSIAMIntegration'}, None),

                 (MockerCases.D, XSOARNightlyTestCollector, {'myTestPlaybook'}, {'myPack'},
                  (Machine.V6_5, Machine.MASTER, Machine.NIGHTLY)),

                 (MockerCases.E, XSOARNightlyTestCollector, {'myTestPlaybook', 'myOtherTestPlaybook'}, {'myPack'},
                  None),
                 (MockerCases.E, XSIAMNightlyTestCollector, {}, {}, None),

                 (MockerCases.F, XSOARNightlyTestCollector, {'myTestPlaybook', 'myOtherTestPlaybook'}, {'myPack'},
                  None),)


@pytest.mark.parametrize('case_mocker,collector_class,expected_tests,expected_packs,expected_machines', NIGHTLY_TESTS)
def test_nightly(monkeypatch, case_mocker, collector_class: Callable, expected_tests: set[str],
                 expected_packs: tuple[str],
                 expected_machines: Optional[tuple[Machine]]):
    """
    given:  a content folder
    when:   collecting tests with a NightlyTestCollector
    then:   make sure tests are collected from integration and id_set
    """

    _test(monkeypatch, case_mocker=case_mocker, run_nightly=True, collector_class=collector_class,
          expected_tests=expected_tests, expected_packs=expected_packs, expected_machines=expected_machines)


XSOAR_BRANCH_ARGS = ('master', MarketplaceVersions.XSOAR, None)
XSIAM_BRANCH_ARGS = ('master', MarketplaceVersions.MarketplaceV2, None)


@pytest.mark.parametrize(
    'case_mocker,expected_tests,expected_packs,expected_machines,collector_class_args,mocked_changed_files',
    ((MockerCases.empty, XSOAR_SANITY_TEST_NAMES, (), None, XSOAR_BRANCH_ARGS, ()),

     (MockerCases.empty, (), (), None, XSIAM_BRANCH_ARGS, ()),

     (MockerCases.empty_xsiam, ('some_xsiam_test_only_mentioned_in_conf_json',), (), None, XSIAM_BRANCH_ARGS,
      ()),

     (MockerCases.A_xsoar, ('myOtherTestPlaybook',), ('myXSOAROnlyPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.yml',)),

     (MockerCases.A_xsoar, ('myOtherTestPlaybook',), ('myXSOAROnlyPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.py',)),

     (MockerCases.A_xsiam, ('myOtherTestPlaybook',), ('myXSIAMOnlyPack',), None, XSIAM_BRANCH_ARGS,
      ('Packs/myXSIAMOnlyPack/Integrations/myIntegration/myIntegration.yml',)),

     (MockerCases.A_xsiam, ('myOtherTestPlaybook',), ('myXSIAMOnlyPack',), None, XSIAM_BRANCH_ARGS,
      ('Packs/myXSIAMOnlyPack/Integrations/myIntegration/myIntegration.py',)),

     (MockerCases.B_xsoar, ('myOtherTestPlaybook',), ('myXSOAROnlyPack',), None, XSOAR_BRANCH_ARGS, (
             'Packs/myXSOAROnlyPack/TestPlaybooks/myOtherTestPlaybook.yml',
     )),
     (MockerCases.B_xsoar, ('myOtherTestPlaybook', 'myTestPlaybook'), ('myXSOAROnlyPack',), None,
      XSOAR_BRANCH_ARGS, ('Packs/myXSOAROnlyPack/TestPlaybooks/myTestPlaybook.yml',
                          'Packs/myXSOAROnlyPack/TestPlaybooks/myOtherTestPlaybook.yml',)),

     (MockerCases.E, ('myOtherTestPlaybook',), ('myPack',), None, XSOAR_BRANCH_ARGS, (
             'Packs/myPack/TestPlaybooks/myOtherTestPlaybook.yml',
     )),
     (MockerCases.E, ('myOtherTestPlaybook',), ('myPack',), None, XSOAR_BRANCH_ARGS, (
             'Packs/myPack/Playbooks/myPlaybook.yml',
     )),
     (MockerCases.F, ('myTestPlaybook',), ('myPack',), None, XSOAR_BRANCH_ARGS, (
             'Packs/myPack/Scripts/myScript/myScript.yml',
     )),
     ))
def test_branch(
        monkeypatch,
        mocker,
        case_mocker,
        expected_tests: set[str],
        expected_packs: tuple[str],
        expected_machines: Optional[tuple[Machine]],
        collector_class_args: tuple[str],
        mocked_changed_files: tuple[str]
):
    mocker.patch.object(BranchTestCollector, '_get_changed_files', return_value=mocked_changed_files)
    _test(monkeypatch, case_mocker, run_nightly=False, collector_class=BranchTestCollector,
          expected_tests=expected_tests, expected_packs=expected_packs, expected_machines=expected_machines,
          collector_class_args=collector_class_args)


ONLY_COLLECT_PACK_TYPES = {
    FileType.RELEASE_NOTES_CONFIG,
    FileType.RELEASE_NOTES,
    FileType.IMAGE,
    FileType.DESCRIPTION,
    FileType.METADATA,
    FileType.INCIDENT_TYPE,
    FileType.INCIDENT_FIELD,
    FileType.INDICATOR_FIELD,
    FileType.LAYOUT,
    FileType.WIDGET,
    FileType.DASHBOARD,
    FileType.PARSING_RULE,
    FileType.MODELING_RULE,
    FileType.CORRELATION_RULE,
    FileType.XSIAM_DASHBOARD,
    FileType.XSIAM_REPORT,
    FileType.REPORT,
    FileType.GENERIC_TYPE,
    FileType.GENERIC_FIELD,
    FileType.GENERIC_MODULE,
    FileType.GENERIC_DEFINITION,
    FileType.PRE_PROCESS_RULES,
    FileType.JOB,
    FileType.CONNECTION,
    FileType.XSOAR_CONFIG,
}


def test_only_collect_pack_args():
    """
    comparing the test_only_collect_packs arguments (ONLY_COLLECT_PACK_TYPES) match constants.ONLY_COLLECT_PACK_TYPES
    Any change there will require a change here.
    """
    from constants import ONLY_INSTALL_PACK
    assert ONLY_COLLECT_PACK_TYPES == ONLY_INSTALL_PACK


@pytest.mark.parametrize('file_type', ONLY_COLLECT_PACK_TYPES)
def test_only_collect_pack(mocker, monkeypatch, file_type: collect_tests.FileType):
    """
    give    a content item type for which no tests should be collected
    when    collecting with a BranchTestCollector
    then    make sure the pack is collected, but tests are not
    """
    # test mockers
    mocker.patch.object(BranchTestCollector, '_get_changed_files', return_value=('Packs/myPack/some_file',))
    mocker.patch('collect_tests.find_type_by_path', return_value=file_type)

    # noinspection PyTypeChecker
    _test(monkeypatch, case_mocker=MockerCases.H, run_nightly=False, collector_class=BranchTestCollector,
          expected_tests=(), expected_packs=('myPack',), expected_machines=None, collector_class_args=XSOAR_BRANCH_ARGS)


def test_invalid_content_item(mocker, monkeypatch):
    """
    given:  a changed file that  _get_changed_files can not identify
    when:   collecting tests
    then:   make sure an appropriate error is raised
    """
    # test mockers
    mocker.patch.object(BranchTestCollector, '_get_changed_files', return_value=('Packs/myPack/some_file',))

    with pytest.raises(ValueError) as e:
        # noinspection PyTypeChecker
        _test(monkeypatch, case_mocker=MockerCases.H, run_nightly=False, collector_class=BranchTestCollector,
              expected_tests=(), expected_packs=('myPack',), expected_machines=None,
              collector_class_args=XSOAR_BRANCH_ARGS)
    assert 'Unexpected file_type=None' in str(e.value)
