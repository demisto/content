import os
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import pytest
from demisto_sdk.commands.common.constants import MarketplaceVersions

from Tests.scripts.collect_tests import collect_tests
# importing Machine,FileType from collect_tests (rather than utils) to compare class member values
from Tests.scripts.collect_tests.collect_tests import (
    BranchTestCollector, FileType, Machine, XSIAMNightlyTestCollector,
    XSOARNightlyTestCollector)
from Tests.scripts.collect_tests.constants import XSOAR_SANITY_TEST_NAMES
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.utils import PackManager

os.environ['UNIT_TESTING'] = 'True'

"""
Test Collection Unit-Test cases
- `empty` has no packs
- `empty_xsiam` has no packs, and only a test that is taken from conf.json (it is not saved elsewhere)
- `A` has a single pack with an integration and two test playbooks.
- `B` has a single pack, with only test playbooks. (they should be collected)
- `C` has a pack supported by both marketplaces, and one only for marketplacev2 and one only for XSOAR.
- `D` has a single pack & test-playbook with from_version == to_version == 6.5, for testing the version range.
- `E` has a single pack with a script tested using myTestPlaybook, and a Playbook used in myOtherTestPlaybook.
- `F` has a single pack with a script set up as `no tests`, and a conf where myTestPlaybook is set as the script's test.
- `G` has objects that trigger collection of the pack (without tests).
- `H` has a single file, that is not a content item, and find_type is mocked to test ONLY_INSTALL_PACK.
- `I` has a single pack with two test playbooks, one of which is ignored in .pack_ignore.
- `J` has a single pack with two integrations, with mySkippedIntegration being skipped in conf.json.
- `K` has a single pack with two integrations, with mySkippedIntegration's TPB skipped in conf.json.
- `L` has a single pack with a Wizard content item.
- `M1` has a pack with support level == xsoar, and tests missing from conf.json -- should raise an error.
- `M2` has a pack with support level != xsoar, and tests missing from conf.json -- should collect pack but not tests.
"""


class CollectTestsMocker:
    """
    Allows testing Test Collection, by injecting a custom PathManager into the imported collect_tests module in memory
    """

    def __init__(self, content_path: Path):
        content_path = Path(__file__).parent / content_path
        self.path_manager = PathManager(content_path)
        self.path_manager.id_set_path = content_path / 'Tests' / 'id_set.json'
        self.path_manager.conf_path = content_path / 'Tests' / 'conf.json'
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


TEST_DATA = Path('tests_data/collect_tests')


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
    I_xsoar = CollectTestsMocker(TEST_DATA / 'I_xsoar')
    J = CollectTestsMocker(TEST_DATA / 'J')
    K = CollectTestsMocker(TEST_DATA / 'K')
    L = CollectTestsMocker(TEST_DATA / 'L_XSIAM')
    M1 = CollectTestsMocker(TEST_DATA / 'M1')
    M2 = CollectTestsMocker(TEST_DATA / 'M2')


ALWAYS_INSTALLED_PACKS = ('Base', 'DeveloperTools')


def _test(monkeypatch, case_mocker: CollectTestsMocker, collector_class: Callable,
          expected_tests: Iterable[str], expected_packs: Iterable[str], expected_machines: Optional[Iterable[Machine]],
          collector_class_args: tuple[Any, ...] = ()):
    """
    Instantiates the given collector class, calls collect with run_nightly and asserts
    that the result packs and tests are expected ones.

    :param case_mocker: with which to run the test
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
        collected = collector.collect()

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
        assert False, f'should have collected something: {expected_tests=}, {expected_packs=}, {expected_machines=}'

    if expected_tests is not None:
        assert collected.tests == set(expected_tests)

    assert collected.packs == set(expected_packs or ()) | set(ALWAYS_INSTALLED_PACKS)

    if expected_machines is not None:
        assert set(collected.machines) == set(expected_machines)

    assert Machine.MASTER in collected.machines

    for test in collected.tests:
        print(f'collected test {test}')
    for machine in collected.machines:
        print(f'machine {machine}')
    for pack in collected.packs:
        print(f'collected pack {pack}')


NIGHTLY_EXPECTED_TESTS = {'myTestPlaybook', 'myOtherTestPlaybook'}

NIGHTLY_TESTS: tuple = (
    (MockerCases.A_xsoar, XSOARNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSOAROnlyPack',), None),
    (MockerCases.B_xsoar, XSOARNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSOAROnlyPack',), None),
    (MockerCases.A_xsiam, XSIAMNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSIAMOnlyPack',), None),
    (MockerCases.B_xsiam, XSIAMNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSIAMOnlyPack',), None),

    (MockerCases.C, XSOARNightlyTestCollector, {'myXSOAROnlyTestPlaybook', 'myTestPlaybook'},
     {'bothMarketplacesPack', 'bothMarketplacesPackOnlyXSIAMIntegration', 'myXSOAROnlyPack'}, None),

    (MockerCases.C, XSIAMNightlyTestCollector, {'myXSIAMOnlyTestPlaybook'},
     {'myXSIAMOnlyPack', 'bothMarketplacesPackOnlyXSIAMIntegration'}, None),

    (MockerCases.D, XSOARNightlyTestCollector, {'myTestPlaybook'}, {'myPack'},
     (Machine.V6_5, Machine.MASTER)),

    (MockerCases.E, XSOARNightlyTestCollector,
     {'myTestPlaybook', 'myOtherTestPlaybook', 'Sanity Test - Playbook with Unmockable Whois Integration'},
     {'myPack', 'Whois'}, None),

    (MockerCases.E, XSIAMNightlyTestCollector,
     {'Sanity Test - Playbook with Unmockable Whois Integration'},
     ALWAYS_INSTALLED_PACKS + ('Whois',),
     None),

    (MockerCases.F, XSOARNightlyTestCollector, {'myTestPlaybook', 'myOtherTestPlaybook'}, {'myPack'},
     None),

    (MockerCases.I_xsoar, XSOARNightlyTestCollector, {'myTestPlaybook'}, {'myXSOAROnlyPack'}, None)
)


@pytest.mark.parametrize('case_mocker,collector_class,expected_tests,expected_packs,expected_machines', NIGHTLY_TESTS)
def test_nightly(monkeypatch, case_mocker: CollectTestsMocker, collector_class: Callable, expected_tests: set[str],
                 expected_packs: tuple[str],
                 expected_machines: Optional[tuple[Machine]]):
    """
    given:  a content folder
    when:   collecting tests with a NightlyTestCollector
    then:   make sure tests are collected from integration and id_set
    """

    _test(monkeypatch, case_mocker=case_mocker, collector_class=collector_class,
          expected_tests=expected_tests, expected_packs=expected_packs, expected_machines=expected_machines)


XSOAR_BRANCH_ARGS = ('master', MarketplaceVersions.XSOAR, None)
XSIAM_BRANCH_ARGS = ('master', MarketplaceVersions.MarketplaceV2, None)


@pytest.mark.parametrize(
    'case_mocker,expected_tests,expected_packs,expected_machines,collector_class_args,mocked_changed_files',
    # change in a sanity-collection-triggering file, expecting xsoar sanity tests to be collected
    ((MockerCases.empty, XSOAR_SANITY_TEST_NAMES, ('Whois', 'HelloWorld'), None, XSOAR_BRANCH_ARGS,
      ('.gitlab/helper_functions.sh',)),

     # Empty content folder: expecting XSIAM collector to not collect anything
     (MockerCases.empty, (), (), None, XSIAM_BRANCH_ARGS, ()),

     # Case A, yml file changes, expect the test playbook testing the integration to be collected
     (MockerCases.A_xsoar, ('myOtherTestPlaybook',), ('myXSOAROnlyPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.yml',)),

     # Case A, py file changes, expect the test playbook testing the integration to be collected
     (MockerCases.A_xsoar, ('myOtherTestPlaybook',), ('myXSOAROnlyPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.py',)),

     # Case A: yml file changes, expect the test playbook testing the integration to be collected
     (MockerCases.A_xsiam, ('myOtherTestPlaybook',), ('myXSIAMOnlyPack',), None, XSIAM_BRANCH_ARGS,
      ('Packs/myXSIAMOnlyPack/Integrations/myIntegration/myIntegration.yml',)),

     # Case A: py file changes, expect the test playbook testing the integration to be collected
     (MockerCases.A_xsiam, ('myOtherTestPlaybook',), ('myXSIAMOnlyPack',), None, XSIAM_BRANCH_ARGS,
      ('Packs/myXSIAMOnlyPack/Integrations/myIntegration/myIntegration.py',)),

     # Case B: test playbook changes, expect it to be collected
     (MockerCases.B_xsoar, ('myOtherTestPlaybook',), ('myXSOAROnlyPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myXSOAROnlyPack/TestPlaybooks/myOtherTestPlaybook.yml',)),

     # Case B: two test playbook change, expect both to be collected
     (MockerCases.B_xsoar, ('myOtherTestPlaybook', 'myTestPlaybook'), ('myXSOAROnlyPack',), None,
      XSOAR_BRANCH_ARGS, ('Packs/myXSOAROnlyPack/TestPlaybooks/myTestPlaybook.yml',
                          'Packs/myXSOAROnlyPack/TestPlaybooks/myOtherTestPlaybook.yml',)),

     (MockerCases.D, ('myTestPlaybook',), ('myPack',), (Machine.V6_5, Machine.MASTER,), XSOAR_BRANCH_ARGS,
      ('Packs/myPack/TestPlaybooks/myTestPlaybook.yml',)),

     (MockerCases.E, ('myOtherTestPlaybook',), ('myPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myPack/TestPlaybooks/myOtherTestPlaybook.yml',)),

     # Playbook changes, expect its test playbook to be collected
     (MockerCases.E, ('myOtherTestPlaybook',), ('myPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myPack/Playbooks/myPlaybook.yml',)),

     # Script changes, expect its test playbook to be collected
     (MockerCases.F, ('myTestPlaybook',), ('myPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myPack/Scripts/myScript/myScript.yml',)),

     # Two test playbooks change, but myOtherTestPlaybook is ignored, so it should not be collected
     (MockerCases.I_xsoar, ('myTestPlaybook',), ('myXSOAROnlyPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myXSOAROnlyPack/TestPlaybooks/myOtherTestPlaybook.yml',
       'Packs/myXSOAROnlyPack/TestPlaybooks/myTestPlaybook.yml')),

     # Skipped integration changes - should not be collected
     (MockerCases.J, (), (), None, XSOAR_BRANCH_ARGS,
      ('Packs/myPack/Integrations/mySkippedIntegration/mySkippedIntegration.yml',)),

     # Integration is changed but its test playbook is skipped - pack should be collected, test should not.
     (MockerCases.K, (), ('myPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myPack/Integrations/mySkippedIntegration/mySkippedIntegration.yml',)),

     # Testing version ranges
     (MockerCases.L, None, ('myXSIAMOnlyPack',), (Machine.MASTER, Machine.V6_9), XSIAM_BRANCH_ARGS,
      ('Packs/myXSIAMOnlyPack/Wizards/harry.json',)),

     (MockerCases.M2, None, ('myXSOAROnlyPack',), None, XSOAR_BRANCH_ARGS,
      ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.py',)),

     ))
def test_branch(
        monkeypatch,
        mocker,
        case_mocker,
        expected_tests: set[str],
        expected_packs: tuple[str, ...],
        expected_machines: Optional[tuple[Machine, ...]],
        collector_class_args: tuple[str, ...],
        mocked_changed_files: tuple[str, ...]
):
    mocker.patch.object(BranchTestCollector, '_get_changed_files', return_value=mocked_changed_files)
    _test(monkeypatch, case_mocker, collector_class=BranchTestCollector,
          expected_tests=expected_tests, expected_packs=expected_packs, expected_machines=expected_machines,
          collector_class_args=collector_class_args)


def test_branch_non_xsoar_support_level(mocker, monkeypatch):
    # # Integration with support level != xsoar - should raise an exception
    mocker.patch.object(BranchTestCollector, '_get_changed_files',
                        return_value=('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.yml',))
    with pytest.raises(ValueError) as e:
        _test(monkeypatch, MockerCases.M1, BranchTestCollector, (), (), (), XSOAR_BRANCH_ARGS)
    assert 'is (1) missing from conf.json' in str(e.value)  # checking it's the right error


ONLY_COLLECT_PACK_TYPES = {
    # see docstring of the test using this set
    FileType.RELEASE_NOTES_CONFIG,
    FileType.RELEASE_NOTES,
    FileType.IMAGE,
    FileType.DESCRIPTION,
    FileType.METADATA,
    FileType.RELEASE_NOTES_CONFIG,
    FileType.INCIDENT_TYPE,
    FileType.INCIDENT_FIELD,
    FileType.INDICATOR_FIELD,
    FileType.LAYOUT,
    FileType.WIDGET,
    FileType.DASHBOARD,
    FileType.REPORT,
    FileType.PARSING_RULE,
    FileType.MODELING_RULE,
    FileType.CORRELATION_RULE,
    FileType.XSIAM_DASHBOARD,
    FileType.XSIAM_REPORT,
    FileType.GENERIC_TYPE,
    FileType.GENERIC_FIELD,
    FileType.GENERIC_MODULE,
    FileType.GENERIC_DEFINITION,
    FileType.PRE_PROCESS_RULES,
    FileType.JOB,
    FileType.CONNECTION,
    FileType.RELEASE_NOTES_CONFIG,
    FileType.XSOAR_CONFIG,
    FileType.AUTHOR_IMAGE,
    FileType.CHANGELOG,
    FileType.DOC_IMAGE,
    FileType.BUILD_CONFIG_FILE,
    FileType.WIZARD,
    FileType.TRIGGER,
    FileType.LISTS,
    FileType.CONF_JSON,
    FileType.MODELING_RULE_SCHEMA,
    FileType.LAYOUTS_CONTAINER,
}


def test_only_collect_pack_args():
    """
    comparing the test_only_collect_packs arguments (ONLY_INSTALL_PACK_FILE_TYPES) match constants.ONLY_COLLECT_PACK_TYPES
    Any change there will require a change here.
    """
    from Tests.scripts.collect_tests.constants import \
        ONLY_INSTALL_PACK_FILE_TYPES
    assert ONLY_COLLECT_PACK_TYPES == ONLY_INSTALL_PACK_FILE_TYPES


def test_only_collect_and_ignore_lists_are_disjoint():
    from Tests.scripts.collect_tests.constants import (
        IGNORED_FILE_TYPES, ONLY_INSTALL_PACK_FILE_TYPES)
    assert ONLY_INSTALL_PACK_FILE_TYPES.isdisjoint(IGNORED_FILE_TYPES)


def test_file_types_with_specific_collection_logic_are_not_ignored():
    """
    the files listed have a specific logic under _collect_single,
    hence they must not be ignored or cause only a pack-installation
    """
    from Tests.scripts.collect_tests.constants import (
        IGNORED_FILE_TYPES, ONLY_INSTALL_PACK_FILE_TYPES)

    assert {
        FileType.PYTHON_FILE,
        FileType.POWERSHELL_FILE,
        FileType.JAVASCRIPT_FILE,
        FileType.REPUTATION,
        FileType.MAPPER,
        FileType.CLASSIFIER
    }.isdisjoint(IGNORED_FILE_TYPES | ONLY_INSTALL_PACK_FILE_TYPES)


@pytest.mark.parametrize('file_type', ONLY_COLLECT_PACK_TYPES)
def test_only_collect_pack(mocker, monkeypatch, file_type: collect_tests.FileType):
    """
    give    a content item type for which no tests should be collected
    when    collecting with a BranchTestCollector
    then    make sure the pack is collected, but tests are not
    """
    # test mockers
    mocker.patch.object(BranchTestCollector, '_get_changed_files', return_value=('Packs/myPack/some_file',))
    mocker.patch('Tests.scripts.collect_tests.collect_tests.find_type', return_value=file_type)

    # noinspection PyTypeChecker
    _test(monkeypatch, case_mocker=MockerCases.H, collector_class=BranchTestCollector,
          expected_tests=(), expected_packs=('myPack',), expected_machines=None, collector_class_args=XSOAR_BRANCH_ARGS)


def test_invalid_content_item(mocker, monkeypatch):
    """
    given:  a changed file that _get_changed_files is not designed to collect
    when:   collecting tests
    then:   make sure nothing is collected, and no exception is raised
    """
    # test mockers
    mocker.patch.object(BranchTestCollector, '_get_changed_files', return_value=('Packs/myPack/some_file',))

    _test(monkeypatch, case_mocker=MockerCases.H, collector_class=BranchTestCollector,
          expected_tests=(), expected_packs=(), expected_machines=None,
          collector_class_args=XSOAR_BRANCH_ARGS)
