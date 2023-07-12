import os
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import pytest
from demisto_sdk.commands.common.constants import MarketplaceVersions

from Tests.scripts.collect_tests import collect_tests
# importing Machine,FileType from collect_tests (rather than utils) to compare class member values
from Tests.scripts.collect_tests.collect_tests import (
    BranchTestCollector, FileType, Machine, XSIAMNightlyTestCollector,
    XSOARNightlyTestCollector, UploadAllCollector)
from Tests.scripts.collect_tests.constants import (
    ALWAYS_INSTALLED_PACKS_MARKETPLACE_V2, MODELING_RULE_COMPONENT_FILES,
    XSOAR_SANITY_TEST_NAMES, ONLY_INSTALL_PACK_FILE_TYPES, XSIAM_COMPONENT_FILES)
from Tests.scripts.collect_tests.path_manager import PathManager
from Tests.scripts.collect_tests.utils import FilesToCollect, PackManager

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
- `J` has a single pack with two integrations, with mySkippedIntegration being skipped in conf.json,
      and a folder named Samples (should be ignored).
- `K` has a single pack with two integrations, with mySkippedIntegration's TPB skipped in conf.json.
- `L` has a single pack with a Wizard content item.
- `M1` has a pack with support level == xsoar, and tests missing from conf.json -- should raise an error.
- `M2` has a pack with support level != xsoar, and tests missing from conf.json -- should collect pack but not tests.
- `M3` has a pack with support level != xsoar -- should collect pack but not tests.
- `P` has a Test Playbook which uses a skipped integration - should not be collected.
- `Q` has a single pack with two integrations, with mySkippedIntegration being skipped in conf.json,
      and a folder named Samples (should be ignored).
- `MR1` has a pack with a modeling rule.
- `S` has 2 packs with support level == xsoar, each pack has its own integration and both of these integrations have
      "myOtherTestPlaybook" TPB that is not skipped in conf.json. The conf.json contains 2 records with the same
      playbook ID "myOtherTestPlaybook".
- `T` Reputation test collection test. one indicator type of reputation, and 3 test playbooks defined in the conf.json file
      under the "reputation_tests" list. Should collect all 3 tests.
- `PR1` has a pack with components for XSOAR and XSIAM, but the component for XSIAM is only parsing rule.
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
        self.previous_path_manager: PathManager | None = None

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
    M3 = CollectTestsMocker(TEST_DATA / 'M3')
    P = CollectTestsMocker(TEST_DATA / 'P')
    Q = CollectTestsMocker(TEST_DATA / 'Q')
    R = CollectTestsMocker(TEST_DATA / 'R')
    S = CollectTestsMocker(TEST_DATA / 'S')
    T = CollectTestsMocker(TEST_DATA / 'T')
    limited_nightly_packs = CollectTestsMocker(TEST_DATA / 'limited_nightly_packs')
    non_api_test = CollectTestsMocker(TEST_DATA / 'non_api_test')
    script_non_api_test = CollectTestsMocker(TEST_DATA / 'script_non_api_test')
    skipped_nightly_test = CollectTestsMocker(TEST_DATA / 'skipped_nightly_test')
    MR1 = CollectTestsMocker(TEST_DATA / 'MR1')
    RN_CONFIG = CollectTestsMocker(TEST_DATA / 'release_notes_config')
    PR1 = CollectTestsMocker(TEST_DATA / 'PR1')


ALWAYS_INSTALLED_PACKS = ('Base', 'DeveloperTools')


def _test(monkeypatch, case_mocker: CollectTestsMocker, collector_class: Callable,
          expected_tests: Iterable[str], expected_packs: Iterable[str], expected_packs_to_upload: Iterable[str],
          expected_machines: Optional[Iterable[Machine]],
          expected_modeling_rules_to_test: Optional[Iterable[str | Path]],
          collector_class_args: tuple[Any, ...] = ()):
    """
    Instantiates the given collector class, calls collect with run_nightly and asserts
    that the result packs and tests are expected ones.

    :param case_mocker: with which to run the test
    :param collector_class: the collector class to test.
    :param expected_tests: the expected test names. (pass None to not check)
    :param expected_packs: the expected pack names. (pass None to not check)
    :param expected_machines: the expected machines. (pass None to not check)
    :param expected_modeling_rules_to_test: the expected modeling rules directory names. (pass None to not check)
    :param collector_class_args: with which to instantiate the collector class.
    :return: Nothing: only calls assert.
    """
    monkeypatch.chdir(case_mocker.path_manager.content_path)
    with case_mocker:
        collector = collector_class(*collector_class_args)
        collected = collector.collect()

    if not any((expected_tests, expected_packs, expected_machines, expected_modeling_rules_to_test)):
        if not collected:
            # matches expectation
            return
        description = 'should NOT have collected '
        if collected.packs_to_install:
            description += f'packs_to_install: {collected.packs_to_install}. '
        if collected.packs_to_upload:
            description += f'packs_to_upload: {collected.packs_to_upload}. '
        if collected.tests:
            description += f'tests {collected.tests}'
        if collected.modeling_rules_to_test:
            description += f'modeling rules: {collected.modeling_rules_to_test}'

        assert False, description

    if collected is None:
        err_msg = (f'should have collected something: {expected_tests=}, {expected_packs=},'
                   f' {expected_machines=}, {expected_modeling_rules_to_test=}')
        assert False, err_msg

    if expected_tests is not None:
        assert collected.tests == set(expected_tests)

    assert collected.packs_to_install == set(expected_packs or ()) | set(ALWAYS_INSTALLED_PACKS)
    assert collected.packs_to_upload == set(expected_packs_to_upload or ())

    if expected_machines is not None:
        assert set(collected.machines) == set(expected_machines)

    if expected_modeling_rules_to_test is not None:
        assert collected.modeling_rules_to_test == set(expected_modeling_rules_to_test)

    assert Machine.MASTER in collected.machines

    for test in collected.tests:
        print(f'collected test {test}')
    for machine in collected.machines:
        print(f'machine {machine}')
    for pack in collected.packs_to_install:
        print(f'collected pack {pack}')
    for mr in collected.modeling_rules_to_test:
        print(f'collected modeling rule to test {mr}')


NIGHTLY_EXPECTED_TESTS = {'myTestPlaybook', 'myOtherTestPlaybook'}
NIGHTLY_EXPECTED_TESTS_XSIAM = NIGHTLY_EXPECTED_TESTS | {'Sanity Test - Playbook with Unmockable Whois Integration'}

NIGHTLY_TESTS: tuple = (
    (MockerCases.A_xsoar, XSOARNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSOAROnlyPack',), None, None),
    (MockerCases.B_xsoar, XSOARNightlyTestCollector, NIGHTLY_EXPECTED_TESTS, ('myXSOAROnlyPack',), None, None),
    (MockerCases.A_xsiam, XSIAMNightlyTestCollector, NIGHTLY_EXPECTED_TESTS_XSIAM,
     ('myXSIAMOnlyPack', 'Whois', 'CoreAlertFields'), None, None),
    (MockerCases.B_xsiam, XSIAMNightlyTestCollector, NIGHTLY_EXPECTED_TESTS_XSIAM,
     ('myXSIAMOnlyPack', 'Whois', 'CoreAlertFields'), None, None),

    (MockerCases.C, XSOARNightlyTestCollector,
     {'myXSOAROnlyTestPlaybook', 'myTestPlaybook', 'Sanity Test - Playbook with Unmockable Whois Integration'},
     {'bothMarketplacesPack', 'bothMarketplacesPackOnlyXSIAMIntegration', 'myXSOAROnlyPack', 'Whois'}, None, None),

    (MockerCases.C, XSIAMNightlyTestCollector,
     {'myXSIAMOnlyTestPlaybook', 'Sanity Test - Playbook with Unmockable Whois Integration'},
     {'myXSIAMOnlyPack', 'bothMarketplacesPackOnlyXSIAMIntegration', 'Whois', 'CoreAlertFields'}, None, None),

    (MockerCases.D, XSOARNightlyTestCollector, {'myTestPlaybook'}, {'myPack'},
     (Machine.V6_8, Machine.MASTER), None),

    (MockerCases.E, XSOARNightlyTestCollector,
     {'myTestPlaybook', 'myOtherTestPlaybook', 'Sanity Test - Playbook with Unmockable Whois Integration'},
     {'myPack', 'Whois'}, None, None),

    (MockerCases.E, XSIAMNightlyTestCollector,
     {'Sanity Test - Playbook with Unmockable Whois Integration'},
     ALWAYS_INSTALLED_PACKS_MARKETPLACE_V2 + ('Whois',),
     None, None),

    (MockerCases.F, XSOARNightlyTestCollector, {'myTestPlaybook', 'myOtherTestPlaybook'}, {'myPack'},
     None, None),

    (MockerCases.I_xsoar, XSOARNightlyTestCollector, {'myTestPlaybook'}, {'myXSOAROnlyPack'}, None, None),

    # cases where nightly_packs doesn't hold all packs
    (MockerCases.limited_nightly_packs, XSOARNightlyTestCollector, {'myTestPlaybook'}, {'myPack', 'myOtherPack'},
     None, None),

    (MockerCases.non_api_test, XSOARNightlyTestCollector, {'myTestPlaybook'}, {'myPack'}, None, None),

    (MockerCases.script_non_api_test, XSOARNightlyTestCollector, {'myTestPlaybook'}, {'myPack', 'myOtherPack'},
     None, None),

    (MockerCases.skipped_nightly_test, XSOARNightlyTestCollector, {}, {'myPack'}, None, None),

    # modeling rule testdata file exists, expect modeling rule to be collected
    (MockerCases.MR1, XSIAMNightlyTestCollector, (), ('MyXSIAMPack', 'CoreAlertFields'), None,
     (Path('MyXSIAMPack/ModelingRules/HarryRule'),)),

    # only parsing rule component exists, expect the pack to be collected for installation
    (MockerCases.PR1, XSIAMNightlyTestCollector, (), ('MyXSIAMPack', 'CoreAlertFields'), None,
     None),
)


@pytest.mark.parametrize(
    'case_mocker,collector_class,expected_tests,'
    'expected_packs,expected_machines,expected_modeling_rules_to_test', NIGHTLY_TESTS
)
def test_nightly(monkeypatch, case_mocker: CollectTestsMocker, collector_class: Callable, expected_tests: set[str],
                 expected_packs: tuple[str],
                 expected_machines: Optional[tuple[Machine]],
                 expected_modeling_rules_to_test: Optional[Iterable[str | Path]]):
    """
    given:  a content folder
    when:   collecting tests with a NightlyTestCollector
    then:   make sure tests are collected from integration and id_set
    """
    _test(monkeypatch, case_mocker=case_mocker, collector_class=collector_class,
          expected_tests=expected_tests, expected_packs=expected_packs, expected_packs_to_upload={},
          expected_machines=expected_machines,
          expected_modeling_rules_to_test=expected_modeling_rules_to_test)


XSOAR_BRANCH_ARGS = ('master', MarketplaceVersions.XSOAR, None)
XSIAM_BRANCH_ARGS = ('master', MarketplaceVersions.MarketplaceV2, None)


@pytest.mark.parametrize(
    'case_mocker,expected_tests,expected_packs,expected_machines,expected_modeling_rules_to_test,'
    'collector_class_args,mocked_changed_files,mocked_packs_files_were_moved_from,expected_packs_to_upload',
    (
        # (0) change in a sanity-collection-triggering file, expecting xsoar sanity tests to be collected
        (MockerCases.empty, XSOAR_SANITY_TEST_NAMES, ('Whois', 'HelloWorld'), None, None, XSOAR_BRANCH_ARGS,
         ('.gitlab/helper_functions.sh',), (), ()),

        # (1) Empty content folder: expecting XSIAM collector to not collect anything
        (MockerCases.empty, (), (), None, None, XSIAM_BRANCH_ARGS, (), (), None),

        # (2) Case A, yml file changes, expect the test playbook testing the integration to be collected
        (MockerCases.A_xsoar, ('myOtherTestPlaybook',), ('myXSOAROnlyPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.yml',), (), ('myXSOAROnlyPack',)),

        # (3) Case A, py file changes, expect the test playbook testing the integration to be collected
        (MockerCases.A_xsoar, ('myOtherTestPlaybook',), ('myXSOAROnlyPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.py',), (), ('myXSOAROnlyPack',)),

        # (4) Case A: yml file changes, expect the test playbook testing the integration to be collected
        (MockerCases.A_xsiam, ('myOtherTestPlaybook',), ('myXSIAMOnlyPack', 'CoreAlertFields'), None, None,
         XSIAM_BRANCH_ARGS, ('Packs/myXSIAMOnlyPack/Integrations/myIntegration/myIntegration.yml',), (),
         ('myXSIAMOnlyPack',)),

        # (5) Case A: py file changes, expect the test playbook testing the integration to be collected
        (MockerCases.A_xsiam, ('myOtherTestPlaybook',), ('myXSIAMOnlyPack', 'CoreAlertFields'), None, None,
         XSIAM_BRANCH_ARGS, ('Packs/myXSIAMOnlyPack/Integrations/myIntegration/myIntegration.py',), (),
         ('myXSIAMOnlyPack',)),

        # (6) Case B: test playbook changes, expect it to be collected
        (MockerCases.B_xsoar, ('myOtherTestPlaybook',), ('myXSOAROnlyPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myXSOAROnlyPack/TestPlaybooks/myOtherTestPlaybook.yml',), (), ('myXSOAROnlyPack',)),

        # (7) Case B: two test playbook change, expect both to be collected
        (MockerCases.B_xsoar, ('myOtherTestPlaybook', 'myTestPlaybook'), ('myXSOAROnlyPack',), None, None,
         XSOAR_BRANCH_ARGS, ('Packs/myXSOAROnlyPack/TestPlaybooks/myTestPlaybook.yml',
                             'Packs/myXSOAROnlyPack/TestPlaybooks/myOtherTestPlaybook.yml',), (),
         ('myXSOAROnlyPack',)),

        # (8) Case D: playbook changes, expect it and its pack to be collected
        (MockerCases.D, ('myTestPlaybook',), ('myPack',), (Machine.V6_8, Machine.MASTER,), None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/TestPlaybooks/myTestPlaybook.yml',), (), ('myPack',)),

        # (9) Case D: playbook changes, expect it and its pack to be collected
        (MockerCases.E, ('myOtherTestPlaybook',), ('myPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/TestPlaybooks/myOtherTestPlaybook.yml',), (), ('myPack',)),

        # (10) Playbook changes, expect its test playbook to be collected
        (MockerCases.E, ('myOtherTestPlaybook',), ('myPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/Playbooks/myPlaybook.yml',), (), ('myPack',)),

        # (11) Script changes, expect its test playbook to be collected
        (MockerCases.F, ('myTestPlaybook',), ('myPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/Scripts/myScript/myScript.yml',), (), ('myPack',)),

        # (12) Two test playbooks change, but myOtherTestPlaybook is ignored, so it should not be collected
        (MockerCases.I_xsoar, ('myTestPlaybook',), ('myXSOAROnlyPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myXSOAROnlyPack/TestPlaybooks/myOtherTestPlaybook.yml',
          'Packs/myXSOAROnlyPack/TestPlaybooks/myTestPlaybook.yml'), (), ('myXSOAROnlyPack',)),

        # (13) Skipped integration changes - should not be collected
        (MockerCases.J, (), (), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/Integrations/mySkippedIntegration/mySkippedIntegration.yml',), (), None),

        # (14) test data file changes - should not be collected
        (MockerCases.J, (), (), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/Integrations/myIntegration/test_data/file.json',), (), None),

        # (15) a file under ParsingRules/Samples is changed, nothing should be collected.
        (MockerCases.J, (), (), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/ParsingRules/Samples/some_sample.json',),
         (), None),

        # (16) Integration is changed but its test playbook is skipped - pack should be collected, test should not.
        (MockerCases.K, (), ('myPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/Integrations/mySkippedIntegration/mySkippedIntegration.yml',), (), ('myPack',)),

        # (17) Testing version ranges
        (MockerCases.L, None, ('myXSIAMOnlyPack', 'CoreAlertFields'), (Machine.MASTER, Machine.V6_9), None,
         XSIAM_BRANCH_ARGS, ('Packs/myXSIAMOnlyPack/Wizards/harry.json',), (), ('myXSIAMOnlyPack',)),

        # (18) see M2 definition at the top of this file
        (MockerCases.M2, None, ('myXSOAROnlyPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.py',), (), ('myXSOAROnlyPack',)),

        # (19) see M3 definition at the top of this file - integration py file is changed
        (MockerCases.M3, None, ('myXSOAROnlyPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.py',), (), ('myXSOAROnlyPack',)),

        # (20) see M3 definition at the top of this file - integration yml file is changed
        (MockerCases.M3, None, ('myXSOAROnlyPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.yml',), (), ('myXSOAROnlyPack',)),

        # (21) see M3 definition at the top of this file - test playbook is changed
        (MockerCases.M3, None, ('myXSOAROnlyPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myXSOAROnlyPack/TestPlaybooks/myTestPlaybook.yml',), (), ('myXSOAROnlyPack',)),

        # (22) Test Playbook using skipped integration - should not be collected.
        (MockerCases.P, None, ('myPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/TestPlaybooks/myTestPlaybook.yml',), (), ('myPack',)),

        # (23) Old-formatted script changes, expecting its test playbook to be collected
        (MockerCases.F, ('myTestPlaybook',), ('myPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/Scripts/script-myScript.yml',), (), ('myPack',)),

        # (24) When content is moved between packs, both packs (old, new) should be collected
        (MockerCases.C, None, ('bothMarketplacesPack', 'bothMarketplacesPackOnlyXSIAMIntegration'), None, None,
         XSOAR_BRANCH_ARGS, (), ('bothMarketplacesPack', 'bothMarketplacesPackOnlyXSIAMIntegration'),
         ('bothMarketplacesPack', 'bothMarketplacesPackOnlyXSIAMIntegration')),

        # (25) Deprecated integration changes - should not be collected
        (MockerCases.Q, (), (), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/Integrations/myDeprecatedIntegration/myDeprecatedIntegration.yml',), (), None),

        # (26) Deprecated integration changes - should not be collected
        (MockerCases.Q, ('myTestPlaybook',), ('myPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/Integrations/myDeprecatedIntegration/myDeprecatedIntegration.yml',
          'Packs/myPack/Integrations/myIntegration/myIntegration.yml'), (), ('myPack',)),

        # (27) Packs for XSOAR & XSIAM will be collected only for upload,
        # test dependency and always install packs will collected only to install
        (MockerCases.R, None, ('bothMarketplacesPackOnlyXSIAMIntegration', 'myXSIAMOnlyPack', 'CoreAlertFields'),
         None,
         None, XSIAM_BRANCH_ARGS,
         ('Packs/bothMarketplacesPack/pack_metadata.json',
          'Packs/bothMarketplacesPackOnlyXSIAMIntegration/Integrations/onlyXSIAMIntegration/onlyXSIAMIntegration.yml'),
         (), ('bothMarketplacesPackOnlyXSIAMIntegration',)),

        # (28) Only packs with changes in XSOAR items will be collected to install and to upload.
        (MockerCases.R, None, ('bothMarketplacesPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/bothMarketplacesPack/pack_metadata.json',
          'Packs/bothMarketplacesPackOnlyXSIAMIntegration/Integrations/onlyXSIAMIntegration/onlyXSIAMIntegration.yml'),
         (), ('bothMarketplacesPack',)),

        # (29) modeling rule yml file is changed - expect the modeling rule dir to be marked
        (MockerCases.MR1, None, ('MyXSIAMPack', 'CoreAlertFields',), None,
         (Path('MyXSIAMPack/ModelingRules/HarryRule'),), XSIAM_BRANCH_ARGS,
         ('Packs/MyXSIAMPack/ModelingRules/HarryRule/HarryRule.yml',), (), ('MyXSIAMPack',)),

        # (30) modeling rule schema json file changed - expect the modeling rule dir to be marked
        (MockerCases.MR1, None, ('MyXSIAMPack', 'CoreAlertFields',), None,
         (Path('MyXSIAMPack/ModelingRules/HarryRule'),), XSIAM_BRANCH_ARGS,
         ('Packs/MyXSIAMPack/ModelingRules/HarryRule/HarryRule_schema.json',), (), ('MyXSIAMPack',)),

        # (31) modeling rule xif file is changed - expect the modeling rule dir to be marked
        (MockerCases.MR1, None, ('MyXSIAMPack', 'CoreAlertFields',), None,
         (Path('MyXSIAMPack/ModelingRules/HarryRule'),), XSIAM_BRANCH_ARGS,
         ('Packs/MyXSIAMPack/ModelingRules/HarryRule/HarryRule.xif',), (), ('MyXSIAMPack',)),

        # (32) modeling rule test data file is changed - expect the modeling rule dir to be marked
        (MockerCases.MR1, None, ('MyXSIAMPack', 'CoreAlertFields',), None,
         (Path('MyXSIAMPack/ModelingRules/HarryRule'),), XSIAM_BRANCH_ARGS,
         ('Packs/MyXSIAMPack/ModelingRules/HarryRule/HarryRule_testdata.json',), (), ('MyXSIAMPack',)),

        # (33) Release Notes Config
        (MockerCases.RN_CONFIG, (), ('myPack',), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/myPack/ReleaseNotes/2_1_3.json',), (), ('myPack',)),

        # (34) see S definition at the top of this file - one of the integration has been changed
        (MockerCases.S, ('myOtherTestPlaybook',), ('myXSOAROnlyPack', 'myXSOAROnlyPack2',), None, None,
         XSOAR_BRANCH_ARGS, ('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.yml',), (),
         ('myXSOAROnlyPack',)),

        # (35) see T definition at the top of this file - reputation indicator type test
        (MockerCases.T, ("FormattingPerformance - Test", "Email extraction test", "Domain extraction test"),
         ('Base', 'DeveloperTools', 'CommonTypes'), None, None, XSOAR_BRANCH_ARGS,
         ('Packs/CommonTypes/IndicatorTypes/reputation-domain.json',), (), ('CommonTypes',)),

        # (36) see PR1 definition at the top of this file - only parsing rules xif file was changed
        (MockerCases.PR1, (), ('MyXSIAMPack', 'CoreAlertFields',), None, None, XSIAM_BRANCH_ARGS,
         ('Packs/MyXSIAMPack/ParsingRules/MyParsingRules/MyParsingRules.xif',), (), ('MyXSIAMPack',)),

        # (37) see PR1 definition at the top of this file - only parsing rules yml file was changed
        (MockerCases.PR1, (), ('MyXSIAMPack', 'CoreAlertFields',), None, None, XSIAM_BRANCH_ARGS,
         ('Packs/MyXSIAMPack/ParsingRules/MyParsingRules/MyParsingRules.yml',), (), ('MyXSIAMPack',)),
    )
)
def test_branch(
        monkeypatch,
        mocker,
        case_mocker,
        expected_tests: Optional[set[str]],
        expected_packs: Optional[tuple[str, ...]],
        expected_machines: Optional[tuple[Machine, ...]],
        expected_modeling_rules_to_test: Optional[Iterable[str | Path]],
        collector_class_args: tuple[str, ...],
        mocked_changed_files: tuple[str, ...],
        mocked_packs_files_were_moved_from: tuple[str, ...],
        expected_packs_to_upload: Optional[tuple[str, ...]],
):
    mocker.patch.object(BranchTestCollector, '_get_git_diff',
                        return_value=FilesToCollect(mocked_changed_files, mocked_packs_files_were_moved_from))
    _test(monkeypatch, case_mocker, collector_class=BranchTestCollector,
          expected_tests=expected_tests, expected_packs=expected_packs,
          expected_packs_to_upload=expected_packs_to_upload,
          expected_machines=expected_machines, expected_modeling_rules_to_test=expected_modeling_rules_to_test,
          collector_class_args=collector_class_args)


def test_branch_test_missing_from_conf(mocker, monkeypatch):
    # Integration with support level == xsoar - should raise an exception
    mocker.patch.object(BranchTestCollector, '_get_git_diff',
                        return_value=FilesToCollect(
                            changed_files=('Packs/myXSOAROnlyPack/Integrations/myIntegration/myIntegration.yml',),
                            pack_ids_files_were_removed_from=()),
                        )
    with pytest.raises(ValueError) as e:
        _test(monkeypatch, MockerCases.M1, BranchTestCollector, (), (), (), (), (), XSOAR_BRANCH_ARGS)
    assert 'is (1) missing from conf.json' in str(e.value)  # checking it's the right error


ONLY_COLLECT_PACK_TYPES = {
    # see docstring of the test using this set
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
    FileType.REPORT,
    FileType.PARSING_RULE,
    FileType.MODELING_RULE,
    FileType.MODELING_RULE_TEST_DATA,
    FileType.MODELING_RULE_XIF,
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
    FileType.XDRC_TEMPLATE,
    FileType.PARSING_RULE_XIF,
    FileType.LAYOUT_RULE,
}


def test_only_collect_pack_args():
    """
    comparing the test_only_collect_packs arguments (ONLY_INSTALL_PACK_FILE_TYPES)
    match constants.ONLY_COLLECT_PACK_TYPES
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


def test_no_file_type_and_non_content_dir_files_are_ignored(mocker, monkeypatch):
    """
    give    a non-content item and unknown file type which no tests should be collected
    when    collecting with a BranchTestCollector
    then    make sure no tests are collected
    """
    mocker.patch('Tests.scripts.collect_tests.collect_tests.find_type', return_value=None)
    mocker.patch.object(BranchTestCollector, '_get_git_diff',
                        return_value=FilesToCollect(('Packs/myXSOAROnlyPack/NonContentItems/Empty.json',), ()))

    _test(monkeypatch, case_mocker=MockerCases.A_xsoar, collector_class=BranchTestCollector, expected_tests=(),
          expected_modeling_rules_to_test=(), expected_packs=(), expected_packs_to_upload=(),
          expected_machines=None, collector_class_args=XSOAR_BRANCH_ARGS)


@pytest.mark.parametrize('file_type', ONLY_COLLECT_PACK_TYPES)
def test_only_collect_pack(mocker, monkeypatch, file_type: collect_tests.FileType):
    """
    give    a content item type for which no tests should be collected
    when    collecting with a BranchTestCollector
    then    make sure the pack is collected, but tests are not
    """
    # test mockers
    mocker.patch.object(BranchTestCollector, '_get_git_diff',
                        return_value=FilesToCollect(('Packs/myPack/some_file',), ()))
    mocker.patch('Tests.scripts.collect_tests.collect_tests.find_type', return_value=file_type)

    # packs of xsiam component files aren't expected to be collected when collecting for an XSOAR marketplace build
    expected_packs = ('myPack',) if file_type not in (MODELING_RULE_COMPONENT_FILES | XSIAM_COMPONENT_FILES) else ()

    # noinspection PyTypeChecker
    _test(monkeypatch, case_mocker=MockerCases.H, collector_class=BranchTestCollector,
          expected_tests=(), expected_packs=expected_packs, expected_packs_to_upload=('myPack',),
          expected_machines=None, expected_modeling_rules_to_test=None, collector_class_args=XSOAR_BRANCH_ARGS)


def test_invalid_content_item(mocker, monkeypatch):
    """
    given:  a changed file that _get_git_diff is not designed to collect
    when:   collecting tests
    then:   make sure nothing is collected, and no exception is raised
    """
    # test mockers
    mocker.patch.object(BranchTestCollector, '_get_git_diff',
                        return_value=FilesToCollect(('Packs/myPack/some_file',), ()))

    _test(monkeypatch, case_mocker=MockerCases.H, collector_class=BranchTestCollector,
          expected_tests=(), expected_packs=(), expected_packs_to_upload=(), expected_machines=None,
          expected_modeling_rules_to_test=None,
          collector_class_args=XSOAR_BRANCH_ARGS)


def test_release_note_config_in_only_install_pack():
    """
    Makes sure the FileType.RELEASE_NOTES_CONFIG is in ONLY_INSTALL_PACK_FILE_TYPES,
    as we have a special treatment for it under __collect_single.
    If this test fails, and you deliberatly removed it from the list, make sure to remove the special case (`except KeyError`...)
    """
    assert FileType.RELEASE_NOTES_CONFIG in ONLY_INSTALL_PACK_FILE_TYPES


def test_number_of_file_types():
    """
    The test collection assumes the list of FileType values does not change.
    If this unit test fails, it means that list has changed (in the SDK).
    Please make sure the change does not break test collection:
        - New type:     1. Add it to IGNORED_FILE_TYPES or ONLY_INSTALL_PACK
                        2. Create a PR and see collection works
                        3. Increase the number in this test

        - Removed type:    Decrease the number here.
    """
    assert len(FileType) == 76


@pytest.mark.parametrize(
    'case_mocker,expected_tests,expected_packs,expected_machines,expected_modeling_rules_to_test,'
    'collector_class_args,mocked_changed_files,mocked_packs_files_were_moved_from,expected_packs_to_upload',
    (
        (MockerCases.C, None,
         ('myXSOAROnlyPack', 'bothMarketplacesPack', 'bothMarketplacesPackOnlyXSIAMIntegration', 'Whois'), None,
         None, (MarketplaceVersions.XSOAR, None),
         ('.gitlab/helper_functions.sh',), (),
         ('myXSOAROnlyPack', 'bothMarketplacesPack', 'bothMarketplacesPackOnlyXSIAMIntegration', 'Whois')),

        (MockerCases.C, None, ('myXSIAMOnlyPack', 'CoreAlertFields'), None, None,
         (MarketplaceVersions.MarketplaceV2, None), (), (), (
             'myXSIAMOnlyPack', 'CoreAlertFields', 'bothMarketplacesPack',
             'bothMarketplacesPackOnlyXSIAMIntegration', 'Whois')),
    ), ids=('install_and_upload_all_xsoar', 'install_and_upload_all_xsiam'))
def test_upload_all_packs(monkeypatch, case_mocker, expected_tests: Optional[set[str]],
                          expected_packs: Optional[tuple[str, ...]],
                          expected_machines: Optional[tuple[Machine, ...]],
                          expected_modeling_rules_to_test: Optional[Iterable[str | Path]],
                          collector_class_args: tuple[str, ...],
                          mocked_changed_files: tuple[str, ...],
                          mocked_packs_files_were_moved_from: tuple[str, ...],
                          expected_packs_to_upload: Optional[tuple[str, ...]],
                          ):
    """
    given:  The override_all_packs flag.
    when:   Collecting tests for the upload flow.
    then:   Make sure all packs are collected to the pack_to_upload, and the pack_to_install list is empty.
    """
    _test(monkeypatch, case_mocker, collector_class=UploadAllCollector,
          expected_tests=expected_tests, expected_packs=expected_packs,
          expected_packs_to_upload=expected_packs_to_upload,
          expected_machines=expected_machines, expected_modeling_rules_to_test=expected_modeling_rules_to_test,
          collector_class_args=collector_class_args)
