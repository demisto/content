import os
from Tests.test_utils import checked_type
import pytest
from Tests.scripts.constants import PACKS_INTEGRATION_PY_REGEX, PACKS_INTEGRATION_YML_REGEX, \
    PACKS_CHANGELOG_REGEX, PACKS_SCRIPT_YML_REGEX, PACKS_SCRIPT_PY_REGEX, PACKS_PLAYBOOK_YML_REGEX, \
    PACKS_TEST_PLAYBOOKS_REGEX, PACKS_CLASSIFIERS_REGEX, PACKS_DASHBOARDS_REGEX, PACKS_INCIDENT_TYPES_REGEX, \
    PACKS_PACKAGE_META_REGEX, PACKS_WIDGETS_REGEX, PACKS_INCIDENT_FIELDS_REGEX, PACKS_INTEGRATION_TEST_PY_REGEX, \
    PACKS_SCRIPT_TEST_PY_REGEX, PACKS_LAYOUTS_REGEX, INTEGRATION_PY_REGEX, SCRIPT_TEST_PY_REGEX, \
    INTEGRATION_TEST_PY_REGEX, PACKS_INTEGRATION_JS_REGEX, PACKS_SCRIPT_JS_REGEX


def verify(acceptable, unacceptable, matched_regex):
    for test_path in acceptable:
        assert checked_type(test_path, compared_regexes=matched_regex)

    for test_path in unacceptable:
        assert not checked_type(test_path, compared_regexes=matched_regex)


def get_test_code_file_paths(folder):
    acceptable_code_files = {
        # python
        os.path.join(folder, 'A', 'A.py'),
        os.path.join(folder, 'Gmail_v2', 'Gmail_v2.py'),
        os.path.join(folder, 'Z_as_as-ds', 'Z_as_as-ds.py'),
        os.path.join(folder, 'RSA-v11.1', 'RSA-v11.1.py'),

        # javascript
        os.path.join(folder, 'A', 'A.js'),
        os.path.join(folder, 'Gmail_v2', 'Gmail_v2.js'),
        os.path.join(folder, 'Z_as_as-ds', 'Z_as_as-ds.js'),
        os.path.join(folder, 'RSA-v11.1', 'RSA-v11.1.js'),
    }

    unacceptable_code_files = {
        # python
        os.path.join(folder, 'A\\A', 'A\\A.py'),
        os.path.join(folder, 'A/A', 'A/A.py'),
        os.path.join(folder, 'hello', 'world.py'),
        os.path.join(folder, 'hello', 'hello_test.py'),
        os.path.join(folder, 'hello', 'test_data', 'hello.py'),
        os.path.join(folder, 'RSA-v11.1', 'RSA-v11.1.pysomeextrachars'),

        # javascript
        os.path.join(folder, 'A\\A', 'A\\A.js'),
        os.path.join(folder, 'A/A', 'A/A.js'),
        os.path.join(folder, 'hello', 'world.js'),
        os.path.join(folder, 'hello', 'hello_test.js'),
        os.path.join(folder, 'hello', 'test_data', 'hello.js'),
        os.path.join(folder, 'RSA-v11.1', 'RSA-v11.1.jssomeextrachars'),
    }

    return acceptable_code_files, unacceptable_code_files


def test_integration_code_files():
    from Tests.scripts.constants import INTEGRATIONS_DIR, INTEGRATION_PY_REGEX, INTEGRATION_JS_REGEX

    acceptable_integration_code_files, unacceptable_integration_code_files = get_test_code_file_paths(INTEGRATIONS_DIR)

    verify(
        acceptable_integration_code_files,
        unacceptable_integration_code_files,
        (INTEGRATION_PY_REGEX, INTEGRATION_JS_REGEX)
    )


def test_script_code_files():
    from Tests.scripts.constants import SCRIPTS_DIR, SCRIPT_PY_REGEX, SCRIPT_JS_REGEX

    acceptable_script_code_files, unacceptable_script_code_files = get_test_code_file_paths(SCRIPTS_DIR)

    verify(
        acceptable_script_code_files,
        unacceptable_script_code_files,
        (SCRIPT_PY_REGEX, SCRIPT_JS_REGEX)
    )


def get_test_yml_file_paths(folder, prefix, legacy_only=False):
    acceptable_yml_files_package = {
        # package
        os.path.join(folder, 'A', 'A.yml'),
        os.path.join(folder, 'Gmail_v2', 'Gmail_v2.yml'),
        os.path.join(folder, 'Z_as_as-ds', 'Z_as_as-ds.yml'),
        os.path.join(folder, 'RSA-v11.1', 'RSA-v11.1.yml'),
    }

    acceptable_yml_files_legacy = {
        # legacy
        os.path.join(folder, '{}-A.yml'.format(prefix)),
        os.path.join(folder, '{}-Gmail_v2.yml'.format(prefix)),
        os.path.join(folder, '{}-Z_as_as-ds.yml'.format(prefix)),
        os.path.join(folder, '{}-RSA-v11.1.yml'.format(prefix)),
    }

    unacceptable_yml_files_package = {
        # package
        os.path.join(folder, 'A\\A', 'A\\A.yml'),
        os.path.join(folder, 'A/A', 'A/A.yml'),
        os.path.join(folder, 'hello', 'world.yml'),
        os.path.join(folder, 'hello', 'hello_test.yml'),
        os.path.join(folder, 'hello', 'test_data', 'hello.yml'),
        os.path.join(folder, 'RSA-v11.1', 'RSA-v11.1.ymlsomeextrachars'),
    }

    unacceptable_yml_files_legacy = {
        # legacy
        os.path.join(folder, 'A\\A', 'A\\A.yml'),
        os.path.join(folder, 'A/A', 'A/A.yml'),
        os.path.join(folder, '{}-hello'.format(prefix), 'hello.yml'),
        os.path.join(folder, 'hello', '{}-hello.yml'.format(prefix)),
        os.path.join(folder, '{}-RSA-v11.1.ymlsomeextrachars'.format(prefix)),
    }

    if legacy_only:
        return acceptable_yml_files_legacy, unacceptable_yml_files_legacy

    return (acceptable_yml_files_package.union(acceptable_yml_files_legacy),
            unacceptable_yml_files_package.union(unacceptable_yml_files_legacy))


def test_integration_yml_files():
    from Tests.scripts.constants import INTEGRATIONS_DIR, INTEGRATION_YML_REGEX, INTEGRATION_REGEX

    acceptable_integration_yml, unacceptable_integration_yml = get_test_yml_file_paths(INTEGRATIONS_DIR, 'integration')

    verify(
        acceptable_integration_yml,
        unacceptable_integration_yml,
        (INTEGRATION_YML_REGEX, INTEGRATION_REGEX),
    )


def test_script_yml_files():
    from Tests.scripts.constants import SCRIPTS_DIR, SCRIPT_YML_REGEX, SCRIPT_REGEX

    acceptable_integration_yml, unacceptable_integration_yml = get_test_yml_file_paths(SCRIPTS_DIR, 'script')

    verify(
        acceptable_integration_yml,
        unacceptable_integration_yml,
        (SCRIPT_YML_REGEX, SCRIPT_REGEX),
    )


def test_beta_script_yml_files():
    from Tests.scripts.constants import BETA_INTEGRATIONS_DIR, BETA_SCRIPT_REGEX

    acceptable_integration_yml, unacceptable_integration_yml = get_test_yml_file_paths(
        BETA_INTEGRATIONS_DIR,
        'script',
        legacy_only=True
    )

    verify(
        acceptable_integration_yml,
        unacceptable_integration_yml,
        (BETA_SCRIPT_REGEX,),
    )


def test_beta_integration_yml_files():
    from Tests.scripts.constants import BETA_INTEGRATIONS_DIR, BETA_INTEGRATION_YML_REGEX, BETA_INTEGRATION_REGEX

    acceptable_integration_yml, unacceptable_integration_yml = get_test_yml_file_paths(
        BETA_INTEGRATIONS_DIR,
        'integration',
    )

    verify(
        acceptable_integration_yml,
        unacceptable_integration_yml,
        (BETA_INTEGRATION_YML_REGEX, BETA_INTEGRATION_REGEX),
    )


test_packs_regex_params = [
    (['Packs/XDR/Integrations/XDR/XDR.py'],
     ['Packs/Integrations/XDR/XDR_test.py', 'Packs/Sade/Integrations/XDR/test_yarden.py'],
     [PACKS_INTEGRATION_PY_REGEX]),
    (['Packs/XDR/Integrations/XDR/XDR.js'],
     ['Packs/Integrations/XDR/XDR_test.js', 'Packs/Sade/Integrations/XDR/test_yarden.js'],
     [PACKS_INTEGRATION_JS_REGEX]),
    (['Packs/XDR/Integrations/XDR/XDR.yml'], ['Packs/Integrations/XDR/XDR_test.py'], [PACKS_INTEGRATION_YML_REGEX]),
    (['Packs/Sade/Integrations/XDR/XDR_test.py'], ['Packs/Sade/Integrations/yarden.py'],
     [PACKS_INTEGRATION_TEST_PY_REGEX]),

    (['Packs/XDR/Scripts/Random/Random.yml'], ['Packs/Scripts/Random/Random.py'], [PACKS_SCRIPT_YML_REGEX]),
    (['Packs/XDR/Scripts/Random/Random.py'], ['Packs/Scripts/Random/Random_test.py'], [PACKS_SCRIPT_PY_REGEX]),
    (['Packs/XDR/Scripts/Random/Random_test.py'], ['Packs/Sade/Scripts/test_yarden.pt'], [PACKS_SCRIPT_TEST_PY_REGEX]),
    (['Packs/XDR/Scripts/Random/Random.js'], ['Packs/Sade/Scripts/lo_yarden.py'], [PACKS_SCRIPT_JS_REGEX]),
    (['Packs/XDR/Playbooks/XDR.yml'], ['Packs/Playbooks/XDR/XDR_test.py'], [PACKS_PLAYBOOK_YML_REGEX]),
    (['Packs/XDR/TestPlaybooks/playbook.yml'], ['Packs/TestPlaybooks/nonpb.xml'], [PACKS_TEST_PLAYBOOKS_REGEX]),
    (['Packs/Sade/Classifiers/yarden.json'], ['Packs/Sade/Classifiers/yarden-json.txt'], [PACKS_CLASSIFIERS_REGEX]),
    (['Packs/Sade/Dashboards/yarden.json'], ['Packs/Sade/Dashboards/yarden-json.txt'], [PACKS_DASHBOARDS_REGEX]),
    (['Packs/Sade/IncidentTypes/yarden.json'], ['Packs/Sade/IncidentTypes/yarden-json.txt'],
     [PACKS_INCIDENT_TYPES_REGEX]),
    (['Packs/Sade/Widgets/yarden.json'], ['Packs/Sade/Widgets/yarden-json.txt'], [PACKS_WIDGETS_REGEX]),
    (['Packs/Sade/Layouts/yarden.json'], ['Packs/Sade/Layouts/yarden_json.yml'], [PACKS_LAYOUTS_REGEX]),
    (['Packs/Sade/package-meta.json'], ['Packs/Sade/Dashboards/yarden-json.txt'], [PACKS_PACKAGE_META_REGEX]),
    (['Packs/XDR/CHANGELOG.md'], ['Packs/Integrations/XDR/CHANGELOG.md'], [PACKS_CHANGELOG_REGEX]),
    (['Packs/Sade/IncidentFields/yarden.json'], ['Packs/Sade/IncidentFields/yarden-json.txt'],
     [PACKS_INCIDENT_FIELDS_REGEX]),
    (['Scripts/Sade/Sade_test.py'], ['Scripts/Sade/Sade.py'], [SCRIPT_TEST_PY_REGEX]),
    (['Integrations/Sade/Sade_test.py'], ['Integrations/Sade/test_Sade.py'], [INTEGRATION_TEST_PY_REGEX]),
]


@pytest.mark.parametrize('acceptable,non_acceptable,regex', test_packs_regex_params)
def test_packs_regex(acceptable, non_acceptable, regex):
    verify(acceptable, non_acceptable, regex)
