import os
from Tests.test_utils import checked_type


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

class TestPacksRegex:
    from Tests.scripts.constants import PACK