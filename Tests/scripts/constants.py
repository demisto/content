import re


class Errors(object):
    BACKWARDS = "Possible backwards compatibility break"

    @staticmethod
    def wrong_filename(filepath, file_type):
        return '{} is not a valid {} filename.'.format(filepath, file_type)

    @staticmethod
    def wrong_path(filepath):
        return "{} is not a valid filepath.".format(filepath)

    @staticmethod
    def wrong_version(file_path, expected="-1"):
        return "{}: The version for our files should always be {}, please update the file.".format(expected, file_path)

    @staticmethod
    def wrong_version_reputations(file_path, object_id, version):
        return "{} Reputation object with id {} must have version {}".format(file_path, object_id, version)

    @staticmethod
    def dbot_invalid_output(file_path, command_name, missing_outputs, context_standard):
        return "{}: The DBotScore outputs of the reputation command {} aren't valid. Missing: {}. " \
               "Fix according to context standard {} ".format(file_path, command_name, missing_outputs,
                                                              context_standard)

    @staticmethod
    def dbot_invalid_description(file_path, command_name, missing_descriptions, context_standard):
        return "{}: The DBotScore description of the reputation command {} aren't valid. Missing: {}. " \
               "Fix according to context standard {} " \
            .format(file_path, command_name, missing_descriptions, context_standard)

    @staticmethod
    def missing_reputation(file_path, command_name, reputation_output, context_standard):
        return "{}: The outputs of the reputation command {} aren't valid. The {} outputs is missing. " \
               "Fix according to context standard {} " \
            .format(file_path, command_name, reputation_output, context_standard)

    @staticmethod
    def wrong_subtype(file_name):
        return "{}: The subtype for our yml files should be either python2 or python3, " \
               "please update the file.".format(file_name)

    @staticmethod
    def beta_in_str(file_path, field):
        return "{}: Field '{}' should NOT contain the substring \"beta\" in a new beta integration. " \
               "please change the id in the file.".format(field, file_path)

    @classmethod
    def beta_in_id(cls, file_path):
        return cls.beta_in_str(file_path, 'id')

    @classmethod
    def beta_in_name(cls, file_path):
        return cls.beta_in_str(file_path, 'name')

    @staticmethod
    def duplicate_arg_in_file(script_path, arg, command_name=None):
        err_msg = "{}: The argument '{}' is duplicated".format(script_path, arg)
        if command_name:
            err_msg += " in '{}'.".format(command_name)
        err_msg += ", please remove one of its appearances."
        return err_msg

    @staticmethod
    def duplicate_param(param_name, file_path):
        return "{}: The parameter '{}' of the " \
               "file is duplicated, please remove one of its appearances.".format(file_path, param_name)

    @staticmethod
    def added_required_fields(file_path, field):
        return "You've added required fields in the file '{}', the field is '{}'".format(file_path, field)

    @staticmethod
    def from_version_modified_after_rename():
        return "fromversion might have been modified, please make sure it hasn't changed."

    @staticmethod
    def from_version_modified(file_path):
        return "{}: You've added fromversion to an existing file in the system, this is not allowed, please undo.".format(
            file_path)

    @classmethod
    def breaking_backwards_no_old_script(cls, e):
        return "{}\n{}, Could not find the old file.".format(cls.BACKWARDS, str(e))

    @classmethod
    def breaking_backwards_subtype(cls, file_path):
        return "{}: {}, You've changed the subtype, please undo.".format(file_path, cls.BACKWARDS)

    @classmethod
    def breaking_backwards_context(cls, file_path):
        return "{}: {}, You've changed the context in the file," \
               " please undo.".format(file_path, cls.BACKWARDS)

    @classmethod
    def breaking_backwards_command(cls, file_path, old_command):
        return "{}: {}, You've changed the context in the file,please " \
               "undo. the command is:\n{}".format(file_path, cls.BACKWARDS, old_command)

    @classmethod
    def breaking_backwards_docker(cls, file_path, old_docker, new_docker):
        return "{}: {}, You've changed the docker for the file," \
               " this is not allowed. Old: {}, New: {} ".format(file_path, cls.BACKWARDS, old_docker, new_docker)

    @classmethod
    def breaking_backwards_arg_changed(cls, file_path):
        return "{}: {}, You've changed the name of an arg in " \
               "the file, please undo.".format(file_path, cls.BACKWARDS)

    @classmethod
    def breaking_backwards_command_arg_changed(cls, file_path, command):
        return "{}: {}, You've changed the name of a command or its arg in" \
               " the file, please undo, the command was:\n{}".format(file_path, cls.BACKWARDS, command)

    @staticmethod
    def no_beta_in_display(file_path):
        return "{} :Field 'display' in Beta integration yml file should include the string \"beta\", but was not found" \
               " in the file.".format(file_path)

    @staticmethod
    def id_might_changed():
        return "ID might have changed, please make sure to check you have the correct one."

    @staticmethod
    def id_changed(file_path):
        return "{}: You've changed the ID of the file, please undo.".format(file_path)

    @staticmethod
    def file_id_contains_slashes():
        return "File's ID contains slashes - please remove."

    @staticmethod
    def missing_release_notes(file_path, rn_path):
        return '{}:  is missing releaseNotes, Please add it under {}'.format(file_path, rn_path)

    @staticmethod
    def display_param(param_name, param_display):
        return 'The display name of the {} parameter should be \'{}\''.format(param_name, param_display)

    @staticmethod
    def wrong_file_extension(file_extension, accepted_extensions):
        return "File extension {} is not valid. accepted {}".format(file_extension, accepted_extensions)

    @staticmethod
    def might_need_release_notes(file_path):
        return "{}: You might need RN in file, please make sure to check that.".format(file_path)

    @staticmethod
    def unknown_file(file_path):
        return "{}:  File type is unknown, check it out.".format(file_path)

    @staticmethod
    def wrong_default_argument(file_path, arg_name, command_name):
        return "{}: The argument '{}' of the command '{}' is not configured as default" \
            .format(file_path, arg_name, command_name)

    @staticmethod
    def wrong_display_name(param_name, param_display):
        return 'The display name of the {} parameter should be \'{}\''.format(param_name, param_display)

    @staticmethod
    def wrong_default_parameter(param_name):
        return 'The default value of the {} parameter should be \'\''.format(param_name)

    @staticmethod
    def wrong_required_value(param_name):
        return 'The required field of the {} parameter should be False'.format(param_name)

    @staticmethod
    def wrong_required_type(param_name):
        return 'The type field of the {} parameter should be 8'.format(param_name)

    @staticmethod
    def beta_field_not_found(file_path):
        return "{}: Beta integration yml file should have the field \"beta: true\", but was not found in the file." \
            .format(file_path)

    @staticmethod
    def no_default_arg(file_path, command_name):
        return "{}: Could not find default argument {} in command {}".format(file_path, command_name, command_name)

    @staticmethod
    def wrong_category(file_path, category):
        return "{}: The category '{}' is not in the integration schemas, the valid options are:\n{}" \
            .format(file_path, category, '\n'.join(INTEGRATION_CATEGORIES))


# dirs
CAN_START_WITH_DOT_SLASH = '(?:./)?'
INTEGRATIONS_DIR = 'Integrations'
SCRIPTS_DIR = 'Scripts'
PLAYBOOKS_DIR = 'Playbooks'
TEST_PLAYBOOKS_DIR = 'TestPlaybooks'
REPORTS_DIR = 'Reports'
DASHBOARDS_DIR = 'Dashboards'
WIDGETS_DIR = 'Widgets'
INCIDENT_FIELDS_DIR = 'IncidentFields'
INCIDENT_TYPES_DIR = 'IncidentTypes'
INDICATOR_FIELDS_DIR = 'IndicatorFields'
LAYOUTS_DIR = 'Layouts'
CLASSIFIERS_DIR = 'Classifiers'
MISC_DIR = 'Misc'
CONNECTIONS_DIR = 'Connections'
BETA_INTEGRATIONS_DIR = 'Beta_Integrations'
PACKS_DIR = 'Packs'

DEFAULT_IMAGE_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAMAAAC5zwKfAAACYVBMVEVHcEwAT4UAT4UAT4YAf/8A//8AT4UAf78AT4U' \
                       'AT4UAT4UAUYcAT4YAT4YAT48AXIsAT4UAT4UAUIUAUIUAT4UAT4UAVaoAW5EAUIYAWYwAT4UAT4UAT4UAUIgAT4YAUo' \
                       'UAUIYAUIUAT4YAVY0AUIUAT4UAUIUAUocAUYUAT4UAT4UAT4UAUIYAT4UAUIUAT4cAUYUAUIUAUIYAUocAT4UAUIUAT' \
                       '4YAUY4AUIUAUIYAT4UAVYgAT4UAT4UAT4YAVYUAT4UAT4UAT4YAT4cAT4UAT4UAUYYAZpkAWIUAT4UAT4gAbZEAT4UA' \
                       'UIYAT4UAUIUAT4cAUYgAT4UAZpkAT4UAT4UAT4UAVaoAUIUAT4UAWIkAT4UAU4kAUIUAUIUAU4gAT4UAT4UAT4UAVYg' \
                       'AUIUAT4YAVYkAUYUAT4UAU4cAUIYAUIUAT4gAUIYAVYsAT4YAUocAUYUAUIYAUYgAT4UAT4UAT4UAT4UAUYUAU4UAUY' \
                       'gAT4UAVY0AUIUAUIUAT4UAT4cAT4oAVY0AUYcAUIcAUIUAUIYAUIcAUYcAUIUAT4UAT4UAUIUAT4UAX58AT4UAUIUAU' \
                       'IYAT4UAUIYAUIgAT4UAT4UAUIUAT4UAUIUAT4YAT4UAUIYAT4YAUYkAT4UAUYYAUIUAT4UAT4YAT4YAT4YAT4cAUokA' \
                       'T4UAT4YAUIUAT4UAT4YAUIUAT4UAUIoAT4YAT4UAT4UAT4UAT4UAUIUAT4UAT4YAT4UAUYYAT4YAUYUAT4UAT4YAT4U' \
                       'AUoUAT4UAT4UAUIYAT4YAUIcAYokAT4UAT4UA65kA0ZYAu5PCXoiOAAAAx3RSTlMA+nO6AgG5BP799i9wShAL9/uVzN' \
                       'rxAw6JFLv08EmWKLyPmhI/x88+ccjz4WjtmU1F76VEoFbXGdKMrh71+K0qoZODIMuzSAoXni0H4HnjfnccQwXDjT0Gi' \
                       '/wa5zSCaSvBsWMPb9EnLMoxe3hHOSG+Ilh/S1BnzvJULjimCayy6UAwG1VPta91UVLNgJvZCNBcRuVsPIbb37BllNjC' \
                       'fTLsbrjukKejYCVtqb/5aqiXI9W0tnad4utdt2HEa1ro5EHWpBOBYg3JeEoS2QAAA5lJREFUGBmtwQN7Y0sABuAvbZK' \
                       'T1Ha3tt2ubdu2vXu517Zt27a+TH/VbXgmaTIz53nyvtDaV1+JdDrxHVvzkD43D5BsyUe6bKxmUP0qJNM2Y/Pxud9bMH' \
                       'd5DsNmlmGa/E8ZsvgumHqikFHzPUhgVTGipBxmun20LUCCw4zZAiPtjPMs4r3MmGvbYGA9E6yD7CwlN0FvPac5CckDl' \
                       'LRBK4dJPAxbDiXvQ+c9H5OZQMwW2lZDJ7eQyQ1vQsR+2j6ARnYnU6nKQ8gdtA1Co6mLqXX1AXBf72GUa6EbGmuotCvT' \
                       'u4tRBcOfQ+sATQ2cqoSBF2go6xiMtNNQA8zkH6GZ0zBU/mLFYEcBtbbCiVtrM6lxEA6NVFOpHk6d9lPpbjjVSKWCvXB' \
                       'oHzUyFyG1vuFzM3Yi3rfUqL5/E5Jzv8spz+chjpdao7VIag9D3kAcLw14szHd7h0MGfVAVkITvj/PI4H1OCNyITlPQ6' \
                       '7eDYjTzqirFmy9NDZnwRhsy0sZsw4xzX46kDVRiahHaPNleBD2+wDJSSGZpNK1v8sRstJP2StDFoDsXh+niIBEUOM/h' \
                       'NzLBDWtD/UwTAQkghr/IGgrFURAIqg2WoagzVQQAYmg2nUELaWKCEgEla56EFRMFRGQCCpdQtBlKomARFClA0GecSqJ' \
                       'gERQZSOCLlBNBCSCCucQZJVQTQQkggpnEHSFGiIgEQx76nhrDRPch5BiaoiARHCKv6gOgNW/n7LCOoT8e7GUSpNCMkm' \
                       'y5xmEeTJ8tBUh6q+K2XTA34yYPYx5qxK25Q0FNFYEmzXOqJ8RZ2eRi2Z8syDpY8RiNxIsmu+niSOQuR9liCsb0638ig' \
                       'a+RJwMhpxCUv1fUGsJ4jSt5ZRGpGBldFKjBPHOznjzmyGkNusHahyFQ1eyqPQZnHqQSv4n4VQVlTovwKGD1Mi89Bica' \
                       'KZWVsstFd35MLSUZoqXwcxLNJQBI699TENzYWDs4mya+hBadYOFjFp9YMlaKuVAw5rYwagb93gA1HYxtefKoeaeyRjf' \
                       'GYTkeZlK6TxofE2bFxHWCibn6oeG+zfatiOmgsn4foHOPEqehu1VJrEXWkOU5EKyhtPkQO9OSjZAdpIJDsOAVcOYccR' \
                       'bSJnvExjZzphuJGigzf8jzBz6gxG3u5HAs4JRrhGYGmthkK9xFaYpu41hWbkwVzbyTsdHb59AMtsyGVTahnRZ9hPJ13' \
                       'cjfQ4V89djSKcm71Ho/A9KDXs8/9v7cAAAAABJRU5ErkJggg=='

# file types regexes
PIPFILE_REGEX = r'.*/Pipfile(\.lock)?'
TEST_DATA_REGEX = r'.*test_data.*'
DOCS_REGEX = r'.*docs.*'
IMAGE_REGEX = r'.*\.png$'
DESCRIPTION_REGEX = r'.*\.md'
CONF_REGEX = 'Tests/conf.json'
SCHEMA_REGEX = 'Tests/schemas/.*.yml'

SCRIPT_TYPE_REGEX = '.*script-.*.yml'
SCRIPT_PY_REGEX = r'{}{}/([^\\/]+)/\1.py$'.format(CAN_START_WITH_DOT_SLASH, SCRIPTS_DIR)
SCRIPT_TEST_PY_REGEX = r'{}{}/([^\\/]+)/\1_test.py$'.format(CAN_START_WITH_DOT_SLASH, SCRIPTS_DIR)
SCRIPT_JS_REGEX = r'{}{}/([^\\/]+)/\1.js$'.format(CAN_START_WITH_DOT_SLASH, SCRIPTS_DIR)
SCRIPT_PS_REGEX = r'{}{}/([^\\/]+)/\1.ps1$'.format(CAN_START_WITH_DOT_SLASH, SCRIPTS_DIR)
SCRIPT_YML_REGEX = r'{}{}/([^\\/]+)/\1.yml$'.format(CAN_START_WITH_DOT_SLASH, SCRIPTS_DIR)
TEST_SCRIPT_REGEX = r'{}{}.*script-.*\.yml$'.format(CAN_START_WITH_DOT_SLASH, TEST_PLAYBOOKS_DIR)
SCRIPT_REGEX = r'{}{}/(script-[^\\/]+)\.yml$'.format(CAN_START_WITH_DOT_SLASH, SCRIPTS_DIR)

INTEGRATION_PY_REGEX = r'{}{}/([^\\/]+)/\1.py$'.format(CAN_START_WITH_DOT_SLASH, INTEGRATIONS_DIR)
INTEGRATION_TEST_PY_REGEX = r'{}{}/([^\\/]+)/\1_test.py$'.format(CAN_START_WITH_DOT_SLASH, INTEGRATIONS_DIR)
INTEGRATION_JS_REGEX = r'{}{}/([^\\/]+)/\1.js$'.format(CAN_START_WITH_DOT_SLASH, INTEGRATIONS_DIR)
INTEGRATION_PS_REGEX = r'{}{}/([^\\/]+)/\1.ps1$'.format(CAN_START_WITH_DOT_SLASH, INTEGRATIONS_DIR)
INTEGRATION_YML_REGEX = r'{}{}/([^\\/]+)/\1.yml$'.format(CAN_START_WITH_DOT_SLASH, INTEGRATIONS_DIR)
INTEGRATION_REGEX = r'{}{}/(integration-[^\\/]+)\.yml$'.format(CAN_START_WITH_DOT_SLASH, INTEGRATIONS_DIR)
INTEGRATION_README_REGEX = r'{}{}/([^\\/]+)/README.md$'.format(CAN_START_WITH_DOT_SLASH, INTEGRATIONS_DIR)

PACKS_DIR_REGEX = r'^{}{}/'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR)
PACKS_INTEGRATION_JS_REGEX = r'{}{}/([^/]+)/{}/([^/]+)/\2\.js'.format(
    CAN_START_WITH_DOT_SLASH, PACKS_DIR, INTEGRATIONS_DIR)
PACKS_SCRIPT_JS_REGEX = r'{}{}/([^/]+)/{}/([^/]+)/\2\.js'.format(
    CAN_START_WITH_DOT_SLASH, PACKS_DIR, SCRIPTS_DIR)
PACKS_INTEGRATION_PY_REGEX = r'{}{}/([^/]+)/{}/([^/]+)/\2\.py'.format(
    CAN_START_WITH_DOT_SLASH, PACKS_DIR, INTEGRATIONS_DIR)
PACKS_INTEGRATION_TEST_PY_REGEX = r'{}{}/([^/]+)/{}/([^/]+)/\2_test\.py'.format(
    CAN_START_WITH_DOT_SLASH, PACKS_DIR, INTEGRATIONS_DIR)
PACKS_INTEGRATION_YML_REGEX = r'{}{}/([^/]+)/{}/([^/]+)/([^.]+)\.yml'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR,
                                                                             INTEGRATIONS_DIR)
PACKS_INTEGRATION_REGEX = r'{}{}/([^/]+)/{}/([^/]+)\.yml'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR, INTEGRATIONS_DIR)
PACKS_SCRIPT_YML_REGEX = r'{}{}/([^/]+)/{}/([^/]+)/\2\.yml'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR, SCRIPTS_DIR)
PACKS_SCRIPT_PY_REGEX = r'{}{}/([^/]+)/{}/([^/]+)/\2\.py'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR, SCRIPTS_DIR)
PACKS_SCRIPT_TEST_PY_REGEX = r'{}{}/([^/]+)/{}/([^/]+)/\2_test\.py'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR,
                                                                           SCRIPTS_DIR)
PACKS_PLAYBOOK_YML_REGEX = r'{}{}/([^/]+)/{}/([^.]+)\.yml'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR, PLAYBOOKS_DIR)
PACKS_TEST_PLAYBOOKS_REGEX = r'{}{}/([^/]+)/{}/([^.]+)\.yml'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR,
                                                                    TEST_PLAYBOOKS_DIR)
PACKS_CLASSIFIERS_REGEX = r'{}{}/([^/]+)/{}/([^.]+)\.json'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR, CLASSIFIERS_DIR)
PACKS_DASHBOARDS_REGEX = r'{}{}/([^/]+)/{}/([^.]+)\.json'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR, DASHBOARDS_DIR)
PACKS_INCIDENT_TYPES_REGEX = r'{}{}/([^/]+)/{}/([^.]+)\.json'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR,
                                                                     INCIDENT_TYPES_DIR)
PACKS_INCIDENT_FIELDS_REGEX = r'{}{}/([^/]+)/{}/([^.]+)\.json'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR,
                                                                      INCIDENT_FIELDS_DIR)
PACKS_LAYOUTS_REGEX = r'{}{}/([^/]+)/{}/([^.]+)\.json'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR, LAYOUTS_DIR)
PACKS_WIDGETS_REGEX = r'{}{}/([^/]+)/{}/([^.]+)\.json'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR, WIDGETS_DIR)
PACKS_CHANGELOG_REGEX = r'{}{}/([^/]+)/CHANGELOG\.md'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR)
PACKS_README_REGEX = r'{}{}/([^/]+)/README\.md'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR)
PACKS_PACKAGE_META_REGEX = r'{}{}/([^/]+)/package-meta\.json'.format(CAN_START_WITH_DOT_SLASH, PACKS_DIR)

BETA_SCRIPT_REGEX = r'{}{}/(script-[^\\/]+)\.yml$'.format(CAN_START_WITH_DOT_SLASH, BETA_INTEGRATIONS_DIR)
BETA_INTEGRATION_REGEX = r'{}{}/(integration-[^\\/]+)\.yml$'.format(CAN_START_WITH_DOT_SLASH, BETA_INTEGRATIONS_DIR)
BETA_INTEGRATION_YML_REGEX = r'{}{}/([^\\/]+)/\1.yml$'.format(CAN_START_WITH_DOT_SLASH, BETA_INTEGRATIONS_DIR)
BETA_PLAYBOOK_REGEX = r'{}{}.*playbook-.*\.yml$'.format(CAN_START_WITH_DOT_SLASH, BETA_INTEGRATIONS_DIR)

PLAYBOOK_REGEX = r'{}(?!Test){}/playbook-.*\.yml$'.format(CAN_START_WITH_DOT_SLASH, PLAYBOOKS_DIR)
TEST_PLAYBOOK_REGEX = r'{}{}/playbook-.*\.yml$'.format(CAN_START_WITH_DOT_SLASH, TEST_PLAYBOOKS_DIR)
TEST_NOT_PLAYBOOK_REGEX = r'{}{}/(?!playbook).*-.*\.yml$'.format(CAN_START_WITH_DOT_SLASH, TEST_PLAYBOOKS_DIR)

INCIDENT_TYPE_REGEX = r'{}{}/incidenttype-.*\.json$'.format(CAN_START_WITH_DOT_SLASH, INCIDENT_TYPES_DIR)
INDICATOR_FIELDS_REGEX = r'{}{}/incidentfield-.*\.json$'.format(CAN_START_WITH_DOT_SLASH, INDICATOR_FIELDS_DIR)
WIDGETS_REGEX = r'{}{}/widget-.*\.json$'.format(CAN_START_WITH_DOT_SLASH, WIDGETS_DIR)
DASHBOARD_REGEX = r'{}{}.*dashboard-.*\.json$'.format(CAN_START_WITH_DOT_SLASH, DASHBOARDS_DIR)
CONNECTIONS_REGEX = r'{}{}.*canvas-context-connections.*\.json$'.format(CAN_START_WITH_DOT_SLASH, CONNECTIONS_DIR)
CLASSIFIER_REGEX = r'{}{}.*classifier-.*\.json$'.format(CAN_START_WITH_DOT_SLASH, CLASSIFIERS_DIR)
LAYOUT_REGEX = r'{}{}.*layout-.*\.json$'.format(CAN_START_WITH_DOT_SLASH, LAYOUTS_DIR)
INCIDENT_FIELD_REGEX = r'{}{}/incidentfield-.*\.json$'.format(CAN_START_WITH_DOT_SLASH, INCIDENT_FIELDS_DIR)
MISC_REGEX = r'{}{}.*reputations\.json$'.format(CAN_START_WITH_DOT_SLASH, MISC_DIR)
REPUTATION_REGEX = r'{}{}.*reputation-.*\.json$'.format(CAN_START_WITH_DOT_SLASH, MISC_DIR)
REPORT_REGEX = r'{}{}.*report-.*\.json$'.format(CAN_START_WITH_DOT_SLASH, REPORTS_DIR)
MISC_REPUTATIONS_REGEX = r'{}{}.reputations.json$'.format(CAN_START_WITH_DOT_SLASH, MISC_DIR)

PYTHON_TEST_REGEXES = [
    PACKS_SCRIPT_TEST_PY_REGEX,
    PACKS_INTEGRATION_TEST_PY_REGEX,
    INTEGRATION_TEST_PY_REGEX,
    SCRIPT_TEST_PY_REGEX
]

PYTHON_INTEGRATION_REGEXES = [
    INTEGRATION_PY_REGEX,
    PACKS_INTEGRATION_PY_REGEX,
]

PYTHON_SCRIPT_REGEXES = [
    SCRIPT_PY_REGEX,
    PACKS_SCRIPT_PY_REGEX
]

PYTHON_ALL_REGEXES = sum(
    [
        PYTHON_SCRIPT_REGEXES,
        PYTHON_INTEGRATION_REGEXES,
        PYTHON_TEST_REGEXES
    ], []
)

YML_INTEGRATION_REGEXES = [
    INTEGRATION_REGEX,
    PACKS_INTEGRATION_YML_REGEX,
    INTEGRATION_YML_REGEX,
]

YML_BETA_INTEGRATIONS_REGEXES = [
    BETA_INTEGRATION_REGEX,
    BETA_INTEGRATION_YML_REGEX,
]

YML_ALL_INTEGRATION_REGEXES = sum(
    [
        YML_INTEGRATION_REGEXES,
        YML_BETA_INTEGRATIONS_REGEXES,
    ], []
)

YML_BETA_SCRIPTS_REGEXES = [
    BETA_SCRIPT_REGEX,
]
YML_SCRIPT_REGEXES = [
    SCRIPT_REGEX,
    PACKS_SCRIPT_YML_REGEX,
    SCRIPT_YML_REGEX
]

YML_ALL_SCRIPTS_REGEXES = sum(
    [
        YML_BETA_SCRIPTS_REGEXES,
        YML_SCRIPT_REGEXES
    ], []
)

YML_PLAYBOOKS_NO_TESTS_REGEXES = [
    PLAYBOOK_REGEX,
    PACKS_PLAYBOOK_YML_REGEX,
    PLAYBOOK_REGEX,
]

YML_TEST_PLAYBOOKS_REGEXES = [
    TEST_PLAYBOOK_REGEX,
    PACKS_TEST_PLAYBOOKS_REGEX,
    TEST_PLAYBOOK_REGEX
]

YML_ALL_PLAYBOOKS_REGEX = sum(
    [
        YML_PLAYBOOKS_NO_TESTS_REGEXES,
        YML_TEST_PLAYBOOKS_REGEXES,
    ], []
)

YML_ALL_REGEXES = sum(
    [
        YML_INTEGRATION_REGEXES,
        YML_SCRIPT_REGEXES,
        YML_PLAYBOOKS_NO_TESTS_REGEXES,
        YML_TEST_PLAYBOOKS_REGEXES
    ], []
)

JSON_ALL_WIDGETS_REGEXES = [
    WIDGETS_REGEX,
    PACKS_WIDGETS_REGEX,
]

JSON_ALL_DASHBOARDS_REGEXES = [
    DASHBOARD_REGEX,
    PACKS_DASHBOARDS_REGEX,
]

JSON_ALL_CLASSIFIER_REGEXES = [
    CLASSIFIER_REGEX,
    PACKS_CLASSIFIERS_REGEX,
]

JSON_ALL_LAYOUT_REGEXES = [
    LAYOUT_REGEX,
    PACKS_LAYOUTS_REGEX,
]

JSON_ALL_INCIDENT_FIELD_REGEXES = [
    INCIDENT_FIELD_REGEX,
    PACKS_INCIDENT_FIELDS_REGEX,
]

JSON_ALL_INCIDENT_TYPES_REGEXES = [
    INCIDENT_TYPE_REGEX,
    PACKS_INCIDENT_TYPES_REGEX,
]

JSON_ALL_INDICATOR_FIELDS_REGEXES = [
    INDICATOR_FIELDS_REGEX,
]

JSON_ALL_CONNECTIONS_REGEXES = [
    CONNECTIONS_REGEX,
]

JSON_ALL_REPORTS_REGEXES = [
    REPORT_REGEX,
]

JSON_ALL_MISC_REGEXES = [
    MISC_REGEX,
    MISC_REPUTATIONS_REGEX,
]

BETA_REGEXES = [
    BETA_SCRIPT_REGEX,
    BETA_INTEGRATION_YML_REGEX,
    BETA_PLAYBOOK_REGEX,
]
CHECKED_TYPES_REGEXES = [
    # Playbooks
    PLAYBOOK_REGEX,
    PACKS_PLAYBOOK_YML_REGEX,
    BETA_PLAYBOOK_REGEX,
    # Integrations yaml
    INTEGRATION_YML_REGEX,
    BETA_INTEGRATION_YML_REGEX,
    PACKS_INTEGRATION_YML_REGEX,
    # Integrations unified
    INTEGRATION_REGEX,
    # Integrations Code
    BETA_INTEGRATION_REGEX,
    PACKS_INTEGRATION_PY_REGEX,
    # Integrations Tests
    PACKS_INTEGRATION_TEST_PY_REGEX,
    # Scripts yaml
    SCRIPT_YML_REGEX,
    SCRIPT_REGEX,
    # Widgets
    WIDGETS_REGEX,
    PACKS_WIDGETS_REGEX,
    DASHBOARD_REGEX,
    CONNECTIONS_REGEX,
    CLASSIFIER_REGEX,
    # Layouts
    LAYOUT_REGEX,
    PACKS_LAYOUTS_REGEX,
    INCIDENT_FIELD_REGEX,
    INDICATOR_FIELDS_REGEX,
    INCIDENT_TYPE_REGEX,
    MISC_REGEX,
    REPORT_REGEX,
    REPUTATION_REGEX
]

PATHS_TO_VALIDATE = sum(
    [
        PYTHON_ALL_REGEXES,
        JSON_ALL_REPORTS_REGEXES,
        JSON_ALL_MISC_REGEXES,
        BETA_REGEXES
    ], []
)

PACKAGE_SCRIPTS_REGEXES = [
    SCRIPT_YML_REGEX,
    SCRIPT_PY_REGEX,
    SCRIPT_JS_REGEX,
    PACKS_SCRIPT_PY_REGEX,
    PACKS_SCRIPT_JS_REGEX,
    PACKS_SCRIPT_YML_REGEX
]

PACKAGE_SUPPORTING_DIRECTORIES = [INTEGRATIONS_DIR, SCRIPTS_DIR, BETA_INTEGRATIONS_DIR]

IGNORED_TYPES_REGEXES = [DESCRIPTION_REGEX, IMAGE_REGEX, PIPFILE_REGEX, SCHEMA_REGEX]

PACKAGE_YML_FILE_REGEX = r'(?:\./)?(?:Integrations|Scripts)/([^\\/]+)/\1.yml'
PACKS_YML_FILE_REGEX = r'{}/([^/]+)/(?:{}|{})/([^/]+)/\2\.yml'.format(PACKS_DIR, INTEGRATIONS_DIR, SCRIPTS_DIR)

OLD_YML_FORMAT_FILE = [INTEGRATION_REGEX, SCRIPT_REGEX]

DIR_LIST = [
    INTEGRATIONS_DIR,
    BETA_INTEGRATIONS_DIR,
    SCRIPTS_DIR,
    PLAYBOOKS_DIR,
    TEST_PLAYBOOKS_DIR,
    REPORTS_DIR,
    DASHBOARDS_DIR,
    WIDGETS_DIR,
    INCIDENT_TYPES_DIR,
    INCIDENT_FIELDS_DIR,
    LAYOUTS_DIR,
    CLASSIFIERS_DIR,
    MISC_DIR,
    CONNECTIONS_DIR,
    INDICATOR_FIELDS_DIR,
]

SPELLCHECK_FILE_TYPES = [
    INTEGRATION_REGEX,
    INTEGRATION_YML_REGEX,
    PLAYBOOK_REGEX,
    SCRIPT_REGEX,
    SCRIPT_YML_REGEX
]

KNOWN_FILE_STATUSES = ['a', 'm', 'd', 'r'] + ['r{:03}'.format(i) for i in range(101)]

CODE_FILES_REGEX = [
    INTEGRATION_JS_REGEX,
    INTEGRATION_PY_REGEX,
    SCRIPT_PY_REGEX,
    SCRIPT_JS_REGEX,
    PACKS_INTEGRATION_PY_REGEX,
    PACKS_INTEGRATION_JS_REGEX,
    PACKS_SCRIPT_PY_REGEX,
    PACKS_SCRIPT_JS_REGEX
]

SCRIPTS_REGEX_LIST = [SCRIPT_YML_REGEX, SCRIPT_PY_REGEX, SCRIPT_JS_REGEX, SCRIPT_PS_REGEX]

# All files that have related yml file
REQUIRED_YML_FILE_TYPES = [SCRIPT_PY_REGEX, INTEGRATION_PY_REGEX, PACKS_INTEGRATION_PY_REGEX, PACKS_SCRIPT_PY_REGEX,
                           SCRIPT_JS_REGEX, INTEGRATION_JS_REGEX, PACKS_SCRIPT_JS_REGEX, PACKS_INTEGRATION_JS_REGEX,
                           PACKS_README_REGEX, INTEGRATION_README_REGEX]

TYPE_TO_EXTENSION = {
    'python': '.py',
    'javascript': '.js',
    'powershell': '.ps1'
}

FILE_TYPES_FOR_TESTING = [
    '.py',
    '.js',
    '.yml',
    '.ps1'
]

# python subtypes
PYTHON_SUBTYPES = {'python3', 'python2'}

# github repository url
CONTENT_GITHUB_LINK = r'https://raw.githubusercontent.com/demisto/content'
CONTENT_GITHUB_MASTER_LINK = CONTENT_GITHUB_LINK + '/master'

# Run all test signal
RUN_ALL_TESTS_FORMAT = 'Run all tests'
FILTER_CONF = './Tests/filter_file.txt'


class PB_Status:
    NOT_SUPPORTED_VERSION = 'Not supported version'
    COMPLETED = 'completed'
    FAILED = 'failed'
    IN_PROGRESS = 'inprogress'


# change log regexes
UNRELEASE_HEADER = '## [Unreleased]\n'
CONTENT_RELEASE_TAG_REGEX = r'^\d{2}\.\d{1,2}\.\d'
RELEASE_NOTES_REGEX = re.escape(UNRELEASE_HEADER) + r'([\s\S]+?)## \[\d{2}\.\d{1,2}\.\d\] - \d{4}-\d{2}-\d{2}'

# Beta integration disclaimer
BETA_INTEGRATION_DISCLAIMER = 'Note: This is a beta Integration,' \
                              ' which lets you implement and test pre-release software. ' \
                              'Since the integration is beta, it might contain bugs. ' \
                              'Updates to the integration during the beta phase might include ' \
                              'non-backward compatible features. We appreciate your feedback on ' \
                              'the quality and usability of the integration to help us identify issues, ' \
                              'fix them, and continually improve.'

# Integration categories according to the schema
INTEGRATION_CATEGORIES = ['Analytics & SIEM', 'Utilities', 'Messaging', 'Endpoint', 'Network Security',
                          'Vulnerability Management', 'Case Management', 'Forensics & Malware Analysis',
                          'IT Services', 'Data Enrichment & Threat Intelligence', 'Authentication', 'Database',
                          'Deception', 'Email Gateway']

EXTERNAL_PR_REGEX = r'^pull/(\d+)$'

SCHEMA_TO_VALIDATOR = {
    'integration': REPORT_REGEX,
    'playbook': YML_ALL_PLAYBOOKS_REGEX,
    'script': YML_SCRIPT_REGEXES,
    'widget': JSON_ALL_WIDGETS_REGEXES,
    'dashboard': JSON_ALL_DASHBOARDS_REGEXES,
    'canvas-context-connections': JSON_ALL_CONNECTIONS_REGEXES,
    'classifier': JSON_ALL_CLASSIFIER_REGEXES,
    'layout': JSON_ALL_LAYOUT_REGEXES,
    'incidentfield': JSON_ALL_INCIDENT_FIELD_REGEXES,
    'reports': JSON_ALL_REPORTS_REGEXES,
    'reputation': [MISC_REPUTATIONS_REGEX],
    'reputations': [MISC_REGEX]
}
