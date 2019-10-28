import re

# dirs
INTEGRATIONS_DIR = 'Integrations'
SCRIPTS_DIR = 'Scripts'
PLAYBOOKS_DIR = 'Playbooks'
TEST_PLAYBOOKS_DIR = 'TestPlaybooks'
REPORTS_DIR = 'Reports'
DASHBOARDS_DIR = 'Dashboards'
WIDGETS_DIR = 'Widgets'
INCIDENT_FIELDS_DIR = 'IncidentFields'
LAYOUTS_DIR = 'Layouts'
CLASSIFIERS_DIR = 'Classifiers'
MISC_DIR = 'Misc'
CONNECTIONS_DIR = 'Connections'
BETA_INTEGRATIONS_DIR = 'Beta_Integrations'

# file types regexes
PIPFILE_REGEX = r'.*/Pipfile(\.lock)?'
TEST_DATA_REGEX = r'.*test_data.*'
DOCS_REGEX = r'.*docs.*'
IMAGE_REGEX = r'.*\.png$'
DESCRIPTION_REGEX = r'.*\.md'
CONF_REGEX = 'Tests/conf.json'
SCHEMA_REGEX = 'Tests/schemas/.*.yml'

SCRIPT_TYPE_REGEX = '.*script-.*.yml'
SCRIPT_PY_REGEX = r'{}/([^\\/]+)/\1.py$'.format(SCRIPTS_DIR)
SCRIPT_JS_REGEX = r'{}/([^\\/]+)/\1.js$'.format(SCRIPTS_DIR)
SCRIPT_YML_REGEX = r'{}/([^\\/]+)/\1.yml$'.format(SCRIPTS_DIR)
TEST_SCRIPT_REGEX = r'{}.*script-.*\.yml$'.format(TEST_PLAYBOOKS_DIR)
SCRIPT_REGEX = r'{}/(script-[^\\/]+)\.yml$'.format(SCRIPTS_DIR)

INTEGRATION_PY_REGEX = r'{}/([^\\/]+)/\1.py$'.format(INTEGRATIONS_DIR)
INTEGRATION_JS_REGEX = r'{}/([^\\/]+)/\1.js$'.format(INTEGRATIONS_DIR)
INTEGRATION_YML_REGEX = r'{}/([^\\/]+)/\1.yml$'.format(INTEGRATIONS_DIR)
INTEGRATION_REGEX = r'{}/(integration-[^\\/]+)\.yml$'.format(INTEGRATIONS_DIR)
INTEGRATION_README_REGEX = r'{}/([^\\/]+)/README.md$'.format(INTEGRATIONS_DIR)

BETA_SCRIPT_REGEX = r'{}/(script-[^\\/]+)\.yml$'.format(BETA_INTEGRATIONS_DIR)
BETA_INTEGRATION_REGEX = r'{}/(integration-[^\\/]+)\.yml$'.format(BETA_INTEGRATIONS_DIR)
BETA_INTEGRATION_YML_REGEX = r'{}/([^\\/]+)/\1.yml$'.format(BETA_INTEGRATIONS_DIR)
BETA_PLAYBOOK_REGEX = r'{}.*playbook-.*\.yml$'.format(BETA_INTEGRATIONS_DIR)

PLAYBOOK_REGEX = r'(?!Test){}/playbook-.*\.yml$'.format(PLAYBOOKS_DIR)
TEST_PLAYBOOK_REGEX = r'{}/playbook-.*\.yml$'.format(TEST_PLAYBOOKS_DIR)
TEST_NOT_PLAYBOOK_REGEX = r'{}/(?!playbook).*-.*\.yml$'.format(TEST_PLAYBOOKS_DIR)


WIDGETS_REGEX = r'{}/widget-.*\.json$'.format(WIDGETS_DIR)
DASHBOARD_REGEX = r'{}.*dashboard-.*\.json$'.format(DASHBOARDS_DIR)
CONNECTIONS_REGEX = r'{}.*canvas-context-connections.*\.json$'.format(CONNECTIONS_DIR)
CLASSIFIER_REGEX = r'{}.*classifier-.*\.json$'.format(CLASSIFIERS_DIR)
LAYOUT_REGEX = r'{}.*layout-.*\.json$'.format(LAYOUTS_DIR)
INCIDENT_FIELD_REGEX = r'{}/incidentfield-.*\.json$'.format(INCIDENT_FIELDS_DIR)
MISC_REGEX = r'{}.*reputations.*\.json$'.format(MISC_DIR)
REPUTATION_REGEX = r'{}.*reputation-.*\.json$'.format(MISC_DIR)
REPORT_REGEX = r'{}.*report-.*\.json$'.format(REPORTS_DIR)
MISC_REPUTATIONS_REGEX = r'{}.reputations.json$'.format(MISC_DIR)


CHECKED_TYPES_REGEXES = [PLAYBOOK_REGEX, BETA_PLAYBOOK_REGEX,
                         INTEGRATION_YML_REGEX, BETA_INTEGRATION_YML_REGEX, INTEGRATION_REGEX, BETA_INTEGRATION_REGEX,
                         WIDGETS_REGEX, DASHBOARD_REGEX, CONNECTIONS_REGEX, CLASSIFIER_REGEX,
                         SCRIPT_YML_REGEX, SCRIPT_REGEX,
                         LAYOUT_REGEX,
                         INCIDENT_FIELD_REGEX,
                         MISC_REGEX,
                         REPORT_REGEX,
                         REPUTATION_REGEX]

PACKAGE_SUPPORTING_DIRECTORIES = [INTEGRATIONS_DIR, SCRIPTS_DIR, BETA_INTEGRATIONS_DIR]

IGNORED_TYPES_REGEXES = [DESCRIPTION_REGEX, IMAGE_REGEX, PIPFILE_REGEX]


PACKAGE_YML_FILE_REGEX = r'(?:\./)?(?:Integrations|Scripts)/([^\\/]+)/\1.yml'

OLD_YML_FORMAT_FILE = [INTEGRATION_REGEX, SCRIPT_REGEX]

DIR_LIST = [
    INTEGRATIONS_DIR,
    SCRIPTS_DIR,
    PLAYBOOKS_DIR,
    TEST_PLAYBOOKS_DIR,
    REPORTS_DIR,
    DASHBOARDS_DIR,
    WIDGETS_DIR,
    INCIDENT_FIELDS_DIR,
    LAYOUTS_DIR,
    CLASSIFIERS_DIR,
    MISC_DIR,
    CONNECTIONS_DIR,
    BETA_INTEGRATIONS_DIR
]

SPELLCHECK_FILE_TYPES = [
    INTEGRATION_REGEX,
    INTEGRATION_YML_REGEX,
    PLAYBOOK_REGEX,
    SCRIPT_REGEX,
    SCRIPT_YML_REGEX
]

KNOWN_FILE_STATUSES = ['a', 'm', 'd', 'r'] + ['r{:03}'.format(i) for i in range(101)]

CODE_FILES_REGEX = [INTEGRATION_JS_REGEX, INTEGRATION_PY_REGEX, SCRIPT_PY_REGEX, SCRIPT_JS_REGEX]

SCRIPTS_REGEX_LIST = [SCRIPT_YML_REGEX, SCRIPT_PY_REGEX, SCRIPT_JS_REGEX]

TYPE_TO_EXTENSION = {
    'python': '.py',
    'javascript': '.js'
}

FILE_TYPES_FOR_TESTING = [
    '.py',
    '.js',
    '.yml'
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
