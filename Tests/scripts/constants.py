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

PACKS_INTEGRATION_PY_REGEX = r'{}/([^/]+)/Integrations/([^/]+)/([^.]+).py'.format(PACKS_DIR)
# TODO
PACKS_INTEGRATION_YML_REGEX = r'{}/([^/]+)/Integrations/([^/]+)/([^.]+).yml'.format(PACKS_DIR)
PACKS_INTEGRATION_README_REGEX = r'{}/([^/]+)/Integrations/([^/]+)/CHANGELOG.md'.format(PACKS_DIR)
PACKS_SCRIPT_YML_REGEX = r'{}/([^/]+)/Scripts/([^/]+)/([^.]+).yml'.format(PACKS_DIR)
PACKS_SCRIPT_PY_REGEX = r'{}/([^/]+)/Scripts/([^/]+)/([^.]+).py'.format(PACKS_DIR)
PACKS_PLAYBOOK_YML = r'{}/([^/]+)/Playbooks/([^.]+).yml'.format(PACKS_DIR)

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
