# dirs
INTEGRATIONS_DIR = "Integrations"
SCRIPTS_DIR = "Scripts"
PLAYBOOKS_DIR = "Playbooks"
TEST_PLAYBOOKS_DIR = "TestPlaybooks"
REPORTS_DIR = "Reports"
DASHBOARDS_DIR = "Dashboards"
WIDGETS_DIR = "Widgets"
INCIDENT_FIELDS_DIR = "IncidentFields"
LAYOUTS_DIR = "Layouts"
CLASSIFIERS_DIR = "Classifiers"
MISC_DIR = "Misc"
CONNECTIONS_DIR = "Connections"
BETA_INTEGRATIONS_DIR = "Beta_Integrations"

# file types regexes
PIPFILE_REGEX = r".*\Pipfile"
TEST_DATA_REGEX = r".*test_data.*"
IMAGE_REGEX = r".*\.png"
CONF_REGEX = "Tests/conf.json"
SCRIPT_TYPE_REGEX = ".*script-.*.yml"
SCRIPT_PY_REGEX = r"{}.*\.py$".format(SCRIPTS_DIR)
SCRIPT_JS_REGEX = r"{}.*\.js$".format(SCRIPTS_DIR)
SCRIPT_YML_REGEX = r"{}.*\.yml$".format(SCRIPTS_DIR)
TEST_SCRIPT_REGEX = r"{}.*script-.*\.yml$".format(TEST_PLAYBOOKS_DIR)
SCRIPT_REGEX = r"{}.*script-.*\.yml$".format(SCRIPTS_DIR)
INTEGRATION_PY_REGEX = r"{}.*\.py$".format(INTEGRATIONS_DIR)
INTEGRATION_JS_REGEX = r"{}.*\.js$".format(INTEGRATIONS_DIR)
INTEGRATION_YML_REGEX = r"{}.*\.yml$".format(INTEGRATIONS_DIR)
INTEGRATION_REGEX = r"{}.*integration-.*\.yml$".format(INTEGRATIONS_DIR)
PLAYBOOK_REGEX = r"(?!Test){}.*playbook-.*\.yml$".format(PLAYBOOKS_DIR)
TEST_PLAYBOOK_REGEX = r"{}.*playbook-.*\.yml$".format(TEST_PLAYBOOKS_DIR)
TEST_NOT_PLAYBOOK_REGEX = r"{}.(?!playbook).*-.*\.yml$".format(TEST_PLAYBOOKS_DIR)

WIDGETS_REGEX = r"{}.*widget-.*\.json$".format(WIDGETS_DIR)
DASHBOARD_REGEX = r"{}.*dashboard-.*\.json$".format(DASHBOARDS_DIR)
CONNECTIONS_REGEX = r"{}.*canvas-context-connections.*\.json$".format(CONNECTIONS_DIR)
CLASSIFIER_REGEX = r"{}.*classifier-.*\.json$".format(CLASSIFIERS_DIR)
LAYOUT_REGEX = r"{}.*layout-.*\.json$".format(LAYOUTS_DIR)
INCIDENT_FIELDS_REGEX = r"{}.*incidentfields.*\.json$".format(INCIDENT_FIELDS_DIR)
INCIDENT_FIELD_REGEX = r"{}.*incidentfield-.*\.json$".format(INCIDENT_FIELDS_DIR)
MISC_REGEX = r"{}.*reputations.*\.json$".format(MISC_DIR)
REPORT_REGEX = r"{}.*report-.*\.json$".format(REPORTS_DIR)

BETA_SCRIPT_REGEX = r"{}.*script-.*\.yml$".format(BETA_INTEGRATIONS_DIR)
BETA_PLAYBOOK_REGEX = r"{}.*playbook-.*\.yml$".format(BETA_INTEGRATIONS_DIR)
BETA_INTEGRATION_REGEX = r"{}.*integration-.*\.yml$".format(BETA_INTEGRATIONS_DIR)

CHECKED_TYPES_REGEXES = [INTEGRATION_REGEX, PLAYBOOK_REGEX, SCRIPT_REGEX, INTEGRATION_YML_REGEX,
                         WIDGETS_REGEX, DASHBOARD_REGEX, CONNECTIONS_REGEX, CLASSIFIER_REGEX, SCRIPT_YML_REGEX,
                         LAYOUT_REGEX, INCIDENT_FIELDS_REGEX, INCIDENT_FIELD_REGEX, MISC_REGEX, REPORT_REGEX]

PACKAGE_SUPPORTING_DIRECTORIES = [INTEGRATIONS_DIR, SCRIPTS_DIR]

KNOWN_FILE_STATUSES = ['a', 'm', 'd'] + ['r{:03}'.format(i) for i in range(101)]

CODE_FILES_REGEX = [INTEGRATION_JS_REGEX, INTEGRATION_PY_REGEX, SCRIPT_PY_REGEX, SCRIPT_JS_REGEX]

SCRIPTS_REGEX_LIST = [SCRIPT_YML_REGEX, SCRIPT_PY_REGEX, SCRIPT_JS_REGEX]

TYPE_TO_EXTENSION = {
    'python': '.py',
    'javascript': '.js'
}
