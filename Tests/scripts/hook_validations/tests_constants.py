INVALID_PLAYBOOK_PATH = "./Tests/scripts/hook_validations/tests/tests_data/Playbooks.playbook-invalid.yml"
VALID_TEST_PLAYBOOK_PATH = "./Tests/scripts/hook_validations/tests/tests_data/Playbooks.playbook-test.yml"
VALID_INTEGRATION_TEST_PATH = "./Tests/scripts/hook_validations/tests/tests_data/integration-test.yml"
VALID_INTEGRATION_ID_PATH = "./Tests/scripts/hook_validations/tests/tests_data/integration-valid-id-test.yml"
INVALID_INTEGRATION_ID_PATH = "./Tests/scripts/hook_validations/tests/tests_data/integration-invalid-id-test.yml"
VALID_PLAYBOOK_ID_PATH = "./Tests/scripts/hook_validations/tests/tests_data/playbook-valid-id-test.yml"
INVALID_PLAYBOOK_ID_PATH = "./Tests/scripts/hook_validations/tests/tests_data/playbook-invalid-id-test.yml"
VALID_REPUTATION_PATH = "./Tests/scripts/hook_validations/tests/tests_data/reputations-valid.json"
INVALID_REPUTATION_PATH = "./Tests/scripts/hook_validations/tests/tests_data/reputations-invalid.json"
VALID_LAYOUT_PATH = "./Tests/scripts/hook_validations/tests/tests_data/layout-valid.json"
INVALID_LAYOUT_PATH = "./Tests/scripts/hook_validations/tests/tests_data/layout-invalid.json"
VALID_WIDGET_PATH = "./Tests/scripts/hook_validations/tests/tests_data/widget-valid.json"
INVALID_WIDGET_PATH = "./Tests/scripts/hook_validations/tests/tests_data/widget-invalid.json"
VALID_DASHBOARD_PATH = "./Tests/scripts/hook_validations/tests/tests_data/dashboard-valid.json"
INVALID_DASHBOARD_PATH = "./Tests/scripts/hook_validations/tests/tests_data/dashboard-invalid.json"
VALID_INCIDENT_FIELD_PATH = "./Tests/scripts/hook_validations/tests/tests_data/incidentfield-valid.json"
INVALID_INCIDENT_FIELD_PATH = "./Tests/scripts/hook_validations/tests/tests_data/incidentfield-invalid.json"
INVALID_WIDGET_VERSION_PATH = "./Tests/scripts/hook_validations/tests/tests_data/widget-invalid-version.json"
VALID_SCRIPT_PATH = "./Tests/scripts/hook_validations/tests/tests_data/script-valid.yml"
INVALID_SCRIPT_PATH = "./Tests/scripts/hook_validations/tests/tests_data/script-invalid.yml"
BANG_COMMAND_NAMES = {'file', 'email', 'domain', 'url', 'ip'}
DBOT_SCORES_DICT = {
    'DBotScore.Indicator': 'The indicator that was tested.',
    'DBotScore.Type': 'The indicator type.',
    'DBotScore.Vendor': 'The vendor used to calculate the score.',
    'DBotScore.Score': 'The actual score.'
}

IOC_OUTPUTS_DICT = {
    'domain': {'Domain.Name'},
    'file': {'File.MD5', 'File.SHA1', 'File.SHA256'},
    'ip': {'IP.Address'},
    'url': {'URL.Data'}
}
