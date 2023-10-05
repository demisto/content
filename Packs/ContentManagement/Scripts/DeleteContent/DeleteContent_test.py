import pytest

from DeleteContent import get_and_delete_needed_ids, CORE_PACKS_LIST_URL
from abc import ABC, abstractmethod
from typing import Tuple, Any


XSOAR_IDS_FULL_STATE = {
    'pack': ['installed_pack_id1', 'installed_pack_id2', 'Base'],
    'list': ['list1', 'list2'],
    'job': ['job1', 'job2'],
    'script': ['script1', 'script2', 'CommonUserServer'],
    'playbook': ['playbook1', 'playbook2'],
    'integration': ['integration1', 'integration2'],
    'incidentfield': ['incidentfield1', 'incidentfield2'],
    'pre-process-rule': ['pre-process-rule1', 'pre-process-rule2'],
    'widget': ['widget1', 'widget2'],
    'dashboard': ['dashboard1', 'dashboard2'],
    'report': ['report1', 'report2'],
    'incidenttype': ['incidenttype1', 'incidenttype2'],
    'classifier': ['classifier1', 'classifier2'],
    'reputation': ['reputation1', 'reputation2'],
    'layoutscontainer': ['layout1', 'layout2']
}


class MockEntityResponses(ABC):
    entity_name = ''

    def __init__(self, xsoar_state):
        self.xsoar_state_ids = xsoar_state.get(self.entity_name)

    @abstractmethod
    def search_response(self, command_name, command_args) -> Tuple[bool, Any]:
        pass

    @abstractmethod
    def delete_response(self, command_name, command_args) -> Tuple[bool, Any]:
        pass


class MockJobResponses(MockEntityResponses):
    entity_name = 'job'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/jobs/search':
            if command_args.get('body', {}).get('size') == 1:
                job_name = command_args.get('body', {}).get('query').split('name:"')[1].split('"')[0]
                if job_name in self.xsoar_state_ids:
                    # if search and found
                    return True, {'data': [{'name': job_name, 'id': job_name}]}

                # if search and not found
                return False, 'Id not found'

            # If search all return all
            return True, {'data': [{'name': job_name, 'id': job_name} for job_name in self.xsoar_state_ids]}
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('jobs/') and command_name == 'demisto-api-delete':
            job_name = command_uri.split('jobs/')[1]
            if job_name in self.xsoar_state_ids:
                return True, {'data': [{'name': job_name, 'id': job_name}]}
            return False, 'Id not found'
        return False, False


class MockListResponses(MockEntityResponses):
    entity_name = 'list'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/lists/download/'):
            list_name = command_uri.split('/lists/download/')[1]
            if list_name in self.xsoar_state_ids:
                return True, list_name
            return False, 'Id not found'

        if command_uri == '/lists/names':
            return True, self.xsoar_state_ids

        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/lists/delete':
            list_name = command_args.get('body').get('id')
            if list_name in self.xsoar_state_ids:
                return True, list_name
            return False, 'Id not found'
        return False, False


class MockPackResponses(MockEntityResponses):
    entity_name = 'pack'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_name == 'demisto-api-get' and command_uri.startswith('/contentpacks/installed/'):
            pack_name = command_uri.split('/contentpacks/installed/')[1]
            return (True, {'id': pack_name}) if pack_name in self.xsoar_state_ids else (False, 'Id not found')

        if command_name == 'demisto-api-get' and command_uri.startswith('/contentpacks/installed-expired'):
            return True, [{'id': pack_name} for pack_name in self.xsoar_state_ids]

        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_name == 'demisto-api-delete' and command_uri.startswith('/contentpacks/installed/'):
            pack_name = command_uri.split('/contentpacks/installed/')[1]
            return (True, {'id': pack_name}) if pack_name in self.xsoar_state_ids else (False, 'Id not found')
        return False, False


class MockScriptResponses(MockEntityResponses):
    entity_name = 'script'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/automation/search':
            if command_args.get('body', {}).get('size') == 1:
                script_name = command_args.get('body', {}).get('query').split('id:"')[1].split('"')[0]
                if script_name in self.xsoar_state_ids:
                    # if search and found
                    return True, {'scripts': [{'id': script_name}]}

                # if search and not found
                return False, 'Id not found'

            # If search all return all
            return True, {'scripts': [{'id': script_name} for script_name in self.xsoar_state_ids]}
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/automation/delete' and command_name == 'demisto-api-post':
            script_name = command_args.get('body', {}).get('script', {}).get('id', '')
            if script_name in self.xsoar_state_ids:
                return True, {'scripts': [{'id': script_name}]}
            return False, 'Id not found'
        return False, False


class MockPlaybookResponses(MockEntityResponses):
    entity_name = 'playbook'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_name == 'demisto-api-get' and command_uri.startswith('/playbook/'):
            name = command_uri.split('/playbook/')[1]
            if name in self.xsoar_state_ids:
                return True, {'id': name}
            return False, 'Id not found'

        if command_name == 'demisto-api-post' and command_uri == '/playbook/search':
            return True, {'playbooks': [{'id': name} for name in self.xsoar_state_ids]}

        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/playbook/delete':
            name = command_args.get('body', {}).get('id')
            if name in self.xsoar_state_ids:
                return True, {'id': name}
            return False, 'Id not found'
        return False, False


class MockIncidentFieldResponses(MockEntityResponses):
    entity_name = 'incidentfield'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/incidentfields' and command_name == 'demisto-api-get':
            return True, [{'id': name} for name in self.xsoar_state_ids]
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/incidentfield/') and command_name == 'demisto-api-delete':
            name = command_uri.split('/incidentfield/')[1]
            if name in self.xsoar_state_ids:
                return True, None
            return False, 'Id not found'
        return False, False


class MockIntegrationResponses(MockEntityResponses):
    entity_name = 'integration'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/settings/integration/search':
            if command_args.get('body', {}).get('query'):
                name = command_args.get('body', {}).get('query').split('name:"')[1].split('"')[0]
                if name in self.xsoar_state_ids:
                    # if search and found
                    return True, {'configurations': [{'id': name}]}

                # if search and not found
                return False, 'Id not found'

            # If search all return all
            return True, {'configurations': [{'id': name} for name in self.xsoar_state_ids]}
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/settings/integration-conf/delete' and command_name == 'demisto-api-post':
            name = command_args.get('body', {}).get('id')
            if name in self.xsoar_state_ids:
                return True, {'configurations': [{'id': name}]}
            return False, 'Id not found'
        return False, False


class MockPreprocessRuleResponses(MockEntityResponses):
    entity_name = 'pre-process-rule'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/preprocess/rules' and command_name == 'demisto-api-get':
            return True, [{'id': name} for name in self.xsoar_state_ids]
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/preprocess/rule/') and command_name == 'demisto-api-delete':
            name = command_uri.split('/preprocess/rule/')[1]
            if name in self.xsoar_state_ids:
                return True, None
            return False, 'Id not found'
        return False, False


class MockWidgetResponses(MockEntityResponses):
    entity_name = 'widget'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/widgets') and command_name == 'demisto-api-get':
            if command_uri.startswith('/widgets/'):
                name = command_uri.split('/widgets/')[1]
                if name in self.xsoar_state_ids:
                    return True, {'id': name}
                return True, 'Id not found'
            return True, [{'id': name} for name in self.xsoar_state_ids]
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/widgets/') and command_name == 'demisto-api-delete':
            name = command_uri.split('/widgets/')[1]
            if name in self.xsoar_state_ids:
                return True, None
            return False, 'Id not found'
        return False, False


class MockDashboardResponses(MockEntityResponses):
    entity_name = 'dashboard'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/dashboards') and command_name == 'demisto-api-get':
            if command_uri.startswith('/dashboards/'):
                name = command_uri.split('/dashboards/')[1]
                if name in self.xsoar_state_ids:
                    return True, {'id': name}
                return True, 'Id not found'
            return True, [{'id': name} for name in self.xsoar_state_ids]
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/dashboards/') and command_name == 'demisto-api-delete':
            name = command_uri.split('/dashboards/')[1]
            if name in self.xsoar_state_ids:
                return True, None
            return False, 'Id not found'
        return False, False


class MockReportResponses(MockEntityResponses):
    entity_name = 'report'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/reports') and command_name == 'demisto-api-get':
            if command_uri.startswith('/reports/'):
                name = command_uri.split('/reports/')[1]
                if name in self.xsoar_state_ids:
                    return True, {'id': name}
                return True, 'Id not found'
            return True, [{'id': name} for name in self.xsoar_state_ids]
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/report/') and command_name == 'demisto-api-delete':
            name = command_uri.split('/report/')[1]
            if name in self.xsoar_state_ids:
                return True, None
            return False, 'Id not found'
        return False, False


class MockIncidentTypeResponses(MockEntityResponses):
    entity_name = 'incidenttype'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/incidenttypes/export') and command_name == 'demisto-api-get':
            return True, [{'id': name} for name in self.xsoar_state_ids]
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/incidenttype/delete') and command_name == 'demisto-api-post':
            name = command_args.get('body', {}).get('id')
            if name in self.xsoar_state_ids:
                return True, None
            return False, 'Id not found'
        return False, False


class MockClassifierResponses(MockEntityResponses):
    entity_name = 'classifier'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri == '/classifier/search' and command_name == 'demisto-api-post':
            return True, {'classifiers': [{'id': name} for name in self.xsoar_state_ids]}
        if command_uri.startswith('/classifier/') and command_name == 'demisto-api-get':
            name = command_uri.split('/classifier/')[1]
            if name in self.xsoar_state_ids:
                return True, {'id': name}
            return False, 'Id not found'
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/classifier/') and command_name == 'demisto-api-delete':
            name = command_uri.split('/classifier/')[1]
            if name in self.xsoar_state_ids:
                return True, None
            return False, 'Id not found'
        return False, False


class MockReputationResponses(MockEntityResponses):
    entity_name = 'reputation'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/reputation/export') and command_name == 'demisto-api-get':
            return True, [{'id': name} for name in self.xsoar_state_ids]
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/reputation/') and command_name == 'demisto-api-delete':
            name = command_uri.split('/reputation/')[1]
            if name in self.xsoar_state_ids:
                return True, None
            return False, 'Id not found'
        return False, False


class MockLayoutResponses(MockEntityResponses):
    entity_name = 'layoutscontainer'

    def search_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/layout/') and command_name == 'demisto-api-get':
            name = command_uri.split('/layout/')[1]
            if name in self.xsoar_state_ids:
                return True, {'id': name}
            return False, 'Id not Found'
        if command_uri == '/layouts' and command_name == 'demisto-api-get':
            return True, [{'id': name} for name in self.xsoar_state_ids]
        return False, False

    def delete_response(self, command_name, command_args):
        command_uri = command_args.get('uri')
        if command_uri.startswith('/layout/') and command_uri.endswith('/remove') and command_name == 'demisto-api-post':
            name = command_uri.split('/layout/')[1]
            name = name.split('/remove')[0]
            if name in self.xsoar_state_ids:
                return True, None
            return False, 'Id not found'
        return False, False


def mock_demisto_responses(command_name, command_args, xsoar_ids_state):
    """Mock function for demisto responses to api calls according to xsoar ids state.

    Args:
        command_name (str): The command name sent to the executeCommand demisto function.
        command_args (dict): The command args sent to the executeCommand demisto function.
        xsoar_ids_state (dict): A representation for the content ids in an xsoar instance.

    Returns:
        status, demisto response
    """
    mocked_entities = [MockJobResponses(xsoar_ids_state), MockPackResponses(xsoar_ids_state),
                       MockListResponses(xsoar_ids_state), MockScriptResponses(xsoar_ids_state),
                       MockPlaybookResponses(xsoar_ids_state), MockIntegrationResponses(xsoar_ids_state),
                       MockIncidentFieldResponses(xsoar_ids_state), MockPreprocessRuleResponses(xsoar_ids_state),
                       MockWidgetResponses(xsoar_ids_state), MockDashboardResponses(xsoar_ids_state),
                       MockReportResponses(xsoar_ids_state), MockIncidentTypeResponses(xsoar_ids_state),
                       MockClassifierResponses(xsoar_ids_state), MockReputationResponses(xsoar_ids_state),
                       MockLayoutResponses(xsoar_ids_state)]
    for mocked_entity in mocked_entities:
        status, response = mocked_entity.search_response(command_name, command_args)
        if (status, response) != (False, False):
            return status, response

        status, response = mocked_entity.delete_response(command_name, command_args)
        if (status, response) != (False, False):
            return status, response

    return False, 'Command Not Mocked.'


@pytest.mark.parametrize('args, xsoar_ids_state, expected_outputs', [
    pytest.param(
        {'dry_run': 'false'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {},
            'successfully_deleted': {},
            'status': 'Completed'}, id='delete nothing'),
    pytest.param(
        {'dry_run': 'false', 'include_ids_dict': {'job': ['job1'],
                                                  'pack': ['installed_pack_id1'],
                                                  'list': ['list1'],
                                                  'script': ['script1'],
                                                  'playbook': ['playbook1'],
                                                  'integration': ['integration1'],
                                                  'incidentfield': ['incidentfield1'],
                                                  'pre-process-rule': ['pre-process-rule1'],
                                                  'widget': ['widget1'],
                                                  'dashboard': ['dashboard1'],
                                                  'report': ['report1'],
                                                  'incidenttype': ['incidenttype1'],
                                                  'classifier': ['classifier1'],
                                                  'reputation': ['reputation1'],
                                                  'layoutscontainer': ['layout1']},
         'delete_unspecified': 'false'}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {},
            'successfully_deleted': {'job': ['job1'], 'list': ['list1'], 'pack': ['installed_pack_id1'],
                                     'script': ['script1'], 'playbook': ['playbook1'], 'integration': ['integration1'],
                                     'incidentfield': ['incidentfield1'], 'pre-process-rule': ['pre-process-rule1'],
                                     'widget': ['widget1'], 'dashboard': ['dashboard1'], 'report': ['report1'],
                                     'incidenttype': ['incidenttype1'], 'classifier': ['classifier1'],
                                     'reputation': ['reputation1'], 'layoutscontainer': ['layout1']},
            'status': 'Completed'}, id='delete only included ids'),
    pytest.param(
        {'dry_run': 'false', 'exclude_ids_dict': {'job': ['job1'],
                                                  'pack': ['installed_pack_id1'],
                                                  'list': ['list1'],
                                                  'script': ['script1'],
                                                  'playbook': ['playbook1'],
                                                  'integration': ['integration1'],
                                                  'incidentfield': ['incidentfield1'],
                                                  'pre-process-rule': ['pre-process-rule1'],
                                                  'widget': ['widget1'],
                                                  'dashboard': ['dashboard1'],
                                                  'report': ['report1'],
                                                  'incidenttype': ['incidenttype1'],
                                                  'classifier': ['classifier1'],
                                                  'reputation': ['reputation1'],
                                                  'layoutscontainer': ['layout1']}}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'pack': ['installed_pack_id1', 'Base'], 'job': ['job1'], 'list': ['list1'],
                            'script': ['script1', 'CommonUserServer'],
                            'playbook': ['playbook1'], 'integration': ['integration1'],
                            'incidentfield': ['incidentfield1'], 'pre-process-rule': ['pre-process-rule1'],
                            'widget': ['widget1'], 'dashboard': ['dashboard1'], 'report': ['report1'],
                            'incidenttype': ['incidenttype1'], 'classifier': ['classifier1'],
                            'reputation': ['reputation1'], 'layoutscontainer': ['layout1']},
            'successfully_deleted': {  # packs can only be deleted when included.
                'job': ['job2'], 'list': ['list2'], 'playbook': ['playbook2'], 'script': ['script2'],
                'integration': ['integration2'], 'incidentfield': ['incidentfield2'],
                'pre-process-rule': ['pre-process-rule2'], 'widget': ['widget2'],
                'dashboard': ['dashboard2'], 'report': ['report2'], 'incidenttype': ['incidenttype2'],
                'classifier': ['classifier2'], 'reputation': ['reputation2'], 'layoutscontainer': ['layout2'],
                'pack': ['installed_pack_id2'],
            },
            'status': 'Completed'}, id='dont delete excluded ids'),
    pytest.param(
        {'dry_run': 'false', 'exclude_ids_dict': {'job': ['job3'],
                                                  'pack': ['installed_pack3'],
                                                  'list': ['list3'],
                                                  'script': ['script3'],
                                                  'playbook': ['playbook3'],
                                                  'integration': ['integration3'],
                                                  'incidentfield': ['incidentfield3'],
                                                  'pre-process-rule': ['pre-process-rule3'],
                                                  'widget': ['widget3'],
                                                  'dashboard': ['dashboard3'],
                                                  'report': ['report3'],
                                                  'incidenttype': ['incidenttype3'],
                                                  'classifier': ['classifier3'],
                                                  'reputation': ['reputation3'],
                                                  'layoutscontainer': ['layout3']}}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'pack': ['Base'], 'script': ['CommonUserServer']},
            'successfully_deleted': {'job': ['job1', 'job2'], 'list': ['list1', 'list2'],
                                     'script': ['script1', 'script2'], 'playbook': ['playbook1', 'playbook2'],
                                     'integration': ['integration1', 'integration2'],
                                     'incidentfield': ['incidentfield1', 'incidentfield2'],
                                     'pre-process-rule': ['pre-process-rule1', 'pre-process-rule2'],
                                     'widget': ['widget1', 'widget2'], 'dashboard': ['dashboard1', 'dashboard2'],
                                     'report': ['report1', 'report2'],
                                     'incidenttype': ['incidenttype1', 'incidenttype2'],
                                     'classifier': ['classifier1', 'classifier2'],
                                     'reputation': ['reputation1', 'reputation2'],
                                     'layoutscontainer': ['layout1', 'layout2'],
                                     'pack': ['installed_pack_id1', 'installed_pack_id2']},
            'status': 'Completed'}, id='exclude unfound id'),
    pytest.param(
        {'dry_run': 'false', 'include_ids_dict': {'job': ['job3'],
                                                  'pack': ['installed_pack3'],
                                                  'list': ['list3'],
                                                  'script': ['script3'],
                                                  'playbook': ['playbook3'],
                                                  'integration': ['integration3'],
                                                  'incidentfield': ['incidentfield3'],
                                                  'pre-process-rule': ['pre-process-rule3'],
                                                  'widget': ['widget3'],
                                                  'dashboard': ['dashboard3'],
                                                  'report': ['report3'],
                                                  'incidenttype': ['incidenttype3'],
                                                  'classifier': ['classifier3'],
                                                  'reputation': ['reputation3'],
                                                  'layoutscontainer': ['layout3']}}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'job': ['job3'], 'pack': ['installed_pack3'], 'list': ['list3'],
                            'script': ['script3'], 'playbook': ['playbook3'], 'integration': ['integration3'],
                            'incidentfield': ['incidentfield3'], 'pre-process-rule': ['pre-process-rule3'],
                            'widget': ['widget3'], 'dashboard': ['dashboard3'], 'report': ['report3'],
                            'incidenttype': ['incidenttype3'], 'classifier': ['classifier3'],
                            'reputation': ['reputation3'],
                            'layoutscontainer': ['layout3']},
            'successfully_deleted': {},
            'status': 'Failed'}, id='include unfound id'),
    pytest.param(
        {'dry_run': 'false', 'include_ids_dict': {'script': ['CommonUserServer'],
                                                  'pack': ['Base']}}, XSOAR_IDS_FULL_STATE, {
            'not_deleted': {'pack': ['Base'], 'script': ['CommonUserServer']},
            'successfully_deleted': {},
            'status': 'Completed'}, id='include always excluded id'),
])
def test_get_and_delete_needed_ids(requests_mock, mocker, args, xsoar_ids_state, expected_outputs):
    """
    Given:
        Xsoar ids state.
        Include_ids and exclude_ids lists.

    When:
        Running get_and_delete_needed_ids with dry_run set to false.

    Then:
         Assert deleted id lists are correct.
    """
    requests_mock.get(CORE_PACKS_LIST_URL, text='{"core_packs_list": [\n  "Base",\n  "rasterize",\n  "DemistoRESTAPI"\n]}')

    def execute_command_mock(command_name, command_args, fail_on_error=False):
        status, response = mock_demisto_responses(command_name, command_args, xsoar_ids_state)
        return status, {'response': response}

    mocker.patch("DeleteContent.execute_command", side_effect=execute_command_mock)

    result = get_and_delete_needed_ids(args)
    assert result.outputs.get('not_deleted') == expected_outputs.get('not_deleted')
    assert result.outputs.get('successfully_deleted') == expected_outputs.get('successfully_deleted')
    assert result.outputs.get('status') == expected_outputs.get('status')


@pytest.mark.parametrize('args, xsoar_ids_state, expected_outputs, call_count', [
    pytest.param(
        {'dry_run': 'true', 'include_ids_dict': {'job': ['job1', 'job2']}},
        XSOAR_IDS_FULL_STATE, {
            'not_deleted': {},
            'successfully_deleted': {'job': ['job1', 'job2']},
            'status': 'Dry run, nothing really deleted.'}, 2, id='dry run, delete.'),
    pytest.param(
        {'dry_run': 'false', 'include_ids_dict': {'job': ['job1', 'job2']}},
        XSOAR_IDS_FULL_STATE, {
            'not_deleted': {},
            'successfully_deleted': {'job': ['job1', 'job2']},
            'status': 'Completed'}, 4, id='not dry run, delete.')
])
def test_dry_run_delete(requests_mock, mocker, args, xsoar_ids_state, expected_outputs, call_count):
    """
    Given:
        Xsoar ids state.
        dry_run flag.

    When:
        Running get_and_delete_needed_ids with dry_run toggled.

    Then:
         Assert deleted id lists are correct.
         Assert call count to executeCommand API does not include calls for actual deletion.
    """
    requests_mock.get(CORE_PACKS_LIST_URL, text='{"core_packs_list": [\n  "Base",\n  "rasterize",\n  "DemistoRESTAPI"\n]}')

    def execute_command_mock(command_name, command_args, fail_on_error=False):
        status, response = mock_demisto_responses(command_name, command_args, xsoar_ids_state)
        return status, {'response': response}

    execute_mock = mocker.patch("DeleteContent.execute_command", side_effect=execute_command_mock)

    result = get_and_delete_needed_ids(args)
    assert result.outputs.get('not_deleted') == expected_outputs.get('not_deleted')
    assert result.outputs.get('successfully_deleted') == expected_outputs.get('successfully_deleted')
    assert result.outputs.get('status') == expected_outputs.get('status')
    assert execute_mock.call_count == call_count
