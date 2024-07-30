"""Delete Content script, used to keep instances tidy."""
from CommonServerPython import *

from abc import ABC, abstractmethod

import requests
import json

SCRIPT_NAME = 'DeleteContent'
CORE_PACKS_LIST_URL = "https://raw.githubusercontent.com/demisto/content/master/Config/core_packs_list.json"
INSTANCE_NAME = demisto.args().get('using')


def verify_search_response_in_list(response: Any, id: str) -> str:
    """
    Return:
        The id if it is in the response, else return empty string
    """
    ids = [entity.get('id', '') for entity in response] if isinstance(response, list) else []
    return '' if id not in ids else id


def verify_search_response_in_dict(response: dict | str | list) -> str:
    """
    Return:
        The id if it is in the response, else return empty string
    """
    if isinstance(response, dict) and response.get("id"):
        return response.get("id", "")
    return ''


def get_the_name_of_specific_id(response: dict | str | list, id: str) -> str:
    if isinstance(response, dict):
        response = [response]
    if isinstance(response, list):
        for entity in response:
            if entity.get("id") == id:
                return entity.get("name", id)
    return id


class EntityAPI(ABC):
    """Abstract class for APIs of different content entities."""
    name = ''

    @abstractmethod
    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        pass

    @abstractmethod
    def search_all(self) -> tuple[bool, dict | str]:
        pass

    @abstractmethod
    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        pass

    @abstractmethod
    def verify_specific_search_response(self, response: dict | str, id: str) -> str:
        pass

    @abstractmethod
    def get_name_by_id(self, response: dict | str, id: str) -> str:
        pass

    def parse_all_entities_response(self, response) -> list:
        return [entity.get('id', '') for entity in response] if isinstance(response, list) else []


class PlaybookAPI(EntityAPI):
    name = 'playbook'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': f'/playbook/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/playbook/search',
                                'body': {'page': 0, 'size': 100},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/playbook/delete',
                                'body': {'id': specific_id},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str, id: str) -> str:
        return verify_search_response_in_dict(response)

    def get_name_by_id(self, response: dict | str, id: str) -> str:
        return get_the_name_of_specific_id(response, id)

    def parse_all_entities_response(self, response: dict | str | list) -> list:
        return [entity.get('id', '') for entity in response.get('playbooks', [])] if type(response) is dict else []


class IntegrationAPI(EntityAPI):
    name = 'integration'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/settings/integration/search',
                                'body': {'page': 0, 'size': 100, 'query': f'name:"{specific_id}"'},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/settings/integration/search',
                                'body': {'page': 0, 'size': 100},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/settings/integration-conf/delete',
                                'body': {'id': specific_id},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str | list, id: str) -> str:
        integrations = response.get('configurations', []) if isinstance(response, dict) else response
        return verify_search_response_in_list(integrations, id)

    def get_name_by_id(self, response: dict | str | list, id: str) -> str:
        integrations = response.get('configurations', []) if isinstance(response, dict) else response
        return get_the_name_of_specific_id(integrations, id)

    def parse_all_entities_response(self, response: dict | str | list) -> list:
        integrations = response.get('configurations', []) if isinstance(response, dict) else response
        return [entity.get('id') for entity in integrations] if type(integrations) is list else []


class ScriptAPI(EntityAPI):
    name = 'script'
    always_excluded = ['CommonServerUserPowerShell', 'CommonServerUserPython', 'CommonUserServer', SCRIPT_NAME]

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/automation/search',
                                'body': {'page': 0, 'size': 1, 'query': f'id:"{specific_id}"'},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/automation/search',
                                'body': {'page': 0, 'size': 100},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/automation/delete',
                                'body': {'script': {'id': specific_id}},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str | list, id: str) -> str:
        scripts = response.get('scripts') if isinstance(response, dict) else response
        return verify_search_response_in_list(scripts, id)

    def get_name_by_id(self, response: dict | str | list, id: str) -> str:
        scripts = response.get('scripts', []) if isinstance(response, dict) else response
        return get_the_name_of_specific_id(scripts, id)

    def parse_all_entities_response(self, response: dict | str | list) -> list:
        return [entity.get('id', '') for entity in response.get('scripts', [])] if type(response) is dict else []


class IncidentFieldAPI(EntityAPI):
    name = 'incidentfield'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/incidentfields',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/incidentfields',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-delete',
                               {'uri': f'/incidentfield/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str, id: str) -> str:
        return verify_search_response_in_list(response, id)

    def get_name_by_id(self, response: dict | str, id: str) -> str:
        return get_the_name_of_specific_id(response, id)


class PreProcessingRuleAPI(EntityAPI):
    name = 'pre-process-rule'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/preprocess/rules',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/preprocess/rules',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-delete',
                               {'uri': f'/preprocess/rule/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str | list, id: str) -> str:
        return verify_search_response_in_list(response, id)

    def get_name_by_id(self, response: dict | str | list, id: str) -> str:
        return get_the_name_of_specific_id(response, id)


class WidgetAPI(EntityAPI):
    name = 'widget'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': f'/widgets/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/widgets',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-delete',
                               {'uri': f'/widgets/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str, id: str) -> str:
        return verify_search_response_in_dict(response)

    def get_name_by_id(self, response: dict | str, id: str) -> str:
        return get_the_name_of_specific_id(response, id)

    def parse_all_entities_response(self, response: dict | str | list) -> list:
        if type(response) is dict:
            return list(response.keys())
        return [entity.get('id', '') for entity in response] if type(response) is list else []


class DashboardAPI(EntityAPI):
    name = 'dashboard'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': f'/dashboards/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/dashboards',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-delete',
                               {'uri': f'/dashboards/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str, id: str) -> str:
        return verify_search_response_in_dict(response)

    def get_name_by_id(self, response: dict | str, id: str) -> str:
        return get_the_name_of_specific_id(response, id)

    def parse_all_entities_response(self, response: dict | str | list) -> list:
        if type(response) is dict:
            return list(response.keys())
        return [entity.get('id', '') for entity in response] if type(response) is list else []


class ReportAPI(EntityAPI):
    name = 'report'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': f'/reports/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/reports',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-delete',
                               {'uri': f'/report/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str, id: str) -> str:
        return verify_search_response_in_dict(response)

    def get_name_by_id(self, response: dict | str, id: str) -> str:
        return get_the_name_of_specific_id(response, id)


class IncidentTypeAPI(EntityAPI):
    name = 'incidenttype'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/incidenttypes/export',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/incidenttypes/export',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/incidenttype/delete',
                                'body': {'id': specific_id},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str | list, id: str) -> str:
        return verify_search_response_in_list(response, id)

    def get_name_by_id(self, response: dict | str | list, id: str) -> str:
        return get_the_name_of_specific_id(response, id)


class ClassifierAPI(EntityAPI):
    name = 'classifier'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': f'/classifier/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/classifier/search',
                                'body': {'page': 0, 'size': 100},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-delete',
                               {'uri': f'/classifier/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str | list, id: str) -> str:
        return verify_search_response_in_dict(response)

    def get_name_by_id(self, response: dict | str | list, id: str) -> str:
        return get_the_name_of_specific_id(response, id)

    def parse_all_entities_response(self, response: dict | str | list) -> list:
        classifiers = response.get('classifiers', []) if type(response) is dict else []
        return [entity.get('id', '') for entity in classifiers] if type(classifiers) is list else []


class MapperAPI(ClassifierAPI):
    name = 'mapper'


class ReputationAPI(EntityAPI):
    name = 'reputation'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/reputation/export',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/reputation/export',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-delete',
                               {'uri': f'/reputation/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str | list, id: str) -> str:
        return verify_search_response_in_list(response, id)

    def get_name_by_id(self, response: dict | str | list, id: str) -> str:
        return get_the_name_of_specific_id(response, id)


class LayoutAPI(EntityAPI):
    name = 'layoutscontainer'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': f'/layout/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/layouts',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': f'/layout/{specific_id}/remove',
                                'body': {},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str | list, id: str) -> str:
        return verify_search_response_in_dict(response)

    def get_name_by_id(self, response: dict | str | list, id: str) -> str:
        return get_the_name_of_specific_id(response, id)


class JobAPI(EntityAPI):
    name = 'job'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/jobs/search',
                                'body': {'page': 0, 'size': 1, 'query': f'name:"{specific_id}"'},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/jobs/search',
                                'body': {'page': 0, 'size': 100},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-delete',
                               {'uri': f'jobs/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: dict | str, id: str) -> str:
        job_params = {}
        if isinstance(response, dict) and (search_results := response.get('data')):
            job_params = search_results[0]

        return job_params.get("id", '') if job_params and job_params.get("id") else ''

    def get_name_by_id(self, response: dict | str, id: str) -> str:
        job_params = {}
        if isinstance(response, dict) and (search_results := response.get('data')):
            job_params = search_results[0]
        return get_the_name_of_specific_id(job_params, id)

    def parse_all_entities_response(self, response: dict | str | list) -> list:
        return [entity.get('name', '') for entity in response.get('data', [])] if type(response) is dict else []


class ListAPI(EntityAPI):
    name = 'list'

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': f'/lists/download/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/lists/names',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-post',
                               {'uri': '/lists/delete',
                                'body': {'id': specific_id},
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], id: str) -> str:
        return id if response else ''

    def get_name_by_id(self, response: dict | str, id: str) -> str:
        return id

    def parse_all_entities_response(self, response: list) -> list:
        return response


class InstalledPackAPI(EntityAPI):
    name = 'pack'
    always_excluded = ['ContentManagement', 'CleanUpContent']

    def __init__(self, proxy_skip=True, verify=True):
        if proxy_skip:
            skip_proxy()
        core_packs_response = requests.get(CORE_PACKS_LIST_URL, verify=verify)
        self.always_excluded = json.loads(core_packs_response.text).get("core_packs_list") + self.always_excluded

    def search_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': f'/contentpacks/installed/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def search_all(self) -> tuple[bool, dict | str]:
        return execute_command('core-api-get',
                               {'uri': '/contentpacks/installed-expired',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str) -> tuple[bool, dict | str]:
        return execute_command('core-api-delete',
                               {'uri': f'/contentpacks/installed/{specific_id}',
                                'using': INSTANCE_NAME},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], id: str) -> str:
        return verify_search_response_in_dict(response)

    def get_name_by_id(self, response: dict | str, id: str) -> str:
        return get_the_name_of_specific_id(response, id)


def search_and_delete_existing_entity(id: str, entity_api: EntityAPI, dry_run: bool = True) -> tuple[bool, str]:
    """Searches the machine for previously configured entity_types with the given id.

    Args:
        id (str): The id of the entity to update it's past configurations.

    Returns:
        True if deleted, False otherwise.
        The name of the entity if it exists, otherwise the given id.
    """

    status, res = entity_api.search_specific_id(specific_id=id)

    if not status:
        demisto.debug(f'Could not find {entity_api.name} with id {id} - Response:\n{res}')
        return False, id

    specific_id = entity_api.verify_specific_search_response(res.get('response', {}), id)  # type: ignore[union-attr]
    specific_name = entity_api.get_name_by_id(res.get('response', {}), id)  # type: ignore[union-attr]

    if not specific_id:
        return False, id

    if not dry_run:
        status, res = entity_api.delete_specific_id(specific_id=specific_id)
    else:
        demisto.debug(f'DRY RUN - Not deleting {entity_api.name} with id "{id}" and name "{specific_name}".')
        status = True

    if not status:
        demisto.debug(f'Could not delete {entity_api.name} with id "{id}" and name "{specific_name}" - Response:\n{res}')
        return False, specific_name

    return True, specific_name


def search_for_all_entities(entity_api: EntityAPI) -> list:
    """Search for all existing entities in xsoar.

    Args:
        entity_api (EntityAPI): The entity api to preform api calls on.

    Returns:
        list of entity ids.
    """
    status, res = entity_api.search_all()

    if not status:
        error_message = f'Search All {entity_api.name}s - {res}'
        demisto.debug(error_message)
        raise Exception(error_message)

    return entity_api.parse_all_entities_response(res.get('response', {}))  # type: ignore[union-attr]


def get_and_delete_entities(entity_api: EntityAPI, excluded_ids: list = [], included_ids: list = [], dry_run: bool = True
                            ) -> tuple[list[dict], list[dict], list]:
    """Search and delete entities with provided EntityAPI.

    Args:
        entity_api (EntityAPI): The api object to use for the get and delete api calls.
        excluded_ids (list): List of ids to exclude from deletion.
        included_ids (list): List of ids to include in deletion.
        dry_run (bool): If true, will not really delete anything.

    Returns:
        (list) successfully deleted ids, (list) not deleted ids, (list) extended excluded ids.
    """
    demisto.debug(f'Starting handling {entity_api.name} entities.')
    successfully_deleted: list[dict] = []
    not_deleted: list[dict] = []
    extended_excluded_ids = excluded_ids.copy()

    if not included_ids and not excluded_ids:
        return [], [], extended_excluded_ids

    if hasattr(entity_api, 'always_excluded'):
        extended_excluded_ids += entity_api.always_excluded  # type: ignore

    new_included_ids = [item for item in included_ids if item not in extended_excluded_ids]
    demisto.debug(f'Included ids for {entity_api.name} after excluding excluded are {new_included_ids}')

    if included_ids:
        for included_id in included_ids:
            if included_id in new_included_ids:
                status, name = search_and_delete_existing_entity(included_id, entity_api=entity_api, dry_run=dry_run)
                id_and_name = {'id': included_id, 'name': name}
                if status:
                    successfully_deleted.append(id_and_name)
                else:
                    not_deleted.append(id_and_name)
            else:
                not_deleted.append({'id': included_id, 'name': included_id})

    else:
        all_entities = search_for_all_entities(entity_api=entity_api)
        if not all_entities:
            return [], [], extended_excluded_ids

        for entity_id in all_entities:
            if entity_id not in extended_excluded_ids:
                status, name = search_and_delete_existing_entity(entity_id, entity_api=entity_api, dry_run=dry_run)
                id_and_name = {'id': entity_id, 'name': name}
                if status:
                    successfully_deleted.append(id_and_name)
                else:
                    demisto.debug(f'Did not find or could not delete {entity_api.name} with '
                                  f'id {entity_id} in xsoar.')
                    not_deleted.append(id_and_name)
            else:
                not_deleted.append({'id': entity_id, 'name': entity_id})

    return successfully_deleted, not_deleted, extended_excluded_ids


def get_deletion_status(excluded: list, included: list, deleted: list, undeleted: list) -> bool:
    deleted_ids = [entity.get('id') for entity in deleted]
    undeleted_ids = [entity.get('id') for entity in undeleted]
    if excluded:
        if undeleted_ids == excluded:
            return True
        else:
            return all(excluded_id not in deleted_ids for excluded_id in excluded)

    elif included:
        if set(deleted_ids) == set(included):
            return True
    # Nothing excluded
    elif not undeleted_ids:
        return True
    return False


def handle_content_entity(entity_api: EntityAPI,
                          included_ids_dict: Optional[dict],
                          excluded_ids_dict: Optional[dict],
                          dry_run: bool) -> tuple[bool, dict, dict]:

    excluded_ids = excluded_ids_dict.get(entity_api.name, []) if excluded_ids_dict else []
    included_ids = included_ids_dict.get(entity_api.name, []) if included_ids_dict else []

    deleted_ids, undeleted_ids, new_excluded_ids = get_and_delete_entities(entity_api=entity_api,
                                                                           excluded_ids=excluded_ids,
                                                                           included_ids=included_ids,
                                                                           dry_run=dry_run)

    deletion_status = get_deletion_status(excluded=new_excluded_ids, included=included_ids,
                                          deleted=deleted_ids, undeleted=undeleted_ids)

    return deletion_status, {entity_api.name: deleted_ids}, {entity_api.name: undeleted_ids}


def handle_input_json(input_dict: Any) -> Any:
    return json.loads(input_dict) if isinstance(input_dict, str) else input_dict


def get_and_delete_needed_ids(args: dict) -> CommandResults:
    """Search and delete provided ids to delete.

    Args:
        args[exclude_ids_dict] (dict): Dict content items ids to exclude. Will delete all the rest of the found ids.
        args[include_ids_dict] (dict): Dict content items ids to include. Will delete all the ids specified.
        args[dry_run] (str(bool)): If True, will only collect items for deletion and will not delete them.

    Remark:
        exclude_ids_dict, include_ids_dict are assumed to be in the {'entity_type': [entity_ids]} format.
        (e.g. {'job': ['job1', 'job2'], 'playbook': ['playbook1', 'playbook2']})

    Raise:
        ValueError if both exclude_ids and include_ids are specified.

    Returns:
        CommandResults with the following outputs:
            successfully_deleted: list of content ids gathered for deletion.
            not_deleted: list of content ids gathered not to delete.
            status: Deletion status (Failed/Completed/Dry run, nothing really deleted.)
    """
    dry_run = argToBoolean(args.get('dry_run', 'true'))
    include_ids = handle_input_json(args.get('include_ids_dict'))
    exclude_ids = handle_input_json(args.get('exclude_ids_dict'))
    skip_proxy = argToBoolean(args.get('skip_proxy', 'false'))
    verify_cert = argToBoolean(args.get('verify_cert', 'true'))

    entities_to_delete = [InstalledPackAPI(proxy_skip=skip_proxy, verify=verify_cert), IntegrationAPI(), ScriptAPI(),
                          IncidentTypeAPI(), PlaybookAPI(), IncidentFieldAPI(),
                          PreProcessingRuleAPI(), WidgetAPI(), DashboardAPI(), ReportAPI(), JobAPI(), ListAPI(),
                          ClassifierAPI(), MapperAPI(), ReputationAPI(), LayoutAPI()]

    all_deleted: dict = {}
    all_not_deleted: dict = {}
    all_deletion_statuses: list = []
    for entity in entities_to_delete:
        entity_deletion_status, deleted, undeleted = handle_content_entity(entity, include_ids, exclude_ids, dry_run)
        all_deleted |= deleted
        all_not_deleted |= undeleted
        all_deletion_statuses.append(entity_deletion_status)

    deletion_status = 'Failed'
    if dry_run:
        deletion_status = 'Dry run, nothing really deleted.'
    elif all(all_deletion_statuses):
        deletion_status = 'Completed'

    successfully_deleted_ids = {key: [value['id'] for value in lst] for key, lst in all_deleted.items() if lst}
    successfully_deleted_names = {key: [value['name'] for value in lst] for key, lst in all_deleted.items() if lst}
    not_deleted_ids = {key: [value['id'] for value in lst] for key, lst in all_not_deleted.items() if lst}
    not_deleted_names = {key: [value['name'] for value in lst] for key, lst in all_not_deleted.items() if lst}
    return CommandResults(
        outputs_prefix='ConfigurationSetup.Deletion',
        outputs_key_field='name',
        outputs={
            # Only show keys with values.
            'successfully_deleted': successfully_deleted_ids,
            'not_deleted': not_deleted_ids,
            'status': deletion_status,
        },
        readable_output=f'### Deletion status: {deletion_status}\n' + tableToMarkdown(
            'Successfully deleted', successfully_deleted_names) + tableToMarkdown('Not deleted', not_deleted_names)
    )


def main():  # pragma: no cover
    try:
        return_results(get_and_delete_needed_ids(demisto.args()))

    except Exception as e:
        return_error(f'Error occurred while deleting contents.\n{e}'
                     f'\n{traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
