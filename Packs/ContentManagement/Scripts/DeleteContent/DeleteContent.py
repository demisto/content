"""Delete Content script, used to keep instances tidy."""
from CommonServerPython import *

from abc import ABC, abstractmethod
from typing import Tuple
from urllib.parse import quote

import requests
import json

SCRIPT_NAME = 'DeleteContent'
CORE_PACKS_LIST_URL = "https://raw.githubusercontent.com/demisto/content/master/Tests/Marketplace/core_packs_list.json"


def verify_search_response_in_list(response: Any, name: str):
    ids = [entity.get('id', '') for entity in response] if type(response) is list else []
    return False if name not in ids else name


def verify_search_response_in_dict(response: Union[dict, str, list]):
    if type(response) is dict and response.get("id"):
        return response.get("id")
    return False


class EntityAPI(ABC):
    """Abstract class for APIs of different content entities."""
    name = ''

    @abstractmethod
    def search_specific_id(self, specific_id: str):
        pass

    @abstractmethod
    def search_all(self):
        pass

    @abstractmethod
    def delete_specific_id(self, specific_id: str):
        pass

    @abstractmethod
    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        pass

    def parse_all_entities_response(self, response: Union[dict, str, list]):
        return [entity.get('id', '') for entity in response] if type(response) is list else []


class PlaybookAPI(EntityAPI):  # works
    name = 'playbook'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': f'/playbook/{specific_id}'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-post',
                               {'uri': '/playbook/search',
                                'body': {'page': 0, 'size': 100}},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-post',
                               {'uri': '/playbook/delete',
                                'body': {'id': specific_id}},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        return verify_search_response_in_dict(response)

    def parse_all_entities_response(self, response: Union[dict, str, list]):
        return [entity.get('id', '') for entity in response.get('playbooks', [])] if type(response) is dict else []


class IntegrationAPI(EntityAPI):  # works
    name = 'integration'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-post',
                               {'uri': '/settings/integration/search',
                                'body': {'page': 0, 'size': 100, 'query': f'name:"{specific_id}"'}},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-post',
                               {'uri': '/settings/integration/search',
                                'body': {'page': 0, 'size': 100}},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-post',
                               {'uri': '/settings/integration-conf/delete',
                                'body': {'id': quote(specific_id)}},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str, list], name: str):
        integrations = response.get('configurations', []) if type(response) is dict else response
        return verify_search_response_in_list(integrations, name)

    def parse_all_entities_response(self, response: Union[dict, str, list]):
        integrations = response.get('configurations', []) if type(response) is dict else response
        return [entity.get('id') for entity in integrations] if type(integrations) is list else []


class ScriptAPI(EntityAPI):  # works :)
    name = 'script'
    always_excluded = ['CommonServerUserPowerShell', 'CommonServerUserPython', 'CommonUserServer', SCRIPT_NAME]

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-post',
                               {'uri': '/automation/search',
                                'body': {'page': 0, 'size': 1, 'query': f'name:"{specific_id}"'}},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-post',
                               {'uri': '/automation/search',
                                'body': {'page': 0, 'size': 100}},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-post',
                               {'uri': '/automation/delete',
                                'body': {'script': {'id': specific_id}}},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str, list], name: str):
        scripts = response.get('scripts') if type(response) is dict else response
        return verify_search_response_in_list(scripts, name)

    def parse_all_entities_response(self, response: Union[dict, str, list]):
        return [entity.get('id', '') for entity in response.get('scripts', [])] if type(response) is dict else []


class IncidentFieldAPI(EntityAPI):  # checked and works
    name = 'incidentfield'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': '/incidentfields'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/incidentfields'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-delete',
                               {'uri': f'/incidentfield/{specific_id}'},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        return verify_search_response_in_list(response, name)


class PreProcessingRuleAPI(EntityAPI):  # checked and works
    name = 'pre-process-rule'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': '/preprocess/rules'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/preprocess/rules'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-delete',
                               {'uri': f'/preprocess/rule/{specific_id}'},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str, list], name: str):
        return verify_search_response_in_list(response, name)


class WidgetAPI(EntityAPI):  # works
    name = 'widget'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': f'/widgets/{specific_id}'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/widgets'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-delete',
                               {'uri': f'/widgets/{specific_id}'},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        return verify_search_response_in_dict(response)

    def parse_all_entities_response(self, response: Union[dict, str, list]):
        if type(response) is dict:
            return list(response.keys())
        return [entity.get('id', '') for entity in response] if type(response) is list else []


class DashboardAPI(EntityAPI):  # works
    name = 'dashboard'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': f'/dashboards/{specific_id}'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/dashboards'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-delete',
                               {'uri': f'/dashboards/{specific_id}'},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        return verify_search_response_in_dict(response)

    def parse_all_entities_response(self, response: Union[dict, str, list]):
        if type(response) is dict:
            return list(response.keys())
        return [entity.get('id', '') for entity in response] if type(response) is list else []


class ReportAPI(EntityAPI):  # works
    name = 'report'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': f'/reports/{specific_id}'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/reports'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-delete',
                               {'uri': f'/report/{specific_id}'},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        return verify_search_response_in_dict(response)


class IncidentTypeAPI(EntityAPI):  # checked and works
    name = 'incidenttype'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': '/incidenttypes/export'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/incidenttypes/export'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-post',
                               {'uri': '/incidenttype/delete',
                                'body': {'id': specific_id}},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str, list], name: str):
        return verify_search_response_in_list(response, name)


class ClassifierAPI(EntityAPI):  # works
    name = 'classifier'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': f'/classifier/{specific_id}'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-post',
                               {'uri': '/classifier/search',
                                'body': {'page': 0, 'size': 100}},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-delete',
                               {'uri': f'/classifier/{specific_id}'},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str, list], name: str):
        return verify_search_response_in_dict(response)

    def parse_all_entities_response(self, response: Union[dict, str, list]):
        classifiers = response.get('classifiers', []) if type(response) is dict else []
        return [entity.get('id', '') for entity in classifiers] if type(classifiers) is list else []


class ReputationAPI(EntityAPI):  # works
    name = 'reputation'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': '/reputation/export'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/reputation/export'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-delete',
                               {'uri': f'/reputation/{specific_id}'},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str, list], name: str):
        return verify_search_response_in_list(response, name)


class LayoutAPI(EntityAPI):  # works
    name = 'layout'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': f'/layout/{specific_id}'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/layouts'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-post',
                               {'uri': f'/layout/{specific_id}/remove',
                                'body': {}},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str, list], name: str):
        return verify_search_response_in_dict(response)


class JobAPI(EntityAPI):
    name = 'job'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-post',
                               {'uri': '/jobs/search',
                                'body': {'page': 0, 'size': 1, 'query': f'name:"{specific_id}"'}},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-post',
                               {'uri': '/jobs/search',
                                'body': {'page': 0, 'size': 100}},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-delete',
                               {'uri': f'jobs/{specific_id}'},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        job_params = {}
        if type(response) is dict:
            search_results = response.get('data')
            if search_results:
                job_params = search_results[0]

        if not job_params or not job_params.get("id"):
            return False
        return job_params.get("id")

    def parse_all_entities_response(self, response: Union[dict, str, list]):
        return [entity.get('name', '') for entity in response.get('data', [])] if type(response) is dict else []


class ListAPI(EntityAPI):
    name = 'list'

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': f'/lists/download/{specific_id}'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/lists/names'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-post',
                               {'uri': '/lists/delete',
                                'body': {'id': specific_id}},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        if response:
            return name
        return False

    def parse_all_entities_response(self, response: Union[dict, str, list]):
        return response


class InstalledPackAPI(EntityAPI):
    name = 'pack'
    always_excluded = ['ContentManagement', 'CleanUpContent']

    def __init__(self, proxy_skip=True, verify=True):
        if proxy_skip:
            skip_proxy()
        core_packs_response = requests.get(CORE_PACKS_LIST_URL, verify=verify)
        self.always_excluded = json.loads(core_packs_response.text) + self.always_excluded

    def search_specific_id(self, specific_id: str):
        return execute_command('demisto-api-get',
                               {'uri': f'/contentpacks/installed/{specific_id}'},
                               fail_on_error=False)

    def search_all(self):
        return execute_command('demisto-api-get',
                               {'uri': '/contentpacks/installed-expired'},
                               fail_on_error=False)

    def delete_specific_id(self, specific_id: str):
        return execute_command('demisto-api-delete',
                               {'uri': f'/contentpacks/installed/{specific_id}'},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        return verify_search_response_in_dict(response)


def search_and_delete_existing_entity(name: str, entity_api: EntityAPI, dry_run: bool = True) -> bool:
    """Searches the machine for previously configured entity_types with the given name.

    Args:
        name (str): The name of the entity to update it's past configurations.

    Returns:
        True if deleted, False otherwise.
    """

    status, res = entity_api.search_specific_id(specific_id=name)

    if not status:
        demisto.debug(f'Could not find {entity_api.name} with id {name} - Response:\n{res}')
        return False

    specific_id = entity_api.verify_specific_search_response(res.get('response'), name)

    if not specific_id:
        return False

    if not dry_run:
        status, res = entity_api.delete_specific_id(specific_id=specific_id)
    else:
        demisto.debug(f'DRY RUN - Not deleting {entity_api.name} with id {name}.')
        status = True
        res = True

    if not status:
        demisto.debug(f'Could not delete {entity_api.name} with id {name} - Response:\n{res}')
        return False

    return True


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

    entity_ids = entity_api.parse_all_entities_response(res.get('response', {}))

    return entity_ids


def get_and_delete_entities(entity_api: EntityAPI, excluded_ids: list = [], included_ids: list = [],
                            dry_run: bool = True) -> Tuple[list, list, list]:
    """Search and delete entities with provided EntityAPI.

    Args:
        entity_api (EntityAPI): The api object to use for the get and delete api calls.
        excluded_ids (list): List of ids to exclude from deletion.
        included_ids (list): List of ids to include in deletion.
        dry_run (bool): If true, will not really delete anything.

    Returns:
        (list) successfully deleted ids, (list) not deleted ids
    """
    demisto.debug(f'Starting handling {entity_api.name} entities.')
    succesfully_deleted = []
    not_deleted = []
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
                if search_and_delete_existing_entity(included_id, entity_api=entity_api, dry_run=dry_run):
                    succesfully_deleted.append(included_id)
                else:
                    not_deleted.append(included_id)
            else:
                not_deleted.append(included_id)

    else:
        all_entities = search_for_all_entities(entity_api=entity_api)
        if not all_entities:
            return [], [], extended_excluded_ids

        for entity_id in all_entities:
            if entity_id not in extended_excluded_ids:
                if search_and_delete_existing_entity(entity_id, entity_api=entity_api, dry_run=dry_run):
                    succesfully_deleted.append(entity_id)
                else:
                    demisto.debug(f'Did not find or could not delete {entity_api.name} with '
                                  f'id {entity_id} in xsoar.')
                    not_deleted.append(entity_id)
            else:
                not_deleted.append(entity_id)

    return succesfully_deleted, not_deleted, extended_excluded_ids


def get_deletion_status(excluded: list, included: list, deleted: list, undeleted: list) -> bool:
    if excluded:
        if undeleted == excluded:
            return True
        else:
            for excluded_id in excluded:
                if excluded_id in deleted:
                    return False
            return True

    elif included:
        if set(deleted) == set(included):
            return True
    # Nothing excluded
    elif not undeleted:
        return True
    return False


def handle_content_enitity(entity_api: EntityAPI,
                           included_ids_dict: Optional[dict],
                           excluded_ids_dict: Optional[dict],
                           dry_run: bool) -> Tuple[bool, dict, dict]:

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
    if type(input_dict) == str:
        return json.loads(input_dict)
    return input_dict


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
                          PlaybookAPI(), IncidentFieldAPI(),
                          PreProcessingRuleAPI(), WidgetAPI(), DashboardAPI(), ReportAPI(), JobAPI(), ListAPI(),
                          IncidentTypeAPI(), ClassifierAPI(), ReputationAPI(), LayoutAPI()]

    all_deleted: dict = dict()
    all_not_deleted: dict = dict()
    all_deletion_statuses: list = []
    for entity in entities_to_delete:
        entity_deletion_status, deleted, undeleted = handle_content_enitity(entity, include_ids, exclude_ids, dry_run)
        all_deleted.update(deleted)
        all_not_deleted.update(undeleted)
        all_deletion_statuses.append(entity_deletion_status)

    deletion_status = 'Failed'
    if dry_run:
        deletion_status = 'Dry run, nothing really deleted.'
    else:
        if all(all_deletion_statuses):
            deletion_status = 'Completed'

    return CommandResults(
        outputs_prefix='ConfigurationSetup.Deletion',
        outputs_key_field='name',
        outputs={
            # Only show keys with values.
            'successfully_deleted': {key: value for key, value in all_deleted.items() if value},
            'not_deleted': {key: value for key, value in all_not_deleted.items() if value},
            'status': deletion_status,
        },
    )


def main():  # pragma: no cover
    try:
        return_results(get_and_delete_needed_ids(demisto.args()))

    except Exception as e:
        return_error(f'Error occurred while deleting contents.\n{e}'
                     f'\n{traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
