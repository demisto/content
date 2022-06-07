"""Delete Content script, used to keep instances tidy."""
import traceback
import enum
import demistomock as demisto
from CommonServerPython import *

from abc import ABC, abstractmethod

SCRIPT_NAME = 'DeleteContent'


class EntityAPI(ABC):
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

    @abstractmethod
    def parse_all_entities_response(self, response: Union[dict, str]):
        pass


class JobAPI(EntityAPI):
    name = 'Job'

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
        search_results = response.get('data')
        if search_results:
            job_params = search_results[0]

        if not job_params or not job_params.get("id"):
            demisto.debug(f'{SCRIPT_NAME} - {self.name} to delete not found. Aborting.')
            return False
        return job_params.get("id")

    def parse_all_entities_response(self, response: Union[dict, str]):
        return [entity.get('name', '') for entity in response.get('data')]


class ListAPI(EntityAPI):
    name = 'List'

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
                               {'uri': f'/lists/delete',
                                'body': {'id': specific_id}},
                               fail_on_error=False)

    def verify_specific_search_response(self, response: Union[dict, str], name: str):
        if response:
            return name
        return False

    def parse_all_entities_response(self, response: Union[dict, str]):
        return response


class InstalledPackAPI(EntityAPI):
    name = 'Installed Pack'

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

        if not response or not response.get("id"):
            demisto.debug(f'{SCRIPT_NAME} - {self.name} to delete not found. Aborting.')
            return False
        return response.get("id")

    def parse_all_entities_response(self, response: Union[dict, str]):
        return [entity.get('id', '') for entity in response]


def search_and_delete_existing_entity(name: str, entity_api: EntityAPI, dry_run: bool = True) -> bool:
    """Searches the machine for previously configured entity_types with the given name.

    Args:
        name (str): The name of the entity to update it's past configurations.

    Returns:
        True if deleted, False otherwise.
    """

    status, res = entity_api.search_specific_id(specific_id=name)

    if not status:
        error_message = f'{SCRIPT_NAME} - Search {entity_api.name} - {res}'
        demisto.debug(error_message)
        return False

    specific_id = entity_api.verify_specific_search_response(res.get('response'), name)

    if not specific_id:
        return False

    if not dry_run:
        status, res = entity_api.delete_specific_id(specific_id=specific_id)
    else:
        status = True
        res = True

    if not status:
        error_message = f'{SCRIPT_NAME} - Delete {entity_api.name} - {res}'
        demisto.debug(error_message)
        return False

    return True


def search_for_all_entities(entity_api: EntityAPI):

    status, res = entity_api.search_all()

    if not status:
        error_message = f'{SCRIPT_NAME} - Search All {entity_api.name}s - {res}'
        return_error(error_message)
        demisto.debug(error_message)
        return False

    entity_ids = entity_api.parse_all_entities_response(res.get('response', {}))

    return entity_ids


def get_and_delete_entities(entity_api: EntityAPI, excluded_ids: List = [], included_ids: List = [],
                            dry_run: bool = True):
    succesfully_deleted = []
    not_deleted = []

    if included_ids and excluded_ids:
        return [], []

    if included_ids:
        for included_id in included_ids:
            if search_and_delete_existing_entity(included_id, entity_api=entity_api, dry_run=dry_run):
                succesfully_deleted.append(included_id)
            else:
                not_deleted.append(included_id)

    else:
        all_entities = search_for_all_entities(entity_api=entity_api)
        if not all_entities:
            return [], []

        for entity_id in all_entities:
            if entity_id not in excluded_ids:
                if search_and_delete_existing_entity(entity_id, entity_api=entity_api, dry_run=dry_run):
                    succesfully_deleted.append(entity_id)
                else:
                    not_deleted.append(entity_id)
            else:
                not_deleted.append(entity_id)

    return succesfully_deleted, not_deleted


def main():
    args = demisto.args()
    excluded_ids = args.get('exclude_ids', []).split(',') if args.get('exclude_ids', []) else []
    included_ids = args.get('include_ids', []).split(',') if args.get('include_ids', []) else []
    dry_run = True if args.get('dry_run', 'true') == 'true' else False
    deletion_status = 'Failed'

    if included_ids and excluded_ids:
        return return_error('')

    try:
        deleted_jobs, undeleted_jobs = get_and_delete_entities(entity_api=JobAPI(), excluded_ids=excluded_ids, included_ids=included_ids, dry_run=dry_run)

        # get all lists
        # delete them if not excluded
        deleted_lists, undeleted_lists = get_and_delete_entities(entity_api=ListAPI(), excluded_ids=excluded_ids, included_ids=included_ids, dry_run=dry_run)

        # get all custom packs
        # delete them if not excluded
        deleted_packs, undeleted_packs = get_and_delete_entities(entity_api=InstalledPackAPI(), excluded_ids=excluded_ids, included_ids=included_ids, dry_run=dry_run)

        # Add integrations, scripts, playbooks.

        deletion_success = deleted_jobs + deleted_lists + deleted_packs
        deletion_failed = undeleted_jobs + undeleted_lists + undeleted_packs
        if dry_run:
            deletion_status = 'Dry run, nothing really deleted.'
        else:
            if excluded_ids:
                if deletion_failed == excluded_ids:
                    deletion_status = 'Completed'
            elif included_ids:
                if deletion_success == included_ids:
                    deletion_status = 'Completed'
            # Nothing excluded
            elif not deletion_failed:
                deletion_status = 'Completed'

        return_results(
            CommandResults(
                outputs_prefix='ConfigurationSetup.Deletion',
                outputs_key_field='name',
                outputs={
                    'successfully_deleted': deletion_success,
                    'not_deleted': deletion_failed,
                    'status': deletion_status,
                },
            )
        )

    except Exception as e:
        return_error(f'{SCRIPT_NAME} - Error occurred while deleting contents.\n{e}'
                     f'\n{traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
