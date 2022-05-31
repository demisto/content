"""Delete Content script, used to keep instances tidy."""
import traceback
import demistomock as demisto
from CommonServerPython import *

SCRIPT_NAME = 'DeleteContent'


def delete_job(existing_job: Optional[Dict[str, Any]] = None) -> bool:
    """Delete the found job in the XSOAR instance.

    Return True on success, False on failure.
    """
    job_params = existing_job or {}

    if not job_params or not job_params.get("id"):
        demisto.debug(f'{SCRIPT_NAME} - Job to delete not found. Aborting.')
        return False

    status, res = execute_command(
        'demisto-api-delete',
        {'uri': f'/jobs/{job_params.get("id")}'},
        fail_on_error=False,
    )

    if not status:
        error_message = f'{SCRIPT_NAME} - {res}'
        demisto.debug(error_message)
        return False

    return True


def search_and_delete_existing_job(job_name: str) -> bool:
    """Searches the machine for previously configured jobs with the given name.

    Args:
        job_name (str): The name of the job to update it's past configurations.

    Returns:
        Dict[str, Any]. The job data as configured on the machine.
    """
    body = {
        'page': 0,
        'size': 1,
        'query': f'name:"{job_name}"',
    }

    status, res = execute_command(
        'demisto-api-post',
        {'uri': '/jobs/search', 'body': body},
        fail_on_error=False,
    )

    job_params = {}

    if not status:
        error_message = f'{SCRIPT_NAME} - Search Job - {res}'
        demisto.debug(error_message)

    search_results = res.get('response', {}).get('data')
    if search_results:
        job_params = search_results[0]

    if not job_params or not job_params.get("id"):
        demisto.debug(f'{SCRIPT_NAME} - Job to delete not found. Aborting.')
        return False

    status, res = execute_command(
        'demisto-api-delete',
        {'uri': f'/jobs/{job_params.get("id")}'},
        fail_on_error=False,
    )

    if not status:
        error_message = f'{SCRIPT_NAME} - Delete Job - {res}'
        demisto.debug(error_message)
        return False

    return True



def main():
    args = demisto.args()
    excluded_ids = args.get('excluded_ids')

    try:
        deleted_jobs, undeleted_jobs = get_and_delete_jobs(excluded_ids=excluded_ids)

        # get all lists
        # delete them if not excluded
        deleted_lists, undeleted_lists = get_and_delete_lists(excluded_ids=excluded_ids)

        # get all custom packs
        # delete them if not excluded
        deleted_custom_packs, undeleted_custom_packs = get_and_delete_custom_packs(excluded_ids=excluded_ids)

        # get all marketplace packs
        # delete them if not excluded
        deleted_custom_packs, undeleted_custom_packs = get_and_delete_marketplace_packs(excluded_ids=excluded_ids)

        return_results(
            CommandResults(
                outputs_prefix='ConfigurationSetup.Deletion',
                outputs_key_field='name',
                outputs={
                    'successfully_deleted': deletion_success,
                    'failed_to_delete': deletion_failed,
                    'status': deletion_status,
                },
            )
        )

    except Exception as e:
        return_error(f'{SCRIPT_NAME} - Error occurred while deleting contents.\n{e}'
                     f'\n{traceback.format_exc()}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
