import demistomock as demisto
from CommonServerPython import *

SCRIPT_NAME = 'JobCreator'


def configure_job(job_name: str, existing_job: Optional[Dict[str, Any]] = None) -> bool:
    """Configures the job in the XSOAR instance.
    """
    instance_context = demisto.context()
    job_params = existing_job or {}
    is_scheduled = job_params.get('scheduled')

    for job in instance_context.get('ConfigurationSetup', {}).get('Jobs', []):
        if job.get('name') == job_name:
            job_params.update(job)
            break

    if not job_params:
        return False

    if is_scheduled is False:
        job_params['scheduled'] = False

    status, res = execute_command(
        'demisto-api-post',
        {'uri': '/jobs', 'body': job_params},
        fail_on_error=False,
    )

    if not status:
        error_message = f'{SCRIPT_NAME} - {res}'
        demisto.debug(error_message)
        return False

    return True


def search_existing_job(job_name: str) -> Dict[str, Any]:
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

    if not status:
        error_message = f'{SCRIPT_NAME} - {res}'
        demisto.debug(error_message)
        return {}

    search_results = res.get('response', {}).get('data')
    if search_results:
        return search_results[0]

    return {}


def main():
    args = demisto.args()
    job_name = args.get('job_name')

    try:
        existing_job = search_existing_job(job_name)
        configuration_status = configure_job(job_name, existing_job)

        return_results(
            CommandResults(
                outputs_prefix='ConfigurationSetup.Jobs',
                outputs_key_field='name',
                outputs={
                    'name': job_name,
                    'jobname': job_name,
                    'creationstatus': 'Success.' if configuration_status else 'Failure.',
                },
            )
        )

    except Exception as e:
        return_error(f'{SCRIPT_NAME} - Error occurred while configuring list "{job_name}".\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
