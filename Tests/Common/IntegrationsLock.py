import datetime
import os
from contextlib import contextmanager
import pytz
import requests
from google.cloud import storage
from google.api_core.exceptions import PreconditionFailed


LOCKS_PATH = 'content-locks'
BUCKET_NAME = os.environ.get('GCS_ARTIFACTS_BUCKET')
CIRCLE_BUILD_NUM = os.environ.get('CIRCLE_BUILD_NUM')
WORKFLOW_ID = os.environ.get('CIRCLE_WORKFLOW_ID')
CIRCLE_STATUS_TOKEN = os.environ.get('CIRCLECI_STATUS_TOKEN')


@contextmanager
def acquire_test_lock(test_playbook) -> None:
    """
    This is a context manager that handles all the locking and unlocking of integrations.
    Execution is as following:
    * Attempts to lock the test's integrations and yields the result of this attempt
    * If lock attempt has failed - yields False, if it succeeds - yields True
    * Once the test is done- will unlock all integrations
    Args:
        test_playbook (TestPlaybook): The test playbook instance we want to test under the lock's context
    Yields:
        A boolean indicating the lock attempt result
    """
    locked = safe_lock_integrations(test_playbook)
    try:
        yield locked
    except Exception:
        test_playbook.build_context.logging_module.exception('Failed with test lock')
    finally:
        if not locked:
            return
        safe_unlock_integrations(test_playbook)


def safe_unlock_integrations(test_playbook):
    """
    This integration safely unlocks the test's integrations.
    If an unexpected error occurs - this method will log it's details and other tests execution will continue
    Args:
        test_playbook (TestPlaybook): The test playbook instance we want to test under the lock's context
    """
    try:
        # executing the test could take a while, re-instancing the storage client
        storage_client = storage.Client()
        unlock_integrations(test_playbook, storage_client)
    except Exception:
        test_playbook.build_context.logging_module.exception('attempt to unlock integration failed for unknown reason.')


def safe_lock_integrations(test_playbook) -> bool:
    """
    This integration safely locks the test's integrations and return it's result
    If an unexpected error occurs - this method will log it's details and return False
    Args:
        test_playbook (TestPlaybook): The test playbook instance we want to test under the lock's context

    Returns:
        A boolean indicating the lock attempt result
    """

    integration_names = [integration.name for integration in test_playbook.integrations_to_lock]
    if integration_names:
        print_msg = f'Attempting to lock integrations {integration_names}, ' \
                    f'with timeout {test_playbook.configuration.timeout}'
    else:
        print_msg = 'No integrations to lock'
    test_playbook.build_context.logging_module.debug(print_msg)
    try:
        storage_client = storage.Client()
        locked = lock_integrations(test_playbook, storage_client)
    except Exception:
        test_playbook.build_context.logging_module.exception('attempt to lock integration failed for unknown reason.')
        locked = False
    return locked


def workflow_still_running(workflow_id: str, test_playbook) -> bool:
    """
    This method takes a workflow id and checks if the workflow is still running
    If given workflow ID is the same as the current workflow, will simply return True
    else it will query circleci api for the workflow and return the status
    Args:
        workflow_id: The ID of the workflow
        test_playbook (TestPlaybook): The test playbook instance we want to test under the lock's context

    Returns:
        True if the workflow is running, else False
    """
    # If this is the current workflow_id
    if workflow_id == WORKFLOW_ID:
        return True
    else:
        try:
            workflow_details_response = requests.get(f'https://circleci.com/api/v2/workflow/{workflow_id}',
                                                     headers={'Accept': 'application/json'},
                                                     auth=(CIRCLE_STATUS_TOKEN, ''))
            workflow_details_response.raise_for_status()
        except Exception:
            test_playbook.build_context.logging_module.exception(
                f'Failed to get circleci response about workflow with id {workflow_id}.')
            return True
        return workflow_details_response.json().get('status') not in ('canceled', 'success', 'failed')


def lock_integrations(test_playbook,
                      storage_client: storage.Client) -> bool:
    """
    Locks all the test's integrations
    Args:
        test_playbook (TestPlaybook): The test playbook instance we want to test under the lock's context
        storage_client: The GCP storage client

    Returns:
        True if all the test's integrations were successfully locked, else False
    """
    integrations = [integration.name for integration in test_playbook.integrations_to_lock]
    if not integrations:
        return True
    existing_integrations_lock_files = get_locked_integrations(integrations, storage_client)
    for integration, lock_file in existing_integrations_lock_files.items():
        # Each file has content in the form of <circleci-build-number>:<timeout in seconds>
        # If it has not expired - it means the integration is currently locked by another test.
        workflow_id, build_number, lock_timeout = lock_file.download_as_string().decode().split(':')
        if not lock_expired(lock_file, lock_timeout) and workflow_still_running(workflow_id, test_playbook):
            # there is a locked integration for which the lock is not expired - test cannot be executed at the moment
            test_playbook.build_context.logging_module.warning(
                f'Could not lock integration {integration}, another lock file was exist with '
                f'build number: {build_number}, timeout: {lock_timeout}, last update at {lock_file.updated}.\n'
                f'Delaying test execution')
            return False
    integrations_generation_number = {}
    # Gathering generation number with which the new file will be created,
    # See https://cloud.google.com/storage/docs/generations-preconditions for details.
    for integration in integrations:
        if integration in existing_integrations_lock_files:
            integrations_generation_number[integration] = existing_integrations_lock_files[integration].generation
        else:
            integrations_generation_number[integration] = 0
    return create_lock_files(integrations_generation_number,
                             storage_client,
                             test_playbook)


def create_lock_files(integrations_generation_number: dict,
                      storage_client: storage.Client,
                      test_playbook) -> bool:
    """
    This method tries to create a lock files for all integrations specified in 'integrations_generation_number'.
    Each file should contain <circle-ci-build-number>:<test-timeout>
    where the <circle-ci-build-number> part is for debugging and troubleshooting
    and the <test-timeout> part is to be able to unlock revoked test files.
    If for any of the integrations, the lock file creation will fail- the already created files will be cleaned.
    Args:
        integrations_generation_number: A dict in the form of {<integration-name>:<integration-generation>}
        storage_client: The GCP storage client
        test_playbook (TestPlaybook): The test playbook instance we want to test under the lock's context

    Returns:

    """
    locked_integrations = []
    bucket = storage_client.bucket(BUCKET_NAME)
    for integration, generation_number in integrations_generation_number.items():
        blob = bucket.blob(f'{LOCKS_PATH}/{integration}')
        try:
            blob.upload_from_string(f'{WORKFLOW_ID}:{CIRCLE_BUILD_NUM}:{test_playbook.configuration.timeout + 30}',
                                    if_generation_match=generation_number)
            test_playbook.build_context.logging_module.debug(f'integration {integration} locked')
            locked_integrations.append(integration)
        except PreconditionFailed:
            # if this exception occurs it means that another build has locked this integration
            # before this build managed to do it.
            # we need to unlock all the integrations we have already locked and try again later
            test_playbook.build_context.logging_module.warning(
                f'Could not lock integration {integration}, Create file with precondition failed.'
                f'delaying test execution.')
            unlock_integrations(test_playbook, storage_client)
            return False
    return True


def unlock_integrations(test_playbook,
                        storage_client: storage.Client) -> None:
    """
    Delete all integration lock files for integrations specified in 'locked_integrations'
    Args:
        test_playbook (TestPlaybook): The test playbook instance we want to test under the lock's context
        storage_client: The GCP storage client
    """
    locked_integrations = [integration.name for integration in test_playbook.integrations]
    locked_integration_blobs = get_locked_integrations(locked_integrations, storage_client)
    for integration, lock_file in locked_integration_blobs.items():
        try:
            # Verifying build number is the same as current build number to avoid deleting other tests lock files
            _, build_number, _ = lock_file.download_as_string().decode().split(':')
            if build_number == CIRCLE_BUILD_NUM:
                lock_file.delete(if_generation_match=lock_file.generation)
                test_playbook.build_context.logging_module.debug(
                    f'Integration {integration} unlocked')
        except PreconditionFailed:
            test_playbook.build_context.logging_module.error(
                f'Could not unlock integration {integration} precondition failure')


def get_locked_integrations(integrations: list, storage_client: storage.Client) -> dict:
    """
    Getting all locked integrations files
    Args:
        integrations: Integrations that we want to get lock files for
        storage_client: The GCP storage client

    Returns:
        A dict of the form {<integration-name>:<integration-blob-object>} for all integrations that has a blob object.
    """
    # Listing all files in lock folder
    # Wrapping in 'list' operator because list_blobs return a generator which can only be iterated once
    lock_files_ls = list(storage_client.list_blobs(BUCKET_NAME, prefix=f'{LOCKS_PATH}'))
    current_integrations_lock_files = {}
    # Getting all existing files details for integrations that we want to lock
    for integration in integrations:
        current_integrations_lock_files.update({integration: [lock_file_blob for lock_file_blob in lock_files_ls if
                                                              lock_file_blob.name == f'{LOCKS_PATH}/{integration}']})
    # Filtering 'current_integrations_lock_files' from integrations with no files
    current_integrations_lock_files = {integration: blob_files[0] for integration, blob_files in
                                       current_integrations_lock_files.items() if blob_files}
    return current_integrations_lock_files


def lock_expired(lock_file: storage.Blob, lock_timeout: str) -> bool:
    """
    Checks if the time that passed since the creation of the 'lock_file' is more then 'lock_timeout'.
    If not- it means that the integration represented by the lock file is currently locked and is tested in another build
    Args:
        lock_file: The lock file blob object
        lock_timeout: The expiration timeout of the lock in seconds

    Returns:
        True if the lock has expired it's timeout, else False
    """
    return datetime.datetime.now(tz=pytz.utc) - lock_file.updated >= datetime.timedelta(seconds=int(lock_timeout))
