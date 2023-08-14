import json

import pytest
import requests
from requests import ConnectionError, Response

from Tests.scripts.lock_cloud_machines import get_my_place_in_the_queue, try_to_lock_machine,\
    get_machines_locks_details, wait_for_build_to_be_first_in_queue, get_and_lock_all_needed_machines, check_job_status


@pytest.mark.parametrize(
    "responses, expected_times_called, expected_status",
    [
        ([{'status': 'running'}], 1, 'running'),
        ([ConnectionError, {'status': 'running'}], 2, 'running'),
        ([ConnectionError, ConnectionError, {'status': 'running'}], 3, 'running'),
        ([ConnectionError, ConnectionError, ConnectionError, {'status': 'running'}], 4, 'running'),
        ([ConnectionError, ConnectionError, ConnectionError, {'status': 'failed'}], 4, 'failed'),
        ([ConnectionError, ConnectionError, {'status': 'done'}], 3, 'done')
    ],
)
def test_check_job_status_with_connection_errors(mocker, responses, expected_times_called, expected_status):
    """
    given:  connection error exceptions and eventually real status.
    when:   trying to retrieve gitlab job status
    then:   make sure retry mechanism will be triggered on ConnectionErrors
    """
    side_effect_responses = []
    for response in responses:
        if not isinstance(response, dict):
            side_effect_responses.append(response)
        else:
            r = Response()
            r._content = json.dumps(response).encode()
            side_effect_responses.append(r)

    requests_mocker = mocker.patch.object(requests, 'get', side_effect=side_effect_responses)

    assert check_job_status('token', job_id='1', interval=0.001) == expected_status
    assert requests_mocker.call_count == expected_times_called


def test_try_to_lock_machine(mocker):
    """
    given:  machine to try to lock.
    when:   locking for a free machine.
    then:   assert that lock_machine_name returned because the machine was free.
    """
    mocker.patch('Tests.scripts.lock_cloud_machines.check_job_status', return_value='running')
    mocker.patch('Tests.scripts.lock_cloud_machines.lock_machine', return_value='')

    lock_machine_name = try_to_lock_machine("storage_bucket", 'qa-test-1234',
                                            [{'job_id': '1235', 'machine_name': 'qa-test-1235'}],
                                            'gitlab_status_token', "gcs_locks_path", "1234")
    assert lock_machine_name == "qa-test-1234"


def test_try_to_lock_occupied_machine(mocker):
    """
    given:  machine to try to lock.
    when:   locking for a free machine.
    then:   assert that lock_machine_name is empty because there is another lock file with a job that is running.
    """
    mocker.patch('Tests.scripts.lock_cloud_machines.check_job_status', return_value='running')
    mocker.patch('Tests.scripts.lock_cloud_machines.lock_machine', return_value='')

    lock_machine_name = try_to_lock_machine("storage_bucket", 'qa-test-1234',
                                            [{'job_id': '1234', 'machine_name': 'qa-test-1234'},
                                             {'job_id': '1235', 'machine_name': 'qa-test-1235'}],
                                            'gitlab_status_token',
                                            "gcs_locks_path", "1234")
    assert not lock_machine_name


class MockResponse:
    def __init__(self, name='', time_created=''):
        self.name = name
        self.time_created = time_created

    def list_blobs(self):
        print(self.name)


def test_get_my_place_in_the_queue(mocker):
    """
    given:  The job id .
    when:   checking the place in teh queue.
    then:   assert that returns the right place and the right previous_build_in_queue.
    """
    storage = MockResponse()
    mocker.patch.object(storage, 'list_blobs', return_value=[MockResponse('test/queue/1234', '08/04/2000'),
                                                             MockResponse('test/queue/1235', '05/04/2000'),
                                                             MockResponse('test/queue/1236', '06/04/2000'),
                                                             MockResponse('test/queue/1237', '03/04/2000')])

    my_place_in_the_queue, previous_build_in_queue = get_my_place_in_the_queue(storage, 'test', '1235')

    assert my_place_in_the_queue == 1
    assert previous_build_in_queue == '1237'


def test_get_my_place_in_the_queue_exception(mocker):
    """
    given:  The job id.
    when:   checking the place in teh queue and its not existing in the queue.
    then:   assert Exception is returned.
    """
    storage = MockResponse()
    mocker.patch.object(storage, 'list_blobs', return_value=[MockResponse('test/queue/1234', '08/04/2000')])
    with pytest.raises(Exception) as excinfo:
        get_my_place_in_the_queue(storage, 'test', '1238')
    assert str(excinfo.value) == 'Unable to find the queue lock file, probably a problem creating the file'


def test_get_machines_locks_details(mocker):
    """
    given:  storage to search.
    when:   get all the lock machines details.
    then:   assert that returns the right details.
    """
    storage = MockResponse()
    mocker.patch.object(storage, 'list_blobs', return_value=[MockResponse('test/machines_locks/qa-test-1234-lock-1234'),
                                                             MockResponse('test/machines_locks/qa-test-1235-lock-1235'),
                                                             MockResponse('test/machines_locks/qa-test-1236-lock-1236'),
                                                             MockResponse('test/machines_locks/qa-test-1237-lock-1237')
                                                             ])
    files = get_machines_locks_details(storage, 'test', "test", "machines_locks")
    assert files == [{'job_id': '1234', 'machine_name': 'qa-test-1234'},
                     {'job_id': '1235', 'machine_name': 'qa-test-1235'},
                     {'job_id': '1236', 'machine_name': 'qa-test-1236'},
                     {'job_id': '1237', 'machine_name': 'qa-test-1237'}]


def test_wait_for_build_to_be_first_in_queue(mocker):
    """
    given:  the queue and the job id.
    when:   the first loop the place in the queue wil be 1 and the previous_build_status wil be running.
            the second loop the place in the queue wil be 1 and the previous_build_status wil be failed.
            the third loop the place in the queue wil be 0.
    then:   assert the function "get_my_place_in_the_queue" wil be called 3 times.
            assert the function "check_job_status" wil be called 2 times.
            assert the function "remove_file" wil be called ones.
    """
    mock_my_place = mocker.patch('Tests.scripts.lock_cloud_machines.get_my_place_in_the_queue',
                                 side_effect=[(1, "1234"),
                                              (1, "1234"),
                                              (0, "1234")])
    mock_job_status = mocker.patch('Tests.scripts.lock_cloud_machines.check_job_status',
                                   side_effect=['running', 'failed'])
    mock_remove_file = mocker.patch('Tests.scripts.lock_cloud_machines.remove_file')

    storage = MockResponse()
    wait_for_build_to_be_first_in_queue(storage, storage, "test", "1234", "12345")
    assert mock_my_place.call_count == 3
    assert mock_job_status.call_count == 2
    assert mock_remove_file.call_count == 1


def test_get_and_lock_all_needed_machines(mocker):
    """
    given:  the 2 available machines, number_machines_to_lock = 2 and the job id.
    when:   the first loop of the machines the machine1 will be busy and the machine2 will be available to lock.
            then the busy_machines will be [machine1] and the function sleep for 60 seconds.
            the second loop of the machines the machine1 will be available to lock.
    then:   assert the function "try_to_lock_machine" wil be called 3 times.
            assert the returned lock_machine_list == ["machine2", "machine1"]
    """
    storage = MockResponse()
    mocker.patch('Tests.scripts.lock_cloud_machines.get_machines_locks_details', return_value=[])
    mock_try_to_lock_machine = mocker.patch('Tests.scripts.lock_cloud_machines.try_to_lock_machine',
                                            side_effect=['', 'machine2', 'machine1'])
    lock_machine_list = get_and_lock_all_needed_machines(storage, storage, ["machine1", "machine2"], "gcs_locks_path",
                                                         2, "job_id", "gitlab_status_token")
    assert mock_try_to_lock_machine.call_count == 3
    assert lock_machine_list == ["machine2", "machine1"]
