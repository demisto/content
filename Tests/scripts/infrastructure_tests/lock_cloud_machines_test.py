import pytest
from Tests.scripts.lock_cloud_machines import get_my_place_in_the_queue, try_to_lock_machine, get_machines_locks_details


def test_try_to_lock_machine(mocker):
    """
    given:  machine to try to lock.
    when:   locking for a free machine.
    then:   assert that lock_machine_name is empty because there is another lock file with a job that is running.
    """
    mocker.patch('Tests.scripts.lock_cloud_machines.check_job_status', return_value='running')
    mocker.patch('Tests.scripts.lock_cloud_machines.lock_machine', return_value='')

    lock_machine_name = try_to_lock_machine("storage_bucket", 'qa-test-1234', [{'job_id': '1234', 'machine_name': 'qa-test-1234'}, {'job_id': '1235', 'machine_name': 'qa-test-1235'}], 'gitlab_status_token',
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
                                                             MockResponse('test/machines_locks/qa-test-1237-lock-1237')])
    files = get_machines_locks_details(storage, 'test', "test", "machines_locks")
    assert files == [{'job_id': '1234', 'machine_name': 'qa-test-1234'},
                     {'job_id': '1235', 'machine_name': 'qa-test-1235'},
                     {'job_id': '1236', 'machine_name': 'qa-test-1236'},
                     {'job_id': '1237', 'machine_name': 'qa-test-1237'}]
    

