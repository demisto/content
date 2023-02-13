import requests
import json
import urllib3
from CommonServerPython import *

urllib3.disable_warnings()


def http_request(method, url_suffix, json=None):
    """
    Helper function to perform http request
    """
    try:
        api_suffix = "/api/v1"
        base_url = demisto.params().get('base_url')
        if base_url.endswith("/"):  # remove slash in the end
            base_url = base_url[:-1]
        api_key = demisto.params().get('apikey')
        verify = not demisto.params().get('insecure', True)

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': str(api_key)
        }
        r = requests.request(
            method,
            base_url + api_suffix + url_suffix,
            json=json,
            headers=headers,
            verify=verify
        )

        if r.status_code == 401:
            return_error(message='Authentication parameters are invalid, '
                                 'Please check your URL address and your API token')

        if r.status_code not in (200, 204):
            result = r.json()
            return_error(message='Error %s occurred with command. Error is: %s' % (r.status_code, str((result)["statusText"])))
        try:
            return r.json()
        except ValueError:
            return None
    except Exception as e:
        return_error(message='Error occurred on API call: %s. Error is: %s'
                             % (base_url + api_suffix + url_suffix, str(e)))


def get_specific_device():
    """
    Get specific device by id
    """
    device_id = demisto.args().get('device_id')
    result = http_request('GET', "/devices/%s" % str(device_id))
    ec = {'DeepInstinct.Devices(val.id && val.id == obj.id)': result}

    return_results(CommandResults(
        readable_output=tableToMarkdown('Device', result),
        outputs=ec,
        raw_response=result
    ))


def get_events():
    """
    Get events
    """
    first_event_id = demisto.args().get('first_event_id')
    result = http_request('GET', '/events?after_event_id=' + str(first_event_id))
    events = {}
    if 'events' in result:
        events = result['events']
    ec = {'DeepInstinct.Events(val.id && val.id == obj.id)': events}

    return_results(CommandResults(
        readable_output=tableToMarkdown('Events', events),
        outputs=ec,
        raw_response=events
    ))


def get_all_groups():
    """
    Get all groups

    """
    result = http_request('GET', "/groups")
    ec = {'DeepInstinct.Groups(val.id && val.id == obj.id)': result}

    return_results(CommandResults(
        readable_output=tableToMarkdown('Groups', result),
        outputs=ec,
        raw_response=result
    ))


def get_all_policies():
    """
    Get all policies

    """
    result = http_request('GET', "/policies")
    ec = {'DeepInstinct.Policies(val.id && val.id == obj.id)': result}

    return_results(CommandResults(
        readable_output=tableToMarkdown('Policies', result),
        outputs=ec,
        raw_response=result
    ))


def add_hash_to_denylist():
    """
    Add hash to deny-list
    """
    policy_id = demisto.args().get('policy_id')
    file_hash = demisto.args().get('file_hash')
    comment = demisto.args().get('comment') or ""
    http_request('POST', '/policies/%s/deny-list/hashes/%s' % (str(policy_id), file_hash), json={"comment": comment})
    return_results('ok')


def add_hash_to_allowlist():
    """
    Add hash to allow-list
    """
    policy_id = demisto.args().get('policy_id')
    file_hash = demisto.args().get('file_hash')
    comment = demisto.args().get('comment') or ""
    http_request('POST', '/policies/%s/allow-list/hashes/%s' % (str(policy_id), file_hash), json={"comment": comment})
    return_results('ok')


def remove_hash_from_denylist():
    """
    Remove hash from deny-list
    """
    policy_id = demisto.args().get('policy_id')
    file_hash = demisto.args().get('file_hash')

    item_list = [{'item': file_hash}]

    http_request('DELETE', '/policies/%s/deny-list/hashes' % (str(policy_id)), json={"items": item_list})
    return_results('ok')


def remove_hash_from_allowlist():
    """
    Remove hash from allow-list
    """
    policy_id = demisto.args().get('policy_id')
    file_hash = demisto.args().get('file_hash')

    item_list = [{'item': file_hash}]

    http_request('DELETE', '/policies/%s/allow-list/hashes' % (str(policy_id)), json={"items": item_list})
    return_results('ok')


def add_devices_to_group():
    """
    Add devices to specific group
    """
    group_id = demisto.args().get('group_id')
    device_ids_input = demisto.args().get('device_ids')
    device_ids = [int(num) for num in device_ids_input.split(",")]
    http_request('POST', '/groups/%s/add-devices' % str(group_id), json={"devices": device_ids})
    return_results('ok')


def remove_devices_from_group():
    """
    Remove devices from group
    """
    group_id = demisto.args().get('group_id')
    device_ids_input = demisto.args().get('device_ids')
    device_ids = [int(num) for num in device_ids_input.split(",")]

    http_request('POST', '/groups/%s/remove-devices' % str(group_id), json={"devices": device_ids})
    return_results('ok')


def delete_files_remotely():
    """
    Delete given file ids remotely
    """
    event_ids_input = demisto.args().get('event_ids')
    event_ids = [int(num) for num in event_ids_input.split(",")]
    http_request('POST', '/devices/actions/delete-remote-files', json={"ids": event_ids})
    return_results('ok')


def terminate_remote_processes():
    """
    Terminate remove processes by given event ids
    """
    event_ids_input = demisto.args().get('event_ids')
    event_ids = [int(num) for num in event_ids_input.split(",")]
    http_request('POST', '/devices/actions/terminate-remote-process', json={"ids": event_ids})
    return_results('ok')


def close_events():
    """
    Close events by event ids
    """
    event_ids_input = demisto.args().get('event_ids')
    event_ids = [int(num) for num in event_ids_input.split(",")]
    http_request('POST', '/events/actions/close', json={"ids": event_ids})
    return_results('ok')


def fetch_incidents():
    incidents: list = []
    last_id = arg_to_number(demisto.params().get('first_fetch', 0))
    max_fetch = arg_to_number(demisto.params().get('max_fetch')) or 50

    last_run = demisto.getLastRun()
    if last_run and last_run.get('last_id') is not None:
        last_id = last_run.get('last_id')

    events = http_request('GET', '/events?after_event_id=' + str(last_id))
    while events and events['events'] and len(incidents) < max_fetch:
        for event in events['events']:
            incident = {
                'name': "DeepInstinct_" + str(event['id']),  # name is required field, must be set
                'occurred': event['insertion_timestamp'],
                'rawJSON': json.dumps(event)
            }
            incidents.append(incident)
            if len(incidents) >= max_fetch:
                demisto.setLastRun({'last_id': event['id']})
                break

        demisto.setLastRun({'last_id': events['last_id']})
        events = http_request('GET', '/events?after_event_id=' + str(events['last_id']))

    demisto.incidents(incidents)


def test_module():
    """
    Test Module
    """
    try:
        api_suffix = "/api/v1"
        base_url = demisto.params().get('base_url')
        if base_url.endswith("/"):  # remove slash in the end
            base_url = base_url[:-1]
        api_key = demisto.params().get('apikey')

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': str(api_key)
        }
        request_url = f'{base_url}/{api_suffix}/groups/'

        r = requests.get(request_url, headers=headers)

        if r.status_code == 200:
            demisto.results("ok")

        if r.status_code == 401:
            return_error(message='Unauthorized request. Please Check your API token and try again')
    except Exception:
        return_error(message='Invalid URL, please correct and try again')


def get_suspicious_events():
    """
    Get suspicious events
    """
    first_event_id = demisto.args().get('first_event_id')
    result = http_request('GET', '/suspicious-events?after_event_id=' + str(first_event_id))
    events = {}
    if 'events' in result:
        events = result['events']
    ec = {'DeepInstinct.Suspicious-Events(val.id && val.id == obj.id)': events}

    return_results(CommandResults(
        readable_output=tableToMarkdown('Events', events),
        outputs=ec,
        raw_response=events
    ))


def isolate_from_network():
    """
    Isolate given Device Id(s) from Network
    """
    device_ids_input = demisto.args().get('device_ids')
    device_ids = [int(num) for num in device_ids_input.split(",")]
    http_request('POST', '/devices/actions/isolate-from-network', json={"ids": device_ids})
    return_results('ok')


def release_from_isolation():
    """
    Release given Device Id(s) from Isolation
    """
    device_ids_input = demisto.args().get('device_ids')
    device_ids = [int(num) for num in device_ids_input.split(",")]
    http_request('POST', '/devices/actions/release-from-isolation', json={"ids": device_ids})
    return_results('ok')


def remote_file_upload():
    """
    Request Remote File Upload by Event ID
    """
    event_id = demisto.args().get('event_id')
    http_request('POST', '/devices/actions/request-remote-file-upload/%s' % (str(event_id)))
    return_results('ok')


def disable_device():
    """
    Disable D-client at next Check-In
    """
    device_id = demisto.args().get('device_id')
    http_request('POST', '/devices/%s/actions/disable' % (str(device_id)))
    return_results('ok')


def enable_device():
    """
    Enable D-Client at next Check-In
    """
    device_id = demisto.args().get('device_id')
    http_request('POST', '/devices/%s/actions/enable' % (str(device_id)))
    return_results('ok')


def remove_device():
    """
    Uninstall D-Client on device at next Check-In
    """
    device_id = demisto.args().get('device_id')
    http_request('POST', '/devices/%s/actions/remove' % (str(device_id)))
    return_results('ok')


def upload_logs():
    """
    Upload D-Client Logs at next Check-In
    """
    device_id = demisto.args().get('device_id')
    http_request('POST', '/devices/%s/actions/upload-logs' % (str(device_id)))
    return_results('ok')


def main():  # pragma: no cover
    try:
        # Commands
        command = demisto.command()
        if command == 'test-module':
            test_module()

        elif command == 'deepinstinctv3-get-device':
            get_specific_device()

        elif command == 'deepinstinctv3-get-events':
            get_events()

        elif command == 'deepinstinctv3-get-suspicious-events':
            get_suspicious_events()

        elif command == 'deepinstinctv3-get-all-groups':
            get_all_groups()

        elif command == 'deepinstinctv3-get-all-policies':
            get_all_policies()

        elif command == 'deepinstinctv3-add-hash-to-deny-list':
            add_hash_to_denylist()

        elif command == 'deepinstinctv3-add-hash-to-allow-list':
            add_hash_to_allowlist()

        elif command == 'deepinstinctv3-remove-hash-from-deny-list':
            remove_hash_from_denylist()

        elif command == 'deepinstinctv3-remove-hash-from-allow-list':
            remove_hash_from_allowlist()

        elif command == 'deepinstinctv3-add-devices-to-group':
            add_devices_to_group()

        elif command == 'deepinstinctv3-remove-devices-from-group':
            remove_devices_from_group()

        elif command == 'deepinstinctv3-delete-files-remotely':
            delete_files_remotely()

        elif command == 'deepinstinctv3-terminate-processes':
            terminate_remote_processes()

        elif command == 'deepinstinctv3-close-events':
            close_events()

        elif command == 'fetch-incidents':
            fetch_incidents()

        elif command == 'deepinstinctv3-isolate-from-network':
            isolate_from_network()

        elif command == 'deepinstinctv3-release-from-isolation':
            release_from_isolation()

        elif command == 'deepinstinctv3-remote-file-upload':
            remote_file_upload()

        elif command == 'deepinstinctv3-disable-device':
            disable_device()

        elif command == 'deepinstinctv3-enable-device':
            enable_device()

        elif command == 'deepinstinctv3-remove-device':
            remove_device()

        elif command == 'deepinstinctv3-upload-logs':
            upload_logs()
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {e}', error=traceback.format_exc())


if __name__ in ('__builtin__', 'builtins'):
    main()
