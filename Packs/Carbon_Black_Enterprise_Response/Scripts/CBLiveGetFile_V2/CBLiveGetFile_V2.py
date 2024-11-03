import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json

from contextlib import contextmanager

'''Globals'''
ERROR_SENSOR = -1
ERROR_SESSION = -1


''' STANDALONE FUNCTION '''


def search_sensor_id(endpoint: str) -> int:
    """ Retrieve list of connected sensors from:
            Integration: VMware Carbon Black EDR (Live Response API).
            Command: cb-list-sensors.
    Args:
        endpoint: Endpoint name - hostname/IP

    Returns:
        str: sensor id if found else empty string.
    """
    sensor_id = ERROR_SENSOR
    # Execute command and extract sensors
    output = demisto.executeCommand("cb-list-sensors", {})
    sensors = dict_safe_get(output, [0, 'EntryContext', 'CbResponse.Sensors(val.CbSensorID==obj.CbSensorID)'],
                            default_return_value=[], return_type=list)  # type: ignore
    # Search for sensor with endpoint or ip
    for sensor in sensors:
        is_same_ipaddress = endpoint in dict_safe_get(sensor, ["IPAddress", "IPAddresses"],
                                                      default_return_value=[], return_type=list)
        is_same_endpoint = sensor.get("Hostname") == endpoint
        if is_same_endpoint or is_same_ipaddress:
            sensor_id = sensor.get("CbSensorID", ERROR_SENSOR)
            break

    return sensor_id


def search_active_session(sensor_id: int) -> int:
    """ Search if exists current active session to sensor (It exists will use this session).

    Args:
        sensor_id: Sensor id to search session for.

    Returns:
        str: Exists active session to sensor, If not exists return '0'.
    """
    output = demisto.executeCommand("cb-list-sessions", {'sensor': sensor_id, 'status': 'active'})
    session_id = dict_safe_get(output, [0, 'EntryContext', 'CbLiveResponse.Sessions(val.CbSessionID==obj.CbSessionID)',
                                        0, 'CbSessionID'], ERROR_SESSION, int)

    return session_id


def create_active_session(sensor_id: int, timeout: str) -> int:
    """ Create active session to sensor.

    Args:
        sensor_id: Sensor to create new session for.
        timeout: Session timeout.

    Returns:
        str: New active session to sensor, If not able to create session return '0'.
    """
    session_id = ERROR_SESSION

    for trial in range(3):
        try:
            output = demisto.executeCommand("cb-session-create-and-wait", {'sensor': sensor_id, 'command-timeout': timeout})
            raw_response = json.loads(dict_safe_get(output, [0, 'Contents']))
            session_id = dict_safe_get(raw_response, ["id"], ERROR_SESSION)
            break
        except json.JSONDecodeError:
            # Session could be failing due to Carbon Response bug, We retry to get session 3 times, Before failing.
            if trial == 2:
                raise Exception("Unable to parse entry context while creating session, try to raise timeout argument.")

    return session_id


def close_session(session_id):
    """ Close sensor session.

    Args:
        session_id: Session id to be closed
    """
    demisto.executeCommand("cb-session-close", {'session': session_id})


@contextmanager
def open_session(endpoint: str, timeout: str):
    """ Handler to Carbon Black sessions.

    Enter:
        1. Translate endpoint name to sensor id.
        2. Search for current active session to sensor id.
        3. If not exists -> Create new active session.

    Args:
        endpoint: Endpoint name to be handled.
        timeout: Session timeout.

    Yields:
        int: active session id.

    Raises:
        Exception: If session not succefully established.
    """
    active_session = ERROR_SESSION
    try:
        # Get sensor id from endpoint name (IP/Hostname)
        sensor_id = search_sensor_id(endpoint)
        if sensor_id == ERROR_SENSOR:
            raise Exception(f"Sensor with {endpoint} is not connected!")
        # Get session to communicate with sensor.
        active_session = search_active_session(sensor_id)
        if active_session == ERROR_SESSION:
            active_session = create_active_session(sensor_id, timeout)
        # Validate that session established succesfully
        if active_session == ERROR_SESSION:
            raise Exception(f"Unable to establish active session to {endpoint}, sensor: {sensor_id}")
        # Yield active session for communication.
        yield active_session

    except Exception as e:
        raise Exception(f"Unable to establish session to endpoint {endpoint}.\nError:{e}")
    finally:
        close_session(active_session)


def get_file_from_endpoint_path(session_id: str, path: str) -> tuple[dict | list, dict]:
    """ Get file from file from session (endpoint/sensor).

    Args:
        session_id: Actvie session id.
        path: Path of file to be retrieved.

    Returns:
        dict/list: entry context.
        dict: raw response.

    Raises:
        Exception: If file can't be retrieved.
    """
    try:
        # Get file from enpoint
        output = demisto.executeCommand("cb-get-file-from-endpoint", {'session': session_id, 'path': path})
        entry_context = dict_safe_get(output, [0, 'EntryContext'])
        # Output file to war-room as soon as possible, But removing human-readable so it will be a single summary in the end.
        output[0]['HumanReadable'] = ""
        demisto.results(output)

    except Exception as e:
        raise Exception(f"Session established but file can't retrieved from endpoint.\nError:{e}")

    return entry_context


def cb_live_get_file(endpoint: str, path: str, timeout: str):
    """ Download list of files from endpoint.

    Args:
        endpoint: Endpoint name to be handled.
        path: List of file paths to download from endpoint.
        timeout: Session timeout.

    Returns:
        list: collected entry contexts from command "cb-get-file-from-endpoint".
    """
    entry_contexts = []
    with open_session(endpoint, timeout) as active_session:
        for single_path in argToList(path):
            entry_context = get_file_from_endpoint_path(active_session, single_path)
            entry_contexts.append(entry_context)

    return entry_contexts


def build_table_dict(entry_contexts: List[dict]) -> List[dict]:
    """ Create table from all retirieved entry context.

    Args:
        entry_contexts: List of entry contexts from command "cb-get-file-from-endpoint"

    Returns:
        list: filtered list with modified headers
    """
    table = []
    for ec in entry_contexts:

        table_entry = {}

        for file_ec in ec.values():
            for key, value in file_ec.items():
                if key == "FileID":
                    table_entry["File ID"] = value
                elif key == "OperandObject":
                    table_entry["File path"] = value

        table.append(table_entry)

    return table


''' COMMAND FUNCTION '''


def cb_live_get_file_command(**kwargs) -> tuple[str, dict, dict]:
    entry_contexts = cb_live_get_file(**kwargs)
    human_readable = tableToMarkdown(name=f"Files downloaded from endpoint {kwargs.get('endpoint')}",
                                     t=build_table_dict(entry_contexts))

    return human_readable, {}, {}


''' MAIN FUNCTION '''


def main():
    try:
        return_outputs(*cb_live_get_file_command(**demisto.args()))
    except Exception as e:
        return_error(f'Failed to execute CBLiveGetFile_v2. Error: {str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
