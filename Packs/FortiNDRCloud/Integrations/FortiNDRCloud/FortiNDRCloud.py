"""    Fortinet FortiNDR Cloud Integration for Cortex XSOAR (aka Demisto)

       This integration allows fetching detections, entities, events and
       saved searches from Fortinet FortiNDR Cloud APIs, also allows for
       some management operations like creating scheduled pcap tasks,
       updating detection rules and resolving detections.
"""
import json
from datetime import datetime, timedelta
from typing import Tuple

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

TRAINING_ACC = 'f6f6f836-8bcd-4f5d-bd61-68d303c4f634'
MAX_DETECTIONS = 10000
DEFAULT_DELAY = 10
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
USER_AGENT = 'FortiNDRCloud_Cortex.v1.0.1'


class Client(BaseClient):
    @staticmethod
    def getUrl(api, testing=False) -> str:
        """Provide the base url to access the specific API.
        :param str api:  The specific API for which we need the base url.
        return: The requested base url
        rtype str
        """
        url: str = ''
        if testing:
            if api == 'Detections':
                url = 'https://detections-uat.icebrg.io/v1/'
            elif api == 'Sensors':
                url = 'https://sensor-uat.icebrg.io/v1/'
            elif api == 'Entity':
                url = 'https://entity-uat.icebrg.io/v1/entity/'
        else:
            if api == 'Detections':
                url = 'https://detections.icebrg.io/v1/'
            elif api == 'Sensors':
                url = 'https://sensor.icebrg.io/v1/'
            elif api == 'Entity':
                url = 'https://entity.icebrg.io/v1/entity/'

        return url

    @staticmethod
    def getClient(api, api_key, testing=False):
        """Provide the required Client instance to interact with
        the specific API.
        :param str api:  The specific API we need to interact with.
        :param str api_key: The API key to authenticate the request bwing made.
        return: The requested Client instance.
        rtype str
        """
        headers = {
            'Authorization': 'IBToken ' + api_key,
            'User-Agent': USER_AGENT,
            'Content-Type': 'application/json',
        }

        match api:
            case 'Entity':
                return EntityClient(
                    base_url=Client.getUrl(api, testing),
                    headers=headers
                )
            case 'Sensors':
                return SensorClient(
                    base_url=Client.getUrl(api, testing),
                    headers=headers
                )
            case 'Detections':
                return DetectionClient(
                    base_url=Client.getUrl(api, testing),
                    headers=headers
                )


class SensorClient(Client):
    """Client that makes HTTP requests to the Sensor API
    """

    def getSensors(self, args: str = '') -> Dict[str, Any]:
        """ Calls the GET /sensors endpoint to retrieve the sensors
            :return JSON response from /sensors endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('SensorClient.getSensors method has been called.')

        return self._http_request(
            method='GET',
            url_suffix='sensors' + args
        )

    def getDevices(self, args: str = '') -> Dict[str, Any]:
        """ Calls the GET /devices endpoint to retrieve the devices
            :return JSON response from /devices endpoint
            :rtype Dict[str, Any]
        """
        demisto.info('SensorClient.getDevices method has been called.')

        result = self._http_request(
            method='GET',
            url_suffix='devices' + args
        )

        return result.get('devices')

    def getTasks(self, taskid: str = '') -> Dict[str, Any]:
        """ Calls the GET endpoint to retrieve either the list of tasks or
        the specific task with id <taskid>
            :return JSON response from endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('SensorClient.getTasks method has been called.')

        suffix = 'pcaptasks'
        if taskid != '':
            suffix += '/' + taskid

        demisto.debug(f"URL SUFFIX= {suffix}")
        return self._http_request(
            method='GET',
            url_suffix=suffix
        )

    def createTasks(self, data=None) -> Dict[str, Any]:
        """ Calls to the Sensors API to create a new PCAP task
            :params data attributes to be added to the request's body
            :return JSON response from endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('SensorClient.createTasks method has been called.')

        return self._http_request(
            method='POST',
            url_suffix='pcaptasks',
            data=json.dumps(data)
        )

    def getTelemetry(self, telemetry: str, args: str) -> Dict[str, Any]:
        """ Calls the GET /telemetry/{telemetry} endpoint to retrieve the
            specific telemetry
            :param str telemetry: the telemetry to be retrieved
            :param str args: some filters
            :return JSON response from /telemetry/{telemetry} endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('SensorClient.getTelemetry method has been called.')

        return self._http_request(
            method='GET',
            url_suffix='telemetry/' + telemetry.lower() + args
        )


class EntityClient(Client):
    """ Client that makes HTTP requests to the Entity API
    """

    def getEntitySummary(self, entity: str) -> Dict[str, Any]:
        """ Calls the GET /{entity}/summary endpoint to retrieve the
            entity's summary
            :param str entity: the entity to retrieve the summary from
            :return JSON response from /{entity}/summary endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('EntityClient.getEntitySummary method has been called.')

        return self._http_request(
            method='GET',
            url_suffix=entity + '/summary'
        )

    def getEntityPdns(self, entity: str, args: str) -> Dict[str, Any]:
        """ Calls the GET /{entity}/pdns endpoint to retrieve the
            entity's pdns
            :param str entity: the entity to retrieve the pdns from
            :return JSON response from /{entity}/pdns endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('EntityClient.getEntityPdns method has been called.')

        return self._http_request(
            method='GET',
            url_suffix=entity + "/pdns" + args
        )

    def getEntityDhcp(self, entity: str, args: str) -> Dict[str, Any]:
        """ Calls the GET /{entity}/dhcp endpoint to retrieve the
            entity's summary
            :param str entity: the entity to retrieve the dhcp from
            :return JSON response from /{entity}/dhcp endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('EntityClient.getEntityDhcp method has been called.')

        return self._http_request(
            method='GET',
            url_suffix=entity + "/dhcp" + args
        )

    def getEntityFile(self, entity: str) -> Dict[str, Any]:
        """ Calls the GET /{entity}/file endpoint to retrieve the
            entity's summary
            :param str entity: the entity to retrieve the file from
            :return JSON response from /{entity}/file endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('EntityClient.getEntityFile method has been called.')

        return self._http_request(
            method='GET',
            url_suffix=entity + "/file"
        )


class DetectionClient(Client):
    """ Client that makes HTTP requests to the Detections API
    """

    def getDetections(self, args: str = '') -> Dict[str, Any]:
        """ Calls the GET /detections endpoint to retrieve the detections
            :return JSON response from /detections endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('DetectionClient.getDetections method has been called.')
        return self._http_request(
            method='GET',
            url_suffix='/detections' + args
        )

    def getDetectionRules(self, args: str = '') -> Dict[str, Any]:
        """ Calls the GET /rules endpoint to retrieve the Detection Rules
            :param str args: some filters to be passed in the request
            :return JSON response from /rules endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('DetectionClient.getDetectionRules method has been called.')
        return self._http_request(
            method='GET',
            url_suffix='/rules' + args
        )

    def getDetectionEvents(self, args: str) -> Dict[str, Any]:
        """ Calls the GET /events endpoint to retrieve
        the detection's events
            :param str args: some filters to be passed in the request
            :return JSON response from /events endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug(
            'DetectionClient.getDetectionEvents method has been called.')

        return self._http_request(
            method='GET',
            url_suffix="/events" + args
        )

    def getDetectionRuleEvents(self, rule_uuid: str,
                               args: str) -> Dict[str, Any]:
        """ Calls the GET /rules/<rule_id>/events endpoint to retrieve
        the detection rule's events
            :param str rule_uuid: the id of the rulefor which the events
            need to be retrieved
            :param str args: some filters to be passed in the request
            :return JSON response from /rules/<rule_id>/events endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug(
            'DetectionClient.getDetectionRuleEvents method has been called.')

        return self._http_request(
            method='GET',
            url_suffix="rules/" + rule_uuid + "/events" + args
        )

    def createDetectionRule(self, data) -> Dict[str, Any]:
        """ Calls the POST endpoint to create a Detection rule
            :param Any data: data to be passed in the request
            :return JSON response from endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug(
            'DetectionClient.createDetectationRule method has been called.')

        return self._http_request(
            method='POST',
            url_suffix='/rules',
            data=json.dumps(data)
        )

    def resolveDetection(self, detection_id: str, data=None):
        """ Calls the Put /detections/{detection_id}/resolve endpoint to
        resolve the provided detection
            :param str detection_id: the detection to be resolved
            :param Any data: data to be passed in the request
            :return JSON response from /detections/{detection_id}/resolve
            endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug(
            'DetectionClient.resolveDetection method has been called.')

        return self._http_request(
            method='Put',
            url_suffix='detections/' + detection_id + '/resolve',
            data=json.dumps(data),
            return_empty_response=True
        )


# Helper Methods


def encodeArgsToURL(args, multiple_values: List = []):
    """ Create the query string with the provided arguments
        :parm Dict[str, Any] args: Arguments to be included in the query string
        :return The querystring
        :rtype str
    """
    url = ''
    first = True

    for arg in args:
        values: List[Any] = []
        if arg in multiple_values:
            values.extend(args[arg].split(','))
        else:
            values.append(args[arg])

        for value in values:
            this_arg = str(arg) + "=" + str(value).strip()
            if first:
                url = url + "?" + this_arg
                first = False
            else:
                url = url + "&" + this_arg
    return url


def flattenFieldDict(field, field_dict):
    """ Recursively flatten a dictionary field.
        :param str field: Field to be flatten
        :parm Dict[str, Any] field_dict: Dictionary containing the
        field to be flatten
        :return A new dictionary with the field flattened
        :rtype Dict[str, Any]
    """
    new_dict = {}
    for key in field_dict:
        if isinstance(field_dict[key], dict):
            new_dict.update(flattenFieldDict(field + "_"
                                             + key, field_dict[key]))
        else:
            new_dict[field + "_" + key] = field_dict[key]
    return new_dict


def flattenList(lt):
    """ Recursively flatten a list.
        :parm List lt: List to be flatten
        :return A new flattened List
        :rtype List
    """
    string = ''
    for i in range(0, len(lt)):
        if isinstance(lt[i], dict):
            string = string + flattenDict(lt[i])
            if i + 1 < len(lt):
                string = string + "---" + "\n"
        elif isinstance(lt[i], list):
            string = string + flattenList(lt[i])
        else:
            string = string + str(lt[i])
            if i + 1 < len(lt):
                string = string + ", "
    return string


def flattenDict(dt):
    """ Recursively flatten a dictionary.
        :parm Dict[str, Any] dt: Dictionary to be flatten
        :return A new flattened dictionary
        :rtype Dict[str, Any]
    """
    string = ''
    for key in dt:
        if isinstance(dt[key], list):
            string = string + str(key) + ": " + flattenList(dt[key]) + "\n"
        elif isinstance(dt[key], dict):
            string = string + str(key) + ": " + flattenDict(dt[key]) + "\n"
        else:
            string = string + str(key) + ": " + str(dt[key]) + "\n"
    return string


def formatEvents(r_json):
    """ Format the events in the response to be shown as a table.
        :parm Any r_json: Received response
        :return The formated response
        :rtype list
    """
    columns = r_json['columns'] if 'columns' in r_json else []
    data = r_json['data'] if 'data' in r_json else []

    if not data:
        return []

    newData = []
    f = 0

    for row in data:
        if len(columns) != len(row):
            f += 1

        newRow = {}
        for i, field in enumerate(columns):
            newRow[field] = row[i]
        newData.append(newRow)

    demisto.info(f"{f} events' size did not matched the headers' size and were ignored.")
    return newData


def getStartDate(first_fetch_str) -> datetime:

    if not first_fetch_str or not first_fetch_str.strip():
        first_fetch_str = "7 days"

    start_date = dateparser.parse(first_fetch_str, settings={'TIMEZONE': 'UTC'})
    assert start_date is not None, f'could not parse {first_fetch_str}'

    return start_date


def mapSeverity(severity) -> int:
    match severity:
        case 'high':
            return 3
        case 'moderate':
            return 2
        case 'low':
            return 1
        case _:
            return 0


def getIncidents(result, end_date) -> Tuple[Dict[str, int], List[dict[str, Any]]]:
    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    detections = result.outputs if result and isinstance(result, CommandResults) else []

    if detections is None or not isinstance(detections, list):
        detections = []

    demisto.info(f'Creating incidents from {len(detections)} detections')
    for detection in detections:
        severity = mapSeverity(detection['rule_severity'])
        incident = {
            'name': 'Fortinet FortiNDR Cloud - ' + detection['rule_name'],
            'occurred': detection['created'],
            'severity': severity,
            'details': detection['rule_description'],
            'dbotMirrorId': detection['uuid'],
            'rawJSON': json.dumps(detection),
            'type': 'Fortinet FortiNDR Cloud Detection',
            'CustomFields': {  # Map specific XSOAR Custom Fields
                'fortindrcloudcategory': detection['rule_category'],
                'fortindrcloudconfidence': detection['rule_confidence'],
                'fortindrcloudstatus': detection['status'],
            }
        }

        incidents.append(incident)

    end_date_str = end_date.strftime(DATE_FORMAT)
    next_run = {'last_fetch': end_date_str}

    demisto.info(f'fetched {len(incidents)} incidents')
    demisto.debug(f'Last run set to: {end_date_str}')

    return next_run, incidents

# Commands Methods


def commandTestModule(detectionClient: DetectionClient):
    """ Test that the module is up and running.
    """
    demisto.info("Testing connection to FortiNDR Cloud Services")

    try:
        commandGetDetections(detectionClient=detectionClient, args={'limit': 1})
        demisto.info("Connection successfully verified.")
        return 'ok'
    except Exception as e:
        demisto.error(f'Module test failed: {e}')
        raise e


# Sensors API commands


def commandGetSensors(sensorClient: SensorClient, args):
    """ Get a list of all sensors.
    """
    demisto.info('CommandGetSensors has been called.')

    result: Dict[str, Any] = sensorClient.getSensors(encodeArgsToURL(args, ['include']))

    prefix = 'FortiNDRCloud.Sensors'
    key = 'sensors'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Sensors."

    demisto.info('CommandGetSensors successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandGetDevices(sensorClient: SensorClient, args):
    """ Get the number of devices.
    """
    demisto.info('CommandGetDevices has been called.')

    result: Dict[str, Any] = sensorClient.getDevices(encodeArgsToURL(args))

    prefix = 'FortiNDRCloud.Devices'
    key = 'device_list'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Devices."

    demisto.info('CommandGetDevices successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandGetTasks(sensorClient: SensorClient, args):
    """ Get a list of all the PCAP tasks.
    """
    demisto.info('commandGetTasks has been called.')

    taskid: str = args['task_uuid'] if 'task_uuid' in args else ''
    result: Dict[str, Any] = sensorClient.getTasks(taskid)

    prefix = 'FortiNDRCloud.Tasks'
    key = 'pcap_task' if taskid != '' else 'pcaptasks'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Tasks."

    demisto.info('CommandGetTasks successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandCreateTask(sensorClient: SensorClient, args):
    """ Create a new PCAP task.
    """
    demisto.info('commandCreateTask has been called.')

    sensor_ids = []
    if 'sensor_ids' in args:
        sensor_ids = args['sensor_ids'].split(',')
        args.pop('sensor_ids')

    args['sensor_ids'] = sensor_ids

    result: Dict[str, Any] = sensorClient.createTasks(args)
    if 'pcaptask' in result:

        demisto.info('CommandCreateTask successfully completed.')

        return CommandResults(
            readable_output='Task created successfully'
        )
    else:
        raise Exception(f"Task creation failed with: {result}")


def commandGetEventsTelemetry(sensorClient: SensorClient, args):
    """ Get event telemetry data grouped by time
    """
    demisto.info('commandGetEventsTelemetry has been called.')

    result: Dict[str, Any] = sensorClient.getTelemetry('events', args)

    prefix = 'FortiNDRCloud.Telemetry.Events'
    key = 'data'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Event Telemetry."

    demisto.info('commandGetEventsTelemetry successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=formatEvents(result)
    )


def commandGetNetworkTelemetry(sensorClient: SensorClient, args):
    """ Get network telemetry data grouped by time
    """
    demisto.info('commandGetNetworkTelemetry has been called.')

    result: Dict[str, Any] = sensorClient.getTelemetry('network_usage', args)

    prefix = 'FortiNDRCloud.Telemetry.NetworkUsage'
    key = 'network_usage'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Network Telemetry."

    demisto.info('commandGetNetworkTelemetry successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandGetPacketstatsTelemetry(sensorClient: SensorClient, args):
    """ Get packetstats telemetry data grouped by time.
    """
    demisto.info('commandGetPacketstatsTelemetry has been called.')

    result: Dict[str, Any] = sensorClient.getTelemetry('packetstats', args)

    prefix = 'FortiNDRCloud.Telemetry.Packetstats'
    key = 'data'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Packetstats Telemetry."

    demisto.info('commandGetPacketstatsTelemetry successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


# Entity API commands


def commandGetEntitySummary(entityClient: EntityClient, entity: str):
    """ Get entity summary information about an IP or domain.
    """
    demisto.info('commandGetEntitySummary has been called.')

    result: Dict[str, Any] = entityClient.getEntitySummary(entity)

    prefix = 'FortiNDRCloud.Entity.Summary'
    key = 'summary'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Entity Summary."

    demisto.info('commandGetEntitySummary successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandGetEntityPdns(entityClient: EntityClient, args: Dict[str, Any]):
    """ Get passive DNS information about an IP or domain.
    """
    demisto.info('commandGetEntityPdns has been called.')

    entity = args.pop('entity')
    result: Dict[str, Any] = entityClient.getEntityPdns(entity, encodeArgsToURL(args, ['record_type', 'source', 'account_uuid']))

    prefix = 'FortiNDRCloud.Entity.PDNS'
    key = 'passivedns'

    if not result:
        raise Exception(f'We receive an invalid response from the server({result})')

    if 'result_count' in result and result.get('result_count') == 0:
        return "We could not find any result for Get Entity PDNS."

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Entity PDNS."

    demisto.info('commandGetEntityPdns successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandGetEntityDhcp(entityClient: EntityClient, args: Dict[str, Any]):
    """ Get DHCP information about an IP address.
    """
    demisto.info('commandGetEntityDhcp has been called.')

    entity = args.pop('entity')
    result: Dict[str, Any] = entityClient.getEntityDhcp(entity, encodeArgsToURL(args, ['account_uuid']))

    prefix = 'FortiNDRCloud.Entity.DHCP'
    key = 'dhcp'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if 'result_count' in result and result.get('result_count') == 0:
        return "We could not find any result for Get Entity DHCP."

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Entity DHCP."

    demisto.info('commandGetEntityDhcp successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandGetEntityFile(entityClient: EntityClient, hash: str):
    """ Get entity information about a file
    """
    demisto.info('commandGetEntityFile has been called.')

    result: Dict[str, Any] = entityClient.getEntityFile(hash)

    prefix = 'FortiNDRCloud.Entity.File'
    key = 'file'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Entity File."

    demisto.info('commandGetEntityFile successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


# Detections API commands


def commandFetchIncidents(detectionClient: DetectionClient, account_uuid, params, last_run) -> Tuple[Dict[str, int], List[dict]]:
    demisto.info('Fetching incidents.')

    start_date = getStartDate(params.get('first_fetch'))

    last_fetch = last_run.get('last_fetch')
    if last_fetch is not None:
        demisto.debug(f'Incidents were last fetched on: {last_fetch}')
        start_date = datetime.strptime(last_fetch, DATE_FORMAT)

    delay = arg_to_number(
        arg=params.get('delay'),
        arg_name='delay',
        required=False
    )
    if not delay or delay < 0 or delay > DEFAULT_DELAY:
        delay = DEFAULT_DELAY

    # Get the utc datetime for now
    now = datetime.utcnow()
    end_date = now - timedelta(minutes=delay)

    if end_date < start_date:
        demisto.info(f'The time window [{start_date} to {end_date}] is not valid.')
        demisto.info('Waiting until next iteration.')
    else:
        start_date_str = datetime.strftime(start_date, DATE_FORMAT)
        end_date_str = datetime.strftime(end_date, DATE_FORMAT)
        demisto.info(f'Fetching detections between {start_date_str} and {end_date_str}')
        args = {
            'created_or_shared_start_date': start_date_str,
            'created_or_shared_end_date': end_date_str,
            'include': 'rules,indicators',
            'sort_by': 'device_ip',
            'sort_order': 'asc',
            'limit': MAX_DETECTIONS,
            'offset': 0,
            'inc_polling': True,
        }

    status = params.get('status', 'active')
    if status != 'all':
        args['status'] = status

    if not params.get('muted', False):
        args['muted'] = False

    if not params.get('muted_device', False):
        args['muted_device'] = False

    if not params.get('muted_rule', False):
        args['muted_rule'] = False

    if account_uuid:
        args['account_uuid'] = account_uuid

    logged_args = args.copy()
    if 'account_uuid' in logged_args:
        logged_args['account_uuid'] = '************'

    demisto.debug(f'Arguments being used for fetching detections: \n {logged_args} ')
    result = commandGetDetections(detectionClient, args)

    return getIncidents(result, end_date)


def addDetectionRules(result):
    """ Create a new detection rule.
    """
    # Create a dictionary with the rules using its uuid as key
    rules = {}
    for rule in result.get('rules', []):
        rules[rule['uuid']] = rule

    # Find the detection's rule in the dictionary and update the detection
    for detection in result.get('detections', []):
        rule = rules[detection['rule_uuid']]

        detection.update({'rule_name': rule['name']})
        detection.update({'rule_description': rule['description']})
        detection.update({'rule_severity': rule['severity']})
        detection.update({'rule_confidence': rule['confidence']})
        detection.update({'rule_category': rule['category']})
        # detection.update({'rule_signature': rule['query_signature']})

    return result


def getDetectionsInc(detectionClient: DetectionClient, result: Dict[str, Any], args) -> Dict[str, Any]:
    """ Get the remaining detections if there are more than
    the maximum allowed in a page.
    """
    if result is None:
        result = {
            'total_count': 0,
            'detections': [],
            'rules': []
        }

    next_piece: Dict[str, Any] = result
    while next_piece and next_piece['detections']:
        offset = args.get('offset', 0) + MAX_DETECTIONS
        args.update({"offset": offset})
        demisto.info(f'Retrieving Detections with offset = {offset}.')
        next_piece = detectionClient.getDetections(
            encodeArgsToURL(args, ['include']))

        count = 0
        if (next_piece is not None):
            count = len(next_piece.get('detections', []))
            result.get('detections', []).extend(next_piece.get('detections', []))
            result.get('rules', []).extend(next_piece.get('rules', []))
            result['total_count'] += next_piece['total_count']

        demisto.debug(f'{count} detections retrieved')

    return result


def commandGetDetections(detectionClient: DetectionClient, args):
    """ Get a list of detections.
    """
    demisto.info('commandGetDetections has been called.')
    inc_polling = args.pop('inc_polling', False)

    limit: int = int(args.pop('limit', MAX_DETECTIONS))
    if limit < 0 or limit > MAX_DETECTIONS:
        limit = MAX_DETECTIONS
    args.update({"limit": limit})

    offset = 0
    demisto.info(f'Retrieving Detections with offset = {offset}.')
    result: Dict[str, Any] = detectionClient.getDetections(
        encodeArgsToURL(args, ['include']))
    demisto.debug(f"{len(result['detections'])} detections retrieved.")

    # if there are more detections to be retrieved, pull the
    # remaining detections incrementally

    if inc_polling:
        result = getDetectionsInc(detectionClient=detectionClient, result=result, args=args)

    # filter out training detections
    demisto.debug('Filtering detections for training account.')
    result['detections'] = list(
        filter(lambda detection: (detection['account_uuid'] != TRAINING_ACC),
               result['detections'])
    )
    result['total_count'] = len(result['detections'])

    # Include the rules if they need to be included
    demisto.debug("Adding rule's information to the detections.")
    if 'include' in args and 'rules' in args['include'].split(','):
        result = addDetectionRules(result)

    demisto.info(f"{len(result['detections'])} detections successfully retrieved.")

    prefix = 'FortiNDRCloud.Detections'
    key = 'detections'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Detections."

    demisto.info('commandGetDetections successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandGetDetectionEvents(detectionClient: DetectionClient, args):
    """ Get a list of the events associated to a specific detection.
    """
    demisto.info('CommandGetDetectionEvents has been called.')

    result: Dict[str, Any] = detectionClient.getDetectionEvents(encodeArgsToURL(args))

    events = []
    detection_uuid = args.get('detection_uuid', '')
    for event in result.get('events', []):
        rule_uuid = event.get('rule_uuid', '')
        event = event.get('event', {})
        if event:
            event['detection_uuid'] = detection_uuid
            event['rule_uuid'] = rule_uuid
            events.append(event)
    result['events'] = events

    prefix = 'FortiNDRCloud.Detections'
    key = 'events'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Detections Events."

    demisto.info('commandGetDetectionEvents successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandGetDetectionRules(detectionClient: DetectionClient, args):
    """ Get a list of detection rules.
    """
    demisto.info('CommandGetDetectionRules has been called.')

    result: Dict[str, Any] = detectionClient.getDetectionRules(
        encodeArgsToURL(args, ['confidence', 'severity', 'category'])
    )

    prefix = 'FortiNDRCloud.Rules'
    key = 'rules'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Detection Rules."

    demisto.info('commandGetDetectionRules successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandGetDetectionRuleEvents(detectionClient: DetectionClient, args):
    """ Get a list of the events that matched on a specific rule.
    """
    demisto.info('CommandGetDetectionRuleEvents has been called.')

    rule_uuid: str = args['rule_uuid']
    args.pop('rule_uuid')

    result: Dict[str, Any] = detectionClient.getDetectionRuleEvents(
        rule_uuid, encodeArgsToURL(args)
    )

    prefix = 'FortiNDRCloud.Detections'
    key = 'events'

    if not result:
        raise Exception(f'We receive an invalid response from the server ({result})')

    if key not in result:
        raise Exception(f'We receive an invalid response from the server (The response does not contains the key: {key})')

    if not result.get(key):
        return "We could not find any result for Get Detections Rule Events."

    demisto.info('commandGetDetectionRuleEvents successfully completed.')

    return CommandResults(
        outputs_prefix=prefix,
        outputs_key_field=key,
        outputs=result.get(key)
    )


def commandCreateDetectionRule(detectionClient: DetectionClient, args):
    """ Create a new detection rule.
    """
    demisto.info('commandCreateDetectionRule has been called.')

    run_accts = [args['run_account_uuids']]
    dev_ip_fields = [args['device_ip_fields']]

    args.pop('run_account_uuids')
    args.pop('device_ip_fields')

    args['run_account_uuids'] = run_accts
    args['device_ip_fields'] = dev_ip_fields

    result: Dict[str, Any] = detectionClient.createDetectionRule(args)
    if 'rule' in result:

        demisto.info('commandCreateDetectionRule successfully completed.')

        return CommandResults(
            readable_output='Rule created successfully'
        )
    else:
        raise Exception(f"Rule creation failed with: {result}")


def commandResolveDetection(detectionClient: DetectionClient, args):
    """ Resolve a specific detection.
    """
    demisto.info('commandResolveDetection has been called.')

    if 'detection_uuid' not in args:
        raise Exception("Detection cannot be resolved: No detection_uuid has been provided.")

    if 'resolution' not in args:
        raise Exception("Detection cannot be resolved: No resolution has been provided.")

    detection_uuid = args.pop('detection_uuid')
    result = detectionClient.resolveDetection(detection_uuid, args)

    if not result or not result.content:

        demisto.info('commandResolveDetection successfully completed.')

        return CommandResults(
            readable_output='Detection resolved successfully'
        )
    else:
        raise Exception(f"Detection resolution failed with: {result}")


def main():
    # get command and args
    command = demisto.command()
    params = demisto.params()

    demisto.info(f'Starting to handle command {command}')

    logged_params = params.copy()
    if 'api_key' in logged_params:
        logged_params['api_key'] = "*********"

    demisto.debug(f'Params being passed is {logged_params}')

    args: Dict[str, Any] = demisto.args()

    # initialize common args
    api_key = params.get('api_key')
    testing = params.get('testing', False)
    account_uuid = params.get('account_uuid')

    # attempt command execution
    try:
        entityClient: EntityClient
        sensorClient: SensorClient
        detectionClient: DetectionClient

        eClient = Client.getClient('Entity', api_key, testing)
        sClient = Client.getClient('Sensors', api_key, testing)
        dClient = Client.getClient(
            'Detections', api_key, testing
        )

        if isinstance(eClient, EntityClient):
            entityClient = eClient
        if isinstance(sClient, SensorClient):
            sensorClient = sClient
        if isinstance(dClient, DetectionClient):
            detectionClient = dClient

        if command == 'test-module':
            return_results(commandTestModule(detectionClient=detectionClient))

        elif command == 'fetch-incidents':
            next_run, incidents = commandFetchIncidents(
                detectionClient,
                account_uuid,
                params,
                demisto.getLastRun()
            )
            # saves next_run for the time fetch-incidents is invoked
            demisto.info('Saving checkpoint in Cortex')
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.info('Sending incidents to Cortex')
            demisto.incidents(incidents)
            
            demisto.info('Incidents successfully sent.')

        elif command == 'fortindr-cloud-get-sensors':
            return_results(commandGetSensors(sensorClient, args))

        elif command == 'fortindr-cloud-get-devices':
            return_results(commandGetDevices(sensorClient, args))

        elif command == 'fortindr-cloud-get-tasks':
            return_results(commandGetTasks(sensorClient, args))

        elif command == 'fortindr-cloud-create-task':
            return_results(commandCreateTask(sensorClient, args))

        elif command == 'fortindr-cloud-get-telemetry-events':
            return_results(
                commandGetEventsTelemetry(
                    sensorClient, encodeArgsToURL(args)
                )
            )

        elif command == 'fortindr-cloud-get-telemetry-network':
            return_results(
                commandGetNetworkTelemetry(
                    sensorClient, encodeArgsToURL(args)
                )
            )

        elif command == 'fortindr-cloud-get-telemetry-packetstats':
            return_results(
                commandGetPacketstatsTelemetry(
                    sensorClient, encodeArgsToURL(args)
                )
            )

        elif command == 'fortindr-cloud-get-detections':
            return_results(commandGetDetections(detectionClient, args))

        elif command == 'fortindr-cloud-get-detection-events':
            return_results(
                commandGetDetectionEvents(detectionClient, args)
            )

        elif command == 'fortindr-cloud-get-detection-rules':
            return_results(commandGetDetectionRules(detectionClient, args))

        elif command == 'fortindr-cloud-get-detection-rule-events':
            return_results(
                commandGetDetectionRuleEvents(detectionClient, args)
            )

        elif command == 'fortindr-cloud-resolve-detection':
            return_results(commandResolveDetection(detectionClient, args))

        elif command == 'fortindr-cloud-create-detection-rule':
            return_results(commandCreateDetectionRule(detectionClient, args))

        elif command == 'fortindr-cloud-get-entity-summary':
            return_results(
                commandGetEntitySummary(entityClient, args['entity'])
            )

        elif command == 'fortindr-cloud-get-entity-pdns':
            return_results(commandGetEntityPdns(entityClient, args))

        elif command == 'fortindr-cloud-get-entity-dhcp':
            return_results(commandGetEntityDhcp(entityClient, args))

        elif command == 'fortindr-cloud-get-entity-file':
            return_results(commandGetEntityFile(entityClient, args['hash']))

    # catch exceptions
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}', str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
