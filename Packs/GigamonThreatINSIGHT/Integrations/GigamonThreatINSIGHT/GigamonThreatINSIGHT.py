"""    Gigamon ThreatINSIGHT Integration for Cortex XSOAR (aka Demisto)

       This integration allows fetching detections, entities, events and
       saved searches from Gigamon ThreatINSIGHT APIs, also allows for
       some management operations like creating scheduled pcap tasks,
       updating detection rules and resolving detections.
"""
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import re
from datetime import datetime, timedelta

TRAINING_ACC = 'f6f6f836-8bcd-4f5d-bd61-68d303c4f634'
MAX_DETECTIONS = 100
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


class Client(BaseClient):
    @staticmethod
    def getUrl(api) -> str:
        """Provide the base url to access the specific API.
        :param str api:  The specific API for which we need the base url.
        return: The requested base url
        rtype str
        """
        url: str = ''
        if api == 'Events':
            url = 'https://events.icebrg.io/v2/query/'
        elif api == 'Detections':
            url = 'https://detections.icebrg.io/v1/'
        elif api == 'Sensors':
            url = 'https://sensor.icebrg.io/v1/'
        elif api == 'Entity':
            url = 'https://entity.icebrg.io/v1/entity/'

        return url

    @staticmethod
    def getClient(api, api_key):
        """Provide the required Client instance to interact with
        the specific API.
        :param str api:  The specific API we need to interact with.
        :param str api_key: The API key to authenticate the request bwing made.
        return: The requested Client instance.
        rtype str
        """
        headers = {
            'Authorization': 'IBToken ' + api_key,
            'User-Agent': 'Cortex_Insight.v3',
            'Content-Type': 'application/json',
        }

        match api:
            case 'Entity':
                return EntityClient(
                    base_url=Client.getUrl(api),
                    headers=headers
                )
            case 'Events':
                return EventClient(
                    base_url=Client.getUrl(api),
                    headers=headers
                )
            case 'Sensors':
                return SensorClient(
                    base_url=Client.getUrl(api),
                    headers=headers
                )
            case 'Detections':
                return DetectionClient(
                    base_url=Client.getUrl(api),
                    headers=headers
                )


class EventClient(Client):
    """Client that makes HTTP requests to the Events API
    """
    def getSavedSearches(self) -> Dict[str, Any]:
        """ Calls the GET /saved endpoint to retrieve the events' saved
        searches
            :return JSON response from /saved endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('EventClient.getSavedSearches method has been called.')

        return self._http_request(
            method='GET',
            url_suffix='saved'
        )

    def getHistory(self) -> Dict[str, Any]:
        """ Calls the GET /history endpoint to retrieve the events' history
            :return JSON response from /history endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('EventClient.getHistory method has been called.')

        return self._http_request(
            method='GET',
            url_suffix='history/'
        )

    def getEvents(self, args: str = '') -> Dict[str, Any]:
        """ Calls the GET /events endpoint to retrieve the Events
            :param str args: some filters to be passed in the request
            :return JSON response from /events endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('EventClient.getEvents method has been called.')

        result = self._http_request(
            method='GET',
            url_suffix='events' + args
        )

        return result


class SensorClient(Client):
    """Client that makes HTTP requests to the Sensor API
    """
    def getSensors(self) -> Dict[str, Any]:
        """ Calls the GET /sensors endpoint to retrieve the sensors
            :return JSON response from /sensors endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('SensorClient.getSensors method has been called.')

        return self._http_request(
            method='GET',
            url_suffix='sensors'
        )

    def getDevices(self) -> Dict[str, Any]:
        """ Calls the GET /devices endpoint to retrieve the devices
            :return JSON response from /devices endpoint
            :rtype Dict[str, Any]
        """
        demisto.info('SensorClient.getDevices method has been called.')

        result = self._http_request(
            method='GET',
            url_suffix='devices'
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

        return self._http_request(
            method='GET',
            url_suffix=suffix
        )

    def createTasks(self, sensor_ids=None) -> Dict[str, Any]:
        """ Calls to the Sensors API to create a new PCAP task
            :params sensor_ids sensors' id to be added to the task
            :return JSON response from endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('SensorClient.createTasks method has been called.')

        return self._http_request(
            method='POST',
            url_suffix='pcaptasks',
            data=sensor_ids
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

    def getEntityPdns(self, entity: str) -> Dict[str, Any]:
        """ Calls the GET /{entity}/pdns endpoint to retrieve the
            entity's pdns
            :param str entity: the entity to retrieve the pdns from
            :return JSON response from /{entity}/pdns endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('EntityClient.getEntityPdns method has been called.')

        return self._http_request(
            method='GET',
            url_suffix=entity + "/pdns"
        )

    def getEntityDhcp(self, entity: str) -> Dict[str, Any]:
        """ Calls the GET /{entity}/dhcp endpoint to retrieve the
            entity's summary
            :param str entity: the entity to retrieve the dhcp from
            :return JSON response from /{entity}/dhcp endpoint
            :rtype Dict[str, Any]
        """
        demisto.debug('EntityClient.getEntityDhcp method has been called.')

        return self._http_request(
            method='GET',
            url_suffix=entity + "/dhcp"
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
        demisto.debug('SensorClient.getDetectionRules method has been called.')
        return self._http_request(
            method='GET',
            url_suffix='/rules' + args
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
            'SensorClient.getDetectionRuleEvents method has been called.')

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

    def resolveDetection(self, detection_id: str, data=None) -> Dict[str, Any]:
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
            data=json.dumps(data)
        )


# Helper Methods


def encodeArgsToURL(args):
    """ Create the query string with the provided arguments
        :parm Dict[str, Any] args: Arguments to be included in the query string
        :return The querystring
        :rtype str
    """
    url = ''
    first = True
    for arg in args:
        this_arg = str(arg) + "=" + str(args[arg])
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


# Commands Methods


def commandTestModule(sensorClient: SensorClient):
    """ Test that the module is up and running.
    """
    try:
        commandGetSensors(sensorClient)
        return 'OK'
    except Exception:
        return 'FAILING'


# Events API commands


def formatEvents(r_json, response_type):
    """ Format the event response according to the provided response type.
        :parm Any r_json: Received response
        :parm str response_type: Response type
        :return The formated response
        :rtype Any
    """
    if response_type == "metadata":
        # If response type is 'metadata', only the metadata will be included

        data: List[Any] = []
        metadata: Dict[str, Any] = {}

        for field in r_json:
            if((field != "events") and (field != "aggregations")
               and (field != "data")):
                metadata[field] = r_json[field]

        data.append(metadata)
        r_json['data'] = data
    elif response_type == "aggregations":
        # If the response type is 'aggregations', only the group by fields
        # from the aggregations will be included

        for x in r_json['aggregations']:
            group_by = x
        fields = []
        aggregations = []
        for column in r_json['aggregations'][group_by]['columns']:
            fields.append(column['field'])
        for datum in r_json['aggregations'][group_by]['data']:
            aggregation = {}
            for i in range(0, len(fields)):
                aggregation[fields[i]] = datum[i]
            aggregations.append(aggregation)
        r_json['data'] = aggregations
    else:
        # Otherwise, all the events will be included in a flat dictionary

        for event in r_json['events']:
            # flatten dict values, convert lists to string
            new_fields = {}
            for field in event:
                if isinstance(event[field], list):
                    event[field] = str(json.dumps(event[field]))
                if isinstance(event[field], dict):
                    new_fields.update(flattenFieldDict(field, event[field]))
                    event[field] = "REMOVE"
            event.update(new_fields)
        # remove fields
        for i in range(0, len(r_json['events'])):
            r_json['events'][i] = {
                k: v for k, v in r_json['events'][i].items() if v != "REMOVE"
            }
    return r_json


def commandGetEventsHistory(eventClient: EventClient):
    """ Get user's query history.
    """
    demisto.debug('CommandGetEventsHistory has been called.')

    result: Dict[str, Any] = eventClient.getHistory()

    return CommandResults(
        outputs_prefix='Insight.UserQueryHistory',
        outputs_key_field='history',
        outputs=result.get('history')
    )


def commandGetEventsSavedSearches(eventClient: EventClient):
    """ Get user's saved searches.
    """
    demisto.debug('CommandGetEventsSavedSearches has been called.')

    result: Dict[str, Any] = eventClient.getSavedSearches()

    return CommandResults(
        outputs_prefix='Insight.SavedSearches',
        outputs_key_field='saved_queries',
        outputs=result.get('saved_queries')
    )


def commandGetEvents(eventClient: EventClient, args):
    """ Perform a search for network events from Insight
    """
    demisto.debug('commandGetEvents has been called.')

    pattern = r"^.*[Gg][Rr][Oo][Uu][Pp]\s+[Bb][Yy].*$"

    # Get the response_type from the args
    response_type = 'events'
    if 'response_type' in args:
        if (args['response_type'] == 'metadata'
           or args['response_type'] == 'aggregations'):
            response_type = args['response_type']
        args.pop('response_type')

    keyField = 'data' if (response_type in
                          ("metadata", "aggregations")) else 'events'

    # If the response_type is aggregation, check that a group by
    # statement is included in the query
    if (response_type == "aggregations"
       and not re.search(pattern, args['query'])):
        raise Exception(
            '''No 'group by' statement in query.
            Aggregation requires a 'group by' statement.'''
        )

    # Make the request and format the response
    result: Dict[str, Any] = eventClient.getEvents(encodeArgsToURL(args))
    formatEvents(result, response_type)

    return CommandResults(
        outputs_prefix='Insight.Events',
        outputs_key_field=keyField,
        outputs=result.get(keyField)
    )


# Sensors API commands


def commandGetSensors(sensorClient: SensorClient):
    """ Get a list of all sensors.
    """
    demisto.debug('CommandGetSensors has been called.')

    result: Dict[str, Any] = sensorClient.getSensors()

    return CommandResults(
        outputs_prefix='Insight.Sensors',
        outputs_key_field='sensors',
        outputs=result.get('sensors')
    )


def commandGetDevices(sensorClient: SensorClient):
    """ Get the number of devices.
    """
    demisto.debug('CommandGetDevices has been called.')

    result: Dict[str, Any] = sensorClient.getDevices()

    return CommandResults(
        outputs_prefix='Insight.Devices',
        outputs_key_field='device_list',
        outputs=result.get('device_list')
    )


def commandGetTasks(sensorClient: SensorClient, args):
    """ Get a list of all the PCAP tasks.
    """
    demisto.debug('commandGetTasks has been called.')

    taskid: str = args['task_uuid'] if 'task_uuid' in args else ''
    keyField = 'pcap_task' if taskid != '' else 'pcaptasks'

    result: Dict[str, Any] = sensorClient.getTasks(taskid)

    return CommandResults(
        outputs_prefix='Insight.Tasks',
        outputs_key_field=keyField,
        outputs=result.get(keyField)
    )


def commandCreateTask(sensorClient: SensorClient, args):
    """ Create a new PCAP task.
    """
    demisto.debug('commandCreateTask has been called.')

    sensor_ids = [args['sensor_ids']]
    args.pop('sensor_ids')
    args['sensor_ids'] = sensor_ids

    sensorClient.createTasks(args)

    return CommandResults(
        readable_output='Task created successfully'
    )


def commandGetTelemetry(sensorClient: SensorClient, telemetry: str, args):
    """ Get the specific requested telemetry:
            - 'events': Get event telemetry data grouped by time
            - 'network': Get network telemetry data grouped by time
            - 'packetstats':Get network metrics to a given sensor's interfaces
        :parm str telemetry: The telemetry being requested
    """
    demisto.debug(f'commandGetTelemetry ({telemetry}) has been called.')

    result: Dict[str, Any] = sensorClient.getTelemetry(telemetry, args)

    return CommandResults(
        outputs_prefix='Insight.Telemetry.' + telemetry,
        outputs_key_field='data',
        outputs=result.get('data')
    )


# Entity API commands


def commandGetEntitySummary(entityClient: EntityClient, entity: str):
    """ Get entity summary information about an IP or domain.
    """
    demisto.debug('commandGetEntitySummary has been called.')

    result: Dict[str, Any] = entityClient.getEntitySummary(entity)

    return CommandResults(
        outputs_prefix='Insight.Entity.Summary',
        outputs_key_field='summary',
        outputs=result.get('summary')
    )


def commandGetEntityPdns(entityClient: EntityClient, entity: str):
    """ Get passive DNS information about an IP or domain.
    """
    demisto.debug('commandGetEntityPdns has been called.')

    result: Dict[str, Any] = entityClient.getEntityPdns(entity)

    return CommandResults(
        outputs_prefix='Insight.Entity.PDNS',
        outputs_key_field='pasivedns',
        outputs=result.get('pasivedns')
    )


def commandGetEntityDhcp(entityClient: EntityClient, entity: str):
    """ Get DHCP information about an IP address.
    """
    demisto.debug('commandGetEntityDhcp has been called.')

    result: Dict[str, Any] = entityClient.getEntityDhcp(entity)

    return CommandResults(
        outputs_prefix='Insight.Entity.DHCP',
        outputs_key_field='dhcp',
        outputs=result.get('dhcp')
    )


def commandGetEntityFile(entityClient: EntityClient, hash: str):
    """ Get entity information about a file
    """
    demisto.debug('commandGetEntityFile has been called.')

    result: Dict[str, Any] = entityClient.getEntityFile(hash)

    return CommandResults(
        outputs_prefix='Insight.Entity.File',
        outputs_key_field='file',
        outputs=result.get('file')
    )


# Detections API commands


def commandFetchIncidents(detectionClient: DetectionClient, account_uuid,
                          max_results, last_run, first_fetch_time):
    demisto.debug(f'last_run retrieved: {last_run}')
    last_fetch = last_run.get('last_fetch')

    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = datetime.strptime(last_fetch, DATE_FORMAT)

    if not max_results or max_results > MAX_DETECTIONS:
        max_results = MAX_DETECTIONS

    args = {'created_or_shared_start_date': last_fetch.strftime(DATE_FORMAT),
            'include': 'rules',
            'sort_by': 'first_seen',
            'sort_order': 'asc',
            'limit': max_results}

    if account_uuid:
        args['account_uuid'] = account_uuid

    result = commandGetDetections(detectionClient, args)

    last_incident_time = last_fetch
    detections = []
    for detection in result.outputs:
        severity = 0
        match detection['rule_severity']:
            case 'high':
                severity = 3
            case 'moderate':
                severity = 2
            case 'low':
                severity = 1
        this_detection = {
            'occurred': detection['first_seen'],
            'name': detection['rule_name'],
            'dbotMirrorId': detection['uuid'],
            'severity': severity,
            'details': detection['rule_description'],
            'rawJSON': json.dumps(detection),
        }
        incident_time = datetime.strptime(detection['first_seen'], DATE_FORMAT)

        # To workaround the issue with multiple detections at same timestamp
        if last_fetch < incident_time:
            detections.append(this_detection)

        if last_incident_time < incident_time:
            last_incident_time = incident_time

    demisto.debug(
        f'Last incident time: {last_incident_time.strftime(DATE_FORMAT)}')

    next_run = {'last_fetch': last_incident_time.strftime(DATE_FORMAT)}

    demisto.debug(f'fetched {len(detections)} incidents')

    demisto.setLastRun(next_run)
    demisto.incidents(detections)

    return next_run, detections


def addDetectionRules(result):
    """ Create a new detection rule.
    """
    # Create a dictionary with the rules using its uuid as key
    rules = {}
    for rule in result.get('rules'):
        rules[rule['uuid']] = rule

    # Find the detection's rule in the dictionary and update the detection
    for detection in result.get('detections'):
        rule = rules[detection['rule_uuid']]

        detection.update({'rule_name': rule['name']})
        detection.update({'rule_description': rule['description']})
        detection.update({'rule_severity': rule['severity']})
        detection.update({'rule_confidence': rule['confidence']})
        detection.update({'rule_category': rule['category']})
        # detection.update({'rule_signature': rule['query_signature']})

    return result


def getDetectionsInc(detectionClient: DetectionClient, result, args):
    """ Get the remaining detections if there are more than
    the maximum allowed in a page.
    """
    total_detections = result.get('total_count')
    offset = MAX_DETECTIONS

    while offset < total_detections:
        # Get the next piece of detections and add them to the result
        args['offset'] = offset
        nextPiece: Dict[str, Any] = detectionClient.getDetections(
            encodeArgsToURL(args))
        result.get('detections').extend(nextPiece.get('detections'))

        # Include rules if they need to be included
        if 'include' in args and args['include'] == 'rules':
            result.get('rules').extend(nextPiece.get('rules'))

        offset += MAX_DETECTIONS

    return result


def commandGetDetections(detectionClient: DetectionClient, args):
    """ Get a list of detections.
    """
    demisto.debug('commandGetDetections has been called.')

    result: Dict[str, Any] = detectionClient.getDetections(
        encodeArgsToURL(args)
    )

    # if there are more detections to be retrieved, pull the
    # remaining detections incrementally
    if 'total_count' in result and int(result['total_count']) > MAX_DETECTIONS:
        if 'limit' not in args or int(args['limit']) > MAX_DETECTIONS:
            result = getDetectionsInc(detectionClient, result, args)

    # filter out training detections
    result['detections'] = list(
        filter(lambda detection: (detection['account_uuid'] != TRAINING_ACC),
               result['detections'])
    )

    # Include the rules if they need to be included
    if 'include' in args and args['include'] == 'rules':
        result = addDetectionRules(result)

    return CommandResults(
        outputs_prefix='Insight.Detections',
        outputs_key_field='detections',
        outputs=result.get('detections')
    )


def commandGetDetectionRules(detectionClient: DetectionClient, args):
    """ Get a list of detection rules.
    """
    demisto.debug('CommandGetDetectionRules has been called.')

    result: Dict[str, Any] = detectionClient.getDetectionRules(
        encodeArgsToURL(args)
    )

    return CommandResults(
        outputs_prefix='Insight.Rules',
        outputs_key_field='rules',
        outputs=result.get('rules')
    )


def commandGetDetectionRuleEvents(detectionClient: DetectionClient, args):
    """ Get a list of the events that matched on a specific rule.
    """
    demisto.debug('CommandGetDetectionRuleEvents has been called.')

    rule_uuid: str = args['rule_uuid']
    args.pop('rule_uuid')

    result: Dict[str, Any] = detectionClient.getDetectionRuleEvents(
        rule_uuid, encodeArgsToURL(args)
    )

    return CommandResults(
        outputs_prefix='Insight.Detections',
        outputs_key_field='events',
        outputs=result.get('events')
    )


def commandCreateDetectionRule(detectionClient: DetectionClient, args):
    """ Create a new detection rule.
    """
    demisto.debug('commandCreateDetectionRule has been called.')

    run_accts = [args['run_account_uuids']]
    dev_ip_fields = [args['device_ip_fields']]

    args.pop('run_account_uuids')
    args.pop('device_ip_fields')

    args['run_account_uuids'] = run_accts
    args['device_ip_fields'] = dev_ip_fields

    detectionClient.createDetectionRule(args)

    return CommandResults(
        readable_output='Rule created successfully'
    )


def commandResolveDetection(detectionClient: DetectionClient, args):
    """ Resolve a specific detection.
    """
    demisto.debug('commandResolveDetection has been called.')

    detection_uuid = args['detection_uuid']
    data = {
        "resolution": args['resolution'],
        "resolution_comment": args['resolution_comment']
    }

    detectionClient.resolveDetection(detection_uuid, data)

    return CommandResults(
        readable_output='Detection resolved successfully'
    )


def main():
    # get command and args
    command = demisto.command()
    params = demisto.params()

    demisto.debug(f'Command being called is {command}')
    demisto.debug(f'Params being passed is {params}')

    args: Dict[str, Any] = demisto.args()

    # initialize common args
    api_key = params.get('api_key')
    account_uuid = params.get('account_uuid')

    # attempt command execution
    try:
        entityClient: EntityClient = Client.getClient('Entity', api_key)

        sensorClient: SensorClient = Client.getClient('Sensors', api_key)

        eventClient: EventClient = Client.getClient('Events', api_key)

        detectionClient: DetectionClient = Client.getClient(
            'Detections', api_key
        )

        if command == 'test-module':
            return_results(commandTestModule(sensorClient))

        if command == 'fetch-incidents':
            # default first fetch to -7days
            first_fetch_time = datetime.now() - timedelta(days=7)
            max_results = arg_to_number(
                arg=params.get('max_fetch'),
                arg_name='max_fetch',
                required=False
            )
            commandFetchIncidents(
                detectionClient,
                account_uuid=account_uuid,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time
            )

        elif command == 'insight-get-events':
            return_results(commandGetEvents(eventClient, args))

        elif command == 'insight-get-history':
            return_results(commandGetEventsHistory(eventClient))

        elif command == 'insight-get-saved-searches':
            return_results(commandGetEventsSavedSearches(eventClient))

        elif command == 'insight-get-sensors':
            return commandGetSensors(sensorClient)

        elif command == 'insight-get-devices':
            return_results(commandGetDevices(sensorClient))

        elif command == 'insight-get-tasks':
            return_results(commandGetTasks(sensorClient, args))

        elif command == 'insight-create-task':
            return_results(commandCreateTask(sensorClient, args))

        elif command == 'insight-get-detections':
            return_results(commandGetDetections(detectionClient, args))

        elif command == 'insight-get-detection-rules':
            return_results(commandGetDetectionRules(detectionClient, args))

        elif command == 'insight-get-detection-rule-events':
            return_results(
                commandGetDetectionRuleEvents(detectionClient, args)
            )

        elif command == 'insight-resolve-detection':
            return_results(commandResolveDetection(detectionClient, args))

        elif command == 'insight-create-detection-rule':
            return_results(commandCreateDetectionRule(detectionClient, args))

        elif command == 'insight-get-entity-summary':
            return_results(
                commandGetEntitySummary(entityClient, args['entity'])
            )

        elif command == 'insight-get-entity-pdns':
            return_results(commandGetEntityPdns(entityClient, args['entity']))

        elif command == 'insight-get-entity-dhcp':
            return_results(commandGetEntityDhcp(entityClient, args['entity']))

        elif command == 'insight-get-entity-file':
            return_results(commandGetEntityFile(entityClient, args['hash']))

        elif command == 'insight-get-telemetry-events':
            return_results(
                commandGetTelemetry(
                    sensorClient, 'Events', encodeArgsToURL(args)
                )
            )

        elif command == 'insight-get-telemetry-network':
            return_results(
                commandGetTelemetry(
                    sensorClient, 'Network', encodeArgsToURL(args)
                )
            )

        elif command == 'insight-get-telemetry-packetstats':
            return_results(
                commandGetTelemetry(
                    sensorClient, 'Packetstats', encodeArgsToURL(args)
                )
            )

    # catch exceptions
    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
