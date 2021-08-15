import re
import mimetypes
from CommonServerPython import *  # noqa: F401

import demistomock as demisto  # noqa: F401

''' GLOBAL VARS '''
ALARM_HEADERS = ['alarmId', 'alarmStatus', 'associatedCases', 'alarmRuleName', 'dateInserted', 'entityName',
                 'alarmDataCached']

ALARM_EVENTS_HEADERS = ['serviceName', 'logMessage', 'entityName']

CASE_STATUS = {'Created': 1,
               'Completed': 2,
               'Incident': 3,
               'Mitigated': 4,
               'Resolved': 5}


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def alarms_list_request(self, alarm_id, alarm_status, offset, count, alarm_rule_name, entity_name, case_association):
        params = assign_params(alarmStatus=alarm_status, offset=offset, count=count, caseAssociation=case_association,
                               alarmRuleName=alarm_rule_name, entityName=entity_name)
        headers = self._headers

        response = self._http_request('GET', 'lr-alarm-api/alarms/', params=params, headers=headers)

        alarms = response.get('alarmsSearchDetails')
        if alarm_id:
            alarms = next((alarm for alarm in alarms if alarm.get('alarmId') == int(alarm_id)), None)
        return alarms, response

    def alarm_update_request(self, alarm_id, alarm_status, rbp):
        data = {"alarmStatus": alarm_status if alarm_status else None,
                "rBP": rbp if rbp else None}

        # delete empty values
        data = {k: v for k, v in data.items() if v}

        headers = self._headers

        response = self._http_request('PATCH', f'lr-alarm-api/alarms/{alarm_id}', json_data=data, headers=headers)

        return response

    def alarm_add_comment_request(self, alarm_id, alarm_comment):
        data = {"alarmComment": alarm_comment}
        headers = self._headers

        response = self._http_request('POST', f'lr-alarm-api/alarms/{alarm_id}/comment', json_data=data, headers=headers)

        return response

    def alarm_history_list_request(self, alarm_id, person_id, date_updated, type_, offset, count):
        params = assign_params(personId=person_id, dateUpdated=date_updated, type=type_, offset=offset, count=count)
        headers = self._headers

        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}/history', params=params, headers=headers)

        alarm_history = response.get('alarmHistoryDetails')
        return alarm_history, response

    def alarm_events_list_request(self, alarm_id):
        headers = self._headers

        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}/events', headers=headers)

        alarm_events = response.get('alarmEventsDetails')
        return alarm_events, response

    def alarm_summary_request(self, alarm_id):
        headers = self._headers

        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}/summary', headers=headers)

        alarm_summary = response.get('alarmSummaryDetails')
        return alarm_summary, response

    def cases_list_request(self, case_id, timestamp_filter_type, timestamp, priority, status, owners, tags,
                                         text, evidence_type, reference_id, external_id, entity_number, offset, count):

        params = assign_params(priority=priority, statusNumber=status, ownerNumber=owners, tagNumber=tags, text=text,
                               evidenceType=evidence_type, referenceId=reference_id, externalId=external_id,
                               entityNumber=entity_number, offset=offset, count=count)
        headers = self._headers

        cases = self._http_request('GET', 'lr-case-api/cases', params=params, headers=headers)

        if case_id:
            cases = next((case for case in cases if case.get('id') == case_id), None)
        return cases

    def case_create_request(self, name, priority, external_id, due_date, summary, entity_id):
        data = {"name": name, "priority": int(priority), "externalId": external_id, "dueDate": due_date,
                "summary": summary, "entityId": int(entity_id) if entity_id else None}

        # delete empty values
        data = {k: v for k, v in data.items() if v}

        headers = self._headers

        response = self._http_request('POST', 'lr-case-api/cases', json_data=data, headers=headers)

        return response

    def case_update_request(self, case_id, name, priority, external_id, due_date, summary, entity_id, resolution):
        data = {"name": name, "externalId": external_id, "dueDate": due_date,
                "summary": summary, "entityId": int(entity_id) if entity_id else None,
                "resolution": int(resolution) if resolution else None,
                "priority": int(priority) if priority else None}

        # delete empty values
        data = {k: v for k, v in data.items() if v}

        headers = self._headers

        response = self._http_request('PUT', f'lr-case-api/cases/{case_id}', json_data=data, headers=headers)

        return response

    def case_status_change_request(self, case_id, status):
        status_number = CASE_STATUS.get(status)

        data = {"statusNumber": status_number}
        headers = self._headers

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/actions/changeStatus/', json_data=data, headers=headers)

        return response

    def case_evidence_list_request(self, case_id, evidence_number, evidence_type, status):
        params = assign_params(type=evidence_type, status=status)
        headers = self._headers

        evidences = self._http_request('GET', f'lr-case-api/cases/{case_id}/evidence', params=params, headers=headers)

        if evidence_number:
            evidences = next((evidence for evidence in evidences if evidence.get('number') == int(evidence_number)), None)
        return evidences

    def case_alarm_evidence_add_request(self, case_id, alarm_numbers):
        headers = self._headers

        alarms = [int(alarm) for alarm in alarm_numbers]
        data = {"alarmNumbers": alarms}

        response = self._http_request(
            'POST', f'lr-case-api/cases/{case_id}/evidence/alarms', json_data=data, headers=headers)

        return response

    def case_note_evidence_add_request(self, case_id, note):
        data = {"text": note}
        headers = self._headers

        response = self._http_request(
            'POST', f'lr-case-api/cases/{case_id}/evidence/note', json_data=data, headers=headers)

        return response

    def case_file_evidence_add_request(self, case_id, entry_id):
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data; boundary=---------------------------'

        get_file_path_res = demisto.getFilePath(entry_id)
        file_path = get_file_path_res["path"]
        file_name = get_file_path_res["name"]
        with open(file_path, 'rb') as file:
            file_bytes = file.read()

        file_content = file_bytes.decode('iso-8859-1')
        content_type = mimetypes.guess_type(file_path)[0]

        data = '-----------------------------\n' \
               f'Content-Disposition: form-data; name="file"; filename="{file_name}"\n' \
               f'Content-Type: {content_type}\n\n' \
               f'{file_content}\n' \
               '-----------------------------\n' \
               'Content-Disposition: form-data; name="note"\n\n' \
               '-------------------------------'

        response = self._http_request('POST', f'lr-case-api/cases/{case_id}/evidence/file', headers=headers, data=data)

        return response

    def case_evidence_delete_request(self, case_id, evidence_number):
        headers = self._headers

        self._http_request('DELETE', f'lr-case-api/cases/{case_id}/evidence/{evidence_number}', headers=headers, resp_type='text')

    def case_file_evidence_download_request(self, case_id, evidence_number):
        headers = self._headers

        response = self._http_request(
            'GET', f'lr-case-api/cases/{case_id}/evidence/{evidence_number}/download/', headers=headers,
            resp_type='other')

        filename = re.findall("filename=\"(.+)\"", response.headers['Content-Disposition'])[0]
        return fileResult(filename, response.content)

    def case_evidence_user_events_list_request(self, case_id, evidence_number):
        headers = self._headers

        response = self._http_request(
            'GET', f'lr-case-api/cases/{case_id}/evidence/{evidence_number}/userEvents/', headers=headers)

        return response

    def case_tags_add_request(self, case_id, tag_numbers):
        headers = self._headers

        tags = [int(tag) for tag in tag_numbers]
        data = {"numbers": tags}

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/actions/addTags', json_data=data, headers=headers)

        return response

    def case_tags_remove_request(self, case_id, tag_numbers):
        headers = self._headers

        tags = [int(tag) for tag in tag_numbers]
        data = {"numbers": tags}

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/actions/removeTags', json_data=data, headers=headers)

        return response

    def tags_list_request(self, tag_name, offset, count):
        params = assign_params(tag=tag_name, offset=offset, count=count)
        headers = self._headers

        response = self._http_request('GET', 'lr-case-api/tags', params=params, headers=headers)

        return response

    def case_collaborators_list_request(self, case_id):
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('GET', f'lr-case-api/cases/{case_id}/collaborators', headers=headers)

        return response

    def case_collaborators_update_request(self, case_id, owner, collaborators):
        collaborators = [int(collaborator) for collaborator in collaborators]

        data = {"owner": int(owner),
                "collaborators": collaborators}

        headers = self._headers

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/collaborators', json_data=data, headers=headers)

        return response

    def entities_list_request(self, entity_id, parent_entity_id, offset, count):
        params = assign_params(parentEntityId=parent_entity_id, offset=offset, count=count)
        headers = self._headers

        entities = self._http_request('GET', 'lr-admin-api/entities', params=params, headers=headers)
        if entity_id:
            entities = next((entity for entity in entities if entity.get('id') == int(entity_id)), None)
        return entities

    def hosts_list_request(self, host_id, host_name, entity_name, record_status, offset, count):
        params = assign_params(name=host_name, entity=entity_name, recordStatus=record_status, offset=offset, count=count)
        headers = self._headers

        hosts = self._http_request('GET', 'lr-admin-api/hosts', params=params, headers=headers)
        if host_id:
            hosts = next((host for host in hosts if host.get('id') == int(host_id)), None)
        return hosts

    def users_list_request(self, user_ids, entity_ids, user_status, offset, count):
        params = assign_params(id=user_ids, entityIds=entity_ids, userStatus=user_status, offset=offset, count=count)
        headers = self._headers

        response = self._http_request('GET', 'lr-admin-api/users', params=params, headers=headers)

        return response

    def lists_get_request(self, listtype, name, canedit):
        params = assign_params(listType=listtype, name=name, canEdit=canedit)
        headers = self._headers

        response = self._http_request('GET', 'lr-admin-api/lists', params=params, headers=headers)

        return response

    def list_summary_create_update_request(self, listtype, name, enabled, usepatterns, replaceexisting, readaccess, writeaccess, restrictedread, entityname, needtonotify, doesexpire):
        data = {"autoImportOption": {"enabled": enabled, "replaceExisting": replaceexisting, "usePatterns": usepatterns}, "doesExpire": doesexpire, "entityName": entityname,
                "listType": listtype, "name": name, "needToNotify": needtonotify, "readAccess": readaccess, "restrictedRead": restrictedread, "writeAccess": writeaccess}
        headers = self._headers

        response = self._http_request('POST', 'lr-admin-api/lists', json_data=data, headers=headers)

        return response

    def list_details_and_items_get_request(self, list_id, maxitemsthreshold):
        params = assign_params(maxItemsThreshold=maxitemsthreshold)
        headers = self._headers

        response = self._http_request('GET', f'lr-admin-api/lists/{list_id}', params=params, headers=headers)

        return response

    def list_items_add_request(self, list_id, displayvalue, expirationdate, isexpired, islistitem, ispattern, listitemdatatype, listitemtype, value, listid, guid, listtype, name):
        data = {"items": [{"displayValue": displayvalue, "expirationDate": expirationdate, "isExpired": isexpired, "isListItem": islistitem, "isPattern": ispattern,
                           "listItemDataType": listitemdatatype, "listItemType": listitemtype, "value": value, "valueAsListReference": {"guid": guid, "listId": listid, "listType": listtype, "name": name}}]}
        headers = self._headers

        response = self._http_request('POST', f'lr-admin-api/lists/{list_id}', json_data=data, headers=headers)

        return response

    def list_items_remove_request(self, list_id, displayvalue, expirationdate, isexpired, islistitem, ispattern, listitemdatatype, listitemtype, value):
        data = {"items": [{"displayValue": displayvalue, "expirationDate": expirationdate, "isExpired": isexpired, "isListItem": islistitem,
                           "isPattern": ispattern, "listItemDataType": listitemdatatype, "listItemType": listitemtype, "value": value}]}
        headers = self._headers

        response = self._http_request('DELETE', f'lr-admin-api/lists/{list_id}', json_data=data, headers=headers)

        return response

    def execute_search_query_request(self, maxmsgstoquery, logcachesize, querytimeout, queryrawlog, queryeventmanager, useinserteddate, lastintervalvalue, lastintervalunit, msgfiltertype, issavedfilter, filteritemtype, fieldoperator, filtermode, filtergroupoperator):
        data = {"dateCriteria": {"lastIntervalUnit": lastintervalunit, "lastIntervalValue": lastintervalvalue, "useInsertedDate": useinserteddate}, "logCacheSize": logcachesize, "maxMsgsToQuery": maxmsgstoquery, "queryEventManager": queryeventmanager, "queryFilter": {"filterGroup": {"fieldOperator": fieldoperator,
                                                                                                                                                                                                                                                                                            "filterGroupOperator": filtergroupoperator, "filterItemType": filteritemtype, "filterItems": filteritems, "filterMode": filtermode}, "isSavedFilter": issavedfilter, "msgFilterType": msgfiltertype}, "queryLogSources": querylogsources, "queryRawLog": queryrawlog, "queryTimeout": querytimeout}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'lr-search-api/actions/search-task', json_data=data, headers=headers)

        return response

    def get_query_result_request(self, maxmsgstoquery, logcachesize, querytimeout, queryrawlog, queryeventmanager, useinserteddate, lastintervalvalue, lastintervalunit, msgfiltertype, issavedfilter, filteritemtype, fieldoperator, filtermode, filtergroupoperator):
        data = {"dateCriteria": {"lastIntervalUnit": lastintervalunit, "lastIntervalValue": lastintervalvalue, "useInsertedDate": useinserteddate}, "logCacheSize": logcachesize, "maxMsgsToQuery": maxmsgstoquery, "queryEventManager": queryeventmanager, "queryFilter": {"filterGroup": {"fieldOperator": fieldoperator,
                                                                                                                                                                                                                                                                                            "filterGroupOperator": filtergroupoperator, "filterItemType": filteritemtype, "filterItems": filteritems, "filterMode": filtermode}, "isSavedFilter": issavedfilter, "msgFilterType": msgfiltertype}, "queryLogSources": querylogsources, "queryRawLog": queryrawlog, "queryTimeout": querytimeout}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'lr-search-api/actions/search-task', json_data=data, headers=headers)

        return response

    def add_host_request(self, id_, id_2, entry_name, name, risklevel, recordstatusname, hostzone, os, useeventlogcredentials):
        data = {"entity": {"id": id_, "name": entry_name}, "hostZone": hostzone, "id": id_2, "name": name, "os": os,
                "recordStatusName": recordstatusname, "riskLevel": risklevel, "useEventlogCredentials": useeventlogcredentials}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'lr-admin-api/hosts', json_data=data, headers=headers)

        return response


def alarms_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')
    alarm_status = args.get('alarm_status')
    alarm_rule_name = args.get('alarm_rule_name')
    entity_name = args.get('entity_name')
    case_association = args.get('case_association')
    offset = args.get('offset')
    count = args.get('count')

    alarms, raw_response = client.alarms_list_request(alarm_id, alarm_status, offset, count, alarm_rule_name, entity_name, case_association)

    if alarms:
        hr = tableToMarkdown('Alarms', alarms, headerTransform=pascalToSpace, headers=ALARM_HEADERS)
    else:
        hr = 'No alarms were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogRhythm.Alarm',
        outputs_key_field='',
        outputs=response,
        raw_response=raw_response
    )

    return command_results


def alarm_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')
    alarm_status = args.get('alarm_status')
    rbp = args.get('rbp')

    if not alarm_status and not rbp:
        raise DemistoException('alarm_status and rbp arguments are empty, please provide at least one of them.')

    response = client.alarm_update_request(alarm_id, alarm_status, rbp)
    command_results = CommandResults(
        readable_output=f'Alarm {alarm_id} has been updated.',
        raw_response=response
    )

    return command_results


def alarm_add_comment_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')
    alarm_comment = args.get('alarm_comment')

    response = client.alarm_add_comment_request(alarm_id, alarm_comment)
    command_results = CommandResults(
        readable_output=f'Comment added successfully to the alarm {alarm_id}.',
        raw_response=response
    )

    return command_results


def alarm_history_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')
    person_id = args.get('person_id')
    date_updated = args.get('date_updated')
    type_ = args.get('type')
    offset = args.get('offset')
    count = args.get('count')

    alarm_history, raw_response = client.alarm_history_list_request(alarm_id, person_id, date_updated, type_, offset, count)

    if alarm_history:
        hr = tableToMarkdown(f'History for alarm {alarm_id}', alarm_history, headerTransform=pascalToSpace)
    else:
        hr = f'No history records found for alarm {alarm_id}.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.AlarmHistoryList',
        outputs_key_field='',
        outputs=alarm_history,
        raw_response=raw_response
    )

    return command_results


def alarm_events_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')

    alarm_events, raw_response = client.alarm_events_list_request(alarm_id)

    if alarm_events:
        hr = tableToMarkdown(f'Events for alarm {alarm_id}', alarm_events, headerTransform=pascalToSpace,
                             headers=ALARM_EVENTS_HEADERS)
    else:
        hr = f'No events found for alarm {alarm_id}.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.AlarmEventsList',
        outputs_key_field='',
        outputs=alarm_events,
        raw_response=raw_response
    )

    return command_results


def alarm_summary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')

    alarm_summary, raw_response = client.alarm_summary_request(alarm_id)

    alarm_event_summary = alarm_summary.get('alarmEventSummary')
    if alarm_event_summary:
        del alarm_summary['alarmEventSummary']
        hr = tableToMarkdown(f'Alarm summary', alarm_summary, headerTransform=pascalToSpace)
        hr = hr +tableToMarkdown(f'Alarm event summary', alarm_event_summary, headerTransform=pascalToSpace)
    else:
        hr = tableToMarkdown(f'Alarm {alarm_id} summary', alarm_summary, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.AlarmSummary',
        outputs_key_field='',
        outputs=alarm_summary,
        raw_response=raw_response
    )

    return command_results


def cases_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    timestamp_filter_type = args.get('timestamp_filter_type')
    timestamp = args.get('timestamp')
    priority = args.get('priority')
    status = args.get('status')
    owners = args.get('owners')
    tags = args.get('tags')
    text = args.get('text')
    evidence_type = args.get('evidence_type')
    reference_id = args.get('reference_id')
    external_id = args.get('external_id')
    entity_number = args.get('entity_number')
    offset = args.get('offset')
    count = args.get('count')

    cases = client.cases_list_request(case_id, timestamp_filter_type, timestamp, priority, status, owners, tags,
                                         text, evidence_type, reference_id, external_id, entity_number, offset, count)

    if cases:
        hr = tableToMarkdown('Cases', cases, headerTransform=pascalToSpace)
    else:
        hr = 'No cases found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CasesList',
        outputs_key_field='',
        outputs=cases,
        raw_response=cases
    )

    return command_results


def case_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    priority = args.get('priority')
    external_id = args.get('external_id')
    due_date = args.get('due_date')
    summary = args.get('summary')
    entity_id = args.get('entity_id')

    response = client.case_create_request(name, priority, external_id, due_date, summary, entity_id)

    hr = tableToMarkdown('Case created successfully', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseCreate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    name = args.get('name')
    priority = args.get('priority')
    external_id = args.get('external_id')
    due_date = args.get('due_date')
    summary = args.get('summary')
    entity_id = args.get('entity_id')
    resolution = args.get('resolution')

    response = client.case_update_request(case_id, name, priority, external_id, due_date, summary, entity_id, resolution)

    hr = tableToMarkdown(f'Case {case_id} updated successfully', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_status_change_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    status = args.get('status')

    response = client.case_status_change_request(case_id, status)

    hr = tableToMarkdown('Case status updated successfully', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_evidence_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    evidence_number = args.get('evidence_number')
    evidence_type = args.get('evidence_type')
    status = args.get('status')

    evidences = client.case_evidence_list_request(case_id, evidence_number, evidence_type, status)

    if evidences:
        hr = tableToMarkdown(f'evidences for case {case_id}', evidences, headerTransform=pascalToSpace)
    else:
        hr = f'No evidences found for case {case_id}.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseUpdate',
        outputs_key_field='',
        outputs=evidences,
        raw_response=evidences
    )

    return command_results


def case_alarm_evidence_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    alarm_numbers = argToList(args.get('alarm_numbers'))

    evidences = client.case_alarm_evidence_add_request(case_id, alarm_numbers)

    hr = tableToMarkdown(f'Alarms added as evidence to case {case_id} successfully', evidences, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseAlarmEvidenceAdd',
        outputs_key_field='',
        outputs=evidences,
        raw_response=evidences
    )

    return command_results


def case_note_evidence_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    note = args.get('note')

    response = client.case_note_evidence_add_request(case_id, note)
    hr = tableToMarkdown(f'Note added as evidence to case {case_id} successfully', response,
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseAlarmEvidenceAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_file_evidence_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    entry_id = args.get('entryId')

    response = client.case_file_evidence_add_request(case_id, entry_id)
    hr = tableToMarkdown(f'File added as evidence to case {case_id} successfully', response,
                         headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseFileEvidenceAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_evidence_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    evidence_number = args.get('evidence_number')

    client.case_evidence_delete_request(case_id, evidence_number)
    command_results = CommandResults(
        readable_output=f'Evidence deleted successfully from case {case_id}.'
    )

    return command_results


def case_file_evidence_download_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    evidence_number = args.get('evidence_number')

    return client.case_file_evidence_download_request(case_id, evidence_number)


def case_evidence_user_events_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    evidence_number = args.get('evidence_number')

    response = client.case_evidence_user_events_list_request(case_id, evidence_number)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseEvidenceUserEventsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_tags_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    tag_numbers = argToList(args.get('tag_numbers'))

    response = client.case_tags_add_request(case_id, tag_numbers)
    hr = tableToMarkdown(f'Tags added successfully to case {case_id}', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseTagsAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_tags_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    tag_numbers = argToList(args.get('tag_numbers'))

    response = client.case_tags_remove_request(case_id, tag_numbers)
    hr = tableToMarkdown(f'Tags removed successfully from case {case_id}', response, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseTagsAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def tags_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    tag_name = args.get('tag_name')
    offset = args.get('offset')
    count = args.get('count')

    response = client.tags_list_request(tag_name, offset, count)
    if response:
        hr = tableToMarkdown('Tags', response, headerTransform=pascalToSpace)
    else:
        hr = 'No tags were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.TagsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_collaborators_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')

    response = client.case_collaborators_list_request(case_id)
    collaborators = response.get('collaborators')

    hr = tableToMarkdown('Case owner', response.get('owner'), headerTransform=pascalToSpace)
    if collaborators:
        hr = hr + tableToMarkdown('Case collaborators', collaborators, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseCollaboratorsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_collaborators_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    owner = args.get('owner')
    collaborators = argToList(args.get('collaborators'))

    response = client.case_collaborators_update_request(case_id, owner, collaborators)
    collaborators = response.get('collaborators')

    hr = f'### Case {case_id} updated successfully\n'
    hr = hr + tableToMarkdown('Case owner', response.get('owner'), headerTransform=pascalToSpace)
    if collaborators:
        hr = hr + tableToMarkdown('Case collaborators', collaborators, headerTransform=pascalToSpace)

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.CaseCollaboratorsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def entities_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    entity_id = args.get('entity_id')
    parent_entity_id = args.get('parent_entity_id')
    offset = args.get('offset')
    count = args.get('count')

    response = client.entities_list_request(entity_id, parent_entity_id, offset, count)
    if response:
        hr = tableToMarkdown('Entities', response, headerTransform=pascalToSpace)
    else:
        hr = 'No entities were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.EntitiesList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def hosts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    host_id = args.get('host_id')
    host_name = args.get('host_name')
    entity_name = args.get('entity_name')
    record_status = args.get('record_status')
    offset = args.get('offset')
    count = args.get('count')

    response = client.hosts_list_request(host_id, host_name, entity_name, record_status, offset, count)
    if response:
        hr = tableToMarkdown('Hosts', response, headerTransform=pascalToSpace)
    else:
        hr = 'No hosts were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.HostsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def users_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    user_ids = args.get('user_ids')
    entity_ids = args.get('entity_ids')
    user_status = args.get('user_status')
    offset = args.get('offset')
    count = args.get('count')

    response = client.users_list_request(user_ids, entity_ids, user_status, offset, count)
    if response:
        hr = tableToMarkdown('Users', response, headerTransform=pascalToSpace)
    else:
        hr = 'No users were found.'

    command_results = CommandResults(
        readable_output=hr,
        outputs_prefix='LogrhythmV2.HostsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def lists_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    listtype = args.get('listtype')
    name = args.get('name')
    canedit = args.get('canedit')

    response = client.lists_get_request(listtype, name, canedit)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.ListsGet',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_summary_create_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    listtype = args.get('listtype')
    name = args.get('name')
    enabled = args.get('enabled')
    usepatterns = args.get('usepatterns')
    replaceexisting = args.get('replaceexisting')
    readaccess = args.get('readaccess')
    writeaccess = args.get('writeaccess')
    restrictedread = args.get('restrictedread')
    entityname = args.get('entityname')
    needtonotify = args.get('needtonotify')
    doesexpire = args.get('doesexpire')

    response = client.list_summary_create_update_request(
        listtype, name, enabled, usepatterns, replaceexisting, readaccess, writeaccess, restrictedread, entityname, needtonotify, doesexpire)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.ListSummaryCreateUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_details_and_items_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    list_id = args.get('list_id')
    maxitemsthreshold = args.get('maxitemsthreshold')

    response = client.list_details_and_items_get_request(list_id, maxitemsthreshold)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.ListDetailsAndItemsGet',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_items_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    list_id = args.get('list_id')
    displayvalue = args.get('displayvalue')
    expirationdate = args.get('expirationdate')
    isexpired = args.get('isexpired')
    islistitem = args.get('islistitem')
    ispattern = args.get('ispattern')
    listitemdatatype = args.get('listitemdatatype')
    listitemtype = args.get('listitemtype')
    value = args.get('value')
    listid = args.get('listid')
    guid = args.get('guid')
    listtype = args.get('listtype')
    name = args.get('name')

    response = client.list_items_add_request(list_id, displayvalue, expirationdate, isexpired,
                                             islistitem, ispattern, listitemdatatype, listitemtype, value, listid, guid, listtype, name)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.ListItemsAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def list_items_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    list_id = args.get('list_id')
    displayvalue = args.get('displayvalue')
    expirationdate = args.get('expirationdate')
    isexpired = args.get('isexpired')
    islistitem = args.get('islistitem')
    ispattern = args.get('ispattern')
    listitemdatatype = args.get('listitemdatatype')
    listitemtype = args.get('listitemtype')
    value = args.get('value')

    response = client.list_items_remove_request(
        list_id, displayvalue, expirationdate, isexpired, islistitem, ispattern, listitemdatatype, listitemtype, value)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.ListItemsRemove',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def execute_search_query_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    maxmsgstoquery = args.get('maxmsgstoquery')
    logcachesize = args.get('logcachesize')
    querytimeout = args.get('querytimeout')
    queryrawlog = args.get('queryrawlog')
    queryeventmanager = args.get('queryeventmanager')
    useinserteddate = args.get('useinserteddate')
    lastintervalvalue = args.get('lastintervalvalue')
    lastintervalunit = args.get('lastintervalunit')
    msgfiltertype = args.get('msgfiltertype')
    issavedfilter = args.get('issavedfilter')
    filteritemtype = args.get('filteritemtype')
    fieldoperator = args.get('fieldoperator')
    filtermode = args.get('filtermode')
    filtergroupoperator = args.get('filtergroupoperator')

    response = client.execute_search_query_request(maxmsgstoquery, logcachesize, querytimeout, queryrawlog, queryeventmanager, useinserteddate,
                                                   lastintervalvalue, lastintervalunit, msgfiltertype, issavedfilter, filteritemtype, fieldoperator, filtermode, filtergroupoperator)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.ExecuteSearchQuery',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_query_result_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    maxmsgstoquery = args.get('maxmsgstoquery')
    logcachesize = args.get('logcachesize')
    querytimeout = args.get('querytimeout')
    queryrawlog = args.get('queryrawlog')
    queryeventmanager = args.get('queryeventmanager')
    useinserteddate = args.get('useinserteddate')
    lastintervalvalue = args.get('lastintervalvalue')
    lastintervalunit = args.get('lastintervalunit')
    msgfiltertype = args.get('msgfiltertype')
    issavedfilter = args.get('issavedfilter')
    filteritemtype = args.get('filteritemtype')
    fieldoperator = args.get('fieldoperator')
    filtermode = args.get('filtermode')
    filtergroupoperator = args.get('filtergroupoperator')

    response = client.get_query_result_request(maxmsgstoquery, logcachesize, querytimeout, queryrawlog, queryeventmanager, useinserteddate,
                                               lastintervalvalue, lastintervalunit, msgfiltertype, issavedfilter, filteritemtype, fieldoperator, filtermode, filtergroupoperator)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.GetQueryResult',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def add_host_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    id_ = args.get('id')
    id_2 = args.get('id')
    name = args.get('name')
    entry_name = args.get('entry_name')
    risklevel = args.get('risklevel')
    recordstatusname = args.get('recordstatusname')
    hostzone = args.get('hostzone')
    os = args.get('os')
    useeventlogcredentials = args.get('useeventlogcredentials')

    response = client.add_host_request(id_, id_2, name, entry_name, risklevel,
                                       recordstatusname, hostzone, os, useeventlogcredentials)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.AddHost',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    client.hosts_list_request()
    return_results('ok')


def main() -> None:

    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    url = params.get('url')
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    headers = {}
    headers['Authorization'] = f'Bearer {params["token"]}'

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client: Client = Client(urljoin(url, ''), verify_certificate, proxy, headers=headers, auth=None)

        commands = {
            'lr-alarms-list': alarms_list_command,
            'lr-alarm-update': alarm_update_command,
            'lr-alarm-add-comment': alarm_add_comment_command,
            'lr-alarm-history-list': alarm_history_list_command,
            'lr-alarm-events-list': alarm_events_list_command,
            'lr-alarm-summary': alarm_summary_command,
            'lr-cases-list': cases_list_command,
            'lr-case-create': case_create_command,
            'lr-case-update': case_update_command,
            'lr-case-status-change': case_status_change_command,
            'lr-case-evidence-list': case_evidence_list_command,
            'lr-case-alarm-evidence-add': case_alarm_evidence_add_command,
            'lr-case-note-evidence-add': case_note_evidence_add_command,
            'lr-case-file-evidence-add': case_file_evidence_add_command,
            'lr-case-evidence-delete': case_evidence_delete_command,
            'lr-case-file-evidence-download': case_file_evidence_download_command,
            'lr-case-evidence-user-events-list': case_evidence_user_events_list_command,
            'lr-case-tags-add': case_tags_add_command,
            'lr-case-tags-remove': case_tags_remove_command,
            'lr-tags-list': tags_list_command,
            'lr-case-collaborators-list': case_collaborators_list_command,
            'lr-case-collaborators-update': case_collaborators_update_command,
            'lr-entities-list': entities_list_command,
            'lr-hosts-list': hosts_list_command,
            'lr-users-list': users_list_command,
            'lr-lists-get': lists_get_command,
            'lr-list-summary-create-update': list_summary_create_update_command,
            'lr-list-details-and-items-get': list_details_and_items_get_command,
            'lr-list-items-add': list_items_add_command,
            'lr-list-items-remove': list_items_remove_command,
            'lr-execute-search-query': execute_search_query_command,
            'lr-get-query-result': get_query_result_command,
            'lr-add-host': add_host_command,
        }

        if command == 'test-module':
            test_module(client)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
