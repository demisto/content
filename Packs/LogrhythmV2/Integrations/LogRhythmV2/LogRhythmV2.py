from CommonServerPython import *  # noqa: F401

import demistomock as demisto  # noqa: F401


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def alarms_list_request(self, alarmstatus, offset, count, alarmrulename, entityname):
        params = assign_params(alarmStatus=alarmstatus, offset=offset, count=count,
                               alarmRuleName=alarmrulename, entityName=entityname)
        headers = self._headers

        response = self._http_request('GET', 'lr-alarm-api/alarms/', params=params, headers=headers)

        return response

    def alarm_update_request(self, alarm_id, alarmstatus, rbp):
        data = {"alarmStatus": alarmstatus, "rBP": rbp}
        headers = self._headers

        response = self._http_request('PATCH', f'lr-alarm-api/alarms/{alarm_id}', json_data=data, headers=headers)

        return response

    def alarm_add_comment_request(self, alarm_id, alarmcomment):
        data = {"alarmComment": alarmcomment}
        headers = self._headers

        response = self._http_request('PATCH', f'lr-alarm-api/alarms/{alarm_id}', json_data=data, headers=headers)

        return response

    def alarm_history_list_request(self, alarm_id, personid, dateupdated, type_, offset, count):
        params = assign_params(personId=personid, dateUpdated=dateupdated, type=type_, offset=offset, count=count)
        headers = self._headers

        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}/history', params=params, headers=headers)

        return response

    def alarm_events_list_request(self, alarm_id):
        headers = self._headers

        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}/events', headers=headers)

        return response

    def alarm_summary_request(self, alarm_id):
        headers = self._headers

        response = self._http_request('GET', f'lr-alarm-api/alarms/{alarm_id}/summary', headers=headers)

        return response

    def cases_list_request(self, priority, statusnumber, ownernumber, tagnumber, text, evidencetype, referenceid, externalid, entitynumber, offset, count):
        params = assign_params(priority=priority, statusNumber=statusnumber, ownerNumber=ownernumber, tagNumber=tagnumber, text=text,
                               evidenceType=evidencetype, referenceId=referenceid, externalId=externalid, entityNumber=entitynumber, offset=offset, count=count)
        headers = self._headers

        response = self._http_request('GET', 'lr-case-api/cases', params=params, headers=headers)

        return response

    def case_create_request(self, name, priority):
        data = {"name": name, "priority": priority}
        headers = self._headers

        response = self._http_request('POST', 'lr-case-api/cases', json_data=data, headers=headers)

        return response

    def case_update_request(self, case_id, name):
        data = {"name": name}
        headers = self._headers

        response = self._http_request('PUT', f'lr-case-api/cases/{case_id}', json_data=data, headers=headers)

        return response

    def case_status_change_request(self, case_id, statusnumber):
        data = {"statusNumber": statusnumber}
        headers = self._headers

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/actions/changeStatus/', json_data=data, headers=headers)

        return response

    def case_evidence_list_request(self, case_id, type_, status):
        params = assign_params(type=type_, status=status)
        headers = self._headers

        response = self._http_request('GET', f'lr-case-api/cases/{case_id}/evidence', params=params, headers=headers)

        return response

    def case_alarm_evidence_add_request(self, case_id, alarmnumbers):
        data = {"alarmNumbers": alarmnumbers}
        headers = self._headers

        response = self._http_request(
            'POST', f'lr-case-api/cases/{case_id}/evidence/alarms', json_data=data, headers=headers)

        return response

    def case_note_evidence_add_request(self, case_id, text):
        data = {"text": text}
        headers = self._headers

        response = self._http_request(
            'POST', f'lr-case-api/cases/{case_id}/evidence/note', json_data=data, headers=headers)

        return response

    def case_file_evidence_add_request(self, case_id):
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('POST', f'lr-case-api/cases/{case_id}/evidence/file', headers=headers)

        return response

    def case_evidence_delete_request(self, case_idevidence, evidence_number):
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request(
            'DELETE', f'lr-case-api/cases/{{case_id}}evidence/{evidence_number}', headers=headers)

        return response

    def case_file_evidence_download_request(self, case_id, evidence_number):
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request(
            'GET', f'lr-case-api/cases/{case_id}/evidence/{evidence_number}/download/', headers=headers)

        return response

    def case_evidence_user_events_list_request(self, case_id, evidence_number):
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request(
            'GET', f'lr-case-api/cases/{case_id}/evidence/{evidence_number}/userEvents/', headers=headers)

        return response

    def case_tags_add_request(self, case_id, numbers):
        data = {"numbers": numbers}
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/actions/addTags', json_data=data, headers=headers)

        return response

    def case_tags_remove_request(self, case_id, numbers):
        data = {"numbers": numbers}
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/actions/removeTags', json_data=data, headers=headers)

        return response

    def tags_list_request(self, offset, count):
        params = assign_params(offset=offset, count=count)
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('GET', 'lr-case-api/tags', params=params, headers=headers)

        return response

    def case_collaborators_list_request(self, case_id):
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('GET', f'lr-case-api/cases/{case_id}/collaborators', headers=headers)

        return response

    def case_collaborators_update_request(self, case_id, owner, collaborators):
        data = {"collaborators": collaborators, "owner": owner}
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request(
            'PUT', f'lr-case-api/cases/{case_id}/collaborators', json_data=data, headers=headers)

        return response

    def entities_list_request(self, parententityid, offset, count):
        params = assign_params(parentEntityId=parententityid, offset=offset, count=count)
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('GET', 'lr-admin-api/entities', params=params, headers=headers)

        return response

    def hosts_list_request(self, name, entity, recordstatus, offset, count):
        params = assign_params(name=name, entity=entity, recordStatus=recordstatus, offset=offset, count=count)
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('GET', 'lr-admin-api/hosts', params=params, headers=headers)

        return response

    def lists_get_request(self, listtype, name, canedit):
        params = assign_params(listType=listtype, name=name, canEdit=canedit)
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('GET', 'lr-admin-api/lists', params=params, headers=headers)

        return response

    def list_summary_create_update_request(self, listtype, name, enabled, usepatterns, replaceexisting, readaccess, writeaccess, restrictedread, entityname, needtonotify, doesexpire):
        data = {"autoImportOption": {"enabled": enabled, "replaceExisting": replaceexisting, "usePatterns": usepatterns}, "doesExpire": doesexpire, "entityName": entityname,
                "listType": listtype, "name": name, "needToNotify": needtonotify, "readAccess": readaccess, "restrictedRead": restrictedread, "writeAccess": writeaccess}
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('POST', 'lr-admin-api/lists', json_data=data, headers=headers)

        return response

    def list_details_and_items_get_request(self, list_id, maxitemsthreshold):
        params = assign_params(maxItemsThreshold=maxitemsthreshold)
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('GET', f'lr-admin-api/lists/{list_id}', params=params, headers=headers)

        return response

    def list_items_add_request(self, list_id, displayvalue, expirationdate, isexpired, islistitem, ispattern, listitemdatatype, listitemtype, value, listid, guid, listtype, name):
        data = {"items": [{"displayValue": displayvalue, "expirationDate": expirationdate, "isExpired": isexpired, "isListItem": islistitem, "isPattern": ispattern,
                           "listItemDataType": listitemdatatype, "listItemType": listitemtype, "value": value, "valueAsListReference": {"guid": guid, "listId": listid, "listType": listtype, "name": name}}]}
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('POST', f'lr-admin-api/lists/{list_id}', json_data=data, headers=headers)

        return response

    def list_items_remove_request(self, list_id, displayvalue, expirationdate, isexpired, islistitem, ispattern, listitemdatatype, listitemtype, value):
        data = {"items": [{"displayValue": displayvalue, "expirationDate": expirationdate, "isExpired": isexpired, "isListItem": islistitem,
                           "isPattern": ispattern, "listItemDataType": listitemdatatype, "listItemType": listitemtype, "value": value}]}
        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

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

    def add_host_request(self, id_, id_, name, name, risklevel, recordstatusname, hostzone, os, useeventlogcredentials):
        data = {"entity": {"id": id, "name": name}, "hostZone": hostzone, "id": id, "name": name, "os": os,
                "recordStatusName": recordstatusname, "riskLevel": risklevel, "useEventlogCredentials": useeventlogcredentials}
        headers = self._headers
        headers['Content-Type'] = 'application/json'

        response = self._http_request('POST', 'lr-admin-api/hosts', json_data=data, headers=headers)

        return response


def alarms_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarmstatus = args.get('alarmstatus')
    offset = args.get('offset')
    count = args.get('count')
    alarmrulename = args.get('alarmrulename')
    entityname = args.get('entityname')

    response = client.alarms_list_request(alarmstatus, offset, count, alarmrulename, entityname)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.AlarmsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def alarm_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')
    alarmstatus = args.get('alarmstatus')
    rbp = args.get('rbp')

    response = client.alarm_update_request(alarm_id, alarmstatus, rbp)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.AlarmUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def alarm_add_comment_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')
    alarmcomment = args.get('alarmcomment')

    response = client.alarm_add_comment_request(alarm_id, alarmcomment)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.AlarmAddComment',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def alarm_history_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')
    personid = args.get('personid')
    dateupdated = args.get('dateupdated')
    type_ = args.get('type')
    offset = args.get('offset')
    count = args.get('count')

    response = client.alarm_history_list_request(alarm_id, personid, dateupdated, type_, offset, count)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.AlarmHistoryList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def alarm_events_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')

    response = client.alarm_events_list_request(alarm_id)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.AlarmEventsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def alarm_summary_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    alarm_id = args.get('alarm_id')

    response = client.alarm_summary_request(alarm_id)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.AlarmSummary',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def cases_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    priority = args.get('priority')
    statusnumber = args.get('statusnumber')
    ownernumber = args.get('ownernumber')
    tagnumber = args.get('tagnumber')
    text = args.get('text')
    evidencetype = args.get('evidencetype')
    referenceid = args.get('referenceid')
    externalid = args.get('externalid')
    entitynumber = args.get('entitynumber')
    offset = args.get('offset')
    count = args.get('count')

    response = client.cases_list_request(priority, statusnumber, ownernumber, tagnumber,
                                         text, evidencetype, referenceid, externalid, entitynumber, offset, count)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CasesList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    priority = args.get('priority')

    response = client.case_create_request(name, priority)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseCreate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    name = args.get('name')

    response = client.case_update_request(case_id, name)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_status_change_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    statusnumber = args.get('statusnumber')

    response = client.case_status_change_request(case_id, statusnumber)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseStatusChange',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_evidence_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    type_ = args.get('type')
    status = args.get('status')

    response = client.case_evidence_list_request(case_id, type_, status)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseEvidenceList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_alarm_evidence_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    alarmnumbers = args.get('alarmnumbers')

    response = client.case_alarm_evidence_add_request(case_id, alarmnumbers)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseAlarmEvidenceAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_note_evidence_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    text = args.get('text')

    response = client.case_note_evidence_add_request(case_id, text)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseNoteEvidenceAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_file_evidence_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')

    response = client.case_file_evidence_add_request(case_id)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseFileEvidenceAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_evidence_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_idevidence = args.get('case_idevidence')
    evidence_number = args.get('evidence_number')

    response = client.case_evidence_delete_request(case_idevidence, evidence_number)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseEvidenceDelete',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_file_evidence_download_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    evidence_number = args.get('evidence_number')

    response = client.case_file_evidence_download_request(case_id, evidence_number)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseFileEvidenceDownload',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


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
    numbers = args.get('numbers')

    response = client.case_tags_add_request(case_id, numbers)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseTagsAdd',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_tags_remove_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    numbers = args.get('numbers')

    response = client.case_tags_remove_request(case_id, numbers)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseTagsRemove',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def tags_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    offset = args.get('offset')
    count = args.get('count')

    response = client.tags_list_request(offset, count)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.TagsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_collaborators_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')

    response = client.case_collaborators_list_request(case_id)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseCollaboratorsList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def case_collaborators_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    case_id = args.get('case_id')
    owner = args.get('owner')
    collaborators = args.get('collaborators')

    response = client.case_collaborators_update_request(case_id, owner, collaborators)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.CaseCollaboratorsUpdate',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def entities_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    parententityid = args.get('parententityid')
    offset = args.get('offset')
    count = args.get('count')

    response = client.entities_list_request(parententityid, offset, count)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.EntitiesList',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def hosts_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    name = args.get('name')
    entity = args.get('entity')
    recordstatus = args.get('recordstatus')
    offset = args.get('offset')
    count = args.get('count')

    response = client.hosts_list_request(name, entity, recordstatus, offset, count)
    command_results = CommandResults(
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
    id_ = args.get('id')
    name = args.get('name')
    name = args.get('name')
    risklevel = args.get('risklevel')
    recordstatusname = args.get('recordstatusname')
    hostzone = args.get('hostzone')
    os = args.get('os')
    useeventlogcredentials = args.get('useeventlogcredentials')

    response = client.add_host_request(id_, id_, name, name, risklevel,
                                       recordstatusname, hostzone, os, useeventlogcredentials)
    command_results = CommandResults(
        outputs_prefix='LogrhythmV2.AddHost',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client: Client) -> None:
    # Test functions here
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
