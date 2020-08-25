import demistomock as demisto
from CommonServerPython import *  # noqa: F401


class Client(BaseClient):
    def __init__(self, server_url, verify, proxy, headers, auth):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers, auth=auth)

    def add_ad_hoc_task_request(self, invplaybooktaskdata_addafter, invplaybooktaskdata_automationscript, invplaybooktaskdata_description, invplaybooktaskdata_loop, invplaybooktaskdata_name, invplaybooktaskdata_neighborinvpbtaskid, invplaybooktaskdata_playbookid, invplaybooktaskdata_scriptarguments, invplaybooktaskdata_tags, invplaybooktaskdata_type, investigationId):
        data = assign_params(addAfter=invplaybooktaskdata_addafter, automationScript=invplaybooktaskdata_automationscript, description=invplaybooktaskdata_description, loop=invplaybooktaskdata_loop, name=invplaybooktaskdata_name,
                             neighborInvPBTaskId=invplaybooktaskdata_neighborinvpbtaskid, playbookId=invplaybooktaskdata_playbookid, scriptArguments=invplaybooktaskdata_scriptarguments, tags=invplaybooktaskdata_tags, type=invplaybooktaskdata_type)

        headers = self._headers

        response = self._http_request('post', f'inv-playbook/task/add/{investigationId}', json_data=data, headers=headers)

        return response

    def close_incidents_batch_request(self, updatedatabatch_customfields, updatedatabatch_all, updatedatabatch_closenotes, updatedatabatch_closereason, updatedatabatch_columns, updatedatabatch_data, updatedatabatch_filter, updatedatabatch_force, updatedatabatch_ids, updatedatabatch_line, updatedatabatch_originalincidentid, updatedatabatch_overrideinvestigation):
        data = assign_params(CustomFields=updatedatabatch_customfields, all=updatedatabatch_all, closeNotes=updatedatabatch_closenotes, closeReason=updatedatabatch_closereason, columns=updatedatabatch_columns, data=updatedatabatch_data,
                             filter=updatedatabatch_filter, force=updatedatabatch_force, ids=updatedatabatch_ids, line=updatedatabatch_line, originalIncidentId=updatedatabatch_originalincidentid, overrideInvestigation=updatedatabatch_overrideinvestigation)

        headers = self._headers

        response = self._http_request('post', 'incident/batchClose', json_data=data, headers=headers)

        return response

    def complete_task_request(self, investigationId, fileName, fileComment, taskId, taskInput, version, file):
        data = assign_params(investigationId=investigationId, fileName=fileName, fileComment=fileComment,
                             taskId=taskId, taskInput=taskInput, version=version, file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'inv-playbook/task/complete', json_data=data, headers=headers)

        return response

    def complete_taskv2_request(self, investigationId, taskId, taskComment, taskInput, version, file, fileNames, fileComments):
        data = assign_params(investigationId=investigationId, taskId=taskId, taskComment=taskComment,
                             taskInput=taskInput, version=version, file=file, fileNames=fileNames, fileComments=fileComments)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'v2/inv-playbook/task/complete', json_data=data, headers=headers)

        return response

    def copy_script_request(self, automationscriptfilterwrapper_filter, automationscriptfilterwrapper_savepassword, automationscriptfilterwrapper_script):
        data = assign_params(filter=automationscriptfilterwrapper_filter,
                             savePassword=automationscriptfilterwrapper_savepassword, script=automationscriptfilterwrapper_script)

        headers = self._headers

        response = self._http_request('post', 'automation/copy', json_data=data, headers=headers)

        return response

    def create_docker_image_request(self, newdockerimage_base, newdockerimage_dependencies, newdockerimage_name, newdockerimage_packages):
        data = assign_params(base=newdockerimage_base, dependencies=newdockerimage_dependencies,
                             name=newdockerimage_name, packages=newdockerimage_packages)

        headers = self._headers

        response = self._http_request('post', 'settings/docker-images', json_data=data, headers=headers)

        return response

    def create_feed_indicators_json_request(self, feedindicatorsrequest_bypassexclusionlist, feedindicatorsrequest_classifierid, feedindicatorsrequest_indicators, feedindicatorsrequest_mapperid):
        data = assign_params(bypassExclusionList=feedindicatorsrequest_bypassexclusionlist, classifierId=feedindicatorsrequest_classifierid,
                             indicators=feedindicatorsrequest_indicators, mapperId=feedindicatorsrequest_mapperid)

        headers = self._headers

        response = self._http_request('post', 'indicators/feed/json', json_data=data, headers=headers)

        return response

    def create_incident_request(self, createincidentrequest_shardid, createincidentrequest_account, createincidentrequest_activated, createincidentrequest_activatinginguserid, createincidentrequest_allread, createincidentrequest_allreadwrite, createincidentrequest_autime, createincidentrequest_canvases, createincidentrequest_category, createincidentrequest_closenotes, createincidentrequest_closereason, createincidentrequest_closed, createincidentrequest_closinguserid, createincidentrequest_createinvestigation, createincidentrequest_created, createincidentrequest_dbotcreatedby, createincidentrequest_dbotcurrentdirtyfields, createincidentrequest_dbotdirtyfields, createincidentrequest_dbotmirrordirection, createincidentrequest_dbotmirrorid, createincidentrequest_dbotmirrorinstance, createincidentrequest_dbotmirrorlastsync, createincidentrequest_dbotmirrortags, createincidentrequest_details, createincidentrequest_droppedcount, createincidentrequest_duedate, createincidentrequest_feedbased, createincidentrequest_hasrole, createincidentrequest_id, createincidentrequest_investigationid, createincidentrequest_isplayground, createincidentrequest_labels, createincidentrequest_lastjobruntime, createincidentrequest_lastopen, createincidentrequest_linkedcount, createincidentrequest_linkedincidents, createincidentrequest_modified, createincidentrequest_name, createincidentrequest_notifytime, createincidentrequest_occurred, createincidentrequest_openduration, createincidentrequest_owner, createincidentrequest_parent, createincidentrequest_phase, createincidentrequest_playbookid, createincidentrequest_previousallread, createincidentrequest_previousallreadwrite, createincidentrequest_previousroles, createincidentrequest_primaryterm, createincidentrequest_rawcategory, createincidentrequest_rawclosereason, createincidentrequest_rawjson, createincidentrequest_rawname, createincidentrequest_rawphase, createincidentrequest_rawtype, createincidentrequest_reason, createincidentrequest_reminder, createincidentrequest_roles, createincidentrequest_runstatus, createincidentrequest_sequencenumber, createincidentrequest_severity, createincidentrequest_sla, createincidentrequest_sortvalues, createincidentrequest_sourcebrand, createincidentrequest_sourceinstance, createincidentrequest_status, createincidentrequest_todotaskids, createincidentrequest_type, createincidentrequest_version, createincidentrequest_xsoarhasreadonlyrole, createincidentrequest_xsoarpreviousreadonlyroles, createincidentrequest_xsoarreadonlyroles):
        data = assign_params(ShardID=createincidentrequest_shardid, account=createincidentrequest_account, activated=createincidentrequest_activated, activatingingUserId=createincidentrequest_activatinginguserid, allRead=createincidentrequest_allread, allReadWrite=createincidentrequest_allreadwrite, autime=createincidentrequest_autime, canvases=createincidentrequest_canvases, category=createincidentrequest_category, closeNotes=createincidentrequest_closenotes, closeReason=createincidentrequest_closereason, closed=createincidentrequest_closed, closingUserId=createincidentrequest_closinguserid, createInvestigation=createincidentrequest_createinvestigation, created=createincidentrequest_created, dbotCreatedBy=createincidentrequest_dbotcreatedby, dbotCurrentDirtyFields=createincidentrequest_dbotcurrentdirtyfields, dbotDirtyFields=createincidentrequest_dbotdirtyfields, dbotMirrorDirection=createincidentrequest_dbotmirrordirection, dbotMirrorId=createincidentrequest_dbotmirrorid, dbotMirrorInstance=createincidentrequest_dbotmirrorinstance, dbotMirrorLastSync=createincidentrequest_dbotmirrorlastsync, dbotMirrorTags=createincidentrequest_dbotmirrortags, details=createincidentrequest_details, droppedCount=createincidentrequest_droppedcount, dueDate=createincidentrequest_duedate, feedBased=createincidentrequest_feedbased, hasRole=createincidentrequest_hasrole, id=createincidentrequest_id, investigationId=createincidentrequest_investigationid, isPlayground=createincidentrequest_isplayground, labels=createincidentrequest_labels, lastJobRunTime=createincidentrequest_lastjobruntime, lastOpen=createincidentrequest_lastopen, linkedCount=createincidentrequest_linkedcount,
                             linkedIncidents=createincidentrequest_linkedincidents, modified=createincidentrequest_modified, name=createincidentrequest_name, notifyTime=createincidentrequest_notifytime, occurred=createincidentrequest_occurred, openDuration=createincidentrequest_openduration, owner=createincidentrequest_owner, parent=createincidentrequest_parent, phase=createincidentrequest_phase, playbookId=createincidentrequest_playbookid, previousAllRead=createincidentrequest_previousallread, previousAllReadWrite=createincidentrequest_previousallreadwrite, previousRoles=createincidentrequest_previousroles, primaryTerm=createincidentrequest_primaryterm, rawCategory=createincidentrequest_rawcategory, rawCloseReason=createincidentrequest_rawclosereason, rawJSON=createincidentrequest_rawjson, rawName=createincidentrequest_rawname, rawPhase=createincidentrequest_rawphase, rawType=createincidentrequest_rawtype, reason=createincidentrequest_reason, reminder=createincidentrequest_reminder, roles=createincidentrequest_roles, runStatus=createincidentrequest_runstatus, sequenceNumber=createincidentrequest_sequencenumber, severity=createincidentrequest_severity, sla=createincidentrequest_sla, sortValues=createincidentrequest_sortvalues, sourceBrand=createincidentrequest_sourcebrand, sourceInstance=createincidentrequest_sourceinstance, status=createincidentrequest_status, todoTaskIds=createincidentrequest_todotaskids, type=createincidentrequest_type, version=createincidentrequest_version, xsoarHasReadOnlyRole=createincidentrequest_xsoarhasreadonlyrole, xsoarPreviousReadOnlyRoles=createincidentrequest_xsoarpreviousreadonlyroles, xsoarReadOnlyRoles=createincidentrequest_xsoarreadonlyroles)

        headers = self._headers

        response = self._http_request('post', 'incident', json_data=data, headers=headers)

        return response

    def create_incident_json_request(self):

        headers = self._headers

        response = self._http_request('post', 'incident/json', headers=headers)

        return response

    def create_incidents_batch_request(self, updatedatabatch_customfields, updatedatabatch_all, updatedatabatch_closenotes, updatedatabatch_closereason, updatedatabatch_columns, updatedatabatch_data, updatedatabatch_filter, updatedatabatch_force, updatedatabatch_ids, updatedatabatch_line, updatedatabatch_originalincidentid, updatedatabatch_overrideinvestigation):
        data = assign_params(CustomFields=updatedatabatch_customfields, all=updatedatabatch_all, closeNotes=updatedatabatch_closenotes, closeReason=updatedatabatch_closereason, columns=updatedatabatch_columns, data=updatedatabatch_data,
                             filter=updatedatabatch_filter, force=updatedatabatch_force, ids=updatedatabatch_ids, line=updatedatabatch_line, originalIncidentId=updatedatabatch_originalincidentid, overrideInvestigation=updatedatabatch_overrideinvestigation)

        headers = self._headers

        response = self._http_request('post', 'incident/batch', json_data=data, headers=headers)

        return response

    def create_or_update_incident_type_request(self, incidenttype_autorun, incidenttype_closurescript, incidenttype_color, incidenttype_commitmessage, incidenttype_days, incidenttype_daysr, incidenttype_default, incidenttype_disabled, incidenttype_fromserverversion, incidenttype_hours, incidenttype_hoursr, incidenttype_id, incidenttype_itemversion, incidenttype_layout, incidenttype_locked, incidenttype_modified, incidenttype_name, incidenttype_packid, incidenttype_packpropagationlabels, incidenttype_playbookid, incidenttype_preprocessingscript, incidenttype_prevname, incidenttype_primaryterm, incidenttype_propagationlabels, incidenttype_readonly, incidenttype_reputationcalc, incidenttype_sequencenumber, incidenttype_shouldcommit, incidenttype_sla, incidenttype_slareminder, incidenttype_sortvalues, incidenttype_system, incidenttype_toserverversion, incidenttype_vcshouldignore, incidenttype_vcshouldkeepitemlegacyprodmachine, incidenttype_version, incidenttype_weeks, incidenttype_weeksr):
        data = assign_params(autorun=incidenttype_autorun, closureScript=incidenttype_closurescript, color=incidenttype_color, commitMessage=incidenttype_commitmessage, days=incidenttype_days, daysR=incidenttype_daysr, default=incidenttype_default, disabled=incidenttype_disabled, fromServerVersion=incidenttype_fromserverversion, hours=incidenttype_hours, hoursR=incidenttype_hoursr, id=incidenttype_id, itemVersion=incidenttype_itemversion, layout=incidenttype_layout, locked=incidenttype_locked, modified=incidenttype_modified, name=incidenttype_name, packID=incidenttype_packid, packPropagationLabels=incidenttype_packpropagationlabels, playbookId=incidenttype_playbookid,
                             preProcessingScript=incidenttype_preprocessingscript, prevName=incidenttype_prevname, primaryTerm=incidenttype_primaryterm, propagationLabels=incidenttype_propagationlabels, readonly=incidenttype_readonly, reputationCalc=incidenttype_reputationcalc, sequenceNumber=incidenttype_sequencenumber, shouldCommit=incidenttype_shouldcommit, sla=incidenttype_sla, slaReminder=incidenttype_slareminder, sortValues=incidenttype_sortvalues, system=incidenttype_system, toServerVersion=incidenttype_toserverversion, vcShouldIgnore=incidenttype_vcshouldignore, vcShouldKeepItemLegacyProdMachine=incidenttype_vcshouldkeepitemlegacyprodmachine, version=incidenttype_version, weeks=incidenttype_weeks, weeksR=incidenttype_weeksr)

        headers = self._headers

        response = self._http_request('post', 'incidenttype', json_data=data, headers=headers)

        return response

    def create_or_update_whitelisted_request(self, whitelistedindicator_id, whitelistedindicator_locked, whitelistedindicator_modified, whitelistedindicator_primaryterm, whitelistedindicator_reason, whitelistedindicator_reputations, whitelistedindicator_sequencenumber, whitelistedindicator_sortvalues, whitelistedindicator_type, whitelistedindicator_user, whitelistedindicator_value, whitelistedindicator_version, whitelistedindicator_whitelisttime):
        data = assign_params(id=whitelistedindicator_id, locked=whitelistedindicator_locked, modified=whitelistedindicator_modified, primaryTerm=whitelistedindicator_primaryterm, reason=whitelistedindicator_reason, reputations=whitelistedindicator_reputations,
                             sequenceNumber=whitelistedindicator_sequencenumber, sortValues=whitelistedindicator_sortvalues, type=whitelistedindicator_type, user=whitelistedindicator_user, value=whitelistedindicator_value, version=whitelistedindicator_version, whitelistTime=whitelistedindicator_whitelisttime)

        headers = self._headers

        response = self._http_request('post', 'indicators/whitelist/update', json_data=data, headers=headers)

        return response

    def delete_ad_hoc_task_request(self, investigationId, invPBTaskId):

        headers = self._headers

        response = self._http_request('post', f'inv-playbook/task/delete/{investigationId}/{invPBTaskId}', headers=headers)

        return response

    def delete_automation_script_request(self, automationscriptfilterwrapper_filter, automationscriptfilterwrapper_savepassword, automationscriptfilterwrapper_script):
        data = assign_params(filter=automationscriptfilterwrapper_filter,
                             savePassword=automationscriptfilterwrapper_savepassword, script=automationscriptfilterwrapper_script)

        headers = self._headers

        response = self._http_request('post', 'automation/delete', json_data=data, headers=headers)

        return response

    def delete_evidence_op_request(self, deleteevidence_evidenceid):
        data = assign_params(evidenceID=deleteevidence_evidenceid)

        headers = self._headers

        response = self._http_request('post', 'evidence/delete', json_data=data, headers=headers)

        return response

    def delete_incidents_batch_request(self, updatedatabatch_customfields, updatedatabatch_all, updatedatabatch_closenotes, updatedatabatch_closereason, updatedatabatch_columns, updatedatabatch_data, updatedatabatch_filter, updatedatabatch_force, updatedatabatch_ids, updatedatabatch_line, updatedatabatch_originalincidentid, updatedatabatch_overrideinvestigation):
        data = assign_params(CustomFields=updatedatabatch_customfields, all=updatedatabatch_all, closeNotes=updatedatabatch_closenotes, closeReason=updatedatabatch_closereason, columns=updatedatabatch_columns, data=updatedatabatch_data,
                             filter=updatedatabatch_filter, force=updatedatabatch_force, ids=updatedatabatch_ids, line=updatedatabatch_line, originalIncidentId=updatedatabatch_originalincidentid, overrideInvestigation=updatedatabatch_overrideinvestigation)

        headers = self._headers

        response = self._http_request('post', 'incident/batchDelete', json_data=data, headers=headers)

        return response

    def delete_indicators_batch_request(self, genericindicatorupdatebatch_all, genericindicatorupdatebatch_columns, genericindicatorupdatebatch_donotwhitelist, genericindicatorupdatebatch_filter, genericindicatorupdatebatch_ids, genericindicatorupdatebatch_reason, genericindicatorupdatebatch_reputations):
        data = assign_params(all=genericindicatorupdatebatch_all, columns=genericindicatorupdatebatch_columns, doNotWhitelist=genericindicatorupdatebatch_donotwhitelist,
                             filter=genericindicatorupdatebatch_filter, ids=genericindicatorupdatebatch_ids, reason=genericindicatorupdatebatch_reason, reputations=genericindicatorupdatebatch_reputations)

        headers = self._headers

        response = self._http_request('post', 'indicators/batchDelete', json_data=data, headers=headers)

        return response

    def delete_widget_request(self, id_):

        headers = self._headers

        response = self._http_request('delete', f'wid_gets/{id_}', headers=headers)

        return response

    def download_file_request(self, entryid):

        headers = self._headers
        headers['Accept'] = 'application/octet-stream'

        response = self._http_request('get', f'entry/download/{entryid}', headers=headers)

        return response

    def download_latest_report_request(self, id_):

        headers = self._headers
        headers['Accept'] = 'application/octet-stream'

        response = self._http_request('get', f'report/{id_}/latest', headers=headers)

        return response

    def edit_ad_hoc_task_request(self, invplaybooktaskdata_addafter, invplaybooktaskdata_automationscript, invplaybooktaskdata_description, invplaybooktaskdata_loop, invplaybooktaskdata_name, invplaybooktaskdata_neighborinvpbtaskid, invplaybooktaskdata_playbookid, invplaybooktaskdata_scriptarguments, invplaybooktaskdata_tags, invplaybooktaskdata_type, investigationId):
        data = assign_params(addAfter=invplaybooktaskdata_addafter, automationScript=invplaybooktaskdata_automationscript, description=invplaybooktaskdata_description, loop=invplaybooktaskdata_loop, name=invplaybooktaskdata_name,
                             neighborInvPBTaskId=invplaybooktaskdata_neighborinvpbtaskid, playbookId=invplaybooktaskdata_playbookid, scriptArguments=invplaybooktaskdata_scriptarguments, tags=invplaybooktaskdata_tags, type=invplaybooktaskdata_type)

        headers = self._headers

        response = self._http_request('post', f'inv-playbook/task/edit/{investigationId}', json_data=data, headers=headers)

        return response

    def entry_export_artifact_request(self, downloadentry_id, downloadentry_investigationid):
        data = assign_params(id=downloadentry_id, investigationId=downloadentry_investigationid)

        headers = self._headers

        response = self._http_request('post', 'entry/exportArtifact', json_data=data, headers=headers)

        return response

    def execute_report_request(self, id_, requestId):

        headers = self._headers

        response = self._http_request('post', f'report/{id_}/{requestId}/execute', headers=headers)

        return response

    def export_incidents_to_csv_batch_request(self, updatedatabatch_customfields, updatedatabatch_all, updatedatabatch_closenotes, updatedatabatch_closereason, updatedatabatch_columns, updatedatabatch_data, updatedatabatch_filter, updatedatabatch_force, updatedatabatch_ids, updatedatabatch_line, updatedatabatch_originalincidentid, updatedatabatch_overrideinvestigation):
        data = assign_params(CustomFields=updatedatabatch_customfields, all=updatedatabatch_all, closeNotes=updatedatabatch_closenotes, closeReason=updatedatabatch_closereason, columns=updatedatabatch_columns, data=updatedatabatch_data,
                             filter=updatedatabatch_filter, force=updatedatabatch_force, ids=updatedatabatch_ids, line=updatedatabatch_line, originalIncidentId=updatedatabatch_originalincidentid, overrideInvestigation=updatedatabatch_overrideinvestigation)

        headers = self._headers

        response = self._http_request('post', 'incident/batch/exportToCsv', json_data=data, headers=headers)

        return response

    def export_indicators_to_csv_batch_request(self, genericindicatorupdatebatch_all, genericindicatorupdatebatch_columns, genericindicatorupdatebatch_donotwhitelist, genericindicatorupdatebatch_filter, genericindicatorupdatebatch_ids, genericindicatorupdatebatch_reason, genericindicatorupdatebatch_reputations):
        data = assign_params(all=genericindicatorupdatebatch_all, columns=genericindicatorupdatebatch_columns, doNotWhitelist=genericindicatorupdatebatch_donotwhitelist,
                             filter=genericindicatorupdatebatch_filter, ids=genericindicatorupdatebatch_ids, reason=genericindicatorupdatebatch_reason, reputations=genericindicatorupdatebatch_reputations)

        headers = self._headers

        response = self._http_request('post', 'indicators/batch/exportToCsv', json_data=data, headers=headers)

        return response

    def export_indicators_to_stix_batch_request(self, genericindicatorupdatebatch_all, genericindicatorupdatebatch_columns, genericindicatorupdatebatch_donotwhitelist, genericindicatorupdatebatch_filter, genericindicatorupdatebatch_ids, genericindicatorupdatebatch_reason, genericindicatorupdatebatch_reputations):
        data = assign_params(all=genericindicatorupdatebatch_all, columns=genericindicatorupdatebatch_columns, doNotWhitelist=genericindicatorupdatebatch_donotwhitelist,
                             filter=genericindicatorupdatebatch_filter, ids=genericindicatorupdatebatch_ids, reason=genericindicatorupdatebatch_reason, reputations=genericindicatorupdatebatch_reputations)

        headers = self._headers

        response = self._http_request('post', 'indicators/batch/export/stix', json_data=data, headers=headers)

        return response

    def get_all_reports_request(self):

        headers = self._headers

        response = self._http_request('get', 'reports', headers=headers)

        return response

    def get_all_widgets_request(self):

        headers = self._headers

        response = self._http_request('get', 'widgets', headers=headers)

        return response

    def get_audits_request(self, genericstringdatefilter_cache, genericstringdatefilter_fromdate, genericstringdatefilter_fromdatelicense, genericstringdatefilter_ignoreworkers, genericstringdatefilter_page, genericstringdatefilter_period, genericstringdatefilter_query, genericstringdatefilter_searchafter, genericstringdatefilter_searchbefore, genericstringdatefilter_size, genericstringdatefilter_sort, genericstringdatefilter_timeframe, genericstringdatefilter_todate):
        data = assign_params(Cache=genericstringdatefilter_cache, fromDate=genericstringdatefilter_fromdate, fromDateLicense=genericstringdatefilter_fromdatelicense, ignoreWorkers=genericstringdatefilter_ignoreworkers, page=genericstringdatefilter_page, period=genericstringdatefilter_period,
                             query=genericstringdatefilter_query, searchAfter=genericstringdatefilter_searchafter, searchBefore=genericstringdatefilter_searchbefore, size=genericstringdatefilter_size, sort=genericstringdatefilter_sort, timeFrame=genericstringdatefilter_timeframe, toDate=genericstringdatefilter_todate)

        headers = self._headers

        response = self._http_request('post', 'settings/audits', json_data=data, headers=headers)

        return response

    def get_automation_scripts_request(self, automationscriptfilter_cache, automationscriptfilter_ignoreworkers, automationscriptfilter_page, automationscriptfilter_query, automationscriptfilter_searchafter, automationscriptfilter_searchbefore, automationscriptfilter_size, automationscriptfilter_sort, automationscriptfilter_stripcontext):
        data = assign_params(Cache=automationscriptfilter_cache, ignoreWorkers=automationscriptfilter_ignoreworkers, page=automationscriptfilter_page, query=automationscriptfilter_query,
                             searchAfter=automationscriptfilter_searchafter, searchBefore=automationscriptfilter_searchbefore, size=automationscriptfilter_size, sort=automationscriptfilter_sort, stripContext=automationscriptfilter_stripcontext)

        headers = self._headers

        response = self._http_request('post', 'automation/search', json_data=data, headers=headers)

        return response

    def get_containers_request(self):

        headers = self._headers

        response = self._http_request('get', 'health/containers', headers=headers)

        return response

    def get_docker_images_request(self):

        headers = self._headers

        response = self._http_request('get', 'settings/docker-images', headers=headers)

        return response

    def get_entry_artifact_request(self, id_):

        headers = self._headers
        headers['Accept'] = 'application/octet-stream'

        response = self._http_request('get', f'entry/artifact/{id_}', headers=headers)

        return response

    def get_incident_as_csv_request(self, id_):

        headers = self._headers
        headers['Accept'] = 'application/octet-stream'

        response = self._http_request('get', f'incid_ent/csv/{id_}', headers=headers)

        return response

    def get_incidents_fields_by_incident_type_request(self, type_):

        headers = self._headers

        response = self._http_request('get', f'incidentfields/associatedTypes/{type_}', headers=headers)

        return response

    def get_indicators_as_csv_request(self, id_):

        headers = self._headers
        headers['Accept'] = 'application/octet-stream'

        response = self._http_request('get', f'indicators/csv/{id_}', headers=headers)

        return response

    def get_indicators_asstix_request(self, id_):

        headers = self._headers
        headers['Accept'] = 'application/octet-stream'

        response = self._http_request('get', f'indicators/stix/v2/{id_}', headers=headers)

        return response

    def get_report_byid_request(self, id_):

        headers = self._headers

        response = self._http_request('get', f'reports/{id_}', headers=headers)

        return response

    def get_stats_for_dashboard_request(self):

        headers = self._headers

        response = self._http_request('post', 'statistics/dashboards/query', headers=headers)

        return response

    def get_stats_for_widget_request(self):

        headers = self._headers

        response = self._http_request('post', 'statistics/widgets/query', headers=headers)

        return response

    def get_widget_request(self, id_):

        headers = self._headers

        response = self._http_request('get', f'wid_gets/{id_}', headers=headers)

        return response

    def health_handler_request(self):

        headers = self._headers

        response = self._http_request('get', 'health', headers=headers)

        return response

    def import_classifier_request(self, file):
        data = assign_params(file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'classifier/import', json_data=data, headers=headers)

        return response

    def import_dashboard_request(self, file):
        data = assign_params(file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'dashboards/import', json_data=data, headers=headers)

        return response

    def import_incident_fields_request(self, file):
        data = assign_params(file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'incidentfields/import', json_data=data, headers=headers)

        return response

    def import_incident_types_handler_request(self, file):
        data = assign_params(file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'incidenttypes/import', json_data=data, headers=headers)

        return response

    def import_script_request(self, file):
        data = assign_params(file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'automation/import', json_data=data, headers=headers)

        return response

    def import_widget_request(self, file):
        data = assign_params(file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'widgets/import', json_data=data, headers=headers)

        return response

    def incident_file_upload_request(self, id_, fileName, fileComment, field, showMediaFile, last, file):
        data = assign_params(fileName=fileName, fileComment=fileComment, field=field,
                             showMediaFile=showMediaFile, last=last, file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', f'incid_ent/upload/{id_}', json_data=data, headers=headers)

        return response

    def indicator_whitelist_request(self):

        headers = self._headers

        response = self._http_request('post', 'indicator/whitelist', headers=headers)

        return response

    def indicators_create_request(self, indicatorcontext_entryid, indicatorcontext_indicator, indicatorcontext_investigationid, indicatorcontext_seennow):
        data = assign_params(entryId=indicatorcontext_entryid, indicator=indicatorcontext_indicator,
                             investigationId=indicatorcontext_investigationid, seenNow=indicatorcontext_seennow)

        headers = self._headers

        response = self._http_request('post', 'indicator/create', json_data=data, headers=headers)

        return response

    def indicators_create_batch_request(self, fileName, file):
        data = assign_params(fileName=fileName, file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'indicators/upload', json_data=data, headers=headers)

        return response

    def indicators_edit_request(self, iocobject_customfields, iocobject_account, iocobject_aggregatedreliability, iocobject_calculatedtime, iocobject_comment, iocobject_comments, iocobject_deletedfeedfetchtime, iocobject_expiration, iocobject_expirationsource, iocobject_expirationstatus, iocobject_firstseen, iocobject_firstseenentryid, iocobject_id, iocobject_indicator_type, iocobject_insightcache, iocobject_investigationids, iocobject_isshared, iocobject_lastreputationrun, iocobject_lastseen, iocobject_lastseenentryid, iocobject_manualexpirationtime, iocobject_manualscore, iocobject_manualsettime, iocobject_manuallyeditedfields, iocobject_modified, iocobject_modifiedtime, iocobject_moduletofeedmap, iocobject_primaryterm, iocobject_relatedinccount, iocobject_score, iocobject_sequencenumber, iocobject_setby, iocobject_sortvalues, iocobject_source, iocobject_sourcebrands, iocobject_sourceinstances, iocobject_timestamp, iocobject_value, iocobject_version):
        data = assign_params(CustomFields=iocobject_customfields, account=iocobject_account, aggregatedReliability=iocobject_aggregatedreliability, calculatedTime=iocobject_calculatedtime, comment=iocobject_comment, comments=iocobject_comments, deletedFeedFetchTime=iocobject_deletedfeedfetchtime, expiration=iocobject_expiration, expirationSource=iocobject_expirationsource, expirationStatus=iocobject_expirationstatus, firstSeen=iocobject_firstseen, firstSeenEntryID=iocobject_firstseenentryid, id=iocobject_id, indicator_type=iocobject_indicator_type, insightCache=iocobject_insightcache, investigationIDs=iocobject_investigationids, isShared=iocobject_isshared, lastReputationRun=iocobject_lastreputationrun, lastSeen=iocobject_lastseen,
                             lastSeenEntryID=iocobject_lastseenentryid, manualExpirationTime=iocobject_manualexpirationtime, manualScore=iocobject_manualscore, manualSetTime=iocobject_manualsettime, manuallyEditedFields=iocobject_manuallyeditedfields, modified=iocobject_modified, modifiedTime=iocobject_modifiedtime, moduleToFeedMap=iocobject_moduletofeedmap, primaryTerm=iocobject_primaryterm, relatedIncCount=iocobject_relatedinccount, score=iocobject_score, sequenceNumber=iocobject_sequencenumber, setBy=iocobject_setby, sortValues=iocobject_sortvalues, source=iocobject_source, sourceBrands=iocobject_sourcebrands, sourceInstances=iocobject_sourceinstances, timestamp=iocobject_timestamp, value=iocobject_value, version=iocobject_version)

        headers = self._headers

        response = self._http_request('post', 'indicator/edit', json_data=data, headers=headers)

        return response

    def indicators_search_request(self, indicatorfilter_cache, indicatorfilter_earlytimeinpage, indicatorfilter_firstseen, indicatorfilter_fromdate, indicatorfilter_fromdatelicense, indicatorfilter_ignoreworkers, indicatorfilter_lastseen, indicatorfilter_latertimeinpage, indicatorfilter_page, indicatorfilter_period, indicatorfilter_prevpage, indicatorfilter_query, indicatorfilter_searchafter, indicatorfilter_searchbefore, indicatorfilter_size, indicatorfilter_sort, indicatorfilter_timeframe, indicatorfilter_todate):
        data = assign_params(Cache=indicatorfilter_cache, earlyTimeInPage=indicatorfilter_earlytimeinpage, firstSeen=indicatorfilter_firstseen, fromDate=indicatorfilter_fromdate, fromDateLicense=indicatorfilter_fromdatelicense, ignoreWorkers=indicatorfilter_ignoreworkers, lastSeen=indicatorfilter_lastseen, laterTimeInPage=indicatorfilter_latertimeinpage,
                             page=indicatorfilter_page, period=indicatorfilter_period, prevPage=indicatorfilter_prevpage, query=indicatorfilter_query, searchAfter=indicatorfilter_searchafter, searchBefore=indicatorfilter_searchbefore, size=indicatorfilter_size, sort=indicatorfilter_sort, timeFrame=indicatorfilter_timeframe, toDate=indicatorfilter_todate)

        headers = self._headers

        response = self._http_request('post', 'indicators/search', json_data=data, headers=headers)

        return response

    def indicators_timeline_delete_request(self, indicatorfilter_cache, indicatorfilter_earlytimeinpage, indicatorfilter_firstseen, indicatorfilter_fromdate, indicatorfilter_fromdatelicense, indicatorfilter_ignoreworkers, indicatorfilter_lastseen, indicatorfilter_latertimeinpage, indicatorfilter_page, indicatorfilter_period, indicatorfilter_prevpage, indicatorfilter_query, indicatorfilter_searchafter, indicatorfilter_searchbefore, indicatorfilter_size, indicatorfilter_sort, indicatorfilter_timeframe, indicatorfilter_todate):
        data = assign_params(Cache=indicatorfilter_cache, earlyTimeInPage=indicatorfilter_earlytimeinpage, firstSeen=indicatorfilter_firstseen, fromDate=indicatorfilter_fromdate, fromDateLicense=indicatorfilter_fromdatelicense, ignoreWorkers=indicatorfilter_ignoreworkers, lastSeen=indicatorfilter_lastseen, laterTimeInPage=indicatorfilter_latertimeinpage,
                             page=indicatorfilter_page, period=indicatorfilter_period, prevPage=indicatorfilter_prevpage, query=indicatorfilter_query, searchAfter=indicatorfilter_searchafter, searchBefore=indicatorfilter_searchbefore, size=indicatorfilter_size, sort=indicatorfilter_sort, timeFrame=indicatorfilter_timeframe, toDate=indicatorfilter_todate)

        headers = self._headers

        response = self._http_request('post', 'indicators/timeline/delete', json_data=data, headers=headers)

        return response

    def integration_upload_request(self, file):
        data = assign_params(file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'settings/integration-conf/upload', json_data=data, headers=headers)

        return response

    def investigation_add_entries_sync_request(self, updateentry_args, updateentry_data, updateentry_id, updateentry_investigationid, updateentry_markdown, updateentry_version):
        data = assign_params(args=updateentry_args, data=updateentry_data, id=updateentry_id,
                             investigationId=updateentry_investigationid, markdown=updateentry_markdown, version=updateentry_version)

        headers = self._headers

        response = self._http_request('post', 'entry/execute/sync', json_data=data, headers=headers)

        return response

    def investigation_add_entry_handler_request(self, updateentry_args, updateentry_data, updateentry_id, updateentry_investigationid, updateentry_markdown, updateentry_version):
        data = assign_params(args=updateentry_args, data=updateentry_data, id=updateentry_id,
                             investigationId=updateentry_investigationid, markdown=updateentry_markdown, version=updateentry_version)

        headers = self._headers

        response = self._http_request('post', 'entry', json_data=data, headers=headers)

        return response

    def investigation_add_formatted_entry_handler_request(self, uploadedentry_contents, uploadedentry_format, uploadedentry_investigationid):
        data = assign_params(contents=uploadedentry_contents, format=uploadedentry_format,
                             investigationId=uploadedentry_investigationid)

        headers = self._headers

        response = self._http_request('post', 'entry/formatted', json_data=data, headers=headers)

        return response

    def logout_myself_handler_request(self):

        headers = self._headers

        response = self._http_request('post', 'logout/myself', headers=headers)

        return response

    def logout_myself_other_sessions_handler_request(self):

        headers = self._headers

        response = self._http_request('post', 'logout/myself/other', headers=headers)

        return response

    def logout_user_sessions_handler_request(self):

        headers = self._headers

        response = self._http_request('post', f'logout/user/{username}', headers=headers)

        return response

    def logouta_everyone_handler_request(self):

        headers = self._headers

        response = self._http_request('post', 'logout/everyone', headers=headers)

        return response

    def override_playbook_yaml_request(self, file):
        data = assign_params(file=file)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'playbook/save/yaml', json_data=data, headers=headers)

        return response

    def revoke_userapi_key_request(self, username):

        headers = self._headers
        headers['Accept'] = 'application/octet-stream'

        response = self._http_request('post', f'apikeys/revoke/user/{username}', headers=headers)

        return response

    def save_evidence_request(self, evidence_shardid, evidence_allread, evidence_allreadwrite, evidence_dbotcreatedby, evidence_description, evidence_entryid, evidence_fetched, evidence_hasrole, evidence_id, evidence_incidentid, evidence_markedby, evidence_markeddate, evidence_modified, evidence_occurred, evidence_previousallread, evidence_previousallreadwrite, evidence_previousroles, evidence_primaryterm, evidence_roles, evidence_sequencenumber, evidence_sortvalues, evidence_tags, evidence_tagsraw, evidence_taskid, evidence_version, evidence_xsoarhasreadonlyrole, evidence_xsoarpreviousreadonlyroles, evidence_xsoarreadonlyroles):
        data = assign_params(ShardID=evidence_shardid, allRead=evidence_allread, allReadWrite=evidence_allreadwrite, dbotCreatedBy=evidence_dbotcreatedby, description=evidence_description, entryId=evidence_entryid, fetched=evidence_fetched, hasRole=evidence_hasrole, id=evidence_id, incidentId=evidence_incidentid, markedBy=evidence_markedby, markedDate=evidence_markeddate, modified=evidence_modified, occurred=evidence_occurred, previousAllRead=evidence_previousallread,
                             previousAllReadWrite=evidence_previousallreadwrite, previousRoles=evidence_previousroles, primaryTerm=evidence_primaryterm, roles=evidence_roles, sequenceNumber=evidence_sequencenumber, sortValues=evidence_sortvalues, tags=evidence_tags, tagsRaw=evidence_tagsraw, taskId=evidence_taskid, version=evidence_version, xsoarHasReadOnlyRole=evidence_xsoarhasreadonlyrole, xsoarPreviousReadOnlyRoles=evidence_xsoarpreviousreadonlyroles, xsoarReadOnlyRoles=evidence_xsoarreadonlyroles)

        headers = self._headers

        response = self._http_request('post', 'evidence', json_data=data, headers=headers)

        return response

    def save_or_update_script_request(self, automationscriptfilterwrapper_filter, automationscriptfilterwrapper_savepassword, automationscriptfilterwrapper_script):
        data = assign_params(filter=automationscriptfilterwrapper_filter,
                             savePassword=automationscriptfilterwrapper_savepassword, script=automationscriptfilterwrapper_script)

        headers = self._headers

        response = self._http_request('post', 'automation', json_data=data, headers=headers)

        return response

    def save_widget_request(self, widget_category, widget_commitmessage, widget_datatype, widget_daterange, widget_description, widget_fromserverversion, widget_id, widget_ispredefined, widget_itemversion, widget_locked, widget_modified, widget_name, widget_packid, widget_packpropagationlabels, widget_params, widget_prevname, widget_primaryterm, widget_propagationlabels, widget_query, widget_sequencenumber, widget_shouldcommit, widget_size, widget_sort, widget_sortvalues, widget_toserverversion, widget_vcshouldignore, widget_vcshouldkeepitemlegacyprodmachine, widget_version, widget_widgettype):
        data = assign_params(category=widget_category, commitMessage=widget_commitmessage, dataType=widget_datatype, dateRange=widget_daterange, description=widget_description, fromServerVersion=widget_fromserverversion, id=widget_id, isPredefined=widget_ispredefined, itemVersion=widget_itemversion, locked=widget_locked, modified=widget_modified, name=widget_name, packID=widget_packid, packPropagationLabels=widget_packpropagationlabels, params=widget_params,
                             prevName=widget_prevname, primaryTerm=widget_primaryterm, propagationLabels=widget_propagationlabels, query=widget_query, sequenceNumber=widget_sequencenumber, shouldCommit=widget_shouldcommit, size=widget_size, sort=widget_sort, sortValues=widget_sortvalues, toServerVersion=widget_toserverversion, vcShouldIgnore=widget_vcshouldignore, vcShouldKeepItemLegacyProdMachine=widget_vcshouldkeepitemlegacyprodmachine, version=widget_version, widgetType=widget_widgettype)

        headers = self._headers

        response = self._http_request('post', 'widgets', json_data=data, headers=headers)

        return response

    def search_evidence_request(self, evidencesfilterwrapper_filter, evidencesfilterwrapper_incidentid):
        data = assign_params(filter=evidencesfilterwrapper_filter, incidentID=evidencesfilterwrapper_incidentid)

        headers = self._headers

        response = self._http_request('post', 'evidence/search', json_data=data, headers=headers)

        return response

    def search_incidents_request(self, searchincidentsdata_filter, searchincidentsdata_userfilter):
        data = assign_params(filter=searchincidentsdata_filter, userFilter=searchincidentsdata_userfilter)

        headers = self._headers

        response = self._http_request('post', 'incidents/search', json_data=data, headers=headers)

        return response

    def search_investigations_request(self, investigationfilter_cache, investigationfilter_andop, investigationfilter_category, investigationfilter_fromclosedate, investigationfilter_fromdate, investigationfilter_fromdatelicense, investigationfilter_id, investigationfilter_idsonly, investigationfilter_ignoreworkers, investigationfilter_includechildinv, investigationfilter_name, investigationfilter_notcategory, investigationfilter_notids, investigationfilter_page, investigationfilter_period, investigationfilter_reason, investigationfilter_searchafter, investigationfilter_searchbefore, investigationfilter_size, investigationfilter_sort, investigationfilter_status, investigationfilter_timeframe, investigationfilter_toclosedate, investigationfilter_todate, investigationfilter_type, investigationfilter_user):
        data = assign_params(Cache=investigationfilter_cache, andOp=investigationfilter_andop, category=investigationfilter_category, fromCloseDate=investigationfilter_fromclosedate, fromDate=investigationfilter_fromdate, fromDateLicense=investigationfilter_fromdatelicense, id=investigationfilter_id, idsOnly=investigationfilter_idsonly, ignoreWorkers=investigationfilter_ignoreworkers, includeChildInv=investigationfilter_includechildinv, name=investigationfilter_name, notCategory=investigationfilter_notcategory,
                             notIDs=investigationfilter_notids, page=investigationfilter_page, period=investigationfilter_period, reason=investigationfilter_reason, searchAfter=investigationfilter_searchafter, searchBefore=investigationfilter_searchbefore, size=investigationfilter_size, sort=investigationfilter_sort, status=investigationfilter_status, timeFrame=investigationfilter_timeframe, toCloseDate=investigationfilter_toclosedate, toDate=investigationfilter_todate, type=investigationfilter_type, user=investigationfilter_user)

        headers = self._headers

        response = self._http_request('post', 'investigations/search', json_data=data, headers=headers)

        return response

    def simple_complete_task_request(self, invtaskinfo_args, invtaskinfo_comment, invtaskinfo_conditions, invtaskinfo_intaskid, invtaskinfo_input, invtaskinfo_invid, invtaskinfo_loopargs, invtaskinfo_loopcondition, invtaskinfo_version):
        data = assign_params(args=invtaskinfo_args, comment=invtaskinfo_comment, conditions=invtaskinfo_conditions, inTaskID=invtaskinfo_intaskid,
                             input=invtaskinfo_input, invId=invtaskinfo_invid, loopArgs=invtaskinfo_loopargs, loopCondition=invtaskinfo_loopcondition, version=invtaskinfo_version)

        headers = self._headers

        response = self._http_request('post', 'inv-playbook/task/complete/simple', json_data=data, headers=headers)

        return response

    def submit_task_form_request(self, investigationId, taskId, answers, file, fileNames, fileComments):
        data = assign_params(investigationId=investigationId, taskId=taskId, answers=answers,
                             file=file, fileNames=fileNames, fileComments=fileComments)

        headers = self._headers
        headers['Content-Type'] = 'multipart/form-data'

        response = self._http_request('post', 'v2/inv-playbook/task/form/submit', json_data=data, headers=headers)

        return response

    def task_add_comment_request(self, invtaskinfo_args, invtaskinfo_comment, invtaskinfo_conditions, invtaskinfo_intaskid, invtaskinfo_input, invtaskinfo_invid, invtaskinfo_loopargs, invtaskinfo_loopcondition, invtaskinfo_version):
        data = assign_params(args=invtaskinfo_args, comment=invtaskinfo_comment, conditions=invtaskinfo_conditions, inTaskID=invtaskinfo_intaskid,
                             input=invtaskinfo_input, invId=invtaskinfo_invid, loopArgs=invtaskinfo_loopargs, loopCondition=invtaskinfo_loopcondition, version=invtaskinfo_version)

        headers = self._headers

        response = self._http_request('post', 'inv-playbook/task/note/add', json_data=data, headers=headers)

        return response

    def task_assign_request(self, invplaybookassignee_assignee, invplaybookassignee_intaskid, invplaybookassignee_invid, invplaybookassignee_version):
        data = assign_params(assignee=invplaybookassignee_assignee, inTaskID=invplaybookassignee_intaskid,
                             invId=invplaybookassignee_invid, version=invplaybookassignee_version)

        headers = self._headers

        response = self._http_request('post', 'inv-playbook/task/assign', json_data=data, headers=headers)

        return response

    def task_set_due_request(self, invplaybookdue_date, invplaybookdue_intaskid, invplaybookdue_invid, invplaybookdue_version):
        data = assign_params(date=invplaybookdue_date, inTaskID=invplaybookdue_intaskid,
                             invId=invplaybookdue_invid, version=invplaybookdue_version)

        headers = self._headers

        response = self._http_request('post', 'inv-playbook/task/due', json_data=data, headers=headers)

        return response

    def task_un_complete_request(self, invtaskinfo_args, invtaskinfo_comment, invtaskinfo_conditions, invtaskinfo_intaskid, invtaskinfo_input, invtaskinfo_invid, invtaskinfo_loopargs, invtaskinfo_loopcondition, invtaskinfo_version):
        data = assign_params(args=invtaskinfo_args, comment=invtaskinfo_comment, conditions=invtaskinfo_conditions, inTaskID=invtaskinfo_intaskid,
                             input=invtaskinfo_input, invId=invtaskinfo_invid, loopArgs=invtaskinfo_loopargs, loopCondition=invtaskinfo_loopcondition, version=invtaskinfo_version)

        headers = self._headers

        response = self._http_request('post', 'inv-playbook/task/uncomplete', json_data=data, headers=headers)

        return response

    def update_entry_note_request(self, updateentry_args, updateentry_data, updateentry_id, updateentry_investigationid, updateentry_markdown, updateentry_version):
        data = assign_params(args=updateentry_args, data=updateentry_data, id=updateentry_id,
                             investigationId=updateentry_investigationid, markdown=updateentry_markdown, version=updateentry_version)

        headers = self._headers

        response = self._http_request('post', 'entry/note', json_data=data, headers=headers)

        return response

    def update_entry_tags_op_request(self, updateentrytags_id, updateentrytags_investigationid, updateentrytags_tags, updateentrytags_version):
        data = assign_params(id=updateentrytags_id, investigationId=updateentrytags_investigationid,
                             tags=updateentrytags_tags, version=updateentrytags_version)

        headers = self._headers

        response = self._http_request('post', 'entry/tags', json_data=data, headers=headers)

        return response

    def workers_status_handler_request(self):

        headers = self._headers

        response = self._http_request('get', 'workers/status', headers=headers)

        return response


def add_ad_hoc_task_command(client, args):
    invplaybooktaskdata_addafter = argToBoolean(args.get('invplaybooktaskdata_addafter', False))
    invplaybooktaskdata_automationscript = str(args.get('invplaybooktaskdata_automationscript', ''))
    invplaybooktaskdata_description = str(args.get('invplaybooktaskdata_description', ''))
    invplaybooktaskdata_loop_brand = str(args.get('invplaybooktaskdata_loop_brand', ''))
    invplaybooktaskdata_loop_builtincondition = str(args.get('invplaybooktaskdata_loop_builtincondition', ''))
    invplaybooktaskdata_loop_exitcondition = str(args.get('invplaybooktaskdata_loop_exitcondition', ''))
    invplaybooktaskdata_loop_foreach = argToBoolean(args.get('invplaybooktaskdata_loop_foreach', False))
    invplaybooktaskdata_loop_iscommand = argToBoolean(args.get('invplaybooktaskdata_loop_iscommand', False))
    invplaybooktaskdata_loop_max = args.get('invplaybooktaskdata_loop_max', None)
    invplaybooktaskdata_loop_scriptarguments = str(args.get('invplaybooktaskdata_loop_scriptarguments', ''))
    invplaybooktaskdata_loop_scriptid = str(args.get('invplaybooktaskdata_loop_scriptid', ''))
    invplaybooktaskdata_loop_scriptname = str(args.get('invplaybooktaskdata_loop_scriptname', ''))
    invplaybooktaskdata_loop_wait = args.get('invplaybooktaskdata_loop_wait', None)
    invplaybooktaskdata_loop = assign_params(brand=invplaybooktaskdata_loop_brand, builtinCondition=invplaybooktaskdata_loop_builtincondition, exitCondition=invplaybooktaskdata_loop_exitcondition, forEach=invplaybooktaskdata_loop_foreach,
                                             isCommand=invplaybooktaskdata_loop_iscommand, max=invplaybooktaskdata_loop_max, scriptArguments=invplaybooktaskdata_loop_scriptarguments, scriptId=invplaybooktaskdata_loop_scriptid, scriptName=invplaybooktaskdata_loop_scriptname, wait=invplaybooktaskdata_loop_wait)
    invplaybooktaskdata_name = str(args.get('invplaybooktaskdata_name', ''))
    invplaybooktaskdata_neighborinvpbtaskid = str(args.get('invplaybooktaskdata_neighborinvpbtaskid', ''))
    invplaybooktaskdata_playbookid = str(args.get('invplaybooktaskdata_playbookid', ''))
    invplaybooktaskdata_scriptarguments = str(args.get('invplaybooktaskdata_scriptarguments', ''))
    invplaybooktaskdata_tags = argToList(args.get('invplaybooktaskdata_tags', []))
    invplaybooktaskdata_type = str(args.get('invplaybooktaskdata_type', ''))
    investigationId = str(args.get('investigationId', ''))

    response = client.add_ad_hoc_task_request(invplaybooktaskdata_addafter, invplaybooktaskdata_automationscript, invplaybooktaskdata_description, invplaybooktaskdata_loop, invplaybooktaskdata_name,
                                              invplaybooktaskdata_neighborinvpbtaskid, invplaybooktaskdata_playbookid, invplaybooktaskdata_scriptarguments, invplaybooktaskdata_tags, invplaybooktaskdata_type, investigationId)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def close_incidents_batch_command(client, args):
    updatedatabatch_customfields = str(args.get('updatedatabatch_customfields', ''))
    updatedatabatch_all = argToBoolean(args.get('updatedatabatch_all', False))
    updatedatabatch_closenotes = str(args.get('updatedatabatch_closenotes', ''))
    updatedatabatch_closereason = str(args.get('updatedatabatch_closereason', ''))
    updatedatabatch_columns = argToList(args.get('updatedatabatch_columns', []))
    updatedatabatch_data = str(args.get('updatedatabatch_data', ''))
    updatedatabatch_filter_cache = str(args.get('updatedatabatch_filter_cache', ''))
    updatedatabatch_filter_andop = argToBoolean(args.get('updatedatabatch_filter_andop', False))
    updatedatabatch_filter_category = str(args.get('updatedatabatch_filter_category', ''))
    updatedatabatch_filter_details = str(args.get('updatedatabatch_filter_details', ''))
    updatedatabatch_filter_files = str(args.get('updatedatabatch_filter_files', ''))
    updatedatabatch_filter_fromactivateddate = str(args.get('updatedatabatch_filter_fromactivateddate', ''))
    updatedatabatch_filter_fromcloseddate = str(args.get('updatedatabatch_filter_fromcloseddate', ''))
    updatedatabatch_filter_fromdate = str(args.get('updatedatabatch_filter_fromdate', ''))
    updatedatabatch_filter_fromdatelicense = str(args.get('updatedatabatch_filter_fromdatelicense', ''))
    updatedatabatch_filter_fromduedate = str(args.get('updatedatabatch_filter_fromduedate', ''))
    updatedatabatch_filter_fromreminder = str(args.get('updatedatabatch_filter_fromreminder', ''))
    updatedatabatch_filter_id = str(args.get('updatedatabatch_filter_id', ''))
    updatedatabatch_filter_ignoreworkers = argToBoolean(args.get('updatedatabatch_filter_ignoreworkers', False))
    updatedatabatch_filter_includetmp = argToBoolean(args.get('updatedatabatch_filter_includetmp', False))
    updatedatabatch_filter_investigation = str(args.get('updatedatabatch_filter_investigation', ''))
    updatedatabatch_filter_level = str(args.get('updatedatabatch_filter_level', ''))
    updatedatabatch_filter_name = str(args.get('updatedatabatch_filter_name', ''))
    updatedatabatch_filter_notcategory = str(args.get('updatedatabatch_filter_notcategory', ''))
    updatedatabatch_filter_notinvestigation = str(args.get('updatedatabatch_filter_notinvestigation', ''))
    updatedatabatch_filter_notstatus = str(args.get('updatedatabatch_filter_notstatus', ''))
    updatedatabatch_filter_page = args.get('updatedatabatch_filter_page', None)
    updatedatabatch_filter_parent = str(args.get('updatedatabatch_filter_parent', ''))
    updatedatabatch_filter_period = str(args.get('updatedatabatch_filter_period', ''))
    updatedatabatch_filter_query = str(args.get('updatedatabatch_filter_query', ''))
    updatedatabatch_filter_reason = str(args.get('updatedatabatch_filter_reason', ''))
    updatedatabatch_filter_searchafter = str(args.get('updatedatabatch_filter_searchafter', ''))
    updatedatabatch_filter_searchbefore = str(args.get('updatedatabatch_filter_searchbefore', ''))
    updatedatabatch_filter_size = args.get('updatedatabatch_filter_size', None)
    updatedatabatch_filter_sort = str(args.get('updatedatabatch_filter_sort', ''))
    updatedatabatch_filter_status = str(args.get('updatedatabatch_filter_status', ''))
    updatedatabatch_filter_systems = str(args.get('updatedatabatch_filter_systems', ''))
    updatedatabatch_filter_timeframe = str(args.get('updatedatabatch_filter_timeframe', ''))
    updatedatabatch_filter_toactivateddate = str(args.get('updatedatabatch_filter_toactivateddate', ''))
    updatedatabatch_filter_tocloseddate = str(args.get('updatedatabatch_filter_tocloseddate', ''))
    updatedatabatch_filter_todate = str(args.get('updatedatabatch_filter_todate', ''))
    updatedatabatch_filter_toduedate = str(args.get('updatedatabatch_filter_toduedate', ''))
    updatedatabatch_filter_toreminder = str(args.get('updatedatabatch_filter_toreminder', ''))
    updatedatabatch_filter_totalonly = argToBoolean(args.get('updatedatabatch_filter_totalonly', False))
    updatedatabatch_filter_type = str(args.get('updatedatabatch_filter_type', ''))
    updatedatabatch_filter_urls = str(args.get('updatedatabatch_filter_urls', ''))
    updatedatabatch_filter_users = str(args.get('updatedatabatch_filter_users', ''))
    updatedatabatch_filter = assign_params(Cache=updatedatabatch_filter_cache, andOp=updatedatabatch_filter_andop, category=updatedatabatch_filter_category, details=updatedatabatch_filter_details, files=updatedatabatch_filter_files, fromActivatedDate=updatedatabatch_filter_fromactivateddate, fromClosedDate=updatedatabatch_filter_fromcloseddate, fromDate=updatedatabatch_filter_fromdate, fromDateLicense=updatedatabatch_filter_fromdatelicense, fromDueDate=updatedatabatch_filter_fromduedate, fromReminder=updatedatabatch_filter_fromreminder, id=updatedatabatch_filter_id, ignoreWorkers=updatedatabatch_filter_ignoreworkers, includeTmp=updatedatabatch_filter_includetmp, investigation=updatedatabatch_filter_investigation, level=updatedatabatch_filter_level, name=updatedatabatch_filter_name, notCategory=updatedatabatch_filter_notcategory, notInvestigation=updatedatabatch_filter_notinvestigation,
                                           notStatus=updatedatabatch_filter_notstatus, page=updatedatabatch_filter_page, parent=updatedatabatch_filter_parent, period=updatedatabatch_filter_period, query=updatedatabatch_filter_query, reason=updatedatabatch_filter_reason, searchAfter=updatedatabatch_filter_searchafter, searchBefore=updatedatabatch_filter_searchbefore, size=updatedatabatch_filter_size, sort=updatedatabatch_filter_sort, status=updatedatabatch_filter_status, systems=updatedatabatch_filter_systems, timeFrame=updatedatabatch_filter_timeframe, toActivatedDate=updatedatabatch_filter_toactivateddate, toClosedDate=updatedatabatch_filter_tocloseddate, toDate=updatedatabatch_filter_todate, toDueDate=updatedatabatch_filter_toduedate, toReminder=updatedatabatch_filter_toreminder, totalOnly=updatedatabatch_filter_totalonly, type=updatedatabatch_filter_type, urls=updatedatabatch_filter_urls, users=updatedatabatch_filter_users)
    updatedatabatch_force = argToBoolean(args.get('updatedatabatch_force', False))
    updatedatabatch_ids = argToList(args.get('updatedatabatch_ids', []))
    updatedatabatch_line = str(args.get('updatedatabatch_line', ''))
    updatedatabatch_originalincidentid = str(args.get('updatedatabatch_originalincidentid', ''))
    updatedatabatch_overrideinvestigation = argToBoolean(args.get('updatedatabatch_overrideinvestigation', False))

    response = client.close_incidents_batch_request(updatedatabatch_customfields, updatedatabatch_all, updatedatabatch_closenotes, updatedatabatch_closereason, updatedatabatch_columns,
                                                    updatedatabatch_data, updatedatabatch_filter, updatedatabatch_force, updatedatabatch_ids, updatedatabatch_line, updatedatabatch_originalincidentid, updatedatabatch_overrideinvestigation)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IncidentSearchResponseWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def complete_task_command(client, args):
    investigationId = str(args.get('investigationId', ''))
    fileName = str(args.get('fileName', ''))
    fileComment = str(args.get('fileComment', ''))
    taskId = str(args.get('taskId', ''))
    taskInput = str(args.get('taskInput', ''))
    version = str(args.get('version', ''))
    file = str(args.get('file', ''))

    response = client.complete_task_request(investigationId, fileName, fileComment, taskId, taskInput, version, file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def complete_taskv2_command(client, args):
    investigationId = str(args.get('investigationId', ''))
    taskId = str(args.get('taskId', ''))
    taskComment = str(args.get('taskComment', ''))
    taskInput = str(args.get('taskInput', ''))
    version = str(args.get('version', ''))
    file = str(args.get('file', ''))
    fileNames = str(args.get('fileNames', ''))
    fileComments = str(args.get('fileComments', ''))

    response = client.complete_taskv2_request(investigationId, taskId, taskComment,
                                              taskInput, version, file, fileNames, fileComments)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def copy_script_command(client, args):
    automationscriptfilterwrapper_filter_cache = str(args.get('automationscriptfilterwrapper_filter_cache', ''))
    automationscriptfilterwrapper_filter_ignoreworkers = argToBoolean(
        args.get('automationscriptfilterwrapper_filter_ignoreworkers', False))
    automationscriptfilterwrapper_filter_page = args.get('automationscriptfilterwrapper_filter_page', None)
    automationscriptfilterwrapper_filter_query = str(args.get('automationscriptfilterwrapper_filter_query', ''))
    automationscriptfilterwrapper_filter_searchafter = str(args.get('automationscriptfilterwrapper_filter_searchafter', ''))
    automationscriptfilterwrapper_filter_searchbefore = str(args.get('automationscriptfilterwrapper_filter_searchbefore', ''))
    automationscriptfilterwrapper_filter_size = args.get('automationscriptfilterwrapper_filter_size', None)
    automationscriptfilterwrapper_filter_sort = str(args.get('automationscriptfilterwrapper_filter_sort', ''))
    automationscriptfilterwrapper_filter = assign_params(Cache=automationscriptfilterwrapper_filter_cache, ignoreWorkers=automationscriptfilterwrapper_filter_ignoreworkers, page=automationscriptfilterwrapper_filter_page, query=automationscriptfilterwrapper_filter_query,
                                                         searchAfter=automationscriptfilterwrapper_filter_searchafter, searchBefore=automationscriptfilterwrapper_filter_searchbefore, size=automationscriptfilterwrapper_filter_size, sort=automationscriptfilterwrapper_filter_sort)
    automationscriptfilterwrapper_savepassword = argToBoolean(args.get('automationscriptfilterwrapper_savepassword', False))
    automationscriptfilterwrapper_script_allread = argToBoolean(args.get('automationscriptfilterwrapper_script_allread', False))
    automationscriptfilterwrapper_script_allreadwrite = argToBoolean(
        args.get('automationscriptfilterwrapper_script_allreadwrite', False))
    automationscriptfilterwrapper_script_arguments = str(args.get('automationscriptfilterwrapper_script_arguments', ''))
    automationscriptfilterwrapper_script_comment = str(args.get('automationscriptfilterwrapper_script_comment', ''))
    automationscriptfilterwrapper_script_commitmessage = str(args.get('automationscriptfilterwrapper_script_commitmessage', ''))
    automationscriptfilterwrapper_script_contextkeys = str(args.get('automationscriptfilterwrapper_script_contextkeys', ''))
    automationscriptfilterwrapper_script_dbotcreatedby = str(args.get('automationscriptfilterwrapper_script_dbotcreatedby', ''))
    automationscriptfilterwrapper_script_dependson = str(args.get('automationscriptfilterwrapper_script_dependson', ''))
    automationscriptfilterwrapper_script_deprecated = argToBoolean(
        args.get('automationscriptfilterwrapper_script_deprecated', False))
    automationscriptfilterwrapper_script_detached = argToBoolean(args.get('automationscriptfilterwrapper_script_detached', False))
    automationscriptfilterwrapper_script_dockerimage = str(args.get('automationscriptfilterwrapper_script_dockerimage', ''))
    automationscriptfilterwrapper_script_enabled = argToBoolean(args.get('automationscriptfilterwrapper_script_enabled', False))
    automationscriptfilterwrapper_script_fromserverversion = str(
        args.get('automationscriptfilterwrapper_script_fromserverversion', ''))
    automationscriptfilterwrapper_script_hasrole = argToBoolean(args.get('automationscriptfilterwrapper_script_hasrole', False))
    automationscriptfilterwrapper_script_hidden = argToBoolean(args.get('automationscriptfilterwrapper_script_hidden', False))
    automationscriptfilterwrapper_script_id = str(args.get('automationscriptfilterwrapper_script_id', ''))
    automationscriptfilterwrapper_script_important = str(args.get('automationscriptfilterwrapper_script_important', ''))
    automationscriptfilterwrapper_script_itemversion = str(args.get('automationscriptfilterwrapper_script_itemversion', ''))
    automationscriptfilterwrapper_script_locked = argToBoolean(args.get('automationscriptfilterwrapper_script_locked', False))
    automationscriptfilterwrapper_script_modified = str(args.get('automationscriptfilterwrapper_script_modified', ''))
    automationscriptfilterwrapper_script_name = str(args.get('automationscriptfilterwrapper_script_name', ''))
    automationscriptfilterwrapper_script_outputs = str(args.get('automationscriptfilterwrapper_script_outputs', ''))
    automationscriptfilterwrapper_script_packid = str(args.get('automationscriptfilterwrapper_script_packid', ''))
    automationscriptfilterwrapper_script_packpropagationlabels = str(
        args.get('automationscriptfilterwrapper_script_packpropagationlabels', ''))
    automationscriptfilterwrapper_script_prevname = str(args.get('automationscriptfilterwrapper_script_prevname', ''))
    automationscriptfilterwrapper_script_previousallread = argToBoolean(
        args.get('automationscriptfilterwrapper_script_previousallread', False))
    automationscriptfilterwrapper_script_previousallreadwrite = argToBoolean(
        args.get('automationscriptfilterwrapper_script_previousallreadwrite', False))
    automationscriptfilterwrapper_script_previousroles = str(args.get('automationscriptfilterwrapper_script_previousroles', ''))
    automationscriptfilterwrapper_script_primaryterm = args.get('automationscriptfilterwrapper_script_primaryterm', None)
    automationscriptfilterwrapper_script_private = argToBoolean(args.get('automationscriptfilterwrapper_script_private', False))
    automationscriptfilterwrapper_script_propagationlabels = str(
        args.get('automationscriptfilterwrapper_script_propagationlabels', ''))
    automationscriptfilterwrapper_script_pswd = str(args.get('automationscriptfilterwrapper_script_pswd', ''))
    automationscriptfilterwrapper_script_rawtags = str(args.get('automationscriptfilterwrapper_script_rawtags', ''))
    automationscriptfilterwrapper_script_roles = str(args.get('automationscriptfilterwrapper_script_roles', ''))
    automationscriptfilterwrapper_script_runas = str(args.get('automationscriptfilterwrapper_script_runas', ''))
    automationscriptfilterwrapper_script_runonce = argToBoolean(args.get('automationscriptfilterwrapper_script_runonce', False))
    automationscriptfilterwrapper_script_script = str(args.get('automationscriptfilterwrapper_script_script', ''))
    automationscriptfilterwrapper_script_scripttarget = str(args.get('automationscriptfilterwrapper_script_scripttarget', ''))
    automationscriptfilterwrapper_script_searchablename = str(args.get('automationscriptfilterwrapper_script_searchablename', ''))
    automationscriptfilterwrapper_script_sensitive = argToBoolean(
        args.get('automationscriptfilterwrapper_script_sensitive', False))
    automationscriptfilterwrapper_script_sequencenumber = args.get('automationscriptfilterwrapper_script_sequencenumber', None)
    automationscriptfilterwrapper_script_shouldcommit = argToBoolean(
        args.get('automationscriptfilterwrapper_script_shouldcommit', False))
    automationscriptfilterwrapper_script_sortvalues = str(args.get('automationscriptfilterwrapper_script_sortvalues', ''))
    automationscriptfilterwrapper_script_sourcescripid = str(args.get('automationscriptfilterwrapper_script_sourcescripid', ''))
    automationscriptfilterwrapper_script_subtype = str(args.get('automationscriptfilterwrapper_script_subtype', ''))
    automationscriptfilterwrapper_script_system = argToBoolean(args.get('automationscriptfilterwrapper_script_system', False))
    automationscriptfilterwrapper_script_tags = str(args.get('automationscriptfilterwrapper_script_tags', ''))
    automationscriptfilterwrapper_script_timeout = str(args.get('automationscriptfilterwrapper_script_timeout', ''))
    automationscriptfilterwrapper_script_toserverversion = str(
        args.get('automationscriptfilterwrapper_script_toserverversion', ''))
    automationscriptfilterwrapper_script_type = str(args.get('automationscriptfilterwrapper_script_type', ''))
    automationscriptfilterwrapper_script_user = str(args.get('automationscriptfilterwrapper_script_user', ''))
    automationscriptfilterwrapper_script_vcshouldignore = argToBoolean(
        args.get('automationscriptfilterwrapper_script_vcshouldignore', False))
    automationscriptfilterwrapper_script_vcshouldkeepitemlegacyprodmachine = argToBoolean(
        args.get('automationscriptfilterwrapper_script_vcshouldkeepitemlegacyprodmachine', False))
    automationscriptfilterwrapper_script_version = args.get('automationscriptfilterwrapper_script_version', None)
    automationscriptfilterwrapper_script_visualscript = str(args.get('automationscriptfilterwrapper_script_visualscript', ''))
    automationscriptfilterwrapper_script_xsoarhasreadonlyrole = argToBoolean(
        args.get('automationscriptfilterwrapper_script_xsoarhasreadonlyrole', False))
    automationscriptfilterwrapper_script_xsoarpreviousreadonlyroles = str(
        args.get('automationscriptfilterwrapper_script_xsoarpreviousreadonlyroles', ''))
    automationscriptfilterwrapper_script_xsoarreadonlyroles = str(
        args.get('automationscriptfilterwrapper_script_xsoarreadonlyroles', ''))
    automationscriptfilterwrapper_script = assign_params(allRead=automationscriptfilterwrapper_script_allread, allReadWrite=automationscriptfilterwrapper_script_allreadwrite, arguments=automationscriptfilterwrapper_script_arguments, comment=automationscriptfilterwrapper_script_comment, commitMessage=automationscriptfilterwrapper_script_commitmessage, contextKeys=automationscriptfilterwrapper_script_contextkeys, dbotCreatedBy=automationscriptfilterwrapper_script_dbotcreatedby, dependsOn=automationscriptfilterwrapper_script_dependson, deprecated=automationscriptfilterwrapper_script_deprecated, detached=automationscriptfilterwrapper_script_detached, dockerImage=automationscriptfilterwrapper_script_dockerimage, enabled=automationscriptfilterwrapper_script_enabled, fromServerVersion=automationscriptfilterwrapper_script_fromserverversion, hasRole=automationscriptfilterwrapper_script_hasrole, hidden=automationscriptfilterwrapper_script_hidden, id=automationscriptfilterwrapper_script_id, important=automationscriptfilterwrapper_script_important, itemVersion=automationscriptfilterwrapper_script_itemversion, locked=automationscriptfilterwrapper_script_locked, modified=automationscriptfilterwrapper_script_modified, name=automationscriptfilterwrapper_script_name, outputs=automationscriptfilterwrapper_script_outputs, packID=automationscriptfilterwrapper_script_packid, packPropagationLabels=automationscriptfilterwrapper_script_packpropagationlabels, prevName=automationscriptfilterwrapper_script_prevname, previousAllRead=automationscriptfilterwrapper_script_previousallread, previousAllReadWrite=automationscriptfilterwrapper_script_previousallreadwrite, previousRoles=automationscriptfilterwrapper_script_previousroles, primaryTerm=automationscriptfilterwrapper_script_primaryterm,
                                                         private=automationscriptfilterwrapper_script_private, propagationLabels=automationscriptfilterwrapper_script_propagationlabels, pswd=automationscriptfilterwrapper_script_pswd, rawTags=automationscriptfilterwrapper_script_rawtags, roles=automationscriptfilterwrapper_script_roles, runAs=automationscriptfilterwrapper_script_runas, runOnce=automationscriptfilterwrapper_script_runonce, script=automationscriptfilterwrapper_script_script, scriptTarget=automationscriptfilterwrapper_script_scripttarget, searchableName=automationscriptfilterwrapper_script_searchablename, sensitive=automationscriptfilterwrapper_script_sensitive, sequenceNumber=automationscriptfilterwrapper_script_sequencenumber, shouldCommit=automationscriptfilterwrapper_script_shouldcommit, sortValues=automationscriptfilterwrapper_script_sortvalues, sourceScripID=automationscriptfilterwrapper_script_sourcescripid, subtype=automationscriptfilterwrapper_script_subtype, system=automationscriptfilterwrapper_script_system, tags=automationscriptfilterwrapper_script_tags, timeout=automationscriptfilterwrapper_script_timeout, toServerVersion=automationscriptfilterwrapper_script_toserverversion, type=automationscriptfilterwrapper_script_type, user=automationscriptfilterwrapper_script_user, vcShouldIgnore=automationscriptfilterwrapper_script_vcshouldignore, vcShouldKeepItemLegacyProdMachine=automationscriptfilterwrapper_script_vcshouldkeepitemlegacyprodmachine, version=automationscriptfilterwrapper_script_version, visualScript=automationscriptfilterwrapper_script_visualscript, xsoarHasReadOnlyRole=automationscriptfilterwrapper_script_xsoarhasreadonlyrole, xsoarPreviousReadOnlyRoles=automationscriptfilterwrapper_script_xsoarpreviousreadonlyroles, xsoarReadOnlyRoles=automationscriptfilterwrapper_script_xsoarreadonlyroles)

    response = client.copy_script_request(automationscriptfilterwrapper_filter,
                                          automationscriptfilterwrapper_savepassword, automationscriptfilterwrapper_script)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.automationScriptResult',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_docker_image_command(client, args):
    newdockerimage_base = str(args.get('newdockerimage_base', ''))
    newdockerimage_dependencies = argToList(args.get('newdockerimage_dependencies', []))
    newdockerimage_name = str(args.get('newdockerimage_name', ''))
    newdockerimage_packages = argToList(args.get('newdockerimage_packages', []))

    response = client.create_docker_image_request(
        newdockerimage_base, newdockerimage_dependencies, newdockerimage_name, newdockerimage_packages)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.newDockerImageResult',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_feed_indicators_json_command(client, args):
    feedindicatorsrequest_bypassexclusionlist = argToBoolean(args.get('feedindicatorsrequest_bypassexclusionlist', False))
    feedindicatorsrequest_classifierid = str(args.get('feedindicatorsrequest_classifierid', ''))
    feedindicatorsrequest_indicators = argToList(args.get('feedindicatorsrequest_indicators', []))
    feedindicatorsrequest_mapperid = str(args.get('feedindicatorsrequest_mapperid', ''))

    response = client.create_feed_indicators_json_request(
        feedindicatorsrequest_bypassexclusionlist, feedindicatorsrequest_classifierid, feedindicatorsrequest_indicators, feedindicatorsrequest_mapperid)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_incident_command(client, args):
    createincidentrequest_shardid = args.get('createincidentrequest_shardid', None)
    createincidentrequest_account = str(args.get('createincidentrequest_account', ''))
    createincidentrequest_activated = str(args.get('createincidentrequest_activated', ''))
    createincidentrequest_activatinginguserid = str(args.get('createincidentrequest_activatinginguserid', ''))
    createincidentrequest_allread = argToBoolean(args.get('createincidentrequest_allread', False))
    createincidentrequest_allreadwrite = argToBoolean(args.get('createincidentrequest_allreadwrite', False))
    createincidentrequest_autime = args.get('createincidentrequest_autime', None)
    createincidentrequest_canvases = argToList(args.get('createincidentrequest_canvases', []))
    createincidentrequest_category = str(args.get('createincidentrequest_category', ''))
    createincidentrequest_closenotes = str(args.get('createincidentrequest_closenotes', ''))
    createincidentrequest_closereason = str(args.get('createincidentrequest_closereason', ''))
    createincidentrequest_closed = str(args.get('createincidentrequest_closed', ''))
    createincidentrequest_closinguserid = str(args.get('createincidentrequest_closinguserid', ''))
    createincidentrequest_createinvestigation = argToBoolean(args.get('createincidentrequest_createinvestigation', False))
    createincidentrequest_created = str(args.get('createincidentrequest_created', ''))
    createincidentrequest_dbotcreatedby = str(args.get('createincidentrequest_dbotcreatedby', ''))
    createincidentrequest_dbotcurrentdirtyfields = argToList(args.get('createincidentrequest_dbotcurrentdirtyfields', []))
    createincidentrequest_dbotdirtyfields = argToList(args.get('createincidentrequest_dbotdirtyfields', []))
    createincidentrequest_dbotmirrordirection = str(args.get('createincidentrequest_dbotmirrordirection', ''))
    createincidentrequest_dbotmirrorid = str(args.get('createincidentrequest_dbotmirrorid', ''))
    createincidentrequest_dbotmirrorinstance = str(args.get('createincidentrequest_dbotmirrorinstance', ''))
    createincidentrequest_dbotmirrorlastsync = str(args.get('createincidentrequest_dbotmirrorlastsync', ''))
    createincidentrequest_dbotmirrortags = argToList(args.get('createincidentrequest_dbotmirrortags', []))
    createincidentrequest_details = str(args.get('createincidentrequest_details', ''))
    createincidentrequest_droppedcount = args.get('createincidentrequest_droppedcount', None)
    createincidentrequest_duedate = str(args.get('createincidentrequest_duedate', ''))
    createincidentrequest_feedbased = argToBoolean(args.get('createincidentrequest_feedbased', False))
    createincidentrequest_hasrole = argToBoolean(args.get('createincidentrequest_hasrole', False))
    createincidentrequest_id = str(args.get('createincidentrequest_id', ''))
    createincidentrequest_investigationid = str(args.get('createincidentrequest_investigationid', ''))
    createincidentrequest_isplayground = argToBoolean(args.get('createincidentrequest_isplayground', False))
    createincidentrequest_labels = argToList(args.get('createincidentrequest_labels', []))
    createincidentrequest_lastjobruntime = str(args.get('createincidentrequest_lastjobruntime', ''))
    createincidentrequest_lastopen = str(args.get('createincidentrequest_lastopen', ''))
    createincidentrequest_linkedcount = args.get('createincidentrequest_linkedcount', None)
    createincidentrequest_linkedincidents = argToList(args.get('createincidentrequest_linkedincidents', []))
    createincidentrequest_modified = str(args.get('createincidentrequest_modified', ''))
    createincidentrequest_name = str(args.get('createincidentrequest_name', ''))
    createincidentrequest_notifytime = str(args.get('createincidentrequest_notifytime', ''))
    createincidentrequest_occurred = str(args.get('createincidentrequest_occurred', ''))
    createincidentrequest_openduration = args.get('createincidentrequest_openduration', None)
    createincidentrequest_owner = str(args.get('createincidentrequest_owner', ''))
    createincidentrequest_parent = str(args.get('createincidentrequest_parent', ''))
    createincidentrequest_phase = str(args.get('createincidentrequest_phase', ''))
    createincidentrequest_playbookid = str(args.get('createincidentrequest_playbookid', ''))
    createincidentrequest_previousallread = argToBoolean(args.get('createincidentrequest_previousallread', False))
    createincidentrequest_previousallreadwrite = argToBoolean(args.get('createincidentrequest_previousallreadwrite', False))
    createincidentrequest_previousroles = argToList(args.get('createincidentrequest_previousroles', []))
    createincidentrequest_primaryterm = args.get('createincidentrequest_primaryterm', None)
    createincidentrequest_rawcategory = str(args.get('createincidentrequest_rawcategory', ''))
    createincidentrequest_rawclosereason = str(args.get('createincidentrequest_rawclosereason', ''))
    createincidentrequest_rawjson = str(args.get('createincidentrequest_rawjson', ''))
    createincidentrequest_rawname = str(args.get('createincidentrequest_rawname', ''))
    createincidentrequest_rawphase = str(args.get('createincidentrequest_rawphase', ''))
    createincidentrequest_rawtype = str(args.get('createincidentrequest_rawtype', ''))
    createincidentrequest_reason = str(args.get('createincidentrequest_reason', ''))
    createincidentrequest_reminder = str(args.get('createincidentrequest_reminder', ''))
    createincidentrequest_roles = argToList(args.get('createincidentrequest_roles', []))
    createincidentrequest_runstatus = str(args.get('createincidentrequest_runstatus', ''))
    createincidentrequest_sequencenumber = args.get('createincidentrequest_sequencenumber', None)
    createincidentrequest_severity = str(args.get('createincidentrequest_severity', ''))
    createincidentrequest_sla = str(args.get('createincidentrequest_sla', ''))
    createincidentrequest_sortvalues = argToList(args.get('createincidentrequest_sortvalues', []))
    createincidentrequest_sourcebrand = str(args.get('createincidentrequest_sourcebrand', ''))
    createincidentrequest_sourceinstance = str(args.get('createincidentrequest_sourceinstance', ''))
    createincidentrequest_status = str(args.get('createincidentrequest_status', ''))
    createincidentrequest_todotaskids = argToList(args.get('createincidentrequest_todotaskids', []))
    createincidentrequest_type = str(args.get('createincidentrequest_type', ''))
    createincidentrequest_version = args.get('createincidentrequest_version', None)
    createincidentrequest_xsoarhasreadonlyrole = argToBoolean(args.get('createincidentrequest_xsoarhasreadonlyrole', False))
    createincidentrequest_xsoarpreviousreadonlyroles = argToList(args.get('createincidentrequest_xsoarpreviousreadonlyroles', []))
    createincidentrequest_xsoarreadonlyroles = argToList(args.get('createincidentrequest_xsoarreadonlyroles', []))

    response = client.create_incident_request(createincidentrequest_shardid, createincidentrequest_account, createincidentrequest_activated, createincidentrequest_activatinginguserid, createincidentrequest_allread, createincidentrequest_allreadwrite, createincidentrequest_autime, createincidentrequest_canvases, createincidentrequest_category, createincidentrequest_closenotes, createincidentrequest_closereason, createincidentrequest_closed, createincidentrequest_closinguserid, createincidentrequest_createinvestigation, createincidentrequest_created, createincidentrequest_dbotcreatedby, createincidentrequest_dbotcurrentdirtyfields, createincidentrequest_dbotdirtyfields, createincidentrequest_dbotmirrordirection, createincidentrequest_dbotmirrorid, createincidentrequest_dbotmirrorinstance, createincidentrequest_dbotmirrorlastsync, createincidentrequest_dbotmirrortags, createincidentrequest_details, createincidentrequest_droppedcount, createincidentrequest_duedate, createincidentrequest_feedbased, createincidentrequest_hasrole, createincidentrequest_id, createincidentrequest_investigationid, createincidentrequest_isplayground, createincidentrequest_labels, createincidentrequest_lastjobruntime, createincidentrequest_lastopen, createincidentrequest_linkedcount,
                                              createincidentrequest_linkedincidents, createincidentrequest_modified, createincidentrequest_name, createincidentrequest_notifytime, createincidentrequest_occurred, createincidentrequest_openduration, createincidentrequest_owner, createincidentrequest_parent, createincidentrequest_phase, createincidentrequest_playbookid, createincidentrequest_previousallread, createincidentrequest_previousallreadwrite, createincidentrequest_previousroles, createincidentrequest_primaryterm, createincidentrequest_rawcategory, createincidentrequest_rawclosereason, createincidentrequest_rawjson, createincidentrequest_rawname, createincidentrequest_rawphase, createincidentrequest_rawtype, createincidentrequest_reason, createincidentrequest_reminder, createincidentrequest_roles, createincidentrequest_runstatus, createincidentrequest_sequencenumber, createincidentrequest_severity, createincidentrequest_sla, createincidentrequest_sortvalues, createincidentrequest_sourcebrand, createincidentrequest_sourceinstance, createincidentrequest_status, createincidentrequest_todotaskids, createincidentrequest_type, createincidentrequest_version, createincidentrequest_xsoarhasreadonlyrole, createincidentrequest_xsoarpreviousreadonlyroles, createincidentrequest_xsoarreadonlyroles)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.CreatedIncident',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_incident_json_command(client, args):

    response = client.create_incident_json_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IncidentWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_incidents_batch_command(client, args):
    updatedatabatch_customfields = str(args.get('updatedatabatch_customfields', ''))
    updatedatabatch_all = argToBoolean(args.get('updatedatabatch_all', False))
    updatedatabatch_closenotes = str(args.get('updatedatabatch_closenotes', ''))
    updatedatabatch_closereason = str(args.get('updatedatabatch_closereason', ''))
    updatedatabatch_columns = argToList(args.get('updatedatabatch_columns', []))
    updatedatabatch_data = str(args.get('updatedatabatch_data', ''))
    updatedatabatch_filter_cache = str(args.get('updatedatabatch_filter_cache', ''))
    updatedatabatch_filter_andop = argToBoolean(args.get('updatedatabatch_filter_andop', False))
    updatedatabatch_filter_category = str(args.get('updatedatabatch_filter_category', ''))
    updatedatabatch_filter_details = str(args.get('updatedatabatch_filter_details', ''))
    updatedatabatch_filter_files = str(args.get('updatedatabatch_filter_files', ''))
    updatedatabatch_filter_fromactivateddate = str(args.get('updatedatabatch_filter_fromactivateddate', ''))
    updatedatabatch_filter_fromcloseddate = str(args.get('updatedatabatch_filter_fromcloseddate', ''))
    updatedatabatch_filter_fromdate = str(args.get('updatedatabatch_filter_fromdate', ''))
    updatedatabatch_filter_fromdatelicense = str(args.get('updatedatabatch_filter_fromdatelicense', ''))
    updatedatabatch_filter_fromduedate = str(args.get('updatedatabatch_filter_fromduedate', ''))
    updatedatabatch_filter_fromreminder = str(args.get('updatedatabatch_filter_fromreminder', ''))
    updatedatabatch_filter_id = str(args.get('updatedatabatch_filter_id', ''))
    updatedatabatch_filter_ignoreworkers = argToBoolean(args.get('updatedatabatch_filter_ignoreworkers', False))
    updatedatabatch_filter_includetmp = argToBoolean(args.get('updatedatabatch_filter_includetmp', False))
    updatedatabatch_filter_investigation = str(args.get('updatedatabatch_filter_investigation', ''))
    updatedatabatch_filter_level = str(args.get('updatedatabatch_filter_level', ''))
    updatedatabatch_filter_name = str(args.get('updatedatabatch_filter_name', ''))
    updatedatabatch_filter_notcategory = str(args.get('updatedatabatch_filter_notcategory', ''))
    updatedatabatch_filter_notinvestigation = str(args.get('updatedatabatch_filter_notinvestigation', ''))
    updatedatabatch_filter_notstatus = str(args.get('updatedatabatch_filter_notstatus', ''))
    updatedatabatch_filter_page = args.get('updatedatabatch_filter_page', None)
    updatedatabatch_filter_parent = str(args.get('updatedatabatch_filter_parent', ''))
    updatedatabatch_filter_period = str(args.get('updatedatabatch_filter_period', ''))
    updatedatabatch_filter_query = str(args.get('updatedatabatch_filter_query', ''))
    updatedatabatch_filter_reason = str(args.get('updatedatabatch_filter_reason', ''))
    updatedatabatch_filter_searchafter = str(args.get('updatedatabatch_filter_searchafter', ''))
    updatedatabatch_filter_searchbefore = str(args.get('updatedatabatch_filter_searchbefore', ''))
    updatedatabatch_filter_size = args.get('updatedatabatch_filter_size', None)
    updatedatabatch_filter_sort = str(args.get('updatedatabatch_filter_sort', ''))
    updatedatabatch_filter_status = str(args.get('updatedatabatch_filter_status', ''))
    updatedatabatch_filter_systems = str(args.get('updatedatabatch_filter_systems', ''))
    updatedatabatch_filter_timeframe = str(args.get('updatedatabatch_filter_timeframe', ''))
    updatedatabatch_filter_toactivateddate = str(args.get('updatedatabatch_filter_toactivateddate', ''))
    updatedatabatch_filter_tocloseddate = str(args.get('updatedatabatch_filter_tocloseddate', ''))
    updatedatabatch_filter_todate = str(args.get('updatedatabatch_filter_todate', ''))
    updatedatabatch_filter_toduedate = str(args.get('updatedatabatch_filter_toduedate', ''))
    updatedatabatch_filter_toreminder = str(args.get('updatedatabatch_filter_toreminder', ''))
    updatedatabatch_filter_totalonly = argToBoolean(args.get('updatedatabatch_filter_totalonly', False))
    updatedatabatch_filter_type = str(args.get('updatedatabatch_filter_type', ''))
    updatedatabatch_filter_urls = str(args.get('updatedatabatch_filter_urls', ''))
    updatedatabatch_filter_users = str(args.get('updatedatabatch_filter_users', ''))
    updatedatabatch_filter = assign_params(Cache=updatedatabatch_filter_cache, andOp=updatedatabatch_filter_andop, category=updatedatabatch_filter_category, details=updatedatabatch_filter_details, files=updatedatabatch_filter_files, fromActivatedDate=updatedatabatch_filter_fromactivateddate, fromClosedDate=updatedatabatch_filter_fromcloseddate, fromDate=updatedatabatch_filter_fromdate, fromDateLicense=updatedatabatch_filter_fromdatelicense, fromDueDate=updatedatabatch_filter_fromduedate, fromReminder=updatedatabatch_filter_fromreminder, id=updatedatabatch_filter_id, ignoreWorkers=updatedatabatch_filter_ignoreworkers, includeTmp=updatedatabatch_filter_includetmp, investigation=updatedatabatch_filter_investigation, level=updatedatabatch_filter_level, name=updatedatabatch_filter_name, notCategory=updatedatabatch_filter_notcategory, notInvestigation=updatedatabatch_filter_notinvestigation,
                                           notStatus=updatedatabatch_filter_notstatus, page=updatedatabatch_filter_page, parent=updatedatabatch_filter_parent, period=updatedatabatch_filter_period, query=updatedatabatch_filter_query, reason=updatedatabatch_filter_reason, searchAfter=updatedatabatch_filter_searchafter, searchBefore=updatedatabatch_filter_searchbefore, size=updatedatabatch_filter_size, sort=updatedatabatch_filter_sort, status=updatedatabatch_filter_status, systems=updatedatabatch_filter_systems, timeFrame=updatedatabatch_filter_timeframe, toActivatedDate=updatedatabatch_filter_toactivateddate, toClosedDate=updatedatabatch_filter_tocloseddate, toDate=updatedatabatch_filter_todate, toDueDate=updatedatabatch_filter_toduedate, toReminder=updatedatabatch_filter_toreminder, totalOnly=updatedatabatch_filter_totalonly, type=updatedatabatch_filter_type, urls=updatedatabatch_filter_urls, users=updatedatabatch_filter_users)
    updatedatabatch_force = argToBoolean(args.get('updatedatabatch_force', False))
    updatedatabatch_ids = argToList(args.get('updatedatabatch_ids', []))
    updatedatabatch_line = str(args.get('updatedatabatch_line', ''))
    updatedatabatch_originalincidentid = str(args.get('updatedatabatch_originalincidentid', ''))
    updatedatabatch_overrideinvestigation = argToBoolean(args.get('updatedatabatch_overrideinvestigation', False))

    response = client.create_incidents_batch_request(updatedatabatch_customfields, updatedatabatch_all, updatedatabatch_closenotes, updatedatabatch_closereason, updatedatabatch_columns,
                                                     updatedatabatch_data, updatedatabatch_filter, updatedatabatch_force, updatedatabatch_ids, updatedatabatch_line, updatedatabatch_originalincidentid, updatedatabatch_overrideinvestigation)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IncidentSearchResponseWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_or_update_incident_type_command(client, args):
    incidenttype_autorun = argToBoolean(args.get('incidenttype_autorun', False))
    incidenttype_closurescript = str(args.get('incidenttype_closurescript', ''))
    incidenttype_color = str(args.get('incidenttype_color', ''))
    incidenttype_commitmessage = str(args.get('incidenttype_commitmessage', ''))
    incidenttype_days = args.get('incidenttype_days', None)
    incidenttype_daysr = args.get('incidenttype_daysr', None)
    incidenttype_default = argToBoolean(args.get('incidenttype_default', False))
    incidenttype_disabled = argToBoolean(args.get('incidenttype_disabled', False))
    incidenttype_fromserverversion_digits = str(args.get('incidenttype_fromserverversion_digits', ''))
    incidenttype_fromserverversion_label = str(args.get('incidenttype_fromserverversion_label', ''))
    incidenttype_fromserverversion = assign_params(
        Digits=incidenttype_fromserverversion_digits, Label=incidenttype_fromserverversion_label)
    incidenttype_hours = args.get('incidenttype_hours', None)
    incidenttype_hoursr = args.get('incidenttype_hoursr', None)
    incidenttype_id = str(args.get('incidenttype_id', ''))
    incidenttype_itemversion_digits = str(args.get('incidenttype_itemversion_digits', ''))
    incidenttype_itemversion_label = str(args.get('incidenttype_itemversion_label', ''))
    incidenttype_itemversion = assign_params(Digits=incidenttype_itemversion_digits, Label=incidenttype_itemversion_label)
    incidenttype_layout = str(args.get('incidenttype_layout', ''))
    incidenttype_locked = argToBoolean(args.get('incidenttype_locked', False))
    incidenttype_modified = str(args.get('incidenttype_modified', ''))
    incidenttype_name = str(args.get('incidenttype_name', ''))
    incidenttype_packid = str(args.get('incidenttype_packid', ''))
    incidenttype_packpropagationlabels = argToList(args.get('incidenttype_packpropagationlabels', []))
    incidenttype_playbookid = str(args.get('incidenttype_playbookid', ''))
    incidenttype_preprocessingscript = str(args.get('incidenttype_preprocessingscript', ''))
    incidenttype_prevname = str(args.get('incidenttype_prevname', ''))
    incidenttype_primaryterm = args.get('incidenttype_primaryterm', None)
    incidenttype_propagationlabels = argToList(args.get('incidenttype_propagationlabels', []))
    incidenttype_readonly = argToBoolean(args.get('incidenttype_readonly', False))
    incidenttype_reputationcalc = str(args.get('incidenttype_reputationcalc', ''))
    incidenttype_sequencenumber = args.get('incidenttype_sequencenumber', None)
    incidenttype_shouldcommit = argToBoolean(args.get('incidenttype_shouldcommit', False))
    incidenttype_sla = args.get('incidenttype_sla', None)
    incidenttype_slareminder = args.get('incidenttype_slareminder', None)
    incidenttype_sortvalues = argToList(args.get('incidenttype_sortvalues', []))
    incidenttype_system = argToBoolean(args.get('incidenttype_system', False))
    incidenttype_toserverversion_digits = str(args.get('incidenttype_toserverversion_digits', ''))
    incidenttype_toserverversion_label = str(args.get('incidenttype_toserverversion_label', ''))
    incidenttype_toserverversion = assign_params(
        Digits=incidenttype_toserverversion_digits, Label=incidenttype_toserverversion_label)
    incidenttype_vcshouldignore = argToBoolean(args.get('incidenttype_vcshouldignore', False))
    incidenttype_vcshouldkeepitemlegacyprodmachine = argToBoolean(
        args.get('incidenttype_vcshouldkeepitemlegacyprodmachine', False))
    incidenttype_version = args.get('incidenttype_version', None)
    incidenttype_weeks = args.get('incidenttype_weeks', None)
    incidenttype_weeksr = args.get('incidenttype_weeksr', None)

    response = client.create_or_update_incident_type_request(incidenttype_autorun, incidenttype_closurescript, incidenttype_color, incidenttype_commitmessage, incidenttype_days, incidenttype_daysr, incidenttype_default, incidenttype_disabled, incidenttype_fromserverversion, incidenttype_hours, incidenttype_hoursr, incidenttype_id, incidenttype_itemversion, incidenttype_layout, incidenttype_locked, incidenttype_modified, incidenttype_name, incidenttype_packid, incidenttype_packpropagationlabels,
                                                             incidenttype_playbookid, incidenttype_preprocessingscript, incidenttype_prevname, incidenttype_primaryterm, incidenttype_propagationlabels, incidenttype_readonly, incidenttype_reputationcalc, incidenttype_sequencenumber, incidenttype_shouldcommit, incidenttype_sla, incidenttype_slareminder, incidenttype_sortvalues, incidenttype_system, incidenttype_toserverversion, incidenttype_vcshouldignore, incidenttype_vcshouldkeepitemlegacyprodmachine, incidenttype_version, incidenttype_weeks, incidenttype_weeksr)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IncidentType',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def create_or_update_whitelisted_command(client, args):
    whitelistedindicator_id = str(args.get('whitelistedindicator_id', ''))
    whitelistedindicator_locked = argToBoolean(args.get('whitelistedindicator_locked', False))
    whitelistedindicator_modified = str(args.get('whitelistedindicator_modified', ''))
    whitelistedindicator_primaryterm = args.get('whitelistedindicator_primaryterm', None)
    whitelistedindicator_reason = str(args.get('whitelistedindicator_reason', ''))
    whitelistedindicator_reputations = argToList(args.get('whitelistedindicator_reputations', []))
    whitelistedindicator_sequencenumber = args.get('whitelistedindicator_sequencenumber', None)
    whitelistedindicator_sortvalues = argToList(args.get('whitelistedindicator_sortvalues', []))
    whitelistedindicator_type = str(args.get('whitelistedindicator_type', ''))
    whitelistedindicator_user = str(args.get('whitelistedindicator_user', ''))
    whitelistedindicator_value = str(args.get('whitelistedindicator_value', ''))
    whitelistedindicator_version = args.get('whitelistedindicator_version', None)
    whitelistedindicator_whitelisttime = str(args.get('whitelistedindicator_whitelisttime', ''))

    response = client.create_or_update_whitelisted_request(whitelistedindicator_id, whitelistedindicator_locked, whitelistedindicator_modified, whitelistedindicator_primaryterm, whitelistedindicator_reason, whitelistedindicator_reputations,
                                                           whitelistedindicator_sequencenumber, whitelistedindicator_sortvalues, whitelistedindicator_type, whitelistedindicator_user, whitelistedindicator_value, whitelistedindicator_version, whitelistedindicator_whitelisttime)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.WhitelistedIndicator',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_ad_hoc_task_command(client, args):
    investigationId = str(args.get('investigationId', ''))
    invPBTaskId = str(args.get('invPBTaskId', ''))

    response = client.delete_ad_hoc_task_request(investigationId, invPBTaskId)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_automation_script_command(client, args):
    automationscriptfilterwrapper_filter_cache = str(args.get('automationscriptfilterwrapper_filter_cache', ''))
    automationscriptfilterwrapper_filter_ignoreworkers = argToBoolean(
        args.get('automationscriptfilterwrapper_filter_ignoreworkers', False))
    automationscriptfilterwrapper_filter_page = args.get('automationscriptfilterwrapper_filter_page', None)
    automationscriptfilterwrapper_filter_query = str(args.get('automationscriptfilterwrapper_filter_query', ''))
    automationscriptfilterwrapper_filter_searchafter = str(args.get('automationscriptfilterwrapper_filter_searchafter', ''))
    automationscriptfilterwrapper_filter_searchbefore = str(args.get('automationscriptfilterwrapper_filter_searchbefore', ''))
    automationscriptfilterwrapper_filter_size = args.get('automationscriptfilterwrapper_filter_size', None)
    automationscriptfilterwrapper_filter_sort = str(args.get('automationscriptfilterwrapper_filter_sort', ''))
    automationscriptfilterwrapper_filter = assign_params(Cache=automationscriptfilterwrapper_filter_cache, ignoreWorkers=automationscriptfilterwrapper_filter_ignoreworkers, page=automationscriptfilterwrapper_filter_page, query=automationscriptfilterwrapper_filter_query,
                                                         searchAfter=automationscriptfilterwrapper_filter_searchafter, searchBefore=automationscriptfilterwrapper_filter_searchbefore, size=automationscriptfilterwrapper_filter_size, sort=automationscriptfilterwrapper_filter_sort)
    automationscriptfilterwrapper_savepassword = argToBoolean(args.get('automationscriptfilterwrapper_savepassword', False))
    automationscriptfilterwrapper_script_allread = argToBoolean(args.get('automationscriptfilterwrapper_script_allread', False))
    automationscriptfilterwrapper_script_allreadwrite = argToBoolean(
        args.get('automationscriptfilterwrapper_script_allreadwrite', False))
    automationscriptfilterwrapper_script_arguments = str(args.get('automationscriptfilterwrapper_script_arguments', ''))
    automationscriptfilterwrapper_script_comment = str(args.get('automationscriptfilterwrapper_script_comment', ''))
    automationscriptfilterwrapper_script_commitmessage = str(args.get('automationscriptfilterwrapper_script_commitmessage', ''))
    automationscriptfilterwrapper_script_contextkeys = str(args.get('automationscriptfilterwrapper_script_contextkeys', ''))
    automationscriptfilterwrapper_script_dbotcreatedby = str(args.get('automationscriptfilterwrapper_script_dbotcreatedby', ''))
    automationscriptfilterwrapper_script_dependson = str(args.get('automationscriptfilterwrapper_script_dependson', ''))
    automationscriptfilterwrapper_script_deprecated = argToBoolean(
        args.get('automationscriptfilterwrapper_script_deprecated', False))
    automationscriptfilterwrapper_script_detached = argToBoolean(args.get('automationscriptfilterwrapper_script_detached', False))
    automationscriptfilterwrapper_script_dockerimage = str(args.get('automationscriptfilterwrapper_script_dockerimage', ''))
    automationscriptfilterwrapper_script_enabled = argToBoolean(args.get('automationscriptfilterwrapper_script_enabled', False))
    automationscriptfilterwrapper_script_fromserverversion = str(
        args.get('automationscriptfilterwrapper_script_fromserverversion', ''))
    automationscriptfilterwrapper_script_hasrole = argToBoolean(args.get('automationscriptfilterwrapper_script_hasrole', False))
    automationscriptfilterwrapper_script_hidden = argToBoolean(args.get('automationscriptfilterwrapper_script_hidden', False))
    automationscriptfilterwrapper_script_id = str(args.get('automationscriptfilterwrapper_script_id', ''))
    automationscriptfilterwrapper_script_important = str(args.get('automationscriptfilterwrapper_script_important', ''))
    automationscriptfilterwrapper_script_itemversion = str(args.get('automationscriptfilterwrapper_script_itemversion', ''))
    automationscriptfilterwrapper_script_locked = argToBoolean(args.get('automationscriptfilterwrapper_script_locked', False))
    automationscriptfilterwrapper_script_modified = str(args.get('automationscriptfilterwrapper_script_modified', ''))
    automationscriptfilterwrapper_script_name = str(args.get('automationscriptfilterwrapper_script_name', ''))
    automationscriptfilterwrapper_script_outputs = str(args.get('automationscriptfilterwrapper_script_outputs', ''))
    automationscriptfilterwrapper_script_packid = str(args.get('automationscriptfilterwrapper_script_packid', ''))
    automationscriptfilterwrapper_script_packpropagationlabels = str(
        args.get('automationscriptfilterwrapper_script_packpropagationlabels', ''))
    automationscriptfilterwrapper_script_prevname = str(args.get('automationscriptfilterwrapper_script_prevname', ''))
    automationscriptfilterwrapper_script_previousallread = argToBoolean(
        args.get('automationscriptfilterwrapper_script_previousallread', False))
    automationscriptfilterwrapper_script_previousallreadwrite = argToBoolean(
        args.get('automationscriptfilterwrapper_script_previousallreadwrite', False))
    automationscriptfilterwrapper_script_previousroles = str(args.get('automationscriptfilterwrapper_script_previousroles', ''))
    automationscriptfilterwrapper_script_primaryterm = args.get('automationscriptfilterwrapper_script_primaryterm', None)
    automationscriptfilterwrapper_script_private = argToBoolean(args.get('automationscriptfilterwrapper_script_private', False))
    automationscriptfilterwrapper_script_propagationlabels = str(
        args.get('automationscriptfilterwrapper_script_propagationlabels', ''))
    automationscriptfilterwrapper_script_pswd = str(args.get('automationscriptfilterwrapper_script_pswd', ''))
    automationscriptfilterwrapper_script_rawtags = str(args.get('automationscriptfilterwrapper_script_rawtags', ''))
    automationscriptfilterwrapper_script_roles = str(args.get('automationscriptfilterwrapper_script_roles', ''))
    automationscriptfilterwrapper_script_runas = str(args.get('automationscriptfilterwrapper_script_runas', ''))
    automationscriptfilterwrapper_script_runonce = argToBoolean(args.get('automationscriptfilterwrapper_script_runonce', False))
    automationscriptfilterwrapper_script_script = str(args.get('automationscriptfilterwrapper_script_script', ''))
    automationscriptfilterwrapper_script_scripttarget = str(args.get('automationscriptfilterwrapper_script_scripttarget', ''))
    automationscriptfilterwrapper_script_searchablename = str(args.get('automationscriptfilterwrapper_script_searchablename', ''))
    automationscriptfilterwrapper_script_sensitive = argToBoolean(
        args.get('automationscriptfilterwrapper_script_sensitive', False))
    automationscriptfilterwrapper_script_sequencenumber = args.get('automationscriptfilterwrapper_script_sequencenumber', None)
    automationscriptfilterwrapper_script_shouldcommit = argToBoolean(
        args.get('automationscriptfilterwrapper_script_shouldcommit', False))
    automationscriptfilterwrapper_script_sortvalues = str(args.get('automationscriptfilterwrapper_script_sortvalues', ''))
    automationscriptfilterwrapper_script_sourcescripid = str(args.get('automationscriptfilterwrapper_script_sourcescripid', ''))
    automationscriptfilterwrapper_script_subtype = str(args.get('automationscriptfilterwrapper_script_subtype', ''))
    automationscriptfilterwrapper_script_system = argToBoolean(args.get('automationscriptfilterwrapper_script_system', False))
    automationscriptfilterwrapper_script_tags = str(args.get('automationscriptfilterwrapper_script_tags', ''))
    automationscriptfilterwrapper_script_timeout = str(args.get('automationscriptfilterwrapper_script_timeout', ''))
    automationscriptfilterwrapper_script_toserverversion = str(
        args.get('automationscriptfilterwrapper_script_toserverversion', ''))
    automationscriptfilterwrapper_script_type = str(args.get('automationscriptfilterwrapper_script_type', ''))
    automationscriptfilterwrapper_script_user = str(args.get('automationscriptfilterwrapper_script_user', ''))
    automationscriptfilterwrapper_script_vcshouldignore = argToBoolean(
        args.get('automationscriptfilterwrapper_script_vcshouldignore', False))
    automationscriptfilterwrapper_script_vcshouldkeepitemlegacyprodmachine = argToBoolean(
        args.get('automationscriptfilterwrapper_script_vcshouldkeepitemlegacyprodmachine', False))
    automationscriptfilterwrapper_script_version = args.get('automationscriptfilterwrapper_script_version', None)
    automationscriptfilterwrapper_script_visualscript = str(args.get('automationscriptfilterwrapper_script_visualscript', ''))
    automationscriptfilterwrapper_script_xsoarhasreadonlyrole = argToBoolean(
        args.get('automationscriptfilterwrapper_script_xsoarhasreadonlyrole', False))
    automationscriptfilterwrapper_script_xsoarpreviousreadonlyroles = str(
        args.get('automationscriptfilterwrapper_script_xsoarpreviousreadonlyroles', ''))
    automationscriptfilterwrapper_script_xsoarreadonlyroles = str(
        args.get('automationscriptfilterwrapper_script_xsoarreadonlyroles', ''))
    automationscriptfilterwrapper_script = assign_params(allRead=automationscriptfilterwrapper_script_allread, allReadWrite=automationscriptfilterwrapper_script_allreadwrite, arguments=automationscriptfilterwrapper_script_arguments, comment=automationscriptfilterwrapper_script_comment, commitMessage=automationscriptfilterwrapper_script_commitmessage, contextKeys=automationscriptfilterwrapper_script_contextkeys, dbotCreatedBy=automationscriptfilterwrapper_script_dbotcreatedby, dependsOn=automationscriptfilterwrapper_script_dependson, deprecated=automationscriptfilterwrapper_script_deprecated, detached=automationscriptfilterwrapper_script_detached, dockerImage=automationscriptfilterwrapper_script_dockerimage, enabled=automationscriptfilterwrapper_script_enabled, fromServerVersion=automationscriptfilterwrapper_script_fromserverversion, hasRole=automationscriptfilterwrapper_script_hasrole, hidden=automationscriptfilterwrapper_script_hidden, id=automationscriptfilterwrapper_script_id, important=automationscriptfilterwrapper_script_important, itemVersion=automationscriptfilterwrapper_script_itemversion, locked=automationscriptfilterwrapper_script_locked, modified=automationscriptfilterwrapper_script_modified, name=automationscriptfilterwrapper_script_name, outputs=automationscriptfilterwrapper_script_outputs, packID=automationscriptfilterwrapper_script_packid, packPropagationLabels=automationscriptfilterwrapper_script_packpropagationlabels, prevName=automationscriptfilterwrapper_script_prevname, previousAllRead=automationscriptfilterwrapper_script_previousallread, previousAllReadWrite=automationscriptfilterwrapper_script_previousallreadwrite, previousRoles=automationscriptfilterwrapper_script_previousroles, primaryTerm=automationscriptfilterwrapper_script_primaryterm,
                                                         private=automationscriptfilterwrapper_script_private, propagationLabels=automationscriptfilterwrapper_script_propagationlabels, pswd=automationscriptfilterwrapper_script_pswd, rawTags=automationscriptfilterwrapper_script_rawtags, roles=automationscriptfilterwrapper_script_roles, runAs=automationscriptfilterwrapper_script_runas, runOnce=automationscriptfilterwrapper_script_runonce, script=automationscriptfilterwrapper_script_script, scriptTarget=automationscriptfilterwrapper_script_scripttarget, searchableName=automationscriptfilterwrapper_script_searchablename, sensitive=automationscriptfilterwrapper_script_sensitive, sequenceNumber=automationscriptfilterwrapper_script_sequencenumber, shouldCommit=automationscriptfilterwrapper_script_shouldcommit, sortValues=automationscriptfilterwrapper_script_sortvalues, sourceScripID=automationscriptfilterwrapper_script_sourcescripid, subtype=automationscriptfilterwrapper_script_subtype, system=automationscriptfilterwrapper_script_system, tags=automationscriptfilterwrapper_script_tags, timeout=automationscriptfilterwrapper_script_timeout, toServerVersion=automationscriptfilterwrapper_script_toserverversion, type=automationscriptfilterwrapper_script_type, user=automationscriptfilterwrapper_script_user, vcShouldIgnore=automationscriptfilterwrapper_script_vcshouldignore, vcShouldKeepItemLegacyProdMachine=automationscriptfilterwrapper_script_vcshouldkeepitemlegacyprodmachine, version=automationscriptfilterwrapper_script_version, visualScript=automationscriptfilterwrapper_script_visualscript, xsoarHasReadOnlyRole=automationscriptfilterwrapper_script_xsoarhasreadonlyrole, xsoarPreviousReadOnlyRoles=automationscriptfilterwrapper_script_xsoarpreviousreadonlyroles, xsoarReadOnlyRoles=automationscriptfilterwrapper_script_xsoarreadonlyroles)

    response = client.delete_automation_script_request(
        automationscriptfilterwrapper_filter, automationscriptfilterwrapper_savepassword, automationscriptfilterwrapper_script)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_evidence_op_command(client, args):
    deleteevidence_evidenceid = str(args.get('deleteevidence_evidenceid', ''))

    response = client.delete_evidence_op_request(deleteevidence_evidenceid)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_incidents_batch_command(client, args):
    updatedatabatch_customfields = str(args.get('updatedatabatch_customfields', ''))
    updatedatabatch_all = argToBoolean(args.get('updatedatabatch_all', False))
    updatedatabatch_closenotes = str(args.get('updatedatabatch_closenotes', ''))
    updatedatabatch_closereason = str(args.get('updatedatabatch_closereason', ''))
    updatedatabatch_columns = argToList(args.get('updatedatabatch_columns', []))
    updatedatabatch_data = str(args.get('updatedatabatch_data', ''))
    updatedatabatch_filter_cache = str(args.get('updatedatabatch_filter_cache', ''))
    updatedatabatch_filter_andop = argToBoolean(args.get('updatedatabatch_filter_andop', False))
    updatedatabatch_filter_category = str(args.get('updatedatabatch_filter_category', ''))
    updatedatabatch_filter_details = str(args.get('updatedatabatch_filter_details', ''))
    updatedatabatch_filter_files = str(args.get('updatedatabatch_filter_files', ''))
    updatedatabatch_filter_fromactivateddate = str(args.get('updatedatabatch_filter_fromactivateddate', ''))
    updatedatabatch_filter_fromcloseddate = str(args.get('updatedatabatch_filter_fromcloseddate', ''))
    updatedatabatch_filter_fromdate = str(args.get('updatedatabatch_filter_fromdate', ''))
    updatedatabatch_filter_fromdatelicense = str(args.get('updatedatabatch_filter_fromdatelicense', ''))
    updatedatabatch_filter_fromduedate = str(args.get('updatedatabatch_filter_fromduedate', ''))
    updatedatabatch_filter_fromreminder = str(args.get('updatedatabatch_filter_fromreminder', ''))
    updatedatabatch_filter_id = str(args.get('updatedatabatch_filter_id', ''))
    updatedatabatch_filter_ignoreworkers = argToBoolean(args.get('updatedatabatch_filter_ignoreworkers', False))
    updatedatabatch_filter_includetmp = argToBoolean(args.get('updatedatabatch_filter_includetmp', False))
    updatedatabatch_filter_investigation = str(args.get('updatedatabatch_filter_investigation', ''))
    updatedatabatch_filter_level = str(args.get('updatedatabatch_filter_level', ''))
    updatedatabatch_filter_name = str(args.get('updatedatabatch_filter_name', ''))
    updatedatabatch_filter_notcategory = str(args.get('updatedatabatch_filter_notcategory', ''))
    updatedatabatch_filter_notinvestigation = str(args.get('updatedatabatch_filter_notinvestigation', ''))
    updatedatabatch_filter_notstatus = str(args.get('updatedatabatch_filter_notstatus', ''))
    updatedatabatch_filter_page = args.get('updatedatabatch_filter_page', None)
    updatedatabatch_filter_parent = str(args.get('updatedatabatch_filter_parent', ''))
    updatedatabatch_filter_period = str(args.get('updatedatabatch_filter_period', ''))
    updatedatabatch_filter_query = str(args.get('updatedatabatch_filter_query', ''))
    updatedatabatch_filter_reason = str(args.get('updatedatabatch_filter_reason', ''))
    updatedatabatch_filter_searchafter = str(args.get('updatedatabatch_filter_searchafter', ''))
    updatedatabatch_filter_searchbefore = str(args.get('updatedatabatch_filter_searchbefore', ''))
    updatedatabatch_filter_size = args.get('updatedatabatch_filter_size', None)
    updatedatabatch_filter_sort = str(args.get('updatedatabatch_filter_sort', ''))
    updatedatabatch_filter_status = str(args.get('updatedatabatch_filter_status', ''))
    updatedatabatch_filter_systems = str(args.get('updatedatabatch_filter_systems', ''))
    updatedatabatch_filter_timeframe = str(args.get('updatedatabatch_filter_timeframe', ''))
    updatedatabatch_filter_toactivateddate = str(args.get('updatedatabatch_filter_toactivateddate', ''))
    updatedatabatch_filter_tocloseddate = str(args.get('updatedatabatch_filter_tocloseddate', ''))
    updatedatabatch_filter_todate = str(args.get('updatedatabatch_filter_todate', ''))
    updatedatabatch_filter_toduedate = str(args.get('updatedatabatch_filter_toduedate', ''))
    updatedatabatch_filter_toreminder = str(args.get('updatedatabatch_filter_toreminder', ''))
    updatedatabatch_filter_totalonly = argToBoolean(args.get('updatedatabatch_filter_totalonly', False))
    updatedatabatch_filter_type = str(args.get('updatedatabatch_filter_type', ''))
    updatedatabatch_filter_urls = str(args.get('updatedatabatch_filter_urls', ''))
    updatedatabatch_filter_users = str(args.get('updatedatabatch_filter_users', ''))
    updatedatabatch_filter = assign_params(Cache=updatedatabatch_filter_cache, andOp=updatedatabatch_filter_andop, category=updatedatabatch_filter_category, details=updatedatabatch_filter_details, files=updatedatabatch_filter_files, fromActivatedDate=updatedatabatch_filter_fromactivateddate, fromClosedDate=updatedatabatch_filter_fromcloseddate, fromDate=updatedatabatch_filter_fromdate, fromDateLicense=updatedatabatch_filter_fromdatelicense, fromDueDate=updatedatabatch_filter_fromduedate, fromReminder=updatedatabatch_filter_fromreminder, id=updatedatabatch_filter_id, ignoreWorkers=updatedatabatch_filter_ignoreworkers, includeTmp=updatedatabatch_filter_includetmp, investigation=updatedatabatch_filter_investigation, level=updatedatabatch_filter_level, name=updatedatabatch_filter_name, notCategory=updatedatabatch_filter_notcategory, notInvestigation=updatedatabatch_filter_notinvestigation,
                                           notStatus=updatedatabatch_filter_notstatus, page=updatedatabatch_filter_page, parent=updatedatabatch_filter_parent, period=updatedatabatch_filter_period, query=updatedatabatch_filter_query, reason=updatedatabatch_filter_reason, searchAfter=updatedatabatch_filter_searchafter, searchBefore=updatedatabatch_filter_searchbefore, size=updatedatabatch_filter_size, sort=updatedatabatch_filter_sort, status=updatedatabatch_filter_status, systems=updatedatabatch_filter_systems, timeFrame=updatedatabatch_filter_timeframe, toActivatedDate=updatedatabatch_filter_toactivateddate, toClosedDate=updatedatabatch_filter_tocloseddate, toDate=updatedatabatch_filter_todate, toDueDate=updatedatabatch_filter_toduedate, toReminder=updatedatabatch_filter_toreminder, totalOnly=updatedatabatch_filter_totalonly, type=updatedatabatch_filter_type, urls=updatedatabatch_filter_urls, users=updatedatabatch_filter_users)
    updatedatabatch_force = argToBoolean(args.get('updatedatabatch_force', False))
    updatedatabatch_ids = argToList(args.get('updatedatabatch_ids', []))
    updatedatabatch_line = str(args.get('updatedatabatch_line', ''))
    updatedatabatch_originalincidentid = str(args.get('updatedatabatch_originalincidentid', ''))
    updatedatabatch_overrideinvestigation = argToBoolean(args.get('updatedatabatch_overrideinvestigation', False))

    response = client.delete_incidents_batch_request(updatedatabatch_customfields, updatedatabatch_all, updatedatabatch_closenotes, updatedatabatch_closereason, updatedatabatch_columns,
                                                     updatedatabatch_data, updatedatabatch_filter, updatedatabatch_force, updatedatabatch_ids, updatedatabatch_line, updatedatabatch_originalincidentid, updatedatabatch_overrideinvestigation)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IncidentSearchResponseWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_indicators_batch_command(client, args):
    genericindicatorupdatebatch_all = argToBoolean(args.get('genericindicatorupdatebatch_all', False))
    genericindicatorupdatebatch_columns = argToList(args.get('genericindicatorupdatebatch_columns', []))
    genericindicatorupdatebatch_donotwhitelist = argToBoolean(args.get('genericindicatorupdatebatch_donotwhitelist', False))
    genericindicatorupdatebatch_filter_cache = str(args.get('genericindicatorupdatebatch_filter_cache', ''))
    genericindicatorupdatebatch_filter_earlytimeinpage = str(args.get('genericindicatorupdatebatch_filter_earlytimeinpage', ''))
    genericindicatorupdatebatch_filter_firstseen = str(args.get('genericindicatorupdatebatch_filter_firstseen', ''))
    genericindicatorupdatebatch_filter_fromdate = str(args.get('genericindicatorupdatebatch_filter_fromdate', ''))
    genericindicatorupdatebatch_filter_fromdatelicense = str(args.get('genericindicatorupdatebatch_filter_fromdatelicense', ''))
    genericindicatorupdatebatch_filter_ignoreworkers = argToBoolean(
        args.get('genericindicatorupdatebatch_filter_ignoreworkers', False))
    genericindicatorupdatebatch_filter_lastseen = str(args.get('genericindicatorupdatebatch_filter_lastseen', ''))
    genericindicatorupdatebatch_filter_latertimeinpage = str(args.get('genericindicatorupdatebatch_filter_latertimeinpage', ''))
    genericindicatorupdatebatch_filter_page = args.get('genericindicatorupdatebatch_filter_page', None)
    genericindicatorupdatebatch_filter_period = str(args.get('genericindicatorupdatebatch_filter_period', ''))
    genericindicatorupdatebatch_filter_prevpage = argToBoolean(args.get('genericindicatorupdatebatch_filter_prevpage', False))
    genericindicatorupdatebatch_filter_query = str(args.get('genericindicatorupdatebatch_filter_query', ''))
    genericindicatorupdatebatch_filter_searchafter = str(args.get('genericindicatorupdatebatch_filter_searchafter', ''))
    genericindicatorupdatebatch_filter_searchbefore = str(args.get('genericindicatorupdatebatch_filter_searchbefore', ''))
    genericindicatorupdatebatch_filter_size = args.get('genericindicatorupdatebatch_filter_size', None)
    genericindicatorupdatebatch_filter_sort = str(args.get('genericindicatorupdatebatch_filter_sort', ''))
    genericindicatorupdatebatch_filter_timeframe = str(args.get('genericindicatorupdatebatch_filter_timeframe', ''))
    genericindicatorupdatebatch_filter_todate = str(args.get('genericindicatorupdatebatch_filter_todate', ''))
    genericindicatorupdatebatch_filter = assign_params(Cache=genericindicatorupdatebatch_filter_cache, earlyTimeInPage=genericindicatorupdatebatch_filter_earlytimeinpage, firstSeen=genericindicatorupdatebatch_filter_firstseen, fromDate=genericindicatorupdatebatch_filter_fromdate, fromDateLicense=genericindicatorupdatebatch_filter_fromdatelicense, ignoreWorkers=genericindicatorupdatebatch_filter_ignoreworkers, lastSeen=genericindicatorupdatebatch_filter_lastseen, laterTimeInPage=genericindicatorupdatebatch_filter_latertimeinpage,
                                                       page=genericindicatorupdatebatch_filter_page, period=genericindicatorupdatebatch_filter_period, prevPage=genericindicatorupdatebatch_filter_prevpage, query=genericindicatorupdatebatch_filter_query, searchAfter=genericindicatorupdatebatch_filter_searchafter, searchBefore=genericindicatorupdatebatch_filter_searchbefore, size=genericindicatorupdatebatch_filter_size, sort=genericindicatorupdatebatch_filter_sort, timeFrame=genericindicatorupdatebatch_filter_timeframe, toDate=genericindicatorupdatebatch_filter_todate)
    genericindicatorupdatebatch_ids = argToList(args.get('genericindicatorupdatebatch_ids', []))
    genericindicatorupdatebatch_reason = str(args.get('genericindicatorupdatebatch_reason', ''))
    genericindicatorupdatebatch_reputations = argToList(args.get('genericindicatorupdatebatch_reputations', []))

    response = client.delete_indicators_batch_request(genericindicatorupdatebatch_all, genericindicatorupdatebatch_columns, genericindicatorupdatebatch_donotwhitelist,
                                                      genericindicatorupdatebatch_filter, genericindicatorupdatebatch_ids, genericindicatorupdatebatch_reason, genericindicatorupdatebatch_reputations)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.UpdateResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def delete_widget_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.delete_widget_request(id_)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def download_file_command(client, args):
    entryid = str(args.get('entryid', ''))

    response = client.download_file_request(entryid)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def download_latest_report_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.download_latest_report_request(id_)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def edit_ad_hoc_task_command(client, args):
    invplaybooktaskdata_addafter = argToBoolean(args.get('invplaybooktaskdata_addafter', False))
    invplaybooktaskdata_automationscript = str(args.get('invplaybooktaskdata_automationscript', ''))
    invplaybooktaskdata_description = str(args.get('invplaybooktaskdata_description', ''))
    invplaybooktaskdata_loop_brand = str(args.get('invplaybooktaskdata_loop_brand', ''))
    invplaybooktaskdata_loop_builtincondition = str(args.get('invplaybooktaskdata_loop_builtincondition', ''))
    invplaybooktaskdata_loop_exitcondition = str(args.get('invplaybooktaskdata_loop_exitcondition', ''))
    invplaybooktaskdata_loop_foreach = argToBoolean(args.get('invplaybooktaskdata_loop_foreach', False))
    invplaybooktaskdata_loop_iscommand = argToBoolean(args.get('invplaybooktaskdata_loop_iscommand', False))
    invplaybooktaskdata_loop_max = args.get('invplaybooktaskdata_loop_max', None)
    invplaybooktaskdata_loop_scriptarguments = str(args.get('invplaybooktaskdata_loop_scriptarguments', ''))
    invplaybooktaskdata_loop_scriptid = str(args.get('invplaybooktaskdata_loop_scriptid', ''))
    invplaybooktaskdata_loop_scriptname = str(args.get('invplaybooktaskdata_loop_scriptname', ''))
    invplaybooktaskdata_loop_wait = args.get('invplaybooktaskdata_loop_wait', None)
    invplaybooktaskdata_loop = assign_params(brand=invplaybooktaskdata_loop_brand, builtinCondition=invplaybooktaskdata_loop_builtincondition, exitCondition=invplaybooktaskdata_loop_exitcondition, forEach=invplaybooktaskdata_loop_foreach,
                                             isCommand=invplaybooktaskdata_loop_iscommand, max=invplaybooktaskdata_loop_max, scriptArguments=invplaybooktaskdata_loop_scriptarguments, scriptId=invplaybooktaskdata_loop_scriptid, scriptName=invplaybooktaskdata_loop_scriptname, wait=invplaybooktaskdata_loop_wait)
    invplaybooktaskdata_name = str(args.get('invplaybooktaskdata_name', ''))
    invplaybooktaskdata_neighborinvpbtaskid = str(args.get('invplaybooktaskdata_neighborinvpbtaskid', ''))
    invplaybooktaskdata_playbookid = str(args.get('invplaybooktaskdata_playbookid', ''))
    invplaybooktaskdata_scriptarguments = str(args.get('invplaybooktaskdata_scriptarguments', ''))
    invplaybooktaskdata_tags = argToList(args.get('invplaybooktaskdata_tags', []))
    invplaybooktaskdata_type = str(args.get('invplaybooktaskdata_type', ''))
    investigationId = str(args.get('investigationId', ''))

    response = client.edit_ad_hoc_task_request(invplaybooktaskdata_addafter, invplaybooktaskdata_automationscript, invplaybooktaskdata_description, invplaybooktaskdata_loop, invplaybooktaskdata_name,
                                               invplaybooktaskdata_neighborinvpbtaskid, invplaybooktaskdata_playbookid, invplaybooktaskdata_scriptarguments, invplaybooktaskdata_tags, invplaybooktaskdata_type, investigationId)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def entry_export_artifact_command(client, args):
    downloadentry_id = str(args.get('downloadentry_id', ''))
    downloadentry_investigationid = str(args.get('downloadentry_investigationid', ''))

    response = client.entry_export_artifact_request(downloadentry_id, downloadentry_investigationid)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def execute_report_command(client, args):
    id_ = str(args.get('id', ''))
    requestId = str(args.get('requestId', ''))

    response = client.execute_report_request(id_, requestId)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def export_incidents_to_csv_batch_command(client, args):
    updatedatabatch_customfields = str(args.get('updatedatabatch_customfields', ''))
    updatedatabatch_all = argToBoolean(args.get('updatedatabatch_all', False))
    updatedatabatch_closenotes = str(args.get('updatedatabatch_closenotes', ''))
    updatedatabatch_closereason = str(args.get('updatedatabatch_closereason', ''))
    updatedatabatch_columns = argToList(args.get('updatedatabatch_columns', []))
    updatedatabatch_data = str(args.get('updatedatabatch_data', ''))
    updatedatabatch_filter_cache = str(args.get('updatedatabatch_filter_cache', ''))
    updatedatabatch_filter_andop = argToBoolean(args.get('updatedatabatch_filter_andop', False))
    updatedatabatch_filter_category = str(args.get('updatedatabatch_filter_category', ''))
    updatedatabatch_filter_details = str(args.get('updatedatabatch_filter_details', ''))
    updatedatabatch_filter_files = str(args.get('updatedatabatch_filter_files', ''))
    updatedatabatch_filter_fromactivateddate = str(args.get('updatedatabatch_filter_fromactivateddate', ''))
    updatedatabatch_filter_fromcloseddate = str(args.get('updatedatabatch_filter_fromcloseddate', ''))
    updatedatabatch_filter_fromdate = str(args.get('updatedatabatch_filter_fromdate', ''))
    updatedatabatch_filter_fromdatelicense = str(args.get('updatedatabatch_filter_fromdatelicense', ''))
    updatedatabatch_filter_fromduedate = str(args.get('updatedatabatch_filter_fromduedate', ''))
    updatedatabatch_filter_fromreminder = str(args.get('updatedatabatch_filter_fromreminder', ''))
    updatedatabatch_filter_id = str(args.get('updatedatabatch_filter_id', ''))
    updatedatabatch_filter_ignoreworkers = argToBoolean(args.get('updatedatabatch_filter_ignoreworkers', False))
    updatedatabatch_filter_includetmp = argToBoolean(args.get('updatedatabatch_filter_includetmp', False))
    updatedatabatch_filter_investigation = str(args.get('updatedatabatch_filter_investigation', ''))
    updatedatabatch_filter_level = str(args.get('updatedatabatch_filter_level', ''))
    updatedatabatch_filter_name = str(args.get('updatedatabatch_filter_name', ''))
    updatedatabatch_filter_notcategory = str(args.get('updatedatabatch_filter_notcategory', ''))
    updatedatabatch_filter_notinvestigation = str(args.get('updatedatabatch_filter_notinvestigation', ''))
    updatedatabatch_filter_notstatus = str(args.get('updatedatabatch_filter_notstatus', ''))
    updatedatabatch_filter_page = args.get('updatedatabatch_filter_page', None)
    updatedatabatch_filter_parent = str(args.get('updatedatabatch_filter_parent', ''))
    updatedatabatch_filter_period = str(args.get('updatedatabatch_filter_period', ''))
    updatedatabatch_filter_query = str(args.get('updatedatabatch_filter_query', ''))
    updatedatabatch_filter_reason = str(args.get('updatedatabatch_filter_reason', ''))
    updatedatabatch_filter_searchafter = str(args.get('updatedatabatch_filter_searchafter', ''))
    updatedatabatch_filter_searchbefore = str(args.get('updatedatabatch_filter_searchbefore', ''))
    updatedatabatch_filter_size = args.get('updatedatabatch_filter_size', None)
    updatedatabatch_filter_sort = str(args.get('updatedatabatch_filter_sort', ''))
    updatedatabatch_filter_status = str(args.get('updatedatabatch_filter_status', ''))
    updatedatabatch_filter_systems = str(args.get('updatedatabatch_filter_systems', ''))
    updatedatabatch_filter_timeframe = str(args.get('updatedatabatch_filter_timeframe', ''))
    updatedatabatch_filter_toactivateddate = str(args.get('updatedatabatch_filter_toactivateddate', ''))
    updatedatabatch_filter_tocloseddate = str(args.get('updatedatabatch_filter_tocloseddate', ''))
    updatedatabatch_filter_todate = str(args.get('updatedatabatch_filter_todate', ''))
    updatedatabatch_filter_toduedate = str(args.get('updatedatabatch_filter_toduedate', ''))
    updatedatabatch_filter_toreminder = str(args.get('updatedatabatch_filter_toreminder', ''))
    updatedatabatch_filter_totalonly = argToBoolean(args.get('updatedatabatch_filter_totalonly', False))
    updatedatabatch_filter_type = str(args.get('updatedatabatch_filter_type', ''))
    updatedatabatch_filter_urls = str(args.get('updatedatabatch_filter_urls', ''))
    updatedatabatch_filter_users = str(args.get('updatedatabatch_filter_users', ''))
    updatedatabatch_filter = assign_params(Cache=updatedatabatch_filter_cache, andOp=updatedatabatch_filter_andop, category=updatedatabatch_filter_category, details=updatedatabatch_filter_details, files=updatedatabatch_filter_files, fromActivatedDate=updatedatabatch_filter_fromactivateddate, fromClosedDate=updatedatabatch_filter_fromcloseddate, fromDate=updatedatabatch_filter_fromdate, fromDateLicense=updatedatabatch_filter_fromdatelicense, fromDueDate=updatedatabatch_filter_fromduedate, fromReminder=updatedatabatch_filter_fromreminder, id=updatedatabatch_filter_id, ignoreWorkers=updatedatabatch_filter_ignoreworkers, includeTmp=updatedatabatch_filter_includetmp, investigation=updatedatabatch_filter_investigation, level=updatedatabatch_filter_level, name=updatedatabatch_filter_name, notCategory=updatedatabatch_filter_notcategory, notInvestigation=updatedatabatch_filter_notinvestigation,
                                           notStatus=updatedatabatch_filter_notstatus, page=updatedatabatch_filter_page, parent=updatedatabatch_filter_parent, period=updatedatabatch_filter_period, query=updatedatabatch_filter_query, reason=updatedatabatch_filter_reason, searchAfter=updatedatabatch_filter_searchafter, searchBefore=updatedatabatch_filter_searchbefore, size=updatedatabatch_filter_size, sort=updatedatabatch_filter_sort, status=updatedatabatch_filter_status, systems=updatedatabatch_filter_systems, timeFrame=updatedatabatch_filter_timeframe, toActivatedDate=updatedatabatch_filter_toactivateddate, toClosedDate=updatedatabatch_filter_tocloseddate, toDate=updatedatabatch_filter_todate, toDueDate=updatedatabatch_filter_toduedate, toReminder=updatedatabatch_filter_toreminder, totalOnly=updatedatabatch_filter_totalonly, type=updatedatabatch_filter_type, urls=updatedatabatch_filter_urls, users=updatedatabatch_filter_users)
    updatedatabatch_force = argToBoolean(args.get('updatedatabatch_force', False))
    updatedatabatch_ids = argToList(args.get('updatedatabatch_ids', []))
    updatedatabatch_line = str(args.get('updatedatabatch_line', ''))
    updatedatabatch_originalincidentid = str(args.get('updatedatabatch_originalincidentid', ''))
    updatedatabatch_overrideinvestigation = argToBoolean(args.get('updatedatabatch_overrideinvestigation', False))

    response = client.export_incidents_to_csv_batch_request(updatedatabatch_customfields, updatedatabatch_all, updatedatabatch_closenotes, updatedatabatch_closereason, updatedatabatch_columns,
                                                            updatedatabatch_data, updatedatabatch_filter, updatedatabatch_force, updatedatabatch_ids, updatedatabatch_line, updatedatabatch_originalincidentid, updatedatabatch_overrideinvestigation)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def export_indicators_to_csv_batch_command(client, args):
    genericindicatorupdatebatch_all = argToBoolean(args.get('genericindicatorupdatebatch_all', False))
    genericindicatorupdatebatch_columns = argToList(args.get('genericindicatorupdatebatch_columns', []))
    genericindicatorupdatebatch_donotwhitelist = argToBoolean(args.get('genericindicatorupdatebatch_donotwhitelist', False))
    genericindicatorupdatebatch_filter_cache = str(args.get('genericindicatorupdatebatch_filter_cache', ''))
    genericindicatorupdatebatch_filter_earlytimeinpage = str(args.get('genericindicatorupdatebatch_filter_earlytimeinpage', ''))
    genericindicatorupdatebatch_filter_firstseen = str(args.get('genericindicatorupdatebatch_filter_firstseen', ''))
    genericindicatorupdatebatch_filter_fromdate = str(args.get('genericindicatorupdatebatch_filter_fromdate', ''))
    genericindicatorupdatebatch_filter_fromdatelicense = str(args.get('genericindicatorupdatebatch_filter_fromdatelicense', ''))
    genericindicatorupdatebatch_filter_ignoreworkers = argToBoolean(
        args.get('genericindicatorupdatebatch_filter_ignoreworkers', False))
    genericindicatorupdatebatch_filter_lastseen = str(args.get('genericindicatorupdatebatch_filter_lastseen', ''))
    genericindicatorupdatebatch_filter_latertimeinpage = str(args.get('genericindicatorupdatebatch_filter_latertimeinpage', ''))
    genericindicatorupdatebatch_filter_page = args.get('genericindicatorupdatebatch_filter_page', None)
    genericindicatorupdatebatch_filter_period = str(args.get('genericindicatorupdatebatch_filter_period', ''))
    genericindicatorupdatebatch_filter_prevpage = argToBoolean(args.get('genericindicatorupdatebatch_filter_prevpage', False))
    genericindicatorupdatebatch_filter_query = str(args.get('genericindicatorupdatebatch_filter_query', ''))
    genericindicatorupdatebatch_filter_searchafter = str(args.get('genericindicatorupdatebatch_filter_searchafter', ''))
    genericindicatorupdatebatch_filter_searchbefore = str(args.get('genericindicatorupdatebatch_filter_searchbefore', ''))
    genericindicatorupdatebatch_filter_size = args.get('genericindicatorupdatebatch_filter_size', None)
    genericindicatorupdatebatch_filter_sort = str(args.get('genericindicatorupdatebatch_filter_sort', ''))
    genericindicatorupdatebatch_filter_timeframe = str(args.get('genericindicatorupdatebatch_filter_timeframe', ''))
    genericindicatorupdatebatch_filter_todate = str(args.get('genericindicatorupdatebatch_filter_todate', ''))
    genericindicatorupdatebatch_filter = assign_params(Cache=genericindicatorupdatebatch_filter_cache, earlyTimeInPage=genericindicatorupdatebatch_filter_earlytimeinpage, firstSeen=genericindicatorupdatebatch_filter_firstseen, fromDate=genericindicatorupdatebatch_filter_fromdate, fromDateLicense=genericindicatorupdatebatch_filter_fromdatelicense, ignoreWorkers=genericindicatorupdatebatch_filter_ignoreworkers, lastSeen=genericindicatorupdatebatch_filter_lastseen, laterTimeInPage=genericindicatorupdatebatch_filter_latertimeinpage,
                                                       page=genericindicatorupdatebatch_filter_page, period=genericindicatorupdatebatch_filter_period, prevPage=genericindicatorupdatebatch_filter_prevpage, query=genericindicatorupdatebatch_filter_query, searchAfter=genericindicatorupdatebatch_filter_searchafter, searchBefore=genericindicatorupdatebatch_filter_searchbefore, size=genericindicatorupdatebatch_filter_size, sort=genericindicatorupdatebatch_filter_sort, timeFrame=genericindicatorupdatebatch_filter_timeframe, toDate=genericindicatorupdatebatch_filter_todate)
    genericindicatorupdatebatch_ids = argToList(args.get('genericindicatorupdatebatch_ids', []))
    genericindicatorupdatebatch_reason = str(args.get('genericindicatorupdatebatch_reason', ''))
    genericindicatorupdatebatch_reputations = argToList(args.get('genericindicatorupdatebatch_reputations', []))

    response = client.export_indicators_to_csv_batch_request(genericindicatorupdatebatch_all, genericindicatorupdatebatch_columns, genericindicatorupdatebatch_donotwhitelist,
                                                             genericindicatorupdatebatch_filter, genericindicatorupdatebatch_ids, genericindicatorupdatebatch_reason, genericindicatorupdatebatch_reputations)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def export_indicators_to_stix_batch_command(client, args):
    genericindicatorupdatebatch_all = argToBoolean(args.get('genericindicatorupdatebatch_all', False))
    genericindicatorupdatebatch_columns = argToList(args.get('genericindicatorupdatebatch_columns', []))
    genericindicatorupdatebatch_donotwhitelist = argToBoolean(args.get('genericindicatorupdatebatch_donotwhitelist', False))
    genericindicatorupdatebatch_filter_cache = str(args.get('genericindicatorupdatebatch_filter_cache', ''))
    genericindicatorupdatebatch_filter_earlytimeinpage = str(args.get('genericindicatorupdatebatch_filter_earlytimeinpage', ''))
    genericindicatorupdatebatch_filter_firstseen = str(args.get('genericindicatorupdatebatch_filter_firstseen', ''))
    genericindicatorupdatebatch_filter_fromdate = str(args.get('genericindicatorupdatebatch_filter_fromdate', ''))
    genericindicatorupdatebatch_filter_fromdatelicense = str(args.get('genericindicatorupdatebatch_filter_fromdatelicense', ''))
    genericindicatorupdatebatch_filter_ignoreworkers = argToBoolean(
        args.get('genericindicatorupdatebatch_filter_ignoreworkers', False))
    genericindicatorupdatebatch_filter_lastseen = str(args.get('genericindicatorupdatebatch_filter_lastseen', ''))
    genericindicatorupdatebatch_filter_latertimeinpage = str(args.get('genericindicatorupdatebatch_filter_latertimeinpage', ''))
    genericindicatorupdatebatch_filter_page = args.get('genericindicatorupdatebatch_filter_page', None)
    genericindicatorupdatebatch_filter_period = str(args.get('genericindicatorupdatebatch_filter_period', ''))
    genericindicatorupdatebatch_filter_prevpage = argToBoolean(args.get('genericindicatorupdatebatch_filter_prevpage', False))
    genericindicatorupdatebatch_filter_query = str(args.get('genericindicatorupdatebatch_filter_query', ''))
    genericindicatorupdatebatch_filter_searchafter = str(args.get('genericindicatorupdatebatch_filter_searchafter', ''))
    genericindicatorupdatebatch_filter_searchbefore = str(args.get('genericindicatorupdatebatch_filter_searchbefore', ''))
    genericindicatorupdatebatch_filter_size = args.get('genericindicatorupdatebatch_filter_size', None)
    genericindicatorupdatebatch_filter_sort = str(args.get('genericindicatorupdatebatch_filter_sort', ''))
    genericindicatorupdatebatch_filter_timeframe = str(args.get('genericindicatorupdatebatch_filter_timeframe', ''))
    genericindicatorupdatebatch_filter_todate = str(args.get('genericindicatorupdatebatch_filter_todate', ''))
    genericindicatorupdatebatch_filter = assign_params(Cache=genericindicatorupdatebatch_filter_cache, earlyTimeInPage=genericindicatorupdatebatch_filter_earlytimeinpage, firstSeen=genericindicatorupdatebatch_filter_firstseen, fromDate=genericindicatorupdatebatch_filter_fromdate, fromDateLicense=genericindicatorupdatebatch_filter_fromdatelicense, ignoreWorkers=genericindicatorupdatebatch_filter_ignoreworkers, lastSeen=genericindicatorupdatebatch_filter_lastseen, laterTimeInPage=genericindicatorupdatebatch_filter_latertimeinpage,
                                                       page=genericindicatorupdatebatch_filter_page, period=genericindicatorupdatebatch_filter_period, prevPage=genericindicatorupdatebatch_filter_prevpage, query=genericindicatorupdatebatch_filter_query, searchAfter=genericindicatorupdatebatch_filter_searchafter, searchBefore=genericindicatorupdatebatch_filter_searchbefore, size=genericindicatorupdatebatch_filter_size, sort=genericindicatorupdatebatch_filter_sort, timeFrame=genericindicatorupdatebatch_filter_timeframe, toDate=genericindicatorupdatebatch_filter_todate)
    genericindicatorupdatebatch_ids = argToList(args.get('genericindicatorupdatebatch_ids', []))
    genericindicatorupdatebatch_reason = str(args.get('genericindicatorupdatebatch_reason', ''))
    genericindicatorupdatebatch_reputations = argToList(args.get('genericindicatorupdatebatch_reputations', []))

    response = client.export_indicators_to_stix_batch_request(genericindicatorupdatebatch_all, genericindicatorupdatebatch_columns, genericindicatorupdatebatch_donotwhitelist,
                                                              genericindicatorupdatebatch_filter, genericindicatorupdatebatch_ids, genericindicatorupdatebatch_reason, genericindicatorupdatebatch_reputations)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_all_reports_command(client, args):

    response = client.get_all_reports_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Report',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_all_widgets_command(client, args):

    response = client.get_all_widgets_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Widget',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_audits_command(client, args):
    genericstringdatefilter_cache = str(args.get('genericstringdatefilter_cache', ''))
    genericstringdatefilter_fromdate = str(args.get('genericstringdatefilter_fromdate', ''))
    genericstringdatefilter_fromdatelicense = str(args.get('genericstringdatefilter_fromdatelicense', ''))
    genericstringdatefilter_ignoreworkers = argToBoolean(args.get('genericstringdatefilter_ignoreworkers', False))
    genericstringdatefilter_page = args.get('genericstringdatefilter_page', None)
    genericstringdatefilter_period_by = str(args.get('genericstringdatefilter_period_by', ''))
    genericstringdatefilter_period_byfrom = str(args.get('genericstringdatefilter_period_byfrom', ''))
    genericstringdatefilter_period_byto = str(args.get('genericstringdatefilter_period_byto', ''))
    genericstringdatefilter_period_field = str(args.get('genericstringdatefilter_period_field', ''))
    genericstringdatefilter_period_fromvalue = str(args.get('genericstringdatefilter_period_fromvalue', ''))
    genericstringdatefilter_period_tovalue = str(args.get('genericstringdatefilter_period_tovalue', ''))
    genericstringdatefilter_period = assign_params(by=genericstringdatefilter_period_by, byFrom=genericstringdatefilter_period_byfrom, byTo=genericstringdatefilter_period_byto,
                                                   field=genericstringdatefilter_period_field, fromValue=genericstringdatefilter_period_fromvalue, toValue=genericstringdatefilter_period_tovalue)
    genericstringdatefilter_query = str(args.get('genericstringdatefilter_query', ''))
    genericstringdatefilter_searchafter = argToList(args.get('genericstringdatefilter_searchafter', []))
    genericstringdatefilter_searchbefore = argToList(args.get('genericstringdatefilter_searchbefore', []))
    genericstringdatefilter_size = args.get('genericstringdatefilter_size', None)
    genericstringdatefilter_sort = argToList(args.get('genericstringdatefilter_sort', []))
    genericstringdatefilter_timeframe = str(args.get('genericstringdatefilter_timeframe', ''))
    genericstringdatefilter_todate = str(args.get('genericstringdatefilter_todate', ''))

    response = client.get_audits_request(genericstringdatefilter_cache, genericstringdatefilter_fromdate, genericstringdatefilter_fromdatelicense, genericstringdatefilter_ignoreworkers, genericstringdatefilter_page, genericstringdatefilter_period,
                                         genericstringdatefilter_query, genericstringdatefilter_searchafter, genericstringdatefilter_searchbefore, genericstringdatefilter_size, genericstringdatefilter_sort, genericstringdatefilter_timeframe, genericstringdatefilter_todate)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.auditResult',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_automation_scripts_command(client, args):
    automationscriptfilter_cache = str(args.get('automationscriptfilter_cache', ''))
    automationscriptfilter_ignoreworkers = argToBoolean(args.get('automationscriptfilter_ignoreworkers', False))
    automationscriptfilter_page = args.get('automationscriptfilter_page', None)
    automationscriptfilter_query = str(args.get('automationscriptfilter_query', ''))
    automationscriptfilter_searchafter = argToList(args.get('automationscriptfilter_searchafter', []))
    automationscriptfilter_searchbefore = argToList(args.get('automationscriptfilter_searchbefore', []))
    automationscriptfilter_size = args.get('automationscriptfilter_size', None)
    automationscriptfilter_sort = argToList(args.get('automationscriptfilter_sort', []))
    automationscriptfilter_stripcontext = argToBoolean(args.get('automationscriptfilter_stripcontext', False))

    response = client.get_automation_scripts_request(automationscriptfilter_cache, automationscriptfilter_ignoreworkers, automationscriptfilter_page, automationscriptfilter_query,
                                                     automationscriptfilter_searchafter, automationscriptfilter_searchbefore, automationscriptfilter_size, automationscriptfilter_sort, automationscriptfilter_stripcontext)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.automationScriptResult',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_containers_command(client, args):

    response = client.get_containers_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.containersInfo',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_docker_images_command(client, args):

    response = client.get_docker_images_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.dockerImagesResult',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_entry_artifact_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.get_entry_artifact_request(id_)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_incident_as_csv_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.get_incident_as_csv_request(id_)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_incidents_fields_by_incident_type_command(client, args):
    type_ = str(args.get('type', ''))

    response = client.get_incidents_fields_by_incident_type_request(type_)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IncidentField',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_indicators_as_csv_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.get_indicators_as_csv_request(id_)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_indicators_asstix_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.get_indicators_asstix_request(id_)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_report_byid_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.get_report_byid_request(id_)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Report',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_stats_for_dashboard_command(client, args):

    response = client.get_stats_for_dashboard_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.StatsQueryResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_stats_for_widget_command(client, args):

    response = client.get_stats_for_widget_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_widget_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.get_widget_request(id_)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Widget',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def health_handler_command(client, args):

    response = client.health_handler_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_classifier_command(client, args):
    file = str(args.get('file', ''))

    response = client.import_classifier_request(file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InstanceClassifier',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_dashboard_command(client, args):
    file = str(args.get('file', ''))

    response = client.import_dashboard_request(file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Dashboard',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_incident_fields_command(client, args):
    file = str(args.get('file', ''))

    response = client.import_incident_fields_request(file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.incidentFieldsWithErrors',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_incident_types_handler_command(client, args):
    file = str(args.get('file', ''))

    response = client.import_incident_types_handler_request(file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.incidentTypesWithErrors',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_script_command(client, args):
    file = str(args.get('file', ''))

    response = client.import_script_request(file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.AutomationScript',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def import_widget_command(client, args):
    file = str(args.get('file', ''))

    response = client.import_widget_request(file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Widget',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def incident_file_upload_command(client, args):
    id_ = str(args.get('id', ''))
    fileName = str(args.get('fileName', ''))
    fileComment = str(args.get('fileComment', ''))
    field = str(args.get('field', ''))
    showMediaFile = argToBoolean(args.get('showMediaFile', False))
    last = argToBoolean(args.get('last', False))
    file = str(args.get('file', ''))

    response = client.incident_file_upload_request(id_, fileName, fileComment, field, showMediaFile, last, file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IncidentWrapper',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicator_whitelist_command(client, args):

    response = client.indicator_whitelist_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.UpdateResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicators_create_command(client, args):
    indicatorcontext_entryid = str(args.get('indicatorcontext_entryid', ''))
    indicatorcontext_indicator_customfields = str(args.get('indicatorcontext_indicator_customfields', ''))
    indicatorcontext_indicator_account = str(args.get('indicatorcontext_indicator_account', ''))
    indicatorcontext_indicator_aggregatedreliability = str(args.get('indicatorcontext_indicator_aggregatedreliability', ''))
    indicatorcontext_indicator_calculatedtime = str(args.get('indicatorcontext_indicator_calculatedtime', ''))
    indicatorcontext_indicator_comment = str(args.get('indicatorcontext_indicator_comment', ''))
    indicatorcontext_indicator_comments = str(args.get('indicatorcontext_indicator_comments', ''))
    indicatorcontext_indicator_deletedfeedfetchtime = str(args.get('indicatorcontext_indicator_deletedfeedfetchtime', ''))
    indicatorcontext_indicator_expiration = str(args.get('indicatorcontext_indicator_expiration', ''))
    indicatorcontext_indicator_expirationsource = str(args.get('indicatorcontext_indicator_expirationsource', ''))
    indicatorcontext_indicator_expirationstatus = str(args.get('indicatorcontext_indicator_expirationstatus', ''))
    indicatorcontext_indicator_firstseen = str(args.get('indicatorcontext_indicator_firstseen', ''))
    indicatorcontext_indicator_firstseenentryid = str(args.get('indicatorcontext_indicator_firstseenentryid', ''))
    indicatorcontext_indicator_id = str(args.get('indicatorcontext_indicator_id', ''))
    indicatorcontext_indicator_indicator_type = str(args.get('indicatorcontext_indicator_indicator_type', ''))
    indicatorcontext_indicator_insightcache = str(args.get('indicatorcontext_indicator_insightcache', ''))
    indicatorcontext_indicator_investigationids = str(args.get('indicatorcontext_indicator_investigationids', ''))
    indicatorcontext_indicator_isshared = argToBoolean(args.get('indicatorcontext_indicator_isshared', False))
    indicatorcontext_indicator_lastreputationrun = str(args.get('indicatorcontext_indicator_lastreputationrun', ''))
    indicatorcontext_indicator_lastseen = str(args.get('indicatorcontext_indicator_lastseen', ''))
    indicatorcontext_indicator_lastseenentryid = str(args.get('indicatorcontext_indicator_lastseenentryid', ''))
    indicatorcontext_indicator_manualexpirationtime = str(args.get('indicatorcontext_indicator_manualexpirationtime', ''))
    indicatorcontext_indicator_manualscore = argToBoolean(args.get('indicatorcontext_indicator_manualscore', False))
    indicatorcontext_indicator_manualsettime = str(args.get('indicatorcontext_indicator_manualsettime', ''))
    indicatorcontext_indicator_manuallyeditedfields = str(args.get('indicatorcontext_indicator_manuallyeditedfields', ''))
    indicatorcontext_indicator_modified = str(args.get('indicatorcontext_indicator_modified', ''))
    indicatorcontext_indicator_modifiedtime = str(args.get('indicatorcontext_indicator_modifiedtime', ''))
    indicatorcontext_indicator_moduletofeedmap = str(args.get('indicatorcontext_indicator_moduletofeedmap', ''))
    indicatorcontext_indicator_primaryterm = args.get('indicatorcontext_indicator_primaryterm', None)
    indicatorcontext_indicator_relatedinccount = args.get('indicatorcontext_indicator_relatedinccount', None)
    indicatorcontext_indicator_score = args.get('indicatorcontext_indicator_score', None)
    indicatorcontext_indicator_sequencenumber = args.get('indicatorcontext_indicator_sequencenumber', None)
    indicatorcontext_indicator_setby = str(args.get('indicatorcontext_indicator_setby', ''))
    indicatorcontext_indicator_sortvalues = str(args.get('indicatorcontext_indicator_sortvalues', ''))
    indicatorcontext_indicator_source = str(args.get('indicatorcontext_indicator_source', ''))
    indicatorcontext_indicator_sourcebrands = str(args.get('indicatorcontext_indicator_sourcebrands', ''))
    indicatorcontext_indicator_sourceinstances = str(args.get('indicatorcontext_indicator_sourceinstances', ''))
    indicatorcontext_indicator_timestamp = str(args.get('indicatorcontext_indicator_timestamp', ''))
    indicatorcontext_indicator_value = str(args.get('indicatorcontext_indicator_value', ''))
    indicatorcontext_indicator_version = args.get('indicatorcontext_indicator_version', None)
    indicatorcontext_indicator = assign_params(CustomFields=indicatorcontext_indicator_customfields, account=indicatorcontext_indicator_account, aggregatedReliability=indicatorcontext_indicator_aggregatedreliability, calculatedTime=indicatorcontext_indicator_calculatedtime, comment=indicatorcontext_indicator_comment, comments=indicatorcontext_indicator_comments, deletedFeedFetchTime=indicatorcontext_indicator_deletedfeedfetchtime, expiration=indicatorcontext_indicator_expiration, expirationSource=indicatorcontext_indicator_expirationsource, expirationStatus=indicatorcontext_indicator_expirationstatus, firstSeen=indicatorcontext_indicator_firstseen, firstSeenEntryID=indicatorcontext_indicator_firstseenentryid, id=indicatorcontext_indicator_id, indicator_type=indicatorcontext_indicator_indicator_type, insightCache=indicatorcontext_indicator_insightcache, investigationIDs=indicatorcontext_indicator_investigationids, isShared=indicatorcontext_indicator_isshared, lastReputationRun=indicatorcontext_indicator_lastreputationrun, lastSeen=indicatorcontext_indicator_lastseen,
                                               lastSeenEntryID=indicatorcontext_indicator_lastseenentryid, manualExpirationTime=indicatorcontext_indicator_manualexpirationtime, manualScore=indicatorcontext_indicator_manualscore, manualSetTime=indicatorcontext_indicator_manualsettime, manuallyEditedFields=indicatorcontext_indicator_manuallyeditedfields, modified=indicatorcontext_indicator_modified, modifiedTime=indicatorcontext_indicator_modifiedtime, moduleToFeedMap=indicatorcontext_indicator_moduletofeedmap, primaryTerm=indicatorcontext_indicator_primaryterm, relatedIncCount=indicatorcontext_indicator_relatedinccount, score=indicatorcontext_indicator_score, sequenceNumber=indicatorcontext_indicator_sequencenumber, setBy=indicatorcontext_indicator_setby, sortValues=indicatorcontext_indicator_sortvalues, source=indicatorcontext_indicator_source, sourceBrands=indicatorcontext_indicator_sourcebrands, sourceInstances=indicatorcontext_indicator_sourceinstances, timestamp=indicatorcontext_indicator_timestamp, value=indicatorcontext_indicator_value, version=indicatorcontext_indicator_version)
    indicatorcontext_investigationid = str(args.get('indicatorcontext_investigationid', ''))
    indicatorcontext_seennow = argToBoolean(args.get('indicatorcontext_seennow', False))

    response = client.indicators_create_request(
        indicatorcontext_entryid, indicatorcontext_indicator, indicatorcontext_investigationid, indicatorcontext_seennow)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IocObject',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicators_create_batch_command(client, args):
    fileName = str(args.get('fileName', ''))
    file = str(args.get('file', ''))

    response = client.indicators_create_batch_request(fileName, file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IocObjects',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicators_edit_command(client, args):
    iocobject_customfields = str(args.get('iocobject_customfields', ''))
    iocobject_account = str(args.get('iocobject_account', ''))
    iocobject_aggregatedreliability = str(args.get('iocobject_aggregatedreliability', ''))
    iocobject_calculatedtime = str(args.get('iocobject_calculatedtime', ''))
    iocobject_comment = str(args.get('iocobject_comment', ''))
    iocobject_comments = str(args.get('iocobject_comments', ''))
    iocobject_deletedfeedfetchtime = str(args.get('iocobject_deletedfeedfetchtime', ''))
    iocobject_expiration = str(args.get('iocobject_expiration', ''))
    iocobject_expirationsource_brand = str(args.get('iocobject_expirationsource_brand', ''))
    iocobject_expirationsource_expirationinterval = args.get('iocobject_expirationsource_expirationinterval', None)
    iocobject_expirationsource_expirationpolicy = str(args.get('iocobject_expirationsource_expirationpolicy', ''))
    iocobject_expirationsource_instance = str(args.get('iocobject_expirationsource_instance', ''))
    iocobject_expirationsource_moduleid = str(args.get('iocobject_expirationsource_moduleid', ''))
    iocobject_expirationsource_settime = str(args.get('iocobject_expirationsource_settime', ''))
    iocobject_expirationsource_source = str(args.get('iocobject_expirationsource_source', ''))
    iocobject_expirationsource_user = str(args.get('iocobject_expirationsource_user', ''))
    iocobject_expirationsource = assign_params(brand=iocobject_expirationsource_brand, expirationInterval=iocobject_expirationsource_expirationinterval, expirationPolicy=iocobject_expirationsource_expirationpolicy,
                                               instance=iocobject_expirationsource_instance, moduleId=iocobject_expirationsource_moduleid, setTime=iocobject_expirationsource_settime, source=iocobject_expirationsource_source, user=iocobject_expirationsource_user)
    iocobject_expirationstatus = str(args.get('iocobject_expirationstatus', ''))
    iocobject_firstseen = str(args.get('iocobject_firstseen', ''))
    iocobject_firstseenentryid = str(args.get('iocobject_firstseenentryid', ''))
    iocobject_id = str(args.get('iocobject_id', ''))
    iocobject_indicator_type = str(args.get('iocobject_indicator_type', ''))
    iocobject_insightcache_id = str(args.get('iocobject_insightcache_id', ''))
    iocobject_insightcache_modified = str(args.get('iocobject_insightcache_modified', ''))
    iocobject_insightcache_primaryterm = args.get('iocobject_insightcache_primaryterm', None)
    iocobject_insightcache_scores = str(args.get('iocobject_insightcache_scores', ''))
    iocobject_insightcache_sequencenumber = args.get('iocobject_insightcache_sequencenumber', None)
    iocobject_insightcache_sortvalues = str(args.get('iocobject_insightcache_sortvalues', ''))
    iocobject_insightcache_version = args.get('iocobject_insightcache_version', None)
    iocobject_insightcache = assign_params(id=iocobject_insightcache_id, modified=iocobject_insightcache_modified, primaryTerm=iocobject_insightcache_primaryterm,
                                           scores=iocobject_insightcache_scores, sequenceNumber=iocobject_insightcache_sequencenumber, sortValues=iocobject_insightcache_sortvalues, version=iocobject_insightcache_version)
    iocobject_investigationids = argToList(args.get('iocobject_investigationids', []))
    iocobject_isshared = argToBoolean(args.get('iocobject_isshared', False))
    iocobject_lastreputationrun = str(args.get('iocobject_lastreputationrun', ''))
    iocobject_lastseen = str(args.get('iocobject_lastseen', ''))
    iocobject_lastseenentryid = str(args.get('iocobject_lastseenentryid', ''))
    iocobject_manualexpirationtime = str(args.get('iocobject_manualexpirationtime', ''))
    iocobject_manualscore = argToBoolean(args.get('iocobject_manualscore', False))
    iocobject_manualsettime = str(args.get('iocobject_manualsettime', ''))
    iocobject_manuallyeditedfields = argToList(args.get('iocobject_manuallyeditedfields', []))
    iocobject_modified = str(args.get('iocobject_modified', ''))
    iocobject_modifiedtime = str(args.get('iocobject_modifiedtime', ''))
    iocobject_moduletofeedmap = str(args.get('iocobject_moduletofeedmap', ''))
    iocobject_primaryterm = args.get('iocobject_primaryterm', None)
    iocobject_relatedinccount = args.get('iocobject_relatedinccount', None)
    iocobject_score = args.get('iocobject_score', None)
    iocobject_sequencenumber = args.get('iocobject_sequencenumber', None)
    iocobject_setby = str(args.get('iocobject_setby', ''))
    iocobject_sortvalues = argToList(args.get('iocobject_sortvalues', []))
    iocobject_source = str(args.get('iocobject_source', ''))
    iocobject_sourcebrands = argToList(args.get('iocobject_sourcebrands', []))
    iocobject_sourceinstances = argToList(args.get('iocobject_sourceinstances', []))
    iocobject_timestamp = str(args.get('iocobject_timestamp', ''))
    iocobject_value = str(args.get('iocobject_value', ''))
    iocobject_version = args.get('iocobject_version', None)

    response = client.indicators_edit_request(iocobject_customfields, iocobject_account, iocobject_aggregatedreliability, iocobject_calculatedtime, iocobject_comment, iocobject_comments, iocobject_deletedfeedfetchtime, iocobject_expiration, iocobject_expirationsource, iocobject_expirationstatus, iocobject_firstseen, iocobject_firstseenentryid, iocobject_id, iocobject_indicator_type, iocobject_insightcache, iocobject_investigationids, iocobject_isshared, iocobject_lastreputationrun,
                                              iocobject_lastseen, iocobject_lastseenentryid, iocobject_manualexpirationtime, iocobject_manualscore, iocobject_manualsettime, iocobject_manuallyeditedfields, iocobject_modified, iocobject_modifiedtime, iocobject_moduletofeedmap, iocobject_primaryterm, iocobject_relatedinccount, iocobject_score, iocobject_sequencenumber, iocobject_setby, iocobject_sortvalues, iocobject_source, iocobject_sourcebrands, iocobject_sourceinstances, iocobject_timestamp, iocobject_value, iocobject_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IocObject',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicators_search_command(client, args):
    indicatorfilter_cache = str(args.get('indicatorfilter_cache', ''))
    indicatorfilter_earlytimeinpage = str(args.get('indicatorfilter_earlytimeinpage', ''))
    indicatorfilter_firstseen_fromdate = str(args.get('indicatorfilter_firstseen_fromdate', ''))
    indicatorfilter_firstseen_fromdatelicense = str(args.get('indicatorfilter_firstseen_fromdatelicense', ''))
    indicatorfilter_firstseen_period = str(args.get('indicatorfilter_firstseen_period', ''))
    indicatorfilter_firstseen_timeframe = str(args.get('indicatorfilter_firstseen_timeframe', ''))
    indicatorfilter_firstseen_todate = str(args.get('indicatorfilter_firstseen_todate', ''))
    indicatorfilter_firstseen = assign_params(fromDate=indicatorfilter_firstseen_fromdate, fromDateLicense=indicatorfilter_firstseen_fromdatelicense,
                                              period=indicatorfilter_firstseen_period, timeFrame=indicatorfilter_firstseen_timeframe, toDate=indicatorfilter_firstseen_todate)
    indicatorfilter_fromdate = str(args.get('indicatorfilter_fromdate', ''))
    indicatorfilter_fromdatelicense = str(args.get('indicatorfilter_fromdatelicense', ''))
    indicatorfilter_ignoreworkers = argToBoolean(args.get('indicatorfilter_ignoreworkers', False))
    indicatorfilter_lastseen_fromdate = str(args.get('indicatorfilter_lastseen_fromdate', ''))
    indicatorfilter_lastseen_fromdatelicense = str(args.get('indicatorfilter_lastseen_fromdatelicense', ''))
    indicatorfilter_lastseen_period = str(args.get('indicatorfilter_lastseen_period', ''))
    indicatorfilter_lastseen_timeframe = str(args.get('indicatorfilter_lastseen_timeframe', ''))
    indicatorfilter_lastseen_todate = str(args.get('indicatorfilter_lastseen_todate', ''))
    indicatorfilter_lastseen = assign_params(fromDate=indicatorfilter_lastseen_fromdate, fromDateLicense=indicatorfilter_lastseen_fromdatelicense,
                                             period=indicatorfilter_lastseen_period, timeFrame=indicatorfilter_lastseen_timeframe, toDate=indicatorfilter_lastseen_todate)
    indicatorfilter_latertimeinpage = str(args.get('indicatorfilter_latertimeinpage', ''))
    indicatorfilter_page = args.get('indicatorfilter_page', None)
    indicatorfilter_period_by = str(args.get('indicatorfilter_period_by', ''))
    indicatorfilter_period_byfrom = str(args.get('indicatorfilter_period_byfrom', ''))
    indicatorfilter_period_byto = str(args.get('indicatorfilter_period_byto', ''))
    indicatorfilter_period_field = str(args.get('indicatorfilter_period_field', ''))
    indicatorfilter_period_fromvalue = str(args.get('indicatorfilter_period_fromvalue', ''))
    indicatorfilter_period_tovalue = str(args.get('indicatorfilter_period_tovalue', ''))
    indicatorfilter_period = assign_params(by=indicatorfilter_period_by, byFrom=indicatorfilter_period_byfrom, byTo=indicatorfilter_period_byto,
                                           field=indicatorfilter_period_field, fromValue=indicatorfilter_period_fromvalue, toValue=indicatorfilter_period_tovalue)
    indicatorfilter_prevpage = argToBoolean(args.get('indicatorfilter_prevpage', False))
    indicatorfilter_query = str(args.get('indicatorfilter_query', ''))
    indicatorfilter_searchafter = argToList(args.get('indicatorfilter_searchafter', []))
    indicatorfilter_searchbefore = argToList(args.get('indicatorfilter_searchbefore', []))
    indicatorfilter_size = args.get('indicatorfilter_size', None)
    indicatorfilter_sort = argToList(args.get('indicatorfilter_sort', []))
    indicatorfilter_timeframe = str(args.get('indicatorfilter_timeframe', ''))
    indicatorfilter_todate = str(args.get('indicatorfilter_todate', ''))

    response = client.indicators_search_request(indicatorfilter_cache, indicatorfilter_earlytimeinpage, indicatorfilter_firstseen, indicatorfilter_fromdate, indicatorfilter_fromdatelicense, indicatorfilter_ignoreworkers, indicatorfilter_lastseen, indicatorfilter_latertimeinpage,
                                                indicatorfilter_page, indicatorfilter_period, indicatorfilter_prevpage, indicatorfilter_query, indicatorfilter_searchafter, indicatorfilter_searchbefore, indicatorfilter_size, indicatorfilter_sort, indicatorfilter_timeframe, indicatorfilter_todate)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IndicatorResult',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def indicators_timeline_delete_command(client, args):
    indicatorfilter_cache = str(args.get('indicatorfilter_cache', ''))
    indicatorfilter_earlytimeinpage = str(args.get('indicatorfilter_earlytimeinpage', ''))
    indicatorfilter_firstseen_fromdate = str(args.get('indicatorfilter_firstseen_fromdate', ''))
    indicatorfilter_firstseen_fromdatelicense = str(args.get('indicatorfilter_firstseen_fromdatelicense', ''))
    indicatorfilter_firstseen_period = str(args.get('indicatorfilter_firstseen_period', ''))
    indicatorfilter_firstseen_timeframe = str(args.get('indicatorfilter_firstseen_timeframe', ''))
    indicatorfilter_firstseen_todate = str(args.get('indicatorfilter_firstseen_todate', ''))
    indicatorfilter_firstseen = assign_params(fromDate=indicatorfilter_firstseen_fromdate, fromDateLicense=indicatorfilter_firstseen_fromdatelicense,
                                              period=indicatorfilter_firstseen_period, timeFrame=indicatorfilter_firstseen_timeframe, toDate=indicatorfilter_firstseen_todate)
    indicatorfilter_fromdate = str(args.get('indicatorfilter_fromdate', ''))
    indicatorfilter_fromdatelicense = str(args.get('indicatorfilter_fromdatelicense', ''))
    indicatorfilter_ignoreworkers = argToBoolean(args.get('indicatorfilter_ignoreworkers', False))
    indicatorfilter_lastseen_fromdate = str(args.get('indicatorfilter_lastseen_fromdate', ''))
    indicatorfilter_lastseen_fromdatelicense = str(args.get('indicatorfilter_lastseen_fromdatelicense', ''))
    indicatorfilter_lastseen_period = str(args.get('indicatorfilter_lastseen_period', ''))
    indicatorfilter_lastseen_timeframe = str(args.get('indicatorfilter_lastseen_timeframe', ''))
    indicatorfilter_lastseen_todate = str(args.get('indicatorfilter_lastseen_todate', ''))
    indicatorfilter_lastseen = assign_params(fromDate=indicatorfilter_lastseen_fromdate, fromDateLicense=indicatorfilter_lastseen_fromdatelicense,
                                             period=indicatorfilter_lastseen_period, timeFrame=indicatorfilter_lastseen_timeframe, toDate=indicatorfilter_lastseen_todate)
    indicatorfilter_latertimeinpage = str(args.get('indicatorfilter_latertimeinpage', ''))
    indicatorfilter_page = args.get('indicatorfilter_page', None)
    indicatorfilter_period_by = str(args.get('indicatorfilter_period_by', ''))
    indicatorfilter_period_byfrom = str(args.get('indicatorfilter_period_byfrom', ''))
    indicatorfilter_period_byto = str(args.get('indicatorfilter_period_byto', ''))
    indicatorfilter_period_field = str(args.get('indicatorfilter_period_field', ''))
    indicatorfilter_period_fromvalue = str(args.get('indicatorfilter_period_fromvalue', ''))
    indicatorfilter_period_tovalue = str(args.get('indicatorfilter_period_tovalue', ''))
    indicatorfilter_period = assign_params(by=indicatorfilter_period_by, byFrom=indicatorfilter_period_byfrom, byTo=indicatorfilter_period_byto,
                                           field=indicatorfilter_period_field, fromValue=indicatorfilter_period_fromvalue, toValue=indicatorfilter_period_tovalue)
    indicatorfilter_prevpage = argToBoolean(args.get('indicatorfilter_prevpage', False))
    indicatorfilter_query = str(args.get('indicatorfilter_query', ''))
    indicatorfilter_searchafter = argToList(args.get('indicatorfilter_searchafter', []))
    indicatorfilter_searchbefore = argToList(args.get('indicatorfilter_searchbefore', []))
    indicatorfilter_size = args.get('indicatorfilter_size', None)
    indicatorfilter_sort = argToList(args.get('indicatorfilter_sort', []))
    indicatorfilter_timeframe = str(args.get('indicatorfilter_timeframe', ''))
    indicatorfilter_todate = str(args.get('indicatorfilter_todate', ''))

    response = client.indicators_timeline_delete_request(indicatorfilter_cache, indicatorfilter_earlytimeinpage, indicatorfilter_firstseen, indicatorfilter_fromdate, indicatorfilter_fromdatelicense, indicatorfilter_ignoreworkers, indicatorfilter_lastseen, indicatorfilter_latertimeinpage,
                                                         indicatorfilter_page, indicatorfilter_period, indicatorfilter_prevpage, indicatorfilter_query, indicatorfilter_searchafter, indicatorfilter_searchbefore, indicatorfilter_size, indicatorfilter_sort, indicatorfilter_timeframe, indicatorfilter_todate)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.IndicatorEditBulkResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def integration_upload_command(client, args):
    file = str(args.get('file', ''))

    response = client.integration_upload_request(file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.ModuleConfiguration',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def investigation_add_entries_sync_command(client, args):
    updateentry_args = str(args.get('updateentry_args', ''))
    updateentry_data = str(args.get('updateentry_data', ''))
    updateentry_id = str(args.get('updateentry_id', ''))
    updateentry_investigationid = str(args.get('updateentry_investigationid', ''))
    updateentry_markdown = argToBoolean(args.get('updateentry_markdown', False))
    updateentry_version = args.get('updateentry_version', None)

    response = client.investigation_add_entries_sync_request(
        updateentry_args, updateentry_data, updateentry_id, updateentry_investigationid, updateentry_markdown, updateentry_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Entry',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def investigation_add_entry_handler_command(client, args):
    updateentry_args = str(args.get('updateentry_args', ''))
    updateentry_data = str(args.get('updateentry_data', ''))
    updateentry_id = str(args.get('updateentry_id', ''))
    updateentry_investigationid = str(args.get('updateentry_investigationid', ''))
    updateentry_markdown = argToBoolean(args.get('updateentry_markdown', False))
    updateentry_version = args.get('updateentry_version', None)

    response = client.investigation_add_entry_handler_request(
        updateentry_args, updateentry_data, updateentry_id, updateentry_investigationid, updateentry_markdown, updateentry_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Entry',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def investigation_add_formatted_entry_handler_command(client, args):
    uploadedentry_contents = str(args.get('uploadedentry_contents', ''))
    uploadedentry_format = str(args.get('uploadedentry_format', ''))
    uploadedentry_investigationid = str(args.get('uploadedentry_investigationid', ''))

    response = client.investigation_add_formatted_entry_handler_request(
        uploadedentry_contents, uploadedentry_format, uploadedentry_investigationid)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Entry',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def logout_myself_handler_command(client, args):

    response = client.logout_myself_handler_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def logout_myself_other_sessions_handler_command(client, args):

    response = client.logout_myself_other_sessions_handler_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def logout_user_sessions_handler_command(client, args):

    response = client.logout_user_sessions_handler_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def logouta_everyone_handler_command(client, args):

    response = client.logouta_everyone_handler_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def override_playbook_yaml_command(client, args):
    file = str(args.get('file', ''))

    response = client.override_playbook_yaml_request(file)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.playbookWithWarnings',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def revoke_userapi_key_command(client, args):
    username = str(args.get('username', ''))

    response = client.revoke_userapi_key_request(username)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def save_evidence_command(client, args):
    evidence_shardid = args.get('evidence_shardid', None)
    evidence_allread = argToBoolean(args.get('evidence_allread', False))
    evidence_allreadwrite = argToBoolean(args.get('evidence_allreadwrite', False))
    evidence_dbotcreatedby = str(args.get('evidence_dbotcreatedby', ''))
    evidence_description = str(args.get('evidence_description', ''))
    evidence_entryid = str(args.get('evidence_entryid', ''))
    evidence_fetched = str(args.get('evidence_fetched', ''))
    evidence_hasrole = argToBoolean(args.get('evidence_hasrole', False))
    evidence_id = str(args.get('evidence_id', ''))
    evidence_incidentid = str(args.get('evidence_incidentid', ''))
    evidence_markedby = str(args.get('evidence_markedby', ''))
    evidence_markeddate = str(args.get('evidence_markeddate', ''))
    evidence_modified = str(args.get('evidence_modified', ''))
    evidence_occurred = str(args.get('evidence_occurred', ''))
    evidence_previousallread = argToBoolean(args.get('evidence_previousallread', False))
    evidence_previousallreadwrite = argToBoolean(args.get('evidence_previousallreadwrite', False))
    evidence_previousroles = argToList(args.get('evidence_previousroles', []))
    evidence_primaryterm = args.get('evidence_primaryterm', None)
    evidence_roles = argToList(args.get('evidence_roles', []))
    evidence_sequencenumber = args.get('evidence_sequencenumber', None)
    evidence_sortvalues = argToList(args.get('evidence_sortvalues', []))
    evidence_tags = argToList(args.get('evidence_tags', []))
    evidence_tagsraw = argToList(args.get('evidence_tagsraw', []))
    evidence_taskid = str(args.get('evidence_taskid', ''))
    evidence_version = args.get('evidence_version', None)
    evidence_xsoarhasreadonlyrole = argToBoolean(args.get('evidence_xsoarhasreadonlyrole', False))
    evidence_xsoarpreviousreadonlyroles = argToList(args.get('evidence_xsoarpreviousreadonlyroles', []))
    evidence_xsoarreadonlyroles = argToList(args.get('evidence_xsoarreadonlyroles', []))

    response = client.save_evidence_request(evidence_shardid, evidence_allread, evidence_allreadwrite, evidence_dbotcreatedby, evidence_description, evidence_entryid, evidence_fetched, evidence_hasrole, evidence_id, evidence_incidentid, evidence_markedby, evidence_markeddate, evidence_modified, evidence_occurred, evidence_previousallread,
                                            evidence_previousallreadwrite, evidence_previousroles, evidence_primaryterm, evidence_roles, evidence_sequencenumber, evidence_sortvalues, evidence_tags, evidence_tagsraw, evidence_taskid, evidence_version, evidence_xsoarhasreadonlyrole, evidence_xsoarpreviousreadonlyroles, evidence_xsoarreadonlyroles)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Evidence',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def save_or_update_script_command(client, args):
    automationscriptfilterwrapper_filter_cache = str(args.get('automationscriptfilterwrapper_filter_cache', ''))
    automationscriptfilterwrapper_filter_ignoreworkers = argToBoolean(
        args.get('automationscriptfilterwrapper_filter_ignoreworkers', False))
    automationscriptfilterwrapper_filter_page = args.get('automationscriptfilterwrapper_filter_page', None)
    automationscriptfilterwrapper_filter_query = str(args.get('automationscriptfilterwrapper_filter_query', ''))
    automationscriptfilterwrapper_filter_searchafter = str(args.get('automationscriptfilterwrapper_filter_searchafter', ''))
    automationscriptfilterwrapper_filter_searchbefore = str(args.get('automationscriptfilterwrapper_filter_searchbefore', ''))
    automationscriptfilterwrapper_filter_size = args.get('automationscriptfilterwrapper_filter_size', None)
    automationscriptfilterwrapper_filter_sort = str(args.get('automationscriptfilterwrapper_filter_sort', ''))
    automationscriptfilterwrapper_filter = assign_params(Cache=automationscriptfilterwrapper_filter_cache, ignoreWorkers=automationscriptfilterwrapper_filter_ignoreworkers, page=automationscriptfilterwrapper_filter_page, query=automationscriptfilterwrapper_filter_query,
                                                         searchAfter=automationscriptfilterwrapper_filter_searchafter, searchBefore=automationscriptfilterwrapper_filter_searchbefore, size=automationscriptfilterwrapper_filter_size, sort=automationscriptfilterwrapper_filter_sort)
    automationscriptfilterwrapper_savepassword = argToBoolean(args.get('automationscriptfilterwrapper_savepassword', False))
    automationscriptfilterwrapper_script_allread = argToBoolean(args.get('automationscriptfilterwrapper_script_allread', False))
    automationscriptfilterwrapper_script_allreadwrite = argToBoolean(
        args.get('automationscriptfilterwrapper_script_allreadwrite', False))
    automationscriptfilterwrapper_script_arguments = str(args.get('automationscriptfilterwrapper_script_arguments', ''))
    automationscriptfilterwrapper_script_comment = str(args.get('automationscriptfilterwrapper_script_comment', ''))
    automationscriptfilterwrapper_script_commitmessage = str(args.get('automationscriptfilterwrapper_script_commitmessage', ''))
    automationscriptfilterwrapper_script_contextkeys = str(args.get('automationscriptfilterwrapper_script_contextkeys', ''))
    automationscriptfilterwrapper_script_dbotcreatedby = str(args.get('automationscriptfilterwrapper_script_dbotcreatedby', ''))
    automationscriptfilterwrapper_script_dependson = str(args.get('automationscriptfilterwrapper_script_dependson', ''))
    automationscriptfilterwrapper_script_deprecated = argToBoolean(
        args.get('automationscriptfilterwrapper_script_deprecated', False))
    automationscriptfilterwrapper_script_detached = argToBoolean(args.get('automationscriptfilterwrapper_script_detached', False))
    automationscriptfilterwrapper_script_dockerimage = str(args.get('automationscriptfilterwrapper_script_dockerimage', ''))
    automationscriptfilterwrapper_script_enabled = argToBoolean(args.get('automationscriptfilterwrapper_script_enabled', False))
    automationscriptfilterwrapper_script_fromserverversion = str(
        args.get('automationscriptfilterwrapper_script_fromserverversion', ''))
    automationscriptfilterwrapper_script_hasrole = argToBoolean(args.get('automationscriptfilterwrapper_script_hasrole', False))
    automationscriptfilterwrapper_script_hidden = argToBoolean(args.get('automationscriptfilterwrapper_script_hidden', False))
    automationscriptfilterwrapper_script_id = str(args.get('automationscriptfilterwrapper_script_id', ''))
    automationscriptfilterwrapper_script_important = str(args.get('automationscriptfilterwrapper_script_important', ''))
    automationscriptfilterwrapper_script_itemversion = str(args.get('automationscriptfilterwrapper_script_itemversion', ''))
    automationscriptfilterwrapper_script_locked = argToBoolean(args.get('automationscriptfilterwrapper_script_locked', False))
    automationscriptfilterwrapper_script_modified = str(args.get('automationscriptfilterwrapper_script_modified', ''))
    automationscriptfilterwrapper_script_name = str(args.get('automationscriptfilterwrapper_script_name', ''))
    automationscriptfilterwrapper_script_outputs = str(args.get('automationscriptfilterwrapper_script_outputs', ''))
    automationscriptfilterwrapper_script_packid = str(args.get('automationscriptfilterwrapper_script_packid', ''))
    automationscriptfilterwrapper_script_packpropagationlabels = str(
        args.get('automationscriptfilterwrapper_script_packpropagationlabels', ''))
    automationscriptfilterwrapper_script_prevname = str(args.get('automationscriptfilterwrapper_script_prevname', ''))
    automationscriptfilterwrapper_script_previousallread = argToBoolean(
        args.get('automationscriptfilterwrapper_script_previousallread', False))
    automationscriptfilterwrapper_script_previousallreadwrite = argToBoolean(
        args.get('automationscriptfilterwrapper_script_previousallreadwrite', False))
    automationscriptfilterwrapper_script_previousroles = str(args.get('automationscriptfilterwrapper_script_previousroles', ''))
    automationscriptfilterwrapper_script_primaryterm = args.get('automationscriptfilterwrapper_script_primaryterm', None)
    automationscriptfilterwrapper_script_private = argToBoolean(args.get('automationscriptfilterwrapper_script_private', False))
    automationscriptfilterwrapper_script_propagationlabels = str(
        args.get('automationscriptfilterwrapper_script_propagationlabels', ''))
    automationscriptfilterwrapper_script_pswd = str(args.get('automationscriptfilterwrapper_script_pswd', ''))
    automationscriptfilterwrapper_script_rawtags = str(args.get('automationscriptfilterwrapper_script_rawtags', ''))
    automationscriptfilterwrapper_script_roles = str(args.get('automationscriptfilterwrapper_script_roles', ''))
    automationscriptfilterwrapper_script_runas = str(args.get('automationscriptfilterwrapper_script_runas', ''))
    automationscriptfilterwrapper_script_runonce = argToBoolean(args.get('automationscriptfilterwrapper_script_runonce', False))
    automationscriptfilterwrapper_script_script = str(args.get('automationscriptfilterwrapper_script_script', ''))
    automationscriptfilterwrapper_script_scripttarget = str(args.get('automationscriptfilterwrapper_script_scripttarget', ''))
    automationscriptfilterwrapper_script_searchablename = str(args.get('automationscriptfilterwrapper_script_searchablename', ''))
    automationscriptfilterwrapper_script_sensitive = argToBoolean(
        args.get('automationscriptfilterwrapper_script_sensitive', False))
    automationscriptfilterwrapper_script_sequencenumber = args.get('automationscriptfilterwrapper_script_sequencenumber', None)
    automationscriptfilterwrapper_script_shouldcommit = argToBoolean(
        args.get('automationscriptfilterwrapper_script_shouldcommit', False))
    automationscriptfilterwrapper_script_sortvalues = str(args.get('automationscriptfilterwrapper_script_sortvalues', ''))
    automationscriptfilterwrapper_script_sourcescripid = str(args.get('automationscriptfilterwrapper_script_sourcescripid', ''))
    automationscriptfilterwrapper_script_subtype = str(args.get('automationscriptfilterwrapper_script_subtype', ''))
    automationscriptfilterwrapper_script_system = argToBoolean(args.get('automationscriptfilterwrapper_script_system', False))
    automationscriptfilterwrapper_script_tags = str(args.get('automationscriptfilterwrapper_script_tags', ''))
    automationscriptfilterwrapper_script_timeout = str(args.get('automationscriptfilterwrapper_script_timeout', ''))
    automationscriptfilterwrapper_script_toserverversion = str(
        args.get('automationscriptfilterwrapper_script_toserverversion', ''))
    automationscriptfilterwrapper_script_type = str(args.get('automationscriptfilterwrapper_script_type', ''))
    automationscriptfilterwrapper_script_user = str(args.get('automationscriptfilterwrapper_script_user', ''))
    automationscriptfilterwrapper_script_vcshouldignore = argToBoolean(
        args.get('automationscriptfilterwrapper_script_vcshouldignore', False))
    automationscriptfilterwrapper_script_vcshouldkeepitemlegacyprodmachine = argToBoolean(
        args.get('automationscriptfilterwrapper_script_vcshouldkeepitemlegacyprodmachine', False))
    automationscriptfilterwrapper_script_version = args.get('automationscriptfilterwrapper_script_version', None)
    automationscriptfilterwrapper_script_visualscript = str(args.get('automationscriptfilterwrapper_script_visualscript', ''))
    automationscriptfilterwrapper_script_xsoarhasreadonlyrole = argToBoolean(
        args.get('automationscriptfilterwrapper_script_xsoarhasreadonlyrole', False))
    automationscriptfilterwrapper_script_xsoarpreviousreadonlyroles = str(
        args.get('automationscriptfilterwrapper_script_xsoarpreviousreadonlyroles', ''))
    automationscriptfilterwrapper_script_xsoarreadonlyroles = str(
        args.get('automationscriptfilterwrapper_script_xsoarreadonlyroles', ''))
    automationscriptfilterwrapper_script = assign_params(allRead=automationscriptfilterwrapper_script_allread, allReadWrite=automationscriptfilterwrapper_script_allreadwrite, arguments=automationscriptfilterwrapper_script_arguments, comment=automationscriptfilterwrapper_script_comment, commitMessage=automationscriptfilterwrapper_script_commitmessage, contextKeys=automationscriptfilterwrapper_script_contextkeys, dbotCreatedBy=automationscriptfilterwrapper_script_dbotcreatedby, dependsOn=automationscriptfilterwrapper_script_dependson, deprecated=automationscriptfilterwrapper_script_deprecated, detached=automationscriptfilterwrapper_script_detached, dockerImage=automationscriptfilterwrapper_script_dockerimage, enabled=automationscriptfilterwrapper_script_enabled, fromServerVersion=automationscriptfilterwrapper_script_fromserverversion, hasRole=automationscriptfilterwrapper_script_hasrole, hidden=automationscriptfilterwrapper_script_hidden, id=automationscriptfilterwrapper_script_id, important=automationscriptfilterwrapper_script_important, itemVersion=automationscriptfilterwrapper_script_itemversion, locked=automationscriptfilterwrapper_script_locked, modified=automationscriptfilterwrapper_script_modified, name=automationscriptfilterwrapper_script_name, outputs=automationscriptfilterwrapper_script_outputs, packID=automationscriptfilterwrapper_script_packid, packPropagationLabels=automationscriptfilterwrapper_script_packpropagationlabels, prevName=automationscriptfilterwrapper_script_prevname, previousAllRead=automationscriptfilterwrapper_script_previousallread, previousAllReadWrite=automationscriptfilterwrapper_script_previousallreadwrite, previousRoles=automationscriptfilterwrapper_script_previousroles, primaryTerm=automationscriptfilterwrapper_script_primaryterm,
                                                         private=automationscriptfilterwrapper_script_private, propagationLabels=automationscriptfilterwrapper_script_propagationlabels, pswd=automationscriptfilterwrapper_script_pswd, rawTags=automationscriptfilterwrapper_script_rawtags, roles=automationscriptfilterwrapper_script_roles, runAs=automationscriptfilterwrapper_script_runas, runOnce=automationscriptfilterwrapper_script_runonce, script=automationscriptfilterwrapper_script_script, scriptTarget=automationscriptfilterwrapper_script_scripttarget, searchableName=automationscriptfilterwrapper_script_searchablename, sensitive=automationscriptfilterwrapper_script_sensitive, sequenceNumber=automationscriptfilterwrapper_script_sequencenumber, shouldCommit=automationscriptfilterwrapper_script_shouldcommit, sortValues=automationscriptfilterwrapper_script_sortvalues, sourceScripID=automationscriptfilterwrapper_script_sourcescripid, subtype=automationscriptfilterwrapper_script_subtype, system=automationscriptfilterwrapper_script_system, tags=automationscriptfilterwrapper_script_tags, timeout=automationscriptfilterwrapper_script_timeout, toServerVersion=automationscriptfilterwrapper_script_toserverversion, type=automationscriptfilterwrapper_script_type, user=automationscriptfilterwrapper_script_user, vcShouldIgnore=automationscriptfilterwrapper_script_vcshouldignore, vcShouldKeepItemLegacyProdMachine=automationscriptfilterwrapper_script_vcshouldkeepitemlegacyprodmachine, version=automationscriptfilterwrapper_script_version, visualScript=automationscriptfilterwrapper_script_visualscript, xsoarHasReadOnlyRole=automationscriptfilterwrapper_script_xsoarhasreadonlyrole, xsoarPreviousReadOnlyRoles=automationscriptfilterwrapper_script_xsoarpreviousreadonlyroles, xsoarReadOnlyRoles=automationscriptfilterwrapper_script_xsoarreadonlyroles)

    response = client.save_or_update_script_request(
        automationscriptfilterwrapper_filter, automationscriptfilterwrapper_savepassword, automationscriptfilterwrapper_script)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.automationScriptResult',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def save_widget_command(client, args):
    widget_category = str(args.get('widget_category', ''))
    widget_commitmessage = str(args.get('widget_commitmessage', ''))
    widget_datatype = str(args.get('widget_datatype', ''))
    widget_daterange_fromdate = str(args.get('widget_daterange_fromdate', ''))
    widget_daterange_fromdatelicense = str(args.get('widget_daterange_fromdatelicense', ''))
    widget_daterange_period = str(args.get('widget_daterange_period', ''))
    widget_daterange_todate = str(args.get('widget_daterange_todate', ''))
    widget_daterange = assign_params(fromDate=widget_daterange_fromdate, fromDateLicense=widget_daterange_fromdatelicense,
                                     period=widget_daterange_period, toDate=widget_daterange_todate)
    widget_description = str(args.get('widget_description', ''))
    widget_fromserverversion_digits = str(args.get('widget_fromserverversion_digits', ''))
    widget_fromserverversion_label = str(args.get('widget_fromserverversion_label', ''))
    widget_fromserverversion = assign_params(Digits=widget_fromserverversion_digits, Label=widget_fromserverversion_label)
    widget_id = str(args.get('widget_id', ''))
    widget_ispredefined = argToBoolean(args.get('widget_ispredefined', False))
    widget_itemversion_digits = str(args.get('widget_itemversion_digits', ''))
    widget_itemversion_label = str(args.get('widget_itemversion_label', ''))
    widget_itemversion = assign_params(Digits=widget_itemversion_digits, Label=widget_itemversion_label)
    widget_locked = argToBoolean(args.get('widget_locked', False))
    widget_modified = str(args.get('widget_modified', ''))
    widget_name = str(args.get('widget_name', ''))
    widget_packid = str(args.get('widget_packid', ''))
    widget_packpropagationlabels = argToList(args.get('widget_packpropagationlabels', []))
    widget_params = str(args.get('widget_params', ''))
    widget_prevname = str(args.get('widget_prevname', ''))
    widget_primaryterm = args.get('widget_primaryterm', None)
    widget_propagationlabels = argToList(args.get('widget_propagationlabels', []))
    widget_query = str(args.get('widget_query', ''))
    widget_sequencenumber = args.get('widget_sequencenumber', None)
    widget_shouldcommit = argToBoolean(args.get('widget_shouldcommit', False))
    widget_size = args.get('widget_size', None)
    widget_sort = argToList(args.get('widget_sort', []))
    widget_sortvalues = argToList(args.get('widget_sortvalues', []))
    widget_toserverversion_digits = str(args.get('widget_toserverversion_digits', ''))
    widget_toserverversion_label = str(args.get('widget_toserverversion_label', ''))
    widget_toserverversion = assign_params(Digits=widget_toserverversion_digits, Label=widget_toserverversion_label)
    widget_vcshouldignore = argToBoolean(args.get('widget_vcshouldignore', False))
    widget_vcshouldkeepitemlegacyprodmachine = argToBoolean(args.get('widget_vcshouldkeepitemlegacyprodmachine', False))
    widget_version = args.get('widget_version', None)
    widget_widgettype = str(args.get('widget_widgettype', ''))

    response = client.save_widget_request(widget_category, widget_commitmessage, widget_datatype, widget_daterange, widget_description, widget_fromserverversion, widget_id, widget_ispredefined, widget_itemversion, widget_locked, widget_modified, widget_name, widget_packid, widget_packpropagationlabels,
                                          widget_params, widget_prevname, widget_primaryterm, widget_propagationlabels, widget_query, widget_sequencenumber, widget_shouldcommit, widget_size, widget_sort, widget_sortvalues, widget_toserverversion, widget_vcshouldignore, widget_vcshouldkeepitemlegacyprodmachine, widget_version, widget_widgettype)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Widget',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def search_evidence_command(client, args):
    evidencesfilterwrapper_filter_cache = str(args.get('evidencesfilterwrapper_filter_cache', ''))
    evidencesfilterwrapper_filter_fromdate = str(args.get('evidencesfilterwrapper_filter_fromdate', ''))
    evidencesfilterwrapper_filter_fromdatelicense = str(args.get('evidencesfilterwrapper_filter_fromdatelicense', ''))
    evidencesfilterwrapper_filter_ignoreworkers = argToBoolean(args.get('evidencesfilterwrapper_filter_ignoreworkers', False))
    evidencesfilterwrapper_filter_page = args.get('evidencesfilterwrapper_filter_page', None)
    evidencesfilterwrapper_filter_period = str(args.get('evidencesfilterwrapper_filter_period', ''))
    evidencesfilterwrapper_filter_query = str(args.get('evidencesfilterwrapper_filter_query', ''))
    evidencesfilterwrapper_filter_searchafter = str(args.get('evidencesfilterwrapper_filter_searchafter', ''))
    evidencesfilterwrapper_filter_searchbefore = str(args.get('evidencesfilterwrapper_filter_searchbefore', ''))
    evidencesfilterwrapper_filter_size = args.get('evidencesfilterwrapper_filter_size', None)
    evidencesfilterwrapper_filter_sort = str(args.get('evidencesfilterwrapper_filter_sort', ''))
    evidencesfilterwrapper_filter_timeframe = str(args.get('evidencesfilterwrapper_filter_timeframe', ''))
    evidencesfilterwrapper_filter_todate = str(args.get('evidencesfilterwrapper_filter_todate', ''))
    evidencesfilterwrapper_filter = assign_params(Cache=evidencesfilterwrapper_filter_cache, fromDate=evidencesfilterwrapper_filter_fromdate, fromDateLicense=evidencesfilterwrapper_filter_fromdatelicense, ignoreWorkers=evidencesfilterwrapper_filter_ignoreworkers, page=evidencesfilterwrapper_filter_page, period=evidencesfilterwrapper_filter_period,
                                                  query=evidencesfilterwrapper_filter_query, searchAfter=evidencesfilterwrapper_filter_searchafter, searchBefore=evidencesfilterwrapper_filter_searchbefore, size=evidencesfilterwrapper_filter_size, sort=evidencesfilterwrapper_filter_sort, timeFrame=evidencesfilterwrapper_filter_timeframe, toDate=evidencesfilterwrapper_filter_todate)
    evidencesfilterwrapper_incidentid = str(args.get('evidencesfilterwrapper_incidentid', ''))

    response = client.search_evidence_request(evidencesfilterwrapper_filter, evidencesfilterwrapper_incidentid)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.EvidencesSearchResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def search_incidents_command(client, args):
    searchincidentsdata_filter_cache = str(args.get('searchincidentsdata_filter_cache', ''))
    searchincidentsdata_filter_andop = argToBoolean(args.get('searchincidentsdata_filter_andop', False))
    searchincidentsdata_filter_category = str(args.get('searchincidentsdata_filter_category', ''))
    searchincidentsdata_filter_details = str(args.get('searchincidentsdata_filter_details', ''))
    searchincidentsdata_filter_files = str(args.get('searchincidentsdata_filter_files', ''))
    searchincidentsdata_filter_fromactivateddate = str(args.get('searchincidentsdata_filter_fromactivateddate', ''))
    searchincidentsdata_filter_fromcloseddate = str(args.get('searchincidentsdata_filter_fromcloseddate', ''))
    searchincidentsdata_filter_fromdate = str(args.get('searchincidentsdata_filter_fromdate', ''))
    searchincidentsdata_filter_fromdatelicense = str(args.get('searchincidentsdata_filter_fromdatelicense', ''))
    searchincidentsdata_filter_fromduedate = str(args.get('searchincidentsdata_filter_fromduedate', ''))
    searchincidentsdata_filter_fromreminder = str(args.get('searchincidentsdata_filter_fromreminder', ''))
    searchincidentsdata_filter_id = str(args.get('searchincidentsdata_filter_id', ''))
    searchincidentsdata_filter_ignoreworkers = argToBoolean(args.get('searchincidentsdata_filter_ignoreworkers', False))
    searchincidentsdata_filter_includetmp = argToBoolean(args.get('searchincidentsdata_filter_includetmp', False))
    searchincidentsdata_filter_investigation = str(args.get('searchincidentsdata_filter_investigation', ''))
    searchincidentsdata_filter_level = str(args.get('searchincidentsdata_filter_level', ''))
    searchincidentsdata_filter_name = str(args.get('searchincidentsdata_filter_name', ''))
    searchincidentsdata_filter_notcategory = str(args.get('searchincidentsdata_filter_notcategory', ''))
    searchincidentsdata_filter_notinvestigation = str(args.get('searchincidentsdata_filter_notinvestigation', ''))
    searchincidentsdata_filter_notstatus = str(args.get('searchincidentsdata_filter_notstatus', ''))
    searchincidentsdata_filter_page = args.get('searchincidentsdata_filter_page', None)
    searchincidentsdata_filter_parent = str(args.get('searchincidentsdata_filter_parent', ''))
    searchincidentsdata_filter_period = str(args.get('searchincidentsdata_filter_period', ''))
    searchincidentsdata_filter_query = str(args.get('searchincidentsdata_filter_query', ''))
    searchincidentsdata_filter_reason = str(args.get('searchincidentsdata_filter_reason', ''))
    searchincidentsdata_filter_searchafter = str(args.get('searchincidentsdata_filter_searchafter', ''))
    searchincidentsdata_filter_searchbefore = str(args.get('searchincidentsdata_filter_searchbefore', ''))
    searchincidentsdata_filter_size = args.get('searchincidentsdata_filter_size', None)
    searchincidentsdata_filter_sort = str(args.get('searchincidentsdata_filter_sort', ''))
    searchincidentsdata_filter_status = str(args.get('searchincidentsdata_filter_status', ''))
    searchincidentsdata_filter_systems = str(args.get('searchincidentsdata_filter_systems', ''))
    searchincidentsdata_filter_timeframe = str(args.get('searchincidentsdata_filter_timeframe', ''))
    searchincidentsdata_filter_toactivateddate = str(args.get('searchincidentsdata_filter_toactivateddate', ''))
    searchincidentsdata_filter_tocloseddate = str(args.get('searchincidentsdata_filter_tocloseddate', ''))
    searchincidentsdata_filter_todate = str(args.get('searchincidentsdata_filter_todate', ''))
    searchincidentsdata_filter_toduedate = str(args.get('searchincidentsdata_filter_toduedate', ''))
    searchincidentsdata_filter_toreminder = str(args.get('searchincidentsdata_filter_toreminder', ''))
    searchincidentsdata_filter_totalonly = argToBoolean(args.get('searchincidentsdata_filter_totalonly', False))
    searchincidentsdata_filter_type = str(args.get('searchincidentsdata_filter_type', ''))
    searchincidentsdata_filter_urls = str(args.get('searchincidentsdata_filter_urls', ''))
    searchincidentsdata_filter_users = str(args.get('searchincidentsdata_filter_users', ''))
    searchincidentsdata_filter = assign_params(Cache=searchincidentsdata_filter_cache, andOp=searchincidentsdata_filter_andop, category=searchincidentsdata_filter_category, details=searchincidentsdata_filter_details, files=searchincidentsdata_filter_files, fromActivatedDate=searchincidentsdata_filter_fromactivateddate, fromClosedDate=searchincidentsdata_filter_fromcloseddate, fromDate=searchincidentsdata_filter_fromdate, fromDateLicense=searchincidentsdata_filter_fromdatelicense, fromDueDate=searchincidentsdata_filter_fromduedate, fromReminder=searchincidentsdata_filter_fromreminder, id=searchincidentsdata_filter_id, ignoreWorkers=searchincidentsdata_filter_ignoreworkers, includeTmp=searchincidentsdata_filter_includetmp, investigation=searchincidentsdata_filter_investigation, level=searchincidentsdata_filter_level, name=searchincidentsdata_filter_name, notCategory=searchincidentsdata_filter_notcategory, notInvestigation=searchincidentsdata_filter_notinvestigation,
                                               notStatus=searchincidentsdata_filter_notstatus, page=searchincidentsdata_filter_page, parent=searchincidentsdata_filter_parent, period=searchincidentsdata_filter_period, query=searchincidentsdata_filter_query, reason=searchincidentsdata_filter_reason, searchAfter=searchincidentsdata_filter_searchafter, searchBefore=searchincidentsdata_filter_searchbefore, size=searchincidentsdata_filter_size, sort=searchincidentsdata_filter_sort, status=searchincidentsdata_filter_status, systems=searchincidentsdata_filter_systems, timeFrame=searchincidentsdata_filter_timeframe, toActivatedDate=searchincidentsdata_filter_toactivateddate, toClosedDate=searchincidentsdata_filter_tocloseddate, toDate=searchincidentsdata_filter_todate, toDueDate=searchincidentsdata_filter_toduedate, toReminder=searchincidentsdata_filter_toreminder, totalOnly=searchincidentsdata_filter_totalonly, type=searchincidentsdata_filter_type, urls=searchincidentsdata_filter_urls, users=searchincidentsdata_filter_users)
    searchincidentsdata_userfilter = argToBoolean(args.get('searchincidentsdata_userfilter', False))

    response = client.search_incidents_request(searchincidentsdata_filter, searchincidentsdata_userfilter)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Incident',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def search_investigations_command(client, args):
    investigationfilter_cache = str(args.get('investigationfilter_cache', ''))
    investigationfilter_andop = argToBoolean(args.get('investigationfilter_andop', False))
    investigationfilter_category = argToList(args.get('investigationfilter_category', []))
    investigationfilter_fromclosedate = str(args.get('investigationfilter_fromclosedate', ''))
    investigationfilter_fromdate = str(args.get('investigationfilter_fromdate', ''))
    investigationfilter_fromdatelicense = str(args.get('investigationfilter_fromdatelicense', ''))
    investigationfilter_id = argToList(args.get('investigationfilter_id', []))
    investigationfilter_idsonly = argToBoolean(args.get('investigationfilter_idsonly', False))
    investigationfilter_ignoreworkers = argToBoolean(args.get('investigationfilter_ignoreworkers', False))
    investigationfilter_includechildinv = argToBoolean(args.get('investigationfilter_includechildinv', False))
    investigationfilter_name = argToList(args.get('investigationfilter_name', []))
    investigationfilter_notcategory = argToList(args.get('investigationfilter_notcategory', []))
    investigationfilter_notids = argToList(args.get('investigationfilter_notids', []))
    investigationfilter_page = args.get('investigationfilter_page', None)
    investigationfilter_period_by = str(args.get('investigationfilter_period_by', ''))
    investigationfilter_period_byfrom = str(args.get('investigationfilter_period_byfrom', ''))
    investigationfilter_period_byto = str(args.get('investigationfilter_period_byto', ''))
    investigationfilter_period_field = str(args.get('investigationfilter_period_field', ''))
    investigationfilter_period_fromvalue = str(args.get('investigationfilter_period_fromvalue', ''))
    investigationfilter_period_tovalue = str(args.get('investigationfilter_period_tovalue', ''))
    investigationfilter_period = assign_params(by=investigationfilter_period_by, byFrom=investigationfilter_period_byfrom, byTo=investigationfilter_period_byto,
                                               field=investigationfilter_period_field, fromValue=investigationfilter_period_fromvalue, toValue=investigationfilter_period_tovalue)
    investigationfilter_reason = argToList(args.get('investigationfilter_reason', []))
    investigationfilter_searchafter = argToList(args.get('investigationfilter_searchafter', []))
    investigationfilter_searchbefore = argToList(args.get('investigationfilter_searchbefore', []))
    investigationfilter_size = args.get('investigationfilter_size', None)
    investigationfilter_sort = argToList(args.get('investigationfilter_sort', []))
    investigationfilter_status = argToList(args.get('investigationfilter_status', []))
    investigationfilter_timeframe = str(args.get('investigationfilter_timeframe', ''))
    investigationfilter_toclosedate = str(args.get('investigationfilter_toclosedate', ''))
    investigationfilter_todate = str(args.get('investigationfilter_todate', ''))
    investigationfilter_type = argToList(args.get('investigationfilter_type', []))
    investigationfilter_user = argToList(args.get('investigationfilter_user', []))

    response = client.search_investigations_request(investigationfilter_cache, investigationfilter_andop, investigationfilter_category, investigationfilter_fromclosedate, investigationfilter_fromdate, investigationfilter_fromdatelicense, investigationfilter_id, investigationfilter_idsonly, investigationfilter_ignoreworkers, investigationfilter_includechildinv, investigationfilter_name, investigationfilter_notcategory,
                                                    investigationfilter_notids, investigationfilter_page, investigationfilter_period, investigationfilter_reason, investigationfilter_searchafter, investigationfilter_searchbefore, investigationfilter_size, investigationfilter_sort, investigationfilter_status, investigationfilter_timeframe, investigationfilter_toclosedate, investigationfilter_todate, investigationfilter_type, investigationfilter_user)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationSearchResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def simple_complete_task_command(client, args):
    invtaskinfo_args = str(args.get('invtaskinfo_args', ''))
    invtaskinfo_comment = str(args.get('invtaskinfo_comment', ''))
    invtaskinfo_conditions = argToList(args.get('invtaskinfo_conditions', []))
    invtaskinfo_intaskid = str(args.get('invtaskinfo_intaskid', ''))
    invtaskinfo_input = str(args.get('invtaskinfo_input', ''))
    invtaskinfo_invid = str(args.get('invtaskinfo_invid', ''))
    invtaskinfo_loopargs = str(args.get('invtaskinfo_loopargs', ''))
    invtaskinfo_loopcondition = argToList(args.get('invtaskinfo_loopcondition', []))
    invtaskinfo_version = args.get('invtaskinfo_version', None)

    response = client.simple_complete_task_request(invtaskinfo_args, invtaskinfo_comment, invtaskinfo_conditions, invtaskinfo_intaskid,
                                                   invtaskinfo_input, invtaskinfo_invid, invtaskinfo_loopargs, invtaskinfo_loopcondition, invtaskinfo_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def submit_task_form_command(client, args):
    investigationId = str(args.get('investigationId', ''))
    taskId = str(args.get('taskId', ''))
    answers = str(args.get('answers', ''))
    file = str(args.get('file', ''))
    fileNames = str(args.get('fileNames', ''))
    fileComments = str(args.get('fileComments', ''))

    response = client.submit_task_form_request(investigationId, taskId, answers, file, fileNames, fileComments)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def task_add_comment_command(client, args):
    invtaskinfo_args = str(args.get('invtaskinfo_args', ''))
    invtaskinfo_comment = str(args.get('invtaskinfo_comment', ''))
    invtaskinfo_conditions = argToList(args.get('invtaskinfo_conditions', []))
    invtaskinfo_intaskid = str(args.get('invtaskinfo_intaskid', ''))
    invtaskinfo_input = str(args.get('invtaskinfo_input', ''))
    invtaskinfo_invid = str(args.get('invtaskinfo_invid', ''))
    invtaskinfo_loopargs = str(args.get('invtaskinfo_loopargs', ''))
    invtaskinfo_loopcondition = argToList(args.get('invtaskinfo_loopcondition', []))
    invtaskinfo_version = args.get('invtaskinfo_version', None)

    response = client.task_add_comment_request(invtaskinfo_args, invtaskinfo_comment, invtaskinfo_conditions, invtaskinfo_intaskid,
                                               invtaskinfo_input, invtaskinfo_invid, invtaskinfo_loopargs, invtaskinfo_loopcondition, invtaskinfo_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def task_assign_command(client, args):
    invplaybookassignee_assignee = str(args.get('invplaybookassignee_assignee', ''))
    invplaybookassignee_intaskid = str(args.get('invplaybookassignee_intaskid', ''))
    invplaybookassignee_invid = str(args.get('invplaybookassignee_invid', ''))
    invplaybookassignee_version = args.get('invplaybookassignee_version', None)

    response = client.task_assign_request(invplaybookassignee_assignee, invplaybookassignee_intaskid,
                                          invplaybookassignee_invid, invplaybookassignee_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def task_set_due_command(client, args):
    invplaybookdue_date = str(args.get('invplaybookdue_date', ''))
    invplaybookdue_intaskid = str(args.get('invplaybookdue_intaskid', ''))
    invplaybookdue_invid = str(args.get('invplaybookdue_invid', ''))
    invplaybookdue_version = args.get('invplaybookdue_version', None)

    response = client.task_set_due_request(invplaybookdue_date, invplaybookdue_intaskid,
                                           invplaybookdue_invid, invplaybookdue_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def task_un_complete_command(client, args):
    invtaskinfo_args = str(args.get('invtaskinfo_args', ''))
    invtaskinfo_comment = str(args.get('invtaskinfo_comment', ''))
    invtaskinfo_conditions = argToList(args.get('invtaskinfo_conditions', []))
    invtaskinfo_intaskid = str(args.get('invtaskinfo_intaskid', ''))
    invtaskinfo_input = str(args.get('invtaskinfo_input', ''))
    invtaskinfo_invid = str(args.get('invtaskinfo_invid', ''))
    invtaskinfo_loopargs = str(args.get('invtaskinfo_loopargs', ''))
    invtaskinfo_loopcondition = argToList(args.get('invtaskinfo_loopcondition', []))
    invtaskinfo_version = args.get('invtaskinfo_version', None)

    response = client.task_un_complete_request(invtaskinfo_args, invtaskinfo_comment, invtaskinfo_conditions, invtaskinfo_intaskid,
                                               invtaskinfo_input, invtaskinfo_invid, invtaskinfo_loopargs, invtaskinfo_loopcondition, invtaskinfo_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.InvestigationPlaybook',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_entry_note_command(client, args):
    updateentry_args = str(args.get('updateentry_args', ''))
    updateentry_data = str(args.get('updateentry_data', ''))
    updateentry_id = str(args.get('updateentry_id', ''))
    updateentry_investigationid = str(args.get('updateentry_investigationid', ''))
    updateentry_markdown = argToBoolean(args.get('updateentry_markdown', False))
    updateentry_version = args.get('updateentry_version', None)

    response = client.update_entry_note_request(
        updateentry_args, updateentry_data, updateentry_id, updateentry_investigationid, updateentry_markdown, updateentry_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Entry',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def update_entry_tags_op_command(client, args):
    updateentrytags_id = str(args.get('updateentrytags_id', ''))
    updateentrytags_investigationid = str(args.get('updateentrytags_investigationid', ''))
    updateentrytags_tags = argToList(args.get('updateentrytags_tags', []))
    updateentrytags_version = args.get('updateentrytags_version', None)

    response = client.update_entry_tags_op_request(
        updateentrytags_id, updateentrytags_investigationid, updateentrytags_tags, updateentrytags_version)
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Entry',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def workers_status_handler_command(client, args):

    response = client.workers_status_handler_request()
    command_results = CommandResults(
        outputs_prefix='CortexXSOAR.Info',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client):
    # Test functions here
    get_all_widgets_command(client, {})
    demisto.results('ok')


def main():

    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    headers = {}
    headers['Authorization'] = f'{params["api_key"]}'

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        requests.packages.urllib3.disable_warnings()
        client = Client(urljoin(url, ""), verify_certificate, proxy, headers=headers, auth=None)
        commands = {
            'cortex-xsoar-add-ad-hoc-task': add_ad_hoc_task_command,
            'cortex-xsoar-close-incidents-batch': close_incidents_batch_command,

            'cortex-xsoar-complete-task': complete_task_command,

            'cortex-xsoar-complete-taskv2': complete_taskv2_command,

            'cortex-xsoar-copy-script': copy_script_command,

            'cortex-xsoar-create-docker-image': create_docker_image_command,

            'cortex-xsoar-create-feed-indicators-json': create_feed_indicators_json_command,

            'cortex-xsoar-create-incident': create_incident_command,

            'cortex-xsoar-create-incident-json': create_incident_json_command,

            'cortex-xsoar-create-incidents-batch': create_incidents_batch_command,

            'cortex-xsoar-create-or-update-incident-type': create_or_update_incident_type_command,

            'cortex-xsoar-create-or-update-whitelisted': create_or_update_whitelisted_command,

            'cortex-xsoar-delete-ad-hoc-task': delete_ad_hoc_task_command,

            'cortex-xsoar-delete-automation-script': delete_automation_script_command,

            'cortex-xsoar-delete-evidence-op': delete_evidence_op_command,

            'cortex-xsoar-delete-incidents-batch': delete_incidents_batch_command,

            'cortex-xsoar-delete-indicators-batch': delete_indicators_batch_command,

            'cortex-xsoar-delete-widget': delete_widget_command,

            'cortex-xsoar-download-file': download_file_command,

            'cortex-xsoar-download-latest-report': download_latest_report_command,

            'cortex-xsoar-edit-ad-hoc-task': edit_ad_hoc_task_command,

            'cortex-xsoar-entry-export-artifact': entry_export_artifact_command,

            'cortex-xsoar-execute-report': execute_report_command,

            'cortex-xsoar-export-incidents-to-csv-batch': export_incidents_to_csv_batch_command,

            'cortex-xsoar-export-indicators-to-csv-batch': export_indicators_to_csv_batch_command,

            'cortex-xsoar-export-indicators-to-stix-batch': export_indicators_to_stix_batch_command,

            'cortex-xsoar-get-all-reports': get_all_reports_command,

            'cortex-xsoar-get-all-widgets': get_all_widgets_command,

            'cortex-xsoar-get-audits': get_audits_command,

            'cortex-xsoar-get-automation-scripts': get_automation_scripts_command,

            'cortex-xsoar-get-containers': get_containers_command,

            'cortex-xsoar-get-docker-images': get_docker_images_command,

            'cortex-xsoar-get-entry-artifact': get_entry_artifact_command,

            'cortex-xsoar-get-incident-as-csv': get_incident_as_csv_command,

            'cortex-xsoar-get-incidents-fields-by-incident-type': get_incidents_fields_by_incident_type_command,

            'cortex-xsoar-get-indicators-as-csv': get_indicators_as_csv_command,

            'cortex-xsoar-get-indicators-asstix': get_indicators_asstix_command,

            'cortex-xsoar-get-report-byid': get_report_byid_command,

            'cortex-xsoar-get-stats-for-dashboard': get_stats_for_dashboard_command,

            'cortex-xsoar-get-stats-for-widget': get_stats_for_widget_command,

            'cortex-xsoar-get-widget': get_widget_command,

            'cortex-xsoar-health-handler': health_handler_command,

            'cortex-xsoar-import-classifier': import_classifier_command,

            'cortex-xsoar-import-dashboard': import_dashboard_command,

            'cortex-xsoar-import-incident-fields': import_incident_fields_command,

            'cortex-xsoar-import-incident-types-handler': import_incident_types_handler_command,

            'cortex-xsoar-import-script': import_script_command,

            'cortex-xsoar-import-widget': import_widget_command,

            'cortex-xsoar-incident-file-upload': incident_file_upload_command,

            'cortex-xsoar-indicator-whitelist': indicator_whitelist_command,

            'cortex-xsoar-indicators-create': indicators_create_command,

            'cortex-xsoar-indicators-create-batch': indicators_create_batch_command,

            'cortex-xsoar-indicators-edit': indicators_edit_command,

            'cortex-xsoar-indicators-search': indicators_search_command,

            'cortex-xsoar-indicators-timeline-delete': indicators_timeline_delete_command,

            'cortex-xsoar-integration-upload': integration_upload_command,

            'cortex-xsoar-investigation-add-entries-sync': investigation_add_entries_sync_command,

            'cortex-xsoar-investigation-add-entry-handler': investigation_add_entry_handler_command,

            'cortex-xsoar-investigation-add-formatted-entry-handler': investigation_add_formatted_entry_handler_command,

            'cortex-xsoar-logout-myself-handler': logout_myself_handler_command,

            'cortex-xsoar-logout-myself-other-sessions-handler': logout_myself_other_sessions_handler_command,

            'cortex-xsoar-logout-user-sessions-handler': logout_user_sessions_handler_command,

            'cortex-xsoar-logouta-everyone-handler': logouta_everyone_handler_command,

            'cortex-xsoar-override-playbook-yaml': override_playbook_yaml_command,

            'cortex-xsoar-revoke-userapi-key': revoke_userapi_key_command,

            'cortex-xsoar-save-evidence': save_evidence_command,

            'cortex-xsoar-save-or-update-script': save_or_update_script_command,

            'cortex-xsoar-save-widget': save_widget_command,

            'cortex-xsoar-search-evidence': search_evidence_command,

            'cortex-xsoar-search-incidents': search_incidents_command,

            'cortex-xsoar-search-investigations': search_investigations_command,

            'cortex-xsoar-simple-complete-task': simple_complete_task_command,

            'cortex-xsoar-submit-task-form': submit_task_form_command,

            'cortex-xsoar-task-add-comment': task_add_comment_command,

            'cortex-xsoar-task-assign': task_assign_command,

            'cortex-xsoar-task-set-due': task_set_due_command,

            'cortex-xsoar-task-un-complete': task_un_complete_command,

            'cortex-xsoar-update-entry-note': update_entry_note_command,

            'cortex-xsoar-update-entry-tags-op': update_entry_tags_op_command,

            'cortex-xsoar-workers-status-handler': workers_status_handler_command,
        }

        if command == 'test-module':
            test_module(client)
        else:
            return_results(commands[command](client, args))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
