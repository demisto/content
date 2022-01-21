import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


''' IMPORTS '''

import os
import json
import requests
from requests.exceptions import HTTPError

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' CONSTANTS '''
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

ACCESS_DATA = 'Accessdata'
JOBID_KEY = 'Accessdata.Job.ID'
JOBRESULT_KEY = 'Accessdata.Job.Result'
JOBSTATE_KEY = 'Accessdata.Job.State'
JOB_KEY = 'Accessdata.Job'

''' HELPERS '''


def create_jobstate_context(contents):
    if 'CaseJobID' not in contents:
        return {
            JOB_KEY + '(val.ID == obj.ID)': contents
        }
    return {
        JOB_KEY + '(val.CaseJobID == obj.CaseJobID)': contents
    }


def create_contents(caseID, jobID, state=None, result=None):
    ec = {
        'CaseID': caseID,
        'ID': jobID,
        'CaseJobID': str(caseID) + "_" + str(jobID)
    }
    if state is not None:
        ec['State'] = state
    if result is not None:
        ec['Result'] = result
    return ec


def wrap_jobstate_context(contents, humanReadableMessage=""):
    return {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': contents,
        'HumanReadable': humanReadableMessage,
        'EntryContext': create_jobstate_context(contents)
    }


class Client:
    """
    Client will implement the service API, should not contain Demisto logic.
    Should do requests and return data
    # """
    def __init__(self, base_url=None, verify=None, proxy=None, token=None):
        self.base_url = base_url
        self.verify = verify
        self.headers = {
            'EnterpriseApiKey': token,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.proxy = proxy

    def http_request(self, method, url_suffix, body=None, params=None):
        try:
            full_url = self.base_url + url_suffix
            res = requests.request(
                method, full_url, data=body, headers=self.headers,
                params=params, proxies=self.proxy, verify=self.verify)
            res.raise_for_status()
            return res.json()

        except ValueError:
            return res.text
        except HTTPError:
            err_json = res.json()
            err_msg = ''
            if 'message' in err_json:
                err_msg = err_msg + \
                    'Error: {0}.\n'.format(err_json['message'])
            elif 'http_response' in err_json:
                err_msg = err_msg + \
                    'Error: {0}.\n'.format(err_json['http_response'])
            if 'code' in err_json:
                err_msg = err_msg + \
                    'QRadar Error Code: {0}'.format(err_json['code'])
            raise Exception(err_msg)

    def test_quinc(self):
        res = self.http_request('GET', 'api/v2/enterpriseapi/statuscheck')
        return res.lower()

    def get_jobstatus(self, args):
        caseID = args['caseID']
        jobID = args['jobID']
        url = 'api/v2/enterpriseapi/core/' + str(caseID) + \
            '/getjobstatus/' + str(jobID)
        res = self.http_request('GET', url)

        if 'resultData' not in res:  # if no data take state from first level of nesting
            contents = create_contents(caseID, jobID, res['state'], res)
            return wrap_jobstate_context(contents, "Current job state: " + res['state'])

        resultData = json.loads(res['resultData'])

        if 'RealData' not in resultData:  # if no data take state from first level of nesting
            contents = create_contents(caseID, jobID, res['state'], resultData)
            return wrap_jobstate_context(contents, "Current job state: " + res['state'])

        RealData = json.loads(resultData['RealData'])

        if 'TaskStatusList' not in RealData:  # if no data take state from first level of nesting
            contents = create_contents(caseID, jobID, res['state'], RealData)
            return wrap_jobstate_context(contents, "Current job state: " + res['state'])

        task = RealData['TaskStatusList'][0]

        if task is not None:

            if task['State'] is None:
                contents = create_contents(caseID, jobID, 'Unknown', task)
                return wrap_jobstate_context(contents, "Cannot get job state")
            if task['State'] != 'Success':
                contents = create_contents(caseID, jobID, task['State'], task)
                return wrap_jobstate_context(contents, "Current job state: " + task['State'])
            else:
                result = json.loads(task['Results'][0]['Data'])
                res = json.loads(task['Results'][1]['Data'])
                if result['OperationType'] == 24:  # software inventory
                    contents = create_contents(
                        caseID, jobID, 'Success', res['Applications'])
                    return wrap_jobstate_context(
                        contents,
                        tableToMarkdown(
                            'Applications', res['Applications'],
                            [
                                'Name', 'Version', 'Publisher', 'InstallDate',
                                'InstallLocation', 'InstallSource',
                                'EstimatedSizeInBytes'
                            ]))
                elif result['OperationType'] == 12:  # volatile data
                    contents = create_contents(caseID, jobID, 'Success', res)
                    return wrap_jobstate_context(contents, "Job completed successfully")
                elif result['OperationType'] == 11:  # memory dump
                    memdumpres = json.loads(task['Results'][2]['Data'])
                    contents = create_contents(caseID, jobID, 'Success', memdumpres)
                    return wrap_jobstate_context(contents, "Job completed successfully")
                else:
                    contents = create_contents(caseID, jobID, 'Success', task)
                    return wrap_jobstate_context(contents, "Job completed successfully")

        contents = create_contents(caseID, jobID, 'Failed', None)
        return wrap_jobstate_context(contents, "Job exited unexpectedly")

    def get_jobstatus_processlist(self, args):
        jobStatus = self.get_jobstatus(args)
        contents = jobStatus['Contents']
        newContents = create_contents(contents['CaseID'], contents['ID'], contents['State'], "")

        message = "(to get path to snapshot job should be finished) "

        if 'Result' not in contents:
            message += "No Result in response scheme"
            return wrap_jobstate_context(newContents, message)

        if 'SnapshotDetails' not in contents['Result']:
            message += "No Result.SnapshotDetails in response scheme"
            return wrap_jobstate_context(newContents, message)

        if 'File' not in contents['Result']['SnapshotDetails']:
            message += "No Result.SnapshotDetails.File in response scheme"
            return wrap_jobstate_context(newContents, message)
        newContents['Result'] = contents['Result']['SnapshotDetails']['File']

        return wrap_jobstate_context(newContents, newContents['Result'])

    def get_jobstatus_memorydump(self, args):
        jobStatus = self.get_jobstatus(args)
        contents = jobStatus['Contents']
        newContents = create_contents(
            contents['CaseID'],
            contents['ID'],
            contents['State'],
            "")
        contents = contents['Result']

        message = "(to get path to memory dump job should be finished) "

        if 'ResultFiles' not in contents:
            message += "No ResultFiles in response scheme"
            return wrap_jobstate_context(newContents, message)

        if not contents['ResultFiles']:
            message += "ResultFiles is empty"
            return wrap_jobstate_context(newContents, message)
        contents = contents['ResultFiles'][0]

        if 'Path' not in contents:
            message += "No Path in response scheme"
            return wrap_jobstate_context(newContents, message)
        newContents['Result'] = contents['Path']

        return wrap_jobstate_context(newContents, newContents['Result'])

    def jobstatus_scan(self, args):
        caseJobID = args['caseJobID']
        preparedParameters = caseJobID.split("_")
        preparedParameters = {
            'caseID': preparedParameters[0],
            'jobID': preparedParameters[1]
        }
        jobStatus = self.get_jobstatus(preparedParameters)
        contents = jobStatus['Contents']

        newContents = create_contents(preparedParameters['caseID'],
                                      preparedParameters['jobID'],
                                      'Unknown')
        if 'State' not in contents:
            return wrap_jobstate_context(newContents, "No state in job result")
        newContents['State'] = contents['State']
        return wrap_jobstate_context(newContents, "Current job state: " + newContents['State'])

    def legacyagent_runvolatilejob(self, args):

        if ('caseid' not in args or args['caseid'] is None):
            args['caseid'] = self.get_processing_case_id()['Contents']

        url = 'api/v2/enterpriseapi/agent/' + str(args['caseid']) + '/volatile'
        data = {
            'ips': {'targets': [args['target_ip']]},
            'Volatile': {
                'Operation': 12,
                'IncludeProcessTree': True,
                'ProcessTreeOptions': {
                    'DetectHiddenProcesses': True,
                    'IncludeDlls': True,
                    'IncludeSockets': True
                }
            }
        }
        jobID = self.http_request('POST', url, json.dumps(data))
        contents = create_contents(args['caseid'], jobID, 'Unknown')
        contents['Type'] = 'Volatile'

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': contents,
            'HumanReadable': "JobID: " + str(jobID),
            'EntryContext': create_jobstate_context(contents)
        }

    def legacyagent_runmemoryacquisition(self, args):

        if ('caseid' not in args or args['caseid'] is None):
            args['caseid'] = self.get_processing_case_id()['Contents']

        url = 'api/v2/enterpriseapi/agent/' + str(args['caseid']) + \
            '/memoryacquistion'
        data = {
            'ips': {'targets': [args['target_ip']]},
            'MemoryAcquistion': {'Operation': 11}
        }
        jobID = self.http_request('POST', url, json.dumps(data))
        contents = create_contents(args['caseid'], jobID, 'Unknown')
        contents['Type'] = 'LegacyMemoryDump'

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': contents,
            'HumanReadable': "JobID: " + str(jobID),
            'EntryContext': create_jobstate_context(contents)
        }

    def read_casefile(self, args):

        url = 'api/v2/enterpriseapi/core/readfilecontents'
        filepath = args['filepath']
        data = self.http_request('POST', url, json.dumps(filepath))

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': data,
            'EntryContext': {'Accessdata.File.Contents': data}
        }

    def get_processing_case_id(self):

        url = 'api/v2/enterpriseapi/processingcaseid'
        processingcaseId = self.http_request('GET', url)

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': processingcaseId,
            'EntryContext': {ACCESS_DATA + '.ProcessingCaseId': processingcaseId}
        }


def test_module(client):
    return client.test_quinc()


def quinc_get_jobstatus_command(client, args):
    return client.get_jobstatus(args)


def quinc_get_jobstatus_processlist_command(client, args):
    return client.get_jobstatus_processlist(args)


def quinc_get_jobstatus_memorydump_command(client, args):
    return client.get_jobstatus_memorydump(args)


def quinc_jobstatus_scan_command(client, args):
    return client.jobstatus_scan(args)


def quinc_legacyagent_runvolatilejob_command(client, args):
    return client.legacyagent_runvolatilejob(args)


def quinc_legacyagent_runmemoryacquisition_command(client, args):
    return client.legacyagent_runmemoryacquisition(args)


def quinc_read_casefile_command(client, args):
    return client.read_casefile(args)


def quinc_get_processing_case_id_command(client):
    return client.get_processing_case_id()


def main():

    use_ssl = not demisto.params().get('insecure', True)
    url = demisto.params().get('server_name') + ':4443/'
    token = demisto.params()['Token']

    if not demisto.params().get('proxy'):
        if 'HTTP_PROXY' in os.environ:
            del os.environ['HTTP_PROXY']
        if 'HTTPS_PROXY' in os.environ:
            del os.environ['HTTPS_PROXY']
        if 'http_proxy' in os.environ:
            del os.environ['http_proxy']
        if 'https_proxy' in os.environ:
            del os.environ['https_proxy']

        PROXIES = {
            'http': None,
            'https': None
        }  # type: dict
    else:
        PROXIES = {
            'http': os.environ['http_proxy'] or os.environ['HTTP_PROXY'],
            'https': os.environ['https_proxy'] or os.environ['HTTPS_PROXY']
        }

    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(url, use_ssl, PROXIES, token)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            demisto.results(test_module(client))

        if demisto.command() == 'accessdata-get-jobstatus-processlist':
            demisto.results(
                quinc_get_jobstatus_processlist_command(
                    client, demisto.args()))

        if demisto.command() == 'accessdata-get-jobstatus-memorydump':
            demisto.results(
                quinc_get_jobstatus_memorydump_command(
                    client, demisto.args()))

        if demisto.command() == 'accessdata-jobstatus-scan':
            demisto.results(
                quinc_jobstatus_scan_command(
                    client, demisto.args()))

        if demisto.command() == 'accessdata-legacyagent-get-processlist':
            demisto.results(
                quinc_legacyagent_runvolatilejob_command(
                    client, demisto.args()))

        if demisto.command() == 'accessdata-legacyagent-get-memorydump':
            demisto.results(
                quinc_legacyagent_runmemoryacquisition_command(
                    client, demisto.args()))

        if demisto.command() == 'accessdata-read-casefile':
            demisto.results(
                quinc_read_casefile_command(
                    client, demisto.args()))

        if demisto.command() == 'accessdata-get-processing-case-id':
            demisto.results(
                quinc_get_processing_case_id_command(client))

    except Exception as e:
        return_error(
            "Failed to execute {} command. Error: {}".format(
                demisto.command(), str(e)))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
