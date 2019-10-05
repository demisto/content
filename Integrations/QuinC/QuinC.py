import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''

import json
import requests
from requests.exceptions import HTTPError

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' CONSTANTS '''
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

JOBID_KEY = 'Accessdata.Job.ID'
JOBRESULT_KEY = 'Accessdata.Job.Result'
JOBSTATE_KEY = 'Accessdata.Job.State'
JOB_KEY = 'Accessdata.Job'


def create_jobstate_context(contents):
    return {
        JOB_KEY + '(val.ID == obj.ID)': contents
    }


def create_contents(id, state, result):
    ec = {
        'ID': id,
        'State': state,
        'Result': result
    }
    return ec


class Client:
    """
    Client will implement the service API, should not contain Demisto logic.
    Should do requests and return data
    # """
    def __init__(self, base_url=None, verify=None, token=None):
        self.base_url = base_url
        self.verify = verify
        self.headers = {
            'EnterpriseApiKey': token,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def http_request(self, method, url_suffix, body=None, params=None):
        try:
            full_url = self.base_url + url_suffix
            res = requests.request(
                method, full_url, data=body, headers=self.headers,
                params=params, verify=self.verify)
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
            return_error(err_msg)
        return ""

    def test_quinc(self):
        res = self.http_request('GET', 'api/v2/enterpriseapi/statuscheck')
        return res.lower()

    def get_jobstatus(self, args):

        url = 'api/v2/enterpriseapi/core/' + str(args['caseID']) + \
            '/getjobstatus/' + str(args['jobID'])
        res = self.http_request('GET', url)

        if 'resultData' not in res:
            contents = create_contents(args['jobID'], 'Failed', res)
            return {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': contents,
                'HumanReadable': "No data in job result",
                'EntryContext': create_jobstate_context(contents)
            }
        resultData = json.loads(res['resultData'])

        if 'RealData' not in resultData:
            contents = create_contents(args['jobID'], 'Failed', resultData)
            return {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': contents,
                'HumanReadable': "No data in job result",
                'EntryContext': create_jobstate_context(contents)
            }
        RealData = json.loads(resultData['RealData'])

        if 'TaskStatusList' not in RealData:
            contents = create_contents(args['jobID'], 'Failed', RealData)
            return {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': contents,
                'HumanReadable': "No task data in job result",
                'EntryContext': create_jobstate_context(contents)
            }

        task = RealData['TaskStatusList'][0]

        if task is not None:

            if task['State'] is None:
                contents = create_contents(args['jobID'], 'Unknown', task)
                return {
                    'Type': entryTypes['note'],
                    'ContentsFormat': formats['json'],
                    'Contents': contents,
                    'HumanReadable': "Cannot get job state",
                    'EntryContext': create_jobstate_context(contents)
                }
            if task['State'] != 'Success':
                contents = create_contents(args['jobID'], task['State'], task)
                return {
                    'Type': entryTypes['note'],
                    'ContentsFormat': formats['json'],
                    'Contents': contents,
                    'HumanReadable': "Current job state: " + task['State'],
                    'EntryContext': create_jobstate_context(contents)
                }
            else:
                result = json.loads(task['Results'][0]['Data'])
                res = json.loads(task['Results'][1]['Data'])
                if result['OperationType'] == 24:  # software inventory
                    contents = create_contents(
                        args['jobID'], 'Success', res['Applications'])
                    return {
                        'Type': entryTypes['note'],
                        'Contents': contents,
                        'ContentsFormat': formats['json'],
                        'HumanReadable': tableToMarkdown(
                            'Applications', res['Applications'],
                            [
                                'Name', 'Version', 'Publisher', 'InstallDate',
                                'InstallLocation', 'InstallSource',
                                'EstimatedSizeInBytes'
                            ]),
                        'EntryContext': create_jobstate_context(contents)
                    }
                elif result['OperationType'] == 12:  # volatile data
                    contents = create_contents(args['jobID'], 'Success', res)
                    return {
                        'Type': entryTypes['note'],
                        'Contents': contents,
                        'ContentsFormat': formats['json'],
                        'HumanReadable': "Job completed successfully",
                        'EntryContext': create_jobstate_context(contents)
                    }
                else:
                    contents = create_contents(args['jobID'], 'Success', task)
                    return {
                        'Type': entryTypes['note'],
                        'ContentsFormat': formats['json'],
                        'Contents': contents,
                        'HumanReadable': "Job completed successfully",
                        'EntryContext': create_jobstate_context(contents)
                    }

        contents = create_contents(args['jobID'], 'Unknown', None)

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': contents,
            'HumanReadable': "Job exited unexpectedly",
            'EntryContext': create_jobstate_context(contents)
        }

    def legacyagent_runvolatilejob(self, args):

        url = 'api/v2/enterpriseapi/agent/' + args['caseid'] + '/volatile'
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
        res = self.http_request('POST', url, json.dumps(data))
        ec = {
            'ID': res,
            'Type': 'Volatile'
        }

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': res,
            'HumanReadable': "JobID: " + str(res),
            'EntryContext': {JOB_KEY + '(val.ID && val.Type == obj.Type)': ec}
        }

    def legacyagent_runmemoryacquisition(self, args):

        url = 'api/v2/enterpriseapi/agent/' + args['caseid'] + \
            '/memoryacquistion'
        data = {
            'ips': {'targets': [args['target_ip']]},
            'MemoryAcquistion': {'Operation': 11}
        }
        res = self.http_request('POST', url, json.dumps(data))
        ec = {
            'ID': res,
            'Type': 'LegacyMemoryDump'
        }

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': ec,
            'HumanReadable': "JobID: " + str(res),
            'EntryContext': {JOB_KEY + '(val.ID && val.Type == obj.Type)': ec}
        }

    def read_casefile(self, args):

        url = 'api/v2/enterpriseapi/core/readfilecontents'
        data = args['filepath']
        res = self.http_request('POST', url, json.dumps(data))

        return {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': res,
            'EntryContext': {'Accessdata.File.Contents': res}
        }


def test_module(client):
    return client.test_quinc()


def quinc_get_jobstatus_command(client, args):
    return client.get_jobstatus(args)


def quinc_legacyagent_runvolatilejob_command(client, args):
    return client.legacyagent_runvolatilejob(args)


def quinc_legacyagent_runmemoryacquisition_command(client, args):
    return client.legacyagent_runmemoryacquisition(args)


def quinc_read_casefile_command(client, args):
    return client.read_casefile(args)


def main():

    use_ssl = not demisto.params().get('Insecure', True)
    url = demisto.params().get('Scheme', 'http') + '://' + \
        demisto.params().get('server_name') + ':4443/'
    token = demisto.params()['Token']

    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(url, use_ssl, token)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            demisto.results(test_module(client))

        if demisto.command() == 'accessdata-get-jobstatus':
            demisto.results(
                quinc_get_jobstatus_command(
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

    except Exception as e:
        return_error(
            "Failed to execute {} command. Error: {}".format(
                demisto.command(), str(e)))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
