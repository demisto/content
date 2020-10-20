import base64

import requests

import demistomock as demisto
from CommonServerPython import *

requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    # let this stay for debugging.
    '''def __repr__(self):
        return " proxy:% s headers:% s" % (self._proxy, self._headers)

    def __str__(self):
        return "proxy:% s headers:% s" % (self._proxy, self._headers)'''

    def updateHeaders(self, base64String):
        base64String = base64String.decode("utf-8")
        headers = {'accept': 'application/json', 'Authorization': 'Basic ' + base64String}
        data = {'grant_type': 'client_credentials', 'scope': 'read'}
        response = self._http_request(method='POST', url_suffix='/token', headers=headers, data=data,
                                      resp_type='response')
        responseJson = response.json()
        access_token = responseJson.get('access_token')
        headers = {'Authorization': 'Bearer' + " " + access_token}
        self._headers = headers

    def test_apiModule(self):
        return self._http_request(method='GET', url_suffix='/realize/ransomwarerecovery/v1/quarantineranges',
                                  resp_type='response')

    def get_quarantineRanges(self):
        return self._http_request(method='GET', url_suffix='/realize/ransomwarerecovery/v1/quarantineranges',
                                  resp_type='response')

    def get_findDevice(self, search_string):
        params = {'hostname': search_string}
        return self._http_request(method='GET', url_suffix='/realize/ransomwarerecovery/v1/search/resource',
                                  params=params, resp_type='response')

    def post_quarantineResource(self, resource_id, resource_type, from_date, to_date):
        json_data = {'resourceType': resource_type, 'fromDate': from_date, 'toDate': to_date}
        url_suffix = '/realize/ransomwarerecovery/v1/quarantineranges/resource/' + resource_id
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=json_data, resp_type='response')

    def delete_quarantineRange(self, resource_id, range_id):
        url_suffix = '/realize/ransomwarerecovery/v1/quarantineranges/resource/' + resource_id + '/range/' + range_id
        return self._http_request(method='DELETE', url_suffix=url_suffix, resp_type='response')

    def view_quarantineRange(self, resource_id, range_id):
        url_suffix = '/realize/ransomwarerecovery/v1/quarantineranges/resource/' + resource_id + '/range/' + range_id
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='response')

    def update_quarantineRange(self, resource_id, resource_type, range_id, from_date, to_date):
        json_data = {'resourceType': resource_type, 'fromDate': from_date, 'toDate': to_date}
        url_suffix = '/realize/ransomwarerecovery/v1/quarantineranges/resource/' + resource_id + '/range/' + range_id
        return self._http_request(method='PUT', url_suffix=url_suffix, json_data=json_data, resp_type='response')

    def get_quarantinedSnapshots(self, resource_id, range_id):
        url_suffix = '/realize/ransomwarerecovery/v1/snapshots/resource/' + resource_id + '/range/' + range_id
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='response')

    def delete_Snapshots(self, resource_id, range_id, snapshot_id):
        url_suffix = '/realize/ransomwarerecovery/v1/snapshots/resource/' + \
                     resource_id + '/range/' + range_id + '/snapshot/' + snapshot_id
        return self._http_request(method='DELETE', url_suffix=url_suffix, resp_type='response')

    def get_searchbyFileHash(self, sha1_checksum):
        url_suffix = '/realize/mds/v1/user/files?sha1Checksum=' + sha1_checksum
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='response')

    def post_restoreToEndpoint(self, source_resourceid, target_resourceid, restore_location):
        url_suffix = '/insync/endpoints/v1/restores'
        json_data = {'deviceID': int(source_resourceid), 'targetDeviceID': int(
            target_resourceid), 'restoreLocation': restore_location}
        return self._http_request(method='POST', url_suffix=url_suffix, json_data=json_data, resp_type='response')

    def get_restoreStatus(self, restore_id):
        url_suffix = '/insync/endpoints/v1/restores/' + str(restore_id)
        return self._http_request(method='GET', url_suffix=url_suffix, resp_type='response')

    def post_decommission(self, resource_id):
        url_suffix = 'https://apis.druva.com/insync/endpoints/v1/devices/' + str(resource_id) + '/decommission'
        return self._http_request(method='POST', url_suffix=url_suffix, resp_type='response')


def test_module(clientObj):
    response = clientObj.test_apiModule()
    statusCode = response.status_code
    if (statusCode == 200):
        return ("ok")
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_ListQuarantineRanges_Command(clientObj):
    response = clientObj.get_quarantineRanges()
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        readable_output = tableToMarkdown('Active quarantined Ranges', responseJson['quarantineRanges'])
        outputs = {"Druva.activeQuarantineRanges(val.rangeID == obj.rangeID)": responseJson['quarantineRanges']}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)

    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_FindDevice_Command(clientObj, search_string):
    response = clientObj.get_findDevice(search_string)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        readable_output = tableToMarkdown('Found Druva Devices', responseJson['resources'])
        outputs = {"Druva.Resource(val.resourceID == obj.resourceID)": responseJson['resources']}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)

    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_QuarantineResource_Command(clientObj, resource_id, resource_type, from_date, to_date):
    response = clientObj.post_quarantineResource(resource_id, resource_type, from_date, to_date)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        headers = ['RangeID']
        readable_output = tableToMarkdown('Resource quarantined successfully', str(responseJson['rangeID']),
                                          headers=headers)
        outputs = {"Druva.QuarantinedRangeID": str(responseJson['rangeID'])}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_DeleteQuarantineRange_Command(clientObj, resource_id, range_id):
    response = clientObj.delete_quarantineRange(resource_id, range_id)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        headers = ['RangeID']
        readable_output = tableToMarkdown('Quarantine Range Deleted Successfully', str(range_id), headers=headers)
        raw_response = responseJson
        return (readable_output, {}, raw_response)
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_ViewQurantineRange_Command(clientObj, resource_id, range_id):
    response = clientObj.view_quarantineRange(resource_id, range_id)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        readable_output = tableToMarkdown('Range Details', responseJson)
        outputs = {"Druva.viewedQuarantineRange(val.rangeID == obj.rangeID)": responseJson}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)


def Druva_UpdateQuarantineRange_Command(clientObj, resource_id, resource_type, range_id, from_date, to_date):
    response = clientObj.update_quarantineRange(resource_id, resource_type, range_id, from_date, to_date)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        headers = ['RangeID']
        readable_output = tableToMarkdown('Range updated successfully', str(responseJson['rangeID']), headers=headers)
        outputs = {"Druva.updatedQuarantineRange": str(range_id)}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_ListQuarantine_Snapshots_Command(clientObj, resource_id, range_id):
    response = clientObj.get_quarantinedSnapshots(resource_id, range_id)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        readable_output = tableToMarkdown('Quarantined Snapshots', responseJson['snapshots'])
        outputs = {"Druva.quarantinedSnapshots(val.snapshotID == obj.snapshotID)": responseJson['snapshots']}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_DeleteQuarantined_Snapshots_Command(clientObj, resource_id, range_id, snapshot_id):
    response = clientObj.delete_Snapshots(resource_id, range_id, snapshot_id)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        headers = ['Snapshot ID']
        readable_output = tableToMarkdown('Snapshot Deleted successfully', str(snapshot_id), headers=headers)
        raw_response = responseJson
        return (readable_output, {}, raw_response)
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_SearchbyFileHash_Command(clientObj, sha1_checksum):
    response = clientObj.get_searchbyFileHash(sha1_checksum)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        readable_output = tableToMarkdown('Search Results', responseJson['results'])
        outputs = {"Druva.searchEndpointsFileHashResults(val.objectID == obj.objectID)": responseJson['results']}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_Restore_Endpoint(clientObj, source_resourceid, target_resourceid, restore_location):
    response = clientObj.post_restoreToEndpoint(source_resourceid, target_resourceid, restore_location)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        readable_output = tableToMarkdown('Restore Job Initiated', responseJson['restores'])
        outputs = {"Druva.restoreJobs(val.restoreID == obj.restoreID)": responseJson['restores']}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_Restore_Status(clientObj, restore_id):
    response = clientObj.get_restoreStatus(restore_id)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        readable_output = tableToMarkdown('Restore Job Status', responseJson)
        outputs = {"Druva.restoreJobs(val.restoreID == obj.restoreID)": responseJson}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def Druva_Decommission(clientObj, resource_id):
    response = clientObj.post_decommission(resource_id)
    statusCode = response.status_code
    if (statusCode == 200):
        responseJson = response.json()
        headers = ['Resource ID']
        readable_output = tableToMarkdown('Device Decomission Request', str(resource_id), headers=headers)
        outputs = {"Druva.decomissionedResource(val.resource_id == obj.resource_id)": str(resource_id)}
        raw_response = responseJson
        return (readable_output, outputs, raw_response)
    else:
        raise RuntimeError('Error: ' + str(response.status_code))


def main():
    command = demisto.command()
    params = demisto.params()
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy') == 'false'
    druvaBaseURL = params.get('url')
    druvaClientID = params.get('clientId')
    druvaSecKey = params.get('secretKey')
    strToEncode = druvaClientID + ":" + druvaSecKey
    base64String = base64.b64encode(strToEncode.encode())

    try:
        clientObj = Client(
            base_url=druvaBaseURL,
            verify=verify_certificate,
            headers=None,
            proxy=proxy)

        clientObj.updateHeaders(base64String)

        if command == 'druva-list-quarantine-ranges':
            return_outputs(*Druva_ListQuarantineRanges_Command(clientObj))

        if command == 'druva-find-device':
            search_string = demisto.args().get('search_string')
            return_outputs(*Druva_FindDevice_Command(clientObj, search_string))

        if command == 'druva-quarantine-resource':
            resource_id = demisto.args().get('resource_id')
            resource_type = demisto.args().get('resource_type')
            from_date = demisto.args().get('from_date')
            to_date = demisto.args().get('to_date')
            return_outputs(*Druva_QuarantineResource_Command(clientObj, resource_id, resource_type, from_date, to_date))
            return_outputs(*Druva_ListQuarantineRanges_Command(clientObj))

        if command == 'druva-delete-quarantine-range':
            resource_id = demisto.args().get('resource_id')
            range_id = demisto.args().get('range_id')
            return_outputs(*Druva_DeleteQuarantineRange_Command(clientObj, resource_id, range_id))
            # return_outputs(*Druva_ListQuarantineRanges_Command(clientObj))

        if command == 'druva-view-quarantine-range':
            resource_id = demisto.args().get('resource_id')
            range_id = demisto.args().get('range_id')
            return_outputs(*Druva_ViewQurantineRange_Command(clientObj, resource_id, range_id))
            # return_outputs(*Druva_ListQuarantine_Snapshots_Command(clientObj, resource_id, range_id))

        if command == 'druva-update-quarantine-range':
            resource_id = demisto.args().get('resource_id')
            range_id = demisto.args().get('range_id')
            resource_type = demisto.args().get('resource_type')
            from_date = demisto.args().get('from_date')
            to_date = demisto.args().get('to_date')
            return_outputs(*Druva_UpdateQuarantineRange_Command(clientObj,
                                                                resource_id, resource_type, range_id, from_date,
                                                                to_date))
            return_outputs(*Druva_ListQuarantineRanges_Command(clientObj))

        if command == 'druva-list-quarantine-snapshots':
            resource_id = demisto.args().get('resource_id')
            range_id = demisto.args().get('range_id')
            return_outputs(*Druva_ListQuarantine_Snapshots_Command(clientObj, resource_id, range_id))

        if command == 'druva-delete-quarantined-snapshot':
            resource_id = demisto.args().get('resource_id')
            range_id = demisto.args().get('range_id')
            snapshot_id = demisto.args().get('snapshot_id')
            return_outputs(*Druva_DeleteQuarantined_Snapshots_Command(clientObj, resource_id, range_id, snapshot_id))
            # return_outputs(*Druva_ListQuarantine_Snapshots_Command(clientObj, resource_id, range_id))

        if command == 'druva-endpoint-search-file-hash':
            sha1_checksum = demisto.args().get('sha1_checksum')
            return_outputs(*Druva_SearchbyFileHash_Command(clientObj, sha1_checksum))

        if command == 'druva-endpoint-initiate-restore':
            source_resourceid = demisto.args().get('source_resourceid')
            target_resourceid = demisto.args().get('target_resourceid')
            restore_location = demisto.args().get('restore_location')
            return_outputs(*Druva_Restore_Endpoint(clientObj, source_resourceid, target_resourceid, restore_location))

        if command == 'druva-endpoint-check-restore-status':
            restore_id = demisto.args().get('restore_id')
            return_outputs(*Druva_Restore_Status(clientObj, restore_id))

        if command == 'druva-endpoint-decommission':
            resource_id = demisto.args().get('resource_id')
            return_outputs(*Druva_Decommission(clientObj, resource_id))

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_outputs(test_module(clientObj))

    except Exception as e:
        return_error('Failed to execute:' + command + 'Error:' + str(e))

    sys.exit(0)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
