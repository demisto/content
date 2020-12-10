import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''

import json
from time import sleep

import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' GLOBAL VARIABLES '''

hostFieldMapping = [
    "KLHST_WKS_FQDN",
    "KLHST_WKS_DNSNAME",
    "KLHST_WKS_HOSTNAME",
    "KLHST_WKS_OS_NAME",
    "KLHST_WKS_GROUPID",
    "KLHST_WKS_DNSDOMAIN",
    "KLHST_INSTANCEID"
]

groupFieldMapping = [
    "id",
    "name",
    "parentId",
    "autoRemovePeriod",
    "notifyPeriod",
    "creationDate",
    "KLGRP_HlfInherited",
    "KLGRP_HlfForceChildren",
    "KLGRP_HlfForced",
    "lastUpdate",
    "hostsNum",
    "childGroupsNum",
    "grp_full_name",
    "level",
    "KLSRV_HSTSTAT_CRITICAL",
    "KLSRV_HSTSTAT_WARNING"
    "KLGRP_GRP_GROUPID_GP",
    "c_grp_autoInstallPackageId"
    "grp_from_unassigned",
    "grp_enable_fscan",
    "KLSRVH_SRV_DN"
    "KLVSRV_ID",
    "KLVSRV_DN",
    "KLGRP_CHLDGRP_CNT",
    "KLGRP_CHLDHST_CNT",
    "KLGRP_CHLDHST_CNT_OK",
    "KLGRP_CHLDHST_CNT_CRT",
    "KLGRP_CHLDHST_CNT_WRN"
]

detailedHostFieldMapping = [
    "KLHST_WKS_DN",
    "KLHST_WKS_GROUPID",
    "KLHST_WKS_CREATED",
    "KLHST_WKS_LAST_VISIBLE",
    "KLHST_WKS_STATUS",
    "KLHST_WKS_HOSTNAME",
    "KLHST_INSTANCEID",
    "KLHST_WKS_DNSDOMAIN",
    "KLHST_WKS_DNSNAME",
    "KLHST_WKS_FQDN",
    "KLHST_WKS_CTYPE",
    "KLHST_WKS_PTYPE",
    "KLHST_WKS_OS_NAME",
    "KLHST_WKS_COMMENT",
    "KLHST_WKS_NAG_VERSION",
    "KLHST_WKS_RTP_AV_VERSION",
    "KLHST_WKS_RTP_AV_BASES_TIME",
    "KLHST_WKS_RBT_REQUIRED",
    "KLHST_WKS_RBT_REQUEST_REASON",
    "KLHST_WKS_OSSP_VER_MAJOR",
    "KLHST_WKS_OSSP_VER_MINOR",
    "KLHST_WKS_CPU_ARCH",
    "KLHST_WKS_OS_BUILD_NUMBER",
    "KLHST_WKS_OS_RELEASE_ID",
    "KLHST_WKS_NAG_VER_ID",
    "KLHST_WKS_OWNER_ID",
    "KLHST_WKS_OWNER_IS_CUSTOM",
    "KLHST_WKS_CUSTOM_OWNER_ID",
    "KLHST_WKS_ANTI_SPAM_STATUS",
    "KLHST_WKS_DLP_STATUS",
    "KLHST_WKS_COLLAB_SRVS_STATUS",
    "KLHST_WKS_EMAIL_AV_STATUS",
    "KLHST_WKS_EDR_STATUS"
]


''' HELPER FUNCTIONS '''


def return_entry(res, dt, tableName):
    if res:
        if type(res) == list:
            for a in res:
                if "value" in a:
                    allFields = [x for x, y in a['value'].items()]
                    for v in allFields:
                        try:
                            a[v] = a['value'][v]
                        except KeyError:
                            pass
                        except Exception as err:
                            return_error(err)
                    del a['value']
                if "type" in a:
                    del a['type']
        md = tableToMarkdown(tableName, res)
        entry = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {dt: res}
        }
        demisto.results(entry)


class Client:

    def __init__(self, kaspersky_url, api_version, verify, username, password, internal, proxies, waitTime):
        self.error = ''
        self.base_url = kaspersky_url + '/api/v1.0'
        self.verify = verify
        self.username = username
        self.password = password
        self.headers = {'Content-Type': 'application/json'}
        self.proxies = proxies
        self.session = None
        self.errors = None
        self.waitTime = waitTime
        self.session = requests.Session()
        self.auth = self.session.post(self.base_url + '/login', headers={'Authorization': 'KSCBasic user="' + self.username
                                                                         + '", pass="' + self.password + '"', 'Content-Type': 'application/json'}, data={}, verify=self.verify)
        if self.auth.status_code not in [200]:
            self.session = None
            self.errors = 'Error in API call to Kaspersky [%d]. Reason: %s' % (self.auth.status_code, self.auth.text)

    def http_request(self, method, url_suffix, params=None, data=None, headers=None):

        full_url = self.base_url + url_suffix

        # Set the headers
        if not headers:
            headers = self.headers

        # Find the calling method
        if method.lower() == 'post':
            res = self.session.post(full_url, json=data, proxies=self.proxies, verify=self.verify)
        elif method.lower() == 'get':
            res = self.session.get(full_url, proxies=self.proxies, verify=self.verify)
        else:
            res = None

        if res.status_code not in [200, 204]:
            raise ValueError('Error in API call to Kaspersky [%d]. Reason: %s' % (res.status_code, res.text))

        try:
            return res.json()
        except Exception:
            raise ValueError(
                "Failed to parse http response to JSON format. Original response body: \n{}".format(res.text))

    def checkError(self, res):
        try:
            if res['PxgError']:
                return True
                #return_error('There was an error ({}) - {}'.format(res['PxgError']['code'],res['PxgError']['message']))
            else:
                return False
        except:
            return False

    def waitForAsync(self, wstrAsyncId):
        status = False
        checkEvery = 5
        for x in range(0, self.waitTime, checkEvery):
            if x >= self.waitTime:
                break
            res = self.http_request('post', '/AsyncActionStateChecker.CheckActionState', data={'wstrActionGuid': wstrAsyncId})
            if res['bFinalized'] == True:
                status = True
                break
            sleep(checkEvery)
        return status

    def getResults(self, strAccessor):

        chunkSize = 1000
        start = 0
        retData = list()
        # First get that count of results
        res = self.http_request('post', '/ChunkAccessor.GetItemsCount', data={'strAccessor': strAccessor})
        try:
            total = res['PxgRetVal']
        except Exception as err:
            return_error(err)
            sys.exit(-1)

        # If there are no results, then return None
        if total == 0:
            retData = None

        # Get all the chunks of data
        else:
            while start < total:
                chunkData = {"strAccessor": strAccessor, "nStart": start, "nCount": chunkSize}
                res = self.http_request('post', '/ChunkAccessor.GetItemsChunk', data=chunkData)
                retData += res['pChunk']['KLCSP_ITERATOR_ARRAY']
                start += chunkSize

        return retData

    def searchHosts(self, wstrFilter="", fields=hostFieldMapping):
        res = self.http_request('post', '/HostGroup.FindHosts',
                                data={"wstrFilter": wstrFilter, "lMaxLifeTime": 60, "vecFieldsToReturn": fields})
        self.checkError(res)
        return self.getResults(res['strAccessor'])

    def searchGroups(self, wstrFilter="", fields=groupFieldMapping):
        res = self.http_request('post', '/HostGroup.FindGroups',
                                data={"wstrFilter": wstrFilter, "lMaxLifeTime": 60, "vecFieldsToReturn": fields})
        self.checkError(res)
        return self.getResults(res['strAccessor'])

    def addGroup(self, createFilter):
        res = self.http_request('post', '/HostGroup.AddGroup', data={"pInfo": createFilter})
        self.checkError(res)
        return res

    def deleteGroup(self, groupId, flags):
        res = self.http_request('post', '/HostGroup.RemoveGroup', data={"nGroup": int(groupId), "nFlags": int(flags)})
        self.checkError(res)
        return res

    def getHostTasks(self, hostId):
        res = self.http_request('post', '/HostGroup.GetHostTasks', data={"strHostName": str(hostId)})
        self.checkError(res)
        try:
            return res['PxgRetVal']
        except:
            return None

    def getInventorySoftware(self):
        res = self.http_request('post', '/InventoryApi.GetInvProductsList', data={})
        self.checkError(res)
        return res

    def getInventoryPatches(self):
        res = self.http_request('post', '/InventoryApi.GetInvPatchesList', data={})
        self.checkError(res)
        return res

    def getHostSoftware(self, hostId):
        res = self.http_request('post', '/InventoryApi.GetHostInvProducts', data={"szwHostId": hostId})
        self.checkError(res)
        return res

    def getHostPatches(self, hostId):
        res = self.http_request('post', '/InventoryApi.GetHostInvPatches', data={"szwHostId": hostId})
        self.checkError(res)
        return res

    def getPolicy(self, policyId):
        res = self.http_request('post', '/Policy.GetPolicyData', data={"nPolicy": int(policyId)})
        self.checkError(res)
        return res

    def getCategoryById(self, categoryId):
        res = self.http_request('post', '/FileCategorizer2.GetCategory', data={"nCategoryId": int(categoryId)})
        return res

    def getAllCategories(self, limit=1000):
        data = list()
        seq = 0
        for x in range(0, limit):
            if seq >= 200:
                break
            res = self.http_request('post', '/FileCategorizer2.GetCategory', data={"nCategoryId": int(x)})
            try:
                if "PxgError" in res:
                    seq += 1
                    continue
                elif "pCategory" in res:
                    res['pCategory']['id'] = int(x)
                    data.append(res['pCategory'])
                    seq = 0
                else:
                    seq += 1
            except:
                seq += 1
        return data

    def addHashToCategory(self, categoryId, arrNewExpressions, bInclusions):
        res = self.http_request('post', '/FileCategorizer2.AddExpressions',
                                data={"nCategoryId": int(categoryId), "arrNewExpressions": arrNewExpressions, "bInclusions": bInclusions})
        return res


def test_module_command(client):
    if client.session:
        demisto.results('ok')
    else:
        return_error(client.errors)


def test_url(client):
    url = demisto.args().get('url')
    data = json.loads(demisto.args().get('data'))
    res = client.http_request('post', url, data=data)
    demisto.results(res)


def searchHosts_command(client):
    inputFilter = demisto.args().get('filter')
    res = client.searchHosts(wstrFilter=inputFilter)
    return_entry(res, 'Kaspersky.SecurityCenter.Hosts(val.KLHST_WKS_HOSTNAME && val.KLHST_WKS_HOSTNAME == obj.KLHST_WKS_HOSTNAME)', 'Host Details:')


def getHosts_command(client):
    res = client.searchHosts()
    return_entry(res, 'Kaspersky.SecurityCenter.Hosts(val.KLHST_WKS_HOSTNAME && val.KLHST_WKS_HOSTNAME == obj.KLHST_WKS_HOSTNAME)', 'Hosts:')


def getHostDetails_command(client):
    hostname = demisto.args().get('hostname')
    inputFilter = "KLHST_WKS_HOSTNAME = \"{}\"".format(hostname)
    res = client.searchHosts(wstrFilter=inputFilter, fields=detailedHostFieldMapping)
    return_entry(res, 'Kaspersky.SecurityCenter.Hosts(val.KLHST_WKS_HOSTNAME && val.KLHST_WKS_HOSTNAME == obj.KLHST_WKS_HOSTNAME)', 'Host Details:')


def getGroups_command(client):
    res = client.searchGroups()
    return_entry(res, 'Kaspersky.SecurityCenter.Groups(val.id && val.id == obj.id)', 'Groups:')


def searchGroups_command(client):
    inputFilter = demisto.args().get('filter', "")
    res = client.searchGroups(wstrFilter=inputFilter)
    return_entry(res, 'Kaspersky.SecurityCenter.Groups(val.id && val.id == obj.id)', 'Groups:')


def getGroup_command(client):
    groupName = demisto.args().get('groupName')
    res = client.searchGroups(wstrFilter="(name = \"{}\")".format(groupName))
    return_entry(res, 'Kaspersky.SecurityCenter.Groups(val.id && val.id == obj.id)', 'Groups:')


def addGroup_command(client):
    groupName = demisto.args().get('groupName')
    parentId = int(demisto.args().get('parentId'))
    createFilter = {"name": groupName, "parentId": parentId}
    res = client.addGroup(createFilter)
    try:
        newId = res['PxgRetVal']
    except:
        newId = None
    data = {"id": newId, "name": groupName}
    return_entry(data, 'Kaspersky.SecurityCenter.Groups(val.id && val.id == obj.id)', 'New Group:')


def deleteGroup_command(client):
    groupId = demisto.args().get('groupId')
    flags = demisto.args().get('flags')
    res = client.deleteGroup(groupId, flags)
    actionGuid = res.get('strActionGuid')
    data = {"GUID": res.get('strActionGuid'), "Status": 2}
    return_entry(data, 'Kaspersky.SecurityCenter.Action(val.GUID && val.GUID == obj.GUID)', 'Delete Group:')


def getInventorySoftware_command(client):
    res = client.getInventorySoftware()
    try:
        res = res['PxgRetVal']['GNRL_EA_PARAM_1']
    except Exception as err:
        return_error(err)
    return_entry(res, 'Kaspersky.SecurityCenter.Inventory.Software(val.ProductID && val.ProductID == obj.ProductID)', 'Software:')


def getInventoryPatches_command(client):
    res = client.getInventoryPatches()
    try:
        res = res['PxgRetVal']['GNRL_EA_PARAM_1']
    except Exception as err:
        return_error(err)
    return_entry(res, 'Kaspersky.SecurityCenter.Inventory.Patches(val.PatchID && val.PatchID == obj.PatchD)', 'Patches:')


def getHostSoftware_command(client):
    hostId = demisto.args().get('hostId')
    res = client.getHostSoftware(hostId)
    try:
        res = res['PxgRetVal']['GNRL_EA_PARAM_1']
    except Exception as err:
        return_error(err)
    return_entry(res, 'Kaspersky.SecurityCenter.Hosts(val.KLHST_WKS_HOSTNAME && val.KLHST_WKS_HOSTNAME == {}).Software'.format(
        hostId), 'Software for {}:'.format(hostId))


def getHostPatches_command(client):
    hostId = demisto.args().get('hostId')
    res = client.getHostPatches(hostId)
    try:
        res = res['PxgRetVal']['GNRL_EA_PARAM_1']
    except Exception as err:
        return_error(err)
    return_entry(res, 'Kaspersky.SecurityCenter.Hosts(val.KLHST_WKS_HOSTNAME && val.KLHST_WKS_HOSTNAME == {}).Patches'.format(
        hostId), 'Patches for {}:'.format(hostId))


def getPolicy_command(client):
    policyId = demisto.args().get('policyId')
    res = client.getPolicy(policyId)
    try:
        res = {"type": "unknown", "value": res['PxgRetVal']}
    except Exception as err:
        return_error(err)
    return_entry([res], 'Kaspersky.SecurityCenter.Policies(val.KLPOL_ID && val.KLPOL_ID == obj.KLPOL_ID)',
                 'Policy ID {}:'.format(policyId))


def getAllCategories_command(client):
    res = client.getAllCategories()
    return_entry(res, 'Kaspersky.SecurityCenter.Categories(val.id && val.id == obj.id)', 'Categories:')


def getCategoryById_command(client):
    categoryId = demisto.args().get('categoryId')
    res = client.getCategoryById(categoryId)
    try:
        if "PxgError" in res:
            demisto.results('No category with ID "{}"'.format(categoryId))
            sys.exit(0)
        else:
            res['pCategory']['id'] = int(categoryId)
            res = {"type": "unknown", "value": res['pCategory']}
    except Exception as err:
        return_error(err)
    return_entry([res], 'Kaspersky.SecurityCenter.Categories(val.id && val.id == obj.id)', 'Category ID {}:'.format(categoryId))


def getCategoryByName_command(client):
    name = demisto.args().get('name')
    res = client.getAllCategories()
    res = [x for x in res if x['name'] == name]
    return_entry(res, 'Kaspersky.SecurityCenter.Categories(val.id && val.id == obj.id)', 'Category "{}":'.format(name))
    # demisto.results(json.dumps(l))
    return


def addHashToCategory_command(client):
    categoryId = demisto.args().get('categoryId')
    hashes = demisto.args().get('hash')
    if "," in hashes:
        hashes = hashes.replace(" ", "").split(",")
    else:
        hashes = [hashes.replace(" ", "")]
    inclusion = demisto.args().get('inclusion')
    if "true" in inclusion.lower():
        bInclusions = True
    else:
        bInclusions = False
    # Get the category and ensure it is suitable
    cat = client.getCategoryById(categoryId)
    if client.checkError(cat):
        demisto.results(cat['PxgError'])
        return
    elif not cat['pCategory']:
        demisto.results('Error')
        return
    elif cat['pCategory']['CategoryType'] != 0:  # 0 - Simple (Manually by user)
        demisto.results('Category ID {} ("{}") is not suitable for manual hash additions'.format(
            categoryId, cat['pCategory']['name']))
        return
    else:
        cat = cat['pCategory']

    # Build the arrNewExpressions array
    arrNewExpressions = list()
    for x in hashes:
        ht = get_hash_type(x)
        if ht != 'md5' and ht != 'sha256':
            continue
        expression = {"type": "params", "value": {
            "ex_type": 3,
            "str": x,
            "str2": "",
            "str_op": 0}
        }
        arrNewExpressions.append(expression)
    res = client.addHashToCategory(int(categoryId), arrNewExpressions, bInclusions)
    if "PxgError" in res:
        return_error(res)
    elif "wstrAsyncId" in res:
        res['Complete'] = client.waitForAsync(str(res['wstrAsyncId']))
        res['Hashes'] = ",".join(hashes)
        res['Category ID'] = categoryId
        res['Name'] = cat['name']
        return_entry(res, 'Kaspersky.SecurityCenter.ASyncActions(val.wstrAsyncId && val.wstrAsyncId == obj.wstrAsyncId)',
                     'Added hashes to category:')


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """

    baseURL = demisto.params().get('url')
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    internal = demisto.params().get('internal')
    apiVersion = demisto.params().get('api_version')
    insecure = demisto.params().get('insecure')
    verify_certificate = not insecure
    waitTime = int(demisto.params().get('waitTime', 60))

    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    # Base64 encode the credentials
    username = base64.b64encode(username.encode('utf-8')).decode('utf-8')
    password = base64.b64encode(password.encode('utf-8')).decode('utf-8')

    LOG('Command being called is %s' % (demisto.command()))

    try:
        # Create an authenticated client with a session to Kaspersky
        client = Client(baseURL, apiVersion, verify_certificate, username, password, internal, proxies, waitTime)

        # Deal with commands
        if demisto.command() == 'ksc-test-url':
            test_url(client)

        if demisto.command() == 'test-module':
            test_module_command(client)

        if demisto.command() == 'ksc-get-hosts':
            getHosts_command(client)

        if demisto.command() == 'ksc-get-host-details':
            getHostDetails_command(client)

        if demisto.command() == 'ksc-search-hosts':
            searchHosts_command(client)

        if demisto.command() == 'ksc-get-groups':
            getGroups_command(client)

        if demisto.command() == 'ksc-search-groups':
            searchGroups_command(client)

        if demisto.command() == 'ksc-get-group':
            getGroup_command(client)

        if demisto.command() == 'ksc-add-group':
            addGroup_command(client)

        if demisto.command() == 'ksc-delete-group':
            deleteGroup_command(client)

        if demisto.command() == 'ksc-get-inventory-software':
            getInventorySoftware_command(client)

        if demisto.command() == 'ksc-get-inventory-patches':
            getInventoryPatches_command(client)

        if demisto.command() == 'ksc-get-host-software':
            getHostSoftware_command(client)

        if demisto.command() == 'ksc-get-host-patches':
            getHostPatches_command(client)

        if demisto.command() == 'ksc-get-policy':
            getPolicy_command(client)

        if demisto.command() == 'ksc-get-categories':
            getAllCategories_command(client)

        if demisto.command() == 'ksc-get-category-by-id':
            getCategoryById_command(client)

        if demisto.command() == 'ksc-get-category-by-name':
            getCategoryByName_command(client)

        if demisto.command() == 'ksc-add-hash-to-category':
            addHashToCategory_command(client)

    except Exception as err:
        return_error(err)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
