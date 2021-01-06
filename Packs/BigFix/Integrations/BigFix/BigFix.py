import requests

import demistomock as demisto
from CommonServerPython import *

requests.packages.urllib3.disable_warnings()

BASE_URL = demisto.params().get('url')
VERIFY_CERTIFICATE = not demisto.params().get('unsecure')

USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


def get_first(iterable, default=None):
    if iterable:
        for item in iterable:
            return item
    return default


def get_sites():
    fullurl = BASE_URL + '/api/sites'
    res = requests.get(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Failed to get sites.\nRequest URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
            fullurl, res.status_code, res.content))

    raw_sites = json.loads(xml2json(res.content))

    if not raw_sites or 'BESAPI' not in raw_sites:
        return []

    sites = []
    master_sites = demisto.get(raw_sites, 'BESAPI.ActionSite')

    if master_sites and not isinstance(master_sites, list):
        master_sites = [master_sites]
    if master_sites:
        for idx, site in enumerate(master_sites):
            master_sites[idx]['Type'] = 'master'
            master_sites[idx]['Resource'] = master_sites[idx]['@Resource']
            del master_sites[idx]['@Resource']
    else:
        master_sites = []

    external_sites = demisto.get(raw_sites, 'BESAPI.ExternalSite')
    if external_sites and not isinstance(external_sites, list):
        external_sites = [external_sites]
    if external_sites:
        for idx, site in enumerate(external_sites):
            external_sites[idx]['Type'] = 'external'
            external_sites[idx]['Resource'] = external_sites[idx]['@Resource']
            del external_sites[idx]['@Resource']
    else:
        external_sites = []

    operator_sites = demisto.get(raw_sites, 'BESAPI.OperatorSite')
    if operator_sites and not isinstance(operator_sites, list):
        operator_sites = [operator_sites]
    if operator_sites:
        for idx, site in enumerate(operator_sites):
            operator_sites[idx]['Type'] = 'operator'
            operator_sites[idx]['Resource'] = operator_sites[idx]['@Resource']
            del operator_sites[idx]['@Resource']
    else:
        operator_sites = []

    custom_sites = demisto.get(raw_sites, 'BESAPI.CustomSite')
    if custom_sites and not isinstance(custom_sites, list):
        custom_sites = [custom_sites]

    if custom_sites:
        for idx, site in enumerate(custom_sites):
            custom_sites[idx]['Type'] = 'custom'
            custom_sites[idx]['Resource'] = custom_sites[idx]['@Resource']
            del custom_sites[idx]['@Resource']
    else:
        custom_sites = []

    sites = master_sites + external_sites + operator_sites + custom_sites
    for idx, site in enumerate(sites):
        site_details = get_site(site['Type'], site['Name'])
        sites[idx] = site_details

    return sites


def get_sites_command():
    sites = get_sites()
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': sites,
        'HumanReadable': tableToMarkdown(
            'BigFix Sites',
            sites,
            ['Name', 'Type', 'GatherURL', 'Description', 'GlobalReadPermissions', 'Subscription']
        ),
        'EntryContext': {
            'Bigfix.Site(val.Resource==obj.Resource)': sites
        }
    })


def get_site(site_type, site_name):
    fullurl = BASE_URL + '/api/site/' + site_type
    if site_type != 'master':
        # if site name is not empty the add to url
        fullurl += '/' + site_name

    res = requests.get(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Failed to get site {}.\nRequest URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
            site_name, fullurl, res.status_code, res.content))

    raw_site = json.loads(xml2json(res.content))

    if not raw_site or 'BES' not in raw_site:
        return None

    site = None
    if site_type == 'master':
        site = demisto.get(raw_site, 'BES.ActionSite')
    elif site_type == 'external':
        site = demisto.get(raw_site, 'BES.ExternalSite')
    elif site_type == 'custom':
        site = demisto.get(raw_site, 'BES.CustomSite')
    elif site_type == 'operator':
        site = demisto.get(raw_site, 'BES.OperatorSite')

    if site is not None:
        site['Type'] = site_type
        site['Resource'] = BASE_URL + '/api/site/{}/{}'.format(site_type, site_name)

    return site


def get_site_command():
    site_name = demisto.args().get('site_name')
    site_type = demisto.args().get('site_type')
    site = get_site(site_type, site_name)

    if site is None:
        demisto.results('No site found')
        sys.exit(0)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': site,
        'HumanReadable': tableToMarkdown(
            'BigFix Site: {} - {}'.format(site_type, site_name),
            [site],
            ['Name', 'Type', 'GatherURL', 'Description', 'GlobalReadPermissions', 'Subscription']
        ),
        'EntryContext': {
            'Bigfix.Site(val.Resource==obj.Resource)': site
        }
    })


def get_endpoints(should_get_endpoint_details):
    fullurl = BASE_URL + '/api/computers'

    res = requests.get(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Failed to get endpoints.\nRequest URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
            fullurl, res.status_code, res.content))

    raw_endpoints = json.loads(xml2json(res.content))

    if not raw_endpoints or 'BESAPI' not in raw_endpoints:
        return None

    raw_endpoints = demisto.get(raw_endpoints, 'BESAPI.Computer')
    if raw_endpoints and not isinstance(raw_endpoints, list):
        raw_endpoints = [raw_endpoints]

    for idx, endpoint in enumerate(raw_endpoints):
        raw_endpoints[idx]['Resource'] = raw_endpoints[idx]['@Resource']
        del raw_endpoints[idx]['@Resource']

    if should_get_endpoint_details:
        endpoints_with_details = []
        for raw_endpoint in raw_endpoints:
            endpoint = get_endpoint_details(raw_endpoint.get('ID'))
            endpoints_with_details.append(endpoint)
        return endpoints_with_details
    else:
        return raw_endpoints


def get_endpoints_command():
    should_get_endpoint_details = demisto.args().get('get_endpoint_details') == 'true'
    endpoints = get_endpoints(should_get_endpoint_details)
    headers = ['ID', 'Resource', 'LastReportTime']
    if should_get_endpoint_details:
        headers.extend([
            'ActiveDirectoryPath',
            'AgentType',
            'AgentVersion',
            'BESRelaySelectionMethod',
            'BESRelayServiceInstalled',
            'BESRootServer',
            'BIOS',
            'CPU',
            'ClientSettings',
            'ComputerName',
            'ComputerType',
            'DNSName',
            'DeviceType',
            'DistancetoBESRelay',
            'FreeSpaceonSystemDrive',
            'IPAddress',
            'LicenseType',
            'Locked',
            'OS',
            'RAM',
            'Relay',
            'RelayNameOfClient',
            'SubnetAddress',
            'SubscribedSites',
            'TotalSizeofSystemDrive',
            'UserName'
        ])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': endpoints,
        'HumanReadable': tableToMarkdown('BigFix Computers', endpoints, headers=headers),
        'EntryContext': {
            'Bigfix.Endpoint(val.ID==obj.ID)': endpoints
        }
    })


def get_endpoint_details(computer_id):
    fullurl = BASE_URL + '/api/computer/{}'.format(computer_id)
    res = requests.get(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error(
            'Failed to get computer {}.\nRequest URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
                computer_id, fullurl, res.status_code, res.content)
        )

    raw_endpoint = json.loads(xml2json(res.content))
    if not raw_endpoint or 'BESAPI' not in raw_endpoint:
        return None

    raw_endpoint = demisto.get(raw_endpoint, 'BESAPI.Computer')

    endpoint = {
        'ID': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "ID")=val["#text"]')),
        'Resource': demisto.get(raw_endpoint, '@Resource'),
        'LastReportTime': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Last Report Time")=val["#text"]')
        ),
        'ActiveDirectoryPath': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Active Directory Path")=val["#text"]')
        ),
        'AgentType': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Agent Type")=val["#text"]')),
        'AgentVersion': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Agent Version")=val["#text"]')),
        'BESRelaySelectionMethod': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "BES Relay Selection Method")=val["#text"]')
        ),
        'BESRelayServiceInstalled': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "BES Relay Selection Method")=val["#text"]')
        ),
        'BESRootServer': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "BES Root Server")=val["#text"]')
        ),
        'BIOS': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "BIOS")=val["#text"]')),
        'CPU': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "CPU")=val["#text"]')),
        'ClientSettings': demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Client Settings")=val["#text"]'),
        'ComputerName': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Computer Name")=val["#text"]')),
        'ComputerType': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Computer Type")=val["#text"]')),
        'DNSName': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "DNS Name")=val["#text"]')),
        'IPAddress': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "IP Address")=val["#text"]')),
        'DeviceType': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Device Type")=val["#text"]')),
        'DistancetoBESRelay': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Distance to BES Relay")=val["#text"]')
        ),
        'FreeSpaceonSystemDrive': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Free Space on System Drive")=val["#text"]')
        ),
        'LicenseType': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "License Type")=val["#text"]')),
        'Locked': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Locked")=val["#text"]')),
        'OS': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "OS")=val["#text"]')),
        'RAM': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "RAM")=val["#text"]')),
        'Relay': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Relay")=val["#text"]')),
        'RelayNameOfClient': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Relay Name of Client")=val["#text"]')
        ),
        'SubnetAddress': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Subnet Address")=val["#text"]')),
        'SubscribedSites': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Subscribed Sites")=val["#text"]')
        ),
        'TotalSizeofSystemDrive': get_first(
            demisto.dt(raw_endpoint, 'Property(val["@Name"] == "Total Size of System Drive")=val["#text"]')
        ),
        'UserName': get_first(demisto.dt(raw_endpoint, 'Property(val["@Name"] == "User Name")=val["#text"]'))
    }

    return endpoint


def get_endpoint_details_command():
    computer_id = demisto.args().get('computer_id')

    endpoint = get_endpoint_details(computer_id)
    if endpoint is None:
        demisto.results('Endpoint with id {} was not found'.format(computer_id))
        sys.exit(0)

    markdown = tableToMarkdown('BigFix Endpoint {}'.format(computer_id), [endpoint], headers=[
        'ID',
        'Resource',
        'LastReportTime',
        'ActiveDirectoryPath',
        'AgentType',
        'AgentVersion',
        'BESRelaySelectionMethod',
        'BESRelayServiceInstalled',
        'BESRootServer',
        'BIOS',
        'CPU',
        'ClientSettings',
        'ComputerName',
        'ComputerType',
        'DNSName',
        'DeviceType',
        'DistancetoBESRelay',
        'FreeSpaceonSystemDrive',
        'IPAddress',
        'LicenseType',
        'Locked',
        'OS',
        'RAM',
        'Relay',
        'RelayNameOfClient',
        'SubnetAddress',
        'SubscribedSites',
        'TotalSizeofSystemDrive',
        'UserName'
    ])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': endpoint,
        'HumanReadable': markdown,
        'EntryContext': {
            'Bigfix.Endpoint(val.ID==obj.ID)': endpoint
        }
    })


def get_patches(site_type='', site_name=''):
    fullurl = BASE_URL + '/api/fixlets/{}'.format(site_type)
    if site_type != 'master':
        # if site name is not empty the add to url
        fullurl += '/' + site_name

    res = requests.get(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error(
            'Failed to get patches. Request URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
                fullurl, res.status_code, res.content)
        )

    raw_patches = json.loads(xml2json(res.content))
    if not raw_patches or 'BESAPI' not in raw_patches:
        return None

    raw_patches = demisto.get(raw_patches, 'BESAPI.Fixlet')
    if raw_patches and not isinstance(raw_patches, list):
        raw_patches = [raw_patches]

    patches_with_details = []
    for raw_patch in raw_patches:
        patch = get_patch_details(site_type, site_name, raw_patch.get('ID'))
        patch['LastModified'] = raw_patch['@LastModified']
        patches_with_details.append(patch)

    return patches_with_details


def get_patches_command():
    site_name = demisto.args().get('site_name')
    site_type = demisto.args().get('site_type')
    patches = get_patches(site_type, site_name)

    markdown = tableToMarkdown('BigFix Patches', patches, headers=[
        'ID',
        'Name',
        'Description',
        'LastModified',
        'Resource',
        'Relevance',
        'Category',
        'DownloadSize',
        'Source',
        'SourceID',
        'SourceReleaseDate',
        'SourceSeverity',
        'ActionID',
        'ActionScript'
    ])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': patches,
        'HumanReadable': markdown,
        'EntryContext': {
            'Bigfix.Patch(val.ID==obj.ID)': patches
        }
    })


def get_patch_details(site_type, site_name, patch_id):
    if site_type == 'master':
        fullurl = BASE_URL + '/api/fixlet/master/{}'.format(patch_id)
    else:
        fullurl = BASE_URL + '/api/fixlet/{}/{}/{}'.format(site_type, site_name, patch_id)

    res = requests.get(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Failed to get patch/fixlet {}. Request URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
            patch_id, fullurl, res.status_code, res.content)
        )

    raw_patch = json.loads(xml2json(res.content))
    if not raw_patch or 'BES' not in raw_patch:
        return None

    raw_patch = demisto.get(raw_patch, 'BES.Fixlet')
    patch = {
        'ID': patch_id,
        'Name': demisto.get(raw_patch, 'Title'),
        'Resource': fullurl,
        'Description': demisto.get(raw_patch, 'Description'),
        'Relevance': demisto.get(raw_patch, 'Relevance'),
        'Category': demisto.get(raw_patch, 'Category'),
        'DownloadSize': demisto.get(raw_patch, 'DownloadSize'),
        'Source': demisto.get(raw_patch, 'Source'),
        'SourceID': demisto.get(raw_patch, 'SourceID'),
        'SourceReleaseDate': demisto.get(raw_patch, 'SourceReleaseDate'),
        'SourceSeverity': demisto.get(raw_patch, 'SourceSeverity'),
        'ActionID': demisto.get(raw_patch, 'DefaultAction.@ID'),
        'ActionScript': demisto.get(raw_patch, 'DefaultAction.ActionScript')
    }

    return patch


def get_patch_details_command():
    site_type = demisto.args().get('site_type')
    site_name = demisto.args().get('site_name')
    patch_id = demisto.args().get('id')

    patch = get_patch_details(site_type, site_name, patch_id)
    markdown = tableToMarkdown('BigFix Patch {}'.format(patch_id), [patch], headers=[
        'ID',
        'Name',
        'Resource',
        'Description',
        'Relevance',
        'Category',
        'DownloadSize',
        'Source',
        'SourceID',
        'SourceReleaseDate',
        'SourceSeverity',
        'ActionID',
        'ActionScript'
    ])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': patch,
        'HumanReadable': markdown,
        'EntryContext': {
            'Bigfix.Patch(val.ID==obj.ID)': patch
        }
    })


def deploy_patch(site_name, computer_ids, fixlet_id, action_id):
    if 'all' in computer_ids:
        target = '<AllComputers>true</AllComputers>'
    else:
        target = '\n'.join(['<ComputerID>{}</ComputerID>'.format(computer_id) for computer_id in computer_ids])

    request_body = """<?xml version="1.0" encoding="UTF-8"?>
    <BES xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="BES.xsd">
     <SourcedFixletAction>
       <SourceFixlet>
         <Sitename>{}</Sitename>
         <FixletID>{}</FixletID>
         <Action>{}</Action>
       </SourceFixlet>
       <Target>
         {}
       </Target>
      <Parameter Name="_BESClient_EMsg_Detail">1000</Parameter>
     </SourcedFixletAction>
    </BES>
    """.format(site_name, fixlet_id, action_id, target)
    LOG('deploy_patch - request: ' + request_body)

    fullurl = BASE_URL + '/api/actions'
    res = requests.post(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE,
        data=request_body
    )

    LOG('deploy_patch - raw response: ' + res.content)
    if res.status_code < 200 or res.status_code >= 300:
        return_error('Failed to deploy patch {}.\nRequest URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
            fixlet_id, fullurl, res.status_code, res.content))

    raw_action = json.loads(xml2json(res.content))
    if not raw_action or 'BESAPI' not in raw_action:
        return None

    raw_action = demisto.get(raw_action, 'BESAPI.Action')
    raw_action['FixletID'] = fixlet_id
    raw_action['ComputerIDs'] = computer_ids
    raw_action['SiteName'] = site_name
    raw_action['Resource'] = raw_action['@Resource']
    del raw_action['@Resource']
    if 'all' in computer_ids:
        raw_action['AllComputers'] = True
        del raw_action['ComputerIDs']

    return raw_action


def deploy_patch_command():
    site_name = demisto.args().get('site_name')
    computer_ids = argToList(demisto.args().get('computer_ids'))

    fixlet_id = demisto.args().get('fixlet_id')
    action_id = demisto.args().get('action_id')

    action = deploy_patch(site_name, computer_ids, fixlet_id, action_id)

    markdown = tableToMarkdown('BigFix Action {}'.format(action_id), [action], headers=[
        'ID',
        'Name',
        'FixletID',
        'ComputerIDs',
        'SiteName',
        'Resource'
    ])

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': action,
        'HumanReadable': markdown,
        'EntryContext': {
            'Bigfix.Action(val.ID==obj.ID)': action
        }
    })


def action_delete(action_id):
    fullurl = BASE_URL + '/api/action/' + action_id
    res = requests.delete(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Failed to delete action {}.\nRequest URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
            action_id, fullurl, res.status_code, res.content))


def action_delete_command():
    action_id = demisto.args().get('action_id')

    action_delete(action_id)

    demisto.results('Action {} was deleted successfully'.format(action_id))


def get_action_status(action_id):
    fullurl = BASE_URL + '/api/action/' + action_id + '/status'
    res = requests.get(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Failed to get action {} status.\nRequest URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
            action_id, fullurl, res.status_code, res.content))

    raw_action = json.loads(xml2json(res.content))
    if not raw_action or 'BESAPI' not in raw_action:
        return None

    raw_action = demisto.get(raw_action, 'BESAPI.ActionResults')
    return raw_action.get('Status')


def get_action_status_command():
    action_id = demisto.args().get('action_id')

    status = get_action_status(action_id)

    output = {
        'ID': action_id,
        'Status': status
    }
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': output,
        'HumanReadable': 'Action {} status is {}'.format(action_id, status),
        'EntryContext': {
            'Bigfix.Action(val.ID==obj.ID)': output
        }
    })


def action_stop(action_id):
    fullurl = BASE_URL + '/api/action/' + action_id + '/stop'
    res = requests.post(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Failed to stop action {}.\nRequest URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
            action_id, fullurl, res.status_code, res.content))


def action_stop_command():
    action_id = demisto.args().get('action_id')

    action_stop(action_id)

    demisto.results('Action {} was stopped successfully'.format(action_id))


def query(relevance):
    fullurl = BASE_URL + '/api/query'
    params = {
        'relevance': relevance
    }
    res = requests.get(
        fullurl,
        auth=(USERNAME, PASSWORD),
        verify=VERIFY_CERTIFICATE,
        params=params
    )

    if res.status_code < 200 or res.status_code >= 300:
        return_error('Query failed.\nRequest URL: {}\nStatusCode: {}\nResponse Body: {}'.format(
            fullurl, res.status_code, res.content))

    raw_action = json.loads(xml2json(res.content))
    if not raw_action or 'BESAPI' not in raw_action:
        demisto.info('BigFix query has incorrect response format. Response Body: {}'.format(res.content))
        return_error('The response has incorrect format. Check the logs')

    if demisto.get(raw_action, 'BESAPI.Query.Error'):
        error = demisto.get(raw_action, 'BESAPI.Query.Error')
        return_error(error)

    raw_query_results = demisto.get(raw_action, 'BESAPI.Query')
    return raw_query_results


def query_command():
    relevance = demisto.args().get('relevance')
    results = query(relevance)

    if results is None:
        demisto.results('No results')
        sys.exit(0)

    output = demisto.dt(results, 'Result.Answer.#text')
    if not isinstance(output, list):
        output = [output]

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'HumanReadable': tableToMarkdown('Query Results: {}'.format(relevance), output, ['Results']),
        'EntryContext': {
            'Bigfix.QueryResults': output
        }
    })


try:
    # do requets to /api/help
    # should be good indicator for test connectivity
    def test():
        fullurl = BASE_URL + '/api/help'
        res = requests.get(
            fullurl,
            auth=(USERNAME, PASSWORD),
            verify=VERIFY_CERTIFICATE
        )
        res.raise_for_status()

    if demisto.command() == 'test-module':
        # do requets to /api/help
        # should be good indicator for test connectivity
        test()
        demisto.results('ok')

    elif demisto.command() == 'bigfix-get-sites':
        get_sites_command()

    elif demisto.command() == 'bigfix-get-site':
        get_site_command()

    elif demisto.command() == 'bigfix-get-endpoints':
        get_endpoints_command()

    elif demisto.command() == 'bigfix-get-endpoint':
        get_endpoint_details_command()

    elif demisto.command() == 'bigfix-get-patches':
        get_patches_command()

    elif demisto.command() == 'bigfix-get-patch':
        get_patch_details_command()

    elif demisto.command() == 'bigfix-deploy-patch':
        deploy_patch_command()

    elif demisto.command() == 'bigfix-action-delete':
        action_delete_command()

    elif demisto.command() == 'bigfix-action-status':
        get_action_status_command()

    elif demisto.command() == 'bigfix-action-stop':
        action_stop_command()

    elif demisto.command() == 'bigfix-query':
        query_command()

except Exception as e:
    LOG(e.message)
    LOG.print_log()
    return_error(e.message)
