import requests

import demistomock as demisto
from CommonServerPython import *

requests.packages.urllib3.disable_warnings()

if not demisto.getParam('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

URL = demisto.getParam('server')
if URL[-1] != '/':
    URL += '/'

API_KEY = str(demisto.getParam('token'))
SUB_API = 'api/v2/'
USER_API = 'api/v3/'
VALIDATE_CERT = not demisto.params().get('insecure', True)

''' Header names maps '''
# Format: {'Key': [correspondng headers]}
SAMPLE_ANALYSIS_HEADERS_MAP = {
    'File': [
        'FileName',
        'Type',
        'Size',
        'MD5',
        'SHA1',
        'SHA256',
        'MagicType'
    ],
    'Domain': [
        'Name',
        'Status'
    ],
    'Network': [
        'Ts_Begin',
        'Destination',
        'DestinationPort',
        'Transport',
        'Packets',
        'PacketSize'
    ],
    'Regitry Keys Created': [
        'name',
        'options',
        'access'
    ],
    'Regitry Keys Deleted': [
        'name'
    ],
    'Regitry Keys Modified': [
        'name',
        'options',
        'access'
    ],
    'Sample': [
        'ID',
        'ThreatScore',
        'HeuristicScore',
        'ProcessName',
        'CMD',
        'Directory',
        'Memory',
        'Children'
    ],
    'Enviornment Details': [
        'VM ID',
        'VM Name',
        'StartedAt',
        'EndedAt',
        'Runtime'
    ],
    'VT': [
        'Hits',
        'Engines'
    ]
}


def req(method, path, params={'api_key': API_KEY}):
    """
    Send the request to ThreatGrid and return the JSON response
    """
    r = requests.request(method, URL + path, params=params, verify=VALIDATE_CERT)
    if r.status_code != requests.codes.ok:
        return_error('Error in API call to Threat Grid service %s - %s' % (path, r.text))
    return r


def handle_filters():
    """
    Handle filters associated with samples
    """
    id_found = False
    id_list = ['sha256', 'md5', 'sha1', 'id']
    params = {'api_key': API_KEY}
    for k in demisto.args():
        if demisto.getArg(k):
            if not id_found and k in id_list:
                params['q'] = demisto.getArg(k)
                id_found = True
            else:
                params[k] = demisto.getArg(k)
    return params


def get_with_limit(obj, path, limit=None):
    """
    Get from path with optional limit
    """
    res = demisto.get(obj, path)
    try:
        if limit:
            if len(res) > limit:
                if isinstance(res, dict):
                    return {k: res[k] for k in res.keys()[:limit]}
                elif isinstance(res, list):
                    return res[:limit]
    # If res has no len, or if not a list or a dictionary return res
    finally:
        return res


def sample_to_readable(k):
    """
    Convert sample request to data dictionary
    """
    return {
        'ID': demisto.get(k, 'id'),
        'Filename': demisto.get(k, 'filename'),
        'State': demisto.get(k, 'state'),
        'Status': demisto.get(k, 'status'),
        'MD5': demisto.get(k, 'md5'),
        'SHA1': demisto.get(k, 'sha1'),
        'SHA256': demisto.get(k, 'sha256'),
        'OS': demisto.get(k, 'os'),
        'SubmittedAt': demisto.get(k, 'submitted_at'),
        'StartedAt': demisto.get(k, 'started_at'),
        'CompletedAt': demisto.get(k, 'completed_at')
    }


def download_sample():
    """
    Download a sample given the sample id
    """
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id + '/sample.zip')
    ec = {'ThreatGrid.DownloadedSamples.Id': sample_id}
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': ec,
            'HumanReadable': '### ThreatGrid Sample Download - \n'
                             + 'Your download request has been completed successfully for ' + sample_id,
            'Contents': ec,
            'ContentsFormat': formats['json']
        },
        fileResult(sample_id + '-sample.zip', r.content)
    ])


def get_samples():
    """
    Get samples matching the provided filters.
    """
    r = req('GET', SUB_API + 'samples', params=handle_filters())
    samples = []
    for k in demisto.get(r.json(), 'data.items'):
        samples.append(sample_to_readable(k))
    md = tableToMarkdown('ThreatGrid - List of Samples', samples, [
        'ID', 'Filename', 'State', 'Status', 'MD5', 'SHA1', 'SHA256', 'OS', 'SubmittedAt', 'StartedAt', 'CompletedAt'
    ])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.Sample(val.ID == obj.ID)': samples},
        'HumanReadable': md,
        'ContentsFormat': formats['json'],
        'Contents': r.json()
    })


def get_sample_by_id():
    """
    Get information about a sample given its id
    """
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id)
    sample = sample_to_readable(r.json().get('data'))
    md = tableToMarkdown('ThreatGrid - Sample', [sample], [
        'ID', 'Filename', 'State', 'Status', 'MD5', 'SHA1', 'SHA256', 'OS', 'SubmittedAt', 'StartedAt', 'CompletedAt'
    ])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.Sample(val.ID == obj.ID)': sample},
        'HumanReadable': md,
        'ContentsFormat': formats['json'],
        'Contents': r.json()
    })


def get_sample_state_helper(sample_ids):
    """
    Helper for getting sample state
    """
    samples = []
    requests = []
    for sample_id in sample_ids:
        r = req('GET', SUB_API + 'samples/' + sample_id + '/state')
        samples.append({
            'ID': sample_id,
            'State': demisto.get(r.json(), 'data.state')
        })
        requests.append(r.json())
    return {'samples': samples, 'requests': requests}


def get_sample_state_by_id():
    """
    Get the state of a sample given its id
    """
    ids = []  # type: list
    if demisto.getArg('ids'):
        ids += argToList(demisto.getArg('ids'))
    if demisto.getArg('id'):
        ids.append(demisto.getArg('id'))
    response = get_sample_state_helper(ids)
    md = tableToMarkdown('ThreatGrid - Sample state', response['samples'], ['ID', 'State'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.Sample(val.ID == obj.ID)': response['samples']},
        'HumanReadable': md,
        'ContentsFormat': formats['json'],
        'Contents': response['requests']
    })


def upload_sample():
    """
    Upload a sample
    """
    args = {}
    for k in demisto.args():
        if demisto.getArg(k) and k != 'file-id':
            args[k] = demisto.getArg(k)
    args['api_key'] = API_KEY
    fileData = demisto.getFilePath(demisto.getArg('file-id'))
    with open(fileData['path'], 'rb') as f:
        r = requests.request('POST', URL + SUB_API + 'samples',
                             files={'sample': (encode_sample_file_name(demisto.getArg('filename')), f)},
                             data=args, verify=VALIDATE_CERT)
        if r.status_code != requests.codes.ok:
            if r.status_code == 503:
                return_error('Sample upload failed. File was already uploaded.')
            return_error('Error in API call to Threat Grid service %s - %s' % ('samples', r.text))
        sample = sample_to_readable(r.json().get('data'))
        md = tableToMarkdown('ThreatGrid - Sample Upload', [sample], [
            'ID', 'Filename', 'State', 'Status', 'MD5', 'SHA1', 'SHA256', 'OS', 'SubmittedAt'
        ])
        demisto.results({
            'Type': entryTypes['note'],
            'EntryContext': {'ThreatGrid.Sample(val.ID == obj.ID)': sample},
            'HumanReadable': md,
            'ContentsFormat': formats['json'],
            'Contents': r.json()
        })
        return sample.get('ID')


def encode_sample_file_name(filename):
    """
    Encodes sample file name
    """
    return filename.encode('ascii', 'ignore').replace('"', '').replace('\n', '')


def get_html_report_by_id():
    """
    Download the html report for a sample given the id
    """
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id + '/report.html')
    ec = {'ThreatGrid.Sample.Id': sample_id}
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': ec,
            'HumanReadable': '### ThreatGrid Sample Run HTML Report -\n'
                             + 'Your sample run HTML report download request has been completed successfully for '
                             + sample_id,
            'Contents': r.content,
            'ContentsFormat': formats['html']
        },
        fileResult(sample_id + '-report.html', r.content, file_type=entryTypes['entryInfoFile'])
    ])


def get_pcap_by_id():
    """
    Download the pcap for a sample given the id
    """
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id + '/network.pcap')
    ec = {'ThreatGrid.Sample.Id': sample_id}
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': ec,
            'HumanReadable': '### ThreatGrid Sample Run PCAP File -\n'
                             + 'Your sample run PCAP file download request has been completed successfully for '
                             + sample_id,
            'Contents': ec,
            'ContentsFormat': formats['json']
        },
        fileResult(sample_id + '-pcap.json', r.content)
    ])


def get_processes_by_id():
    """
    Download processes file for a sample given the id
    """
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id + '/processes.json')
    ec = {'ThreatGrid.Sample.Id': sample_id}
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': ec,
            'HumanReadable': '### ThreatGrid Sample Run Processes File -\n'
                             + 'Your sample run processes file download request has been completed successfully for '
                             + sample_id,
            'Contents': r.json(),
            'ContentsFormat': formats['json']
        },
        fileResult(sample_id + '-processes.json', r.content)
    ])


def get_summary_by_id():
    """
    Get analysis summary information for a sample given the id
    """
    sample_id = demisto.getArg('id')
    request = req('GET', SUB_API + 'samples/' + sample_id + '/summary')
    r = request.json()
    sample = {'ID': sample_id, 'AnalysisSummary': [], 'ArtifactsCount': []}

    # Search submissions request for extra information
    sub_request = req('GET', SUB_API + 'search/submissions',
                      params={'api_key': API_KEY, 'q': demisto.get(r, 'data.sha256')})
    sub_r = sub_request.json()
    sub_r_first_item = demisto.get(sub_r, 'data.items')[0]

    sample['AnalysisSummary'] = {
        'RegistryCount': demisto.get(r, 'data.registry_count'),
        'FileName': demisto.get(r, 'data.filename'),
        'SHA256': demisto.get(r, 'data.sha256'),
        'SampleType': demisto.get(sub_r_first_item, 'item.analysis.metadata.submitted_file.type'),
        'FirstSeen': demisto.get(r, 'data.first_seen'),
        'LastSeen': demisto.get(r, 'data.last_seen'),
    }
    sample['ArtifactsCount'] = {
        'Network': demisto.get(r, 'data.artifacts.network'),
        'Disk': demisto.get(r, 'data.artifacts.disk'),
        'Memory': demisto.get(r, 'data.artifacts.memory'),
        'Extracted': demisto.get(r, 'data.artifacts.extracted')
    }
    md = tableToMarkdown('ThreatGrid - Sample Summary for ' + sample_id,
                         [sample['AnalysisSummary']], ['RegistryCount', 'FileName',
                                                       'SHA256', 'SampleType', 'FirstSeen', 'LastSeen'])
    md += tableToMarkdown('ThreatGrid - Sample Artifacts', [sample['ArtifactsCount']],
                          ['Network', 'Disk', 'Memory', 'Extracted'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.Sample(val.ID == obj.ID)': sample},
        'HumanReadable': md,
        'ContentsFormat': formats['json'],
        'Contents': r
    })


def calc_score(score):
    """
    Convert threatgrid score to dbot score
    """
    dbot_score = 1
    if score >= 95:
        dbot_score = 3
    elif score >= 75:
        dbot_score = 2
    return dbot_score


def get_threat_summary_by_id():
    """
    Get threat summary information for a sample given the id
    """
    sample_id = demisto.getArg('id')
    request = req('GET', SUB_API + 'samples/' + sample_id + '/threat')
    r = request.json()
    sample = {
        'ID': sample_id,
        'MaxSeverity': demisto.get(r, 'data.max-severity'),
        'Score': demisto.get(r, 'data.score'),
        'Count': demisto.get(r, 'data.count'),
        'MaxConfidence': demisto.get(r, 'data.max-confidence'),
        'ThreatFeeds': demisto.get(r, 'data.bis')
    }
    dbot = {
        'Vendor': 'ThreatGrid',
        'Type': 'Sample ID',
        'Indicator': sample['ID'],
        'Score': calc_score(sample['Score'])
    }
    md = tableToMarkdown('ThreatGrid - Threat Summary', [sample],
                         ['ID', 'MaxSeverity', 'Score', 'Count', 'MaxConfidence'])
    mdTableList = []
    for threatfeed in sample['ThreatFeeds']:
        mdTableList.append({'Threat Feed': threatfeed})
    md += tableToMarkdown('Threat Feeds', mdTableList, ['Threat Feed'])
    md += tableToMarkdown('DBot', [dbot], ['Indicator', 'Score', 'Type', 'Vendor'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.Sample(val.ID == obj.ID)': sample, 'DBotScore': dbot},
        'HumanReadable': md,
        'ContentsFormat': formats['json'],
        'Contents': r
    })


def get_video_by_id():
    """
    Download the video for a sample given the id
    """
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id + '/video.webm')
    ec = {'ThreatGrid.Sample.Id': sample_id}
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': ec,
            'HumanReadable': '### ThreatGrid Sample Run Video File -\n'
                             + 'Your sample run video file download request has been completed successfully for '
                             + sample_id,
            'Contents': r.json(),
            'ContentsFormat': formats['json']
        },
        fileResult(sample_id + '.webm', r.content)
    ])


def get_warnings_by_id():
    """
    Download the warnings for a sample given the id
    """
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id + '/warnings.json')
    ec = {'ThreatGrid.Sample.Id': sample_id}
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': ec,
            'HumanReadable': '### ThreatGrid Sample Run Warnings -\n'
                             + 'Your sample run warnings file download request has been completed successfully for '
                             + sample_id,
            'Contents': ec,
            'ContentsFormat': formats['json']
        },
        fileResult(sample_id + '-warnings.json', r.content)
    ])


def user_get_rate_limit():
    """
    Get rate limit for a specified user
    """
    login = demisto.getArg('login')
    request = req('GET', USER_API + 'users/' + login + '/rate-limit')
    r = request.json()
    rate_limit = {
        'SubmissionWaitSeconds': demisto.get(r, 'data.user.submission-wait-seconds'),
        'SubmissionsAvailable': demisto.get(r, 'data.user.submissions-available')
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.User.RateLimit': rate_limit},
        'HumanReadable': tableToMarkdown('ThreatGrid - User Rate Limit', [rate_limit], [
            'SubmissionWaitSeconds', 'SubmissionsAvailable'
        ]),
        'ContentsFormat': formats['json'],
        'Contents': r
    })


def organization_get_rate_limit():
    """
    Get rate limit for a specified organization
    """
    login = demisto.getArg('adminLogin')
    request = req('GET', USER_API + 'users/' + login + '/rate-limit')
    r = request.json()
    rate_limits = [
        {
            'Minutes': demisto.get(rate_limit, 'minutes'),
            'Samples': demisto.get(rate_limit, 'samples'),
            'SubmissionWaitSeconds': demisto.get(rate_limit, 'submission-wait-seconds'),
            'SubmissionsAvailable': demisto.get(rate_limit, 'submissions-available')
        }
        for rate_limit in demisto.get(r, 'data.organization.submission-rate-limit')
    ]
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.User.RateLimit': rate_limits},
        'HumanReadable': tableToMarkdown('ThreatGrid - Organization Rate Limit', rate_limits, [
            'Minutes', 'Samples', 'SubmissionWaitSeconds', 'SubmissionsAvailable'
        ]),
        'ContentsFormat': formats['json'],
        'Contents': r
    })


def who_am_i():
    """
    Get information about the current session's user
    """
    request = req('GET', USER_API + 'session/whoami')
    r = request.json()
    user = {
        'Email': demisto.get(r, 'data.email'),
        'Login': demisto.get(r, 'data.login'),
        'Name': demisto.get(r, 'data.name'),
        'Organization': demisto.get(r, 'data.organization_id'),
        'Role': demisto.get(r, 'data.role')
    }
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.User': user},
        'HumanReadable': tableToMarkdown('ThreatGrid - Current Session User', [user], [
            'Email', 'Login', 'Name', 'Organization', 'Role'
        ]),
        'ContentsFormat': formats['json'],
        'Contents': user
    })


def get_analysis_annotations():
    """
    Get analysis annotations for a given sample
    """
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id + '/analysis/annotations')

    annotations = []
    context_path = 'ThreatGrid.AnalysisResults.Sample.Id.Annotations'
    ec = {context_path: []}    # type: ignore
    ips = demisto.get(r.json(), 'data.items.network')  # type: ignore
    if ips:
        for k in ips:
            annotation = {
                'IP': k,
                'IP.Asn': ips[k].get('asn'),
                'IP.City': ips[k].get('city'),
                'IP.Country': ips[k].get('country'),
                'IP.Org': ips[k].get('org'),
                'IP.Region': ips[k].get('region'),
                'IP.Timestamp': ips[k].get('ts')
            }
            annotations.append(annotation)
            ec[context_path].append(annotation)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': r.json(),
        'EntryContext': ec,
        'HumanReadable': tableToMarkdown('ThreatGrid - Analysis Annotations', annotations, [
            'IP', 'IP.Asn', 'IP.City', 'IP.Country', 'IP.Org', 'IP.Region', 'IP.Timestamp'
        ])
    })


def get_analysis_by_id():
    """
    Download the analysis for a given sample
    """
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id + '/analysis.json')
    ec, hr = extract_data_from_analysis_json(json.loads(r.content), sample_id, demisto.getArg('limit'))
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': ec,
            'HumanReadable': hr,
            'Contents': r.json(),
            'ContentsFormat': formats['json']
        },
        fileResult(sample_id + '-analysis.json', r.content, file_type=entryTypes['entryInfoFile'])
    ])


def extract_data_from_analysis_json(analysis_json, sample_id, limit):
    """
    Extracts relevant data from an analysis json
    """
    ec = {}
    hr = {}
    sample_key = 'ThreatGrid.Sample(val.ID === obj.ID)'
    sample_process = extract_sample_process_from_analysis_processes(demisto.get(analysis_json,
                                                                                'dynamic.processes')) or {}
    ec[sample_key] = create_sample_ec_from_analysis_json(analysis_json, sample_id, sample_process, limit)
    hr['Sample'] = create_sample_hr_from_analysis_json(ec[sample_key], analysis_json, sample_process, limit)
    hr['File'] = ec[sample_key]["File"] = create_file_ec_from_analysis_json(analysis_json)
    handle_artifact_from_analysis_json(ec, hr, analysis_json, limit)
    hr_str = create_analysis_json_human_readable(hr)
    return ec, hr_str


def handle_artifact_from_analysis_json(ec, hr, analysis_json, limit):
    '''
    Populates ec and hr with artifact data from analysis json
    '''
    hr['Artifact'] = {}
    for artifact in get_with_limit(analysis_json, 'artifacts', limit).values():
        id = None
        yaras = demisto.get(artifact, 'antivirus.yara')
        if yaras:
            for yara in filter(lambda yara: 'id' in yara, yaras):
                id = yara['id']
                break
            if id:
                artifact_key = 'ThreatGrid.Artifact(val.ID === obj.{0})'.format(id)
                artifact_hr_key = 'Artifact(ID = {0})'.format(id)
                tags = set()
                for yara in filter(lambda yara: 'tags' in yara, yaras):
                    if yara['tags']:
                        for tag in yara['tags']:
                            tags.add(tag)
                # converting to list for tableToMarkdown
                tags = list(tags)
                hr['Artifact'][artifact_hr_key] = ec[artifact_key] = {
                    'ID': id,
                    'Tags': tags,
                    'FamilyName': demisto.get(artifact, 'antivirus.reversing_labs.classification.family_name'),
                    'ThreatName': demisto.get(artifact, 'antivirus.reversing_labs.threat_name')
                }


def create_analysis_json_human_readable(hr):
    hr_str = tableToMarkdown('Files scanned:', hr['File'], SAMPLE_ANALYSIS_HEADERS_MAP['File'])
    tmp_hr_str = ''
    for k in hr['Sample'].keys():
        if isinstance(hr['Sample'][k], dict) or (isinstance(hr['Sample'][k], list) and len(hr['Sample'][k]) > 0
                                                 and k in SAMPLE_ANALYSIS_HEADERS_MAP):
            tmp_hr_str = tmp_hr_str + tableToMarkdown('{0}:'.format(str(k)), hr['Sample'][k],
                                                      SAMPLE_ANALYSIS_HEADERS_MAP[k])
            del hr['Sample'][k]
    return_sting = hr_str + tableToMarkdown('Sample analysis:', hr['Sample'], SAMPLE_ANALYSIS_HEADERS_MAP['Sample'])
    return_sting = return_sting + tmp_hr_str + tableToMarkdown('Artifact analysis:', hr['Artifact'])
    return return_sting


def extract_sample_process_from_analysis_processes(processes):
    """
    Extracts the relevant process (i.e. sample process) from the processes
    """
    if processes:
        for process in processes.values():
            if demisto.get(process, 'analyzed_because') == "Is target sample.":
                return process
    return None


def create_sample_ec_from_analysis_json(analysis_json, sample_id, sample_process, limit):
    """
    Creates a dictionary corresponding to required field from the analysis_json
    """
    # Handling special case escape character
    directory = demisto.get(sample_process, 'startup_info.current_directory')
    if directory:
        directory = directory[:len(directory) - 1]
    domain_with_limit = get_with_limit(analysis_json, 'domains', limit) or {}
    return {
        'ID': sample_id,
        'VM': {'ID': demisto.get(analysis_json, 'metadata.sandcastle_env.vm_id'),
               'Name': demisto.get(analysis_json, 'metadata.sandcastle_env.display_name')},
        'StartedAt': demisto.get(analysis_json, 'metadata.sandcastle_env.analysis_start'),
        'EndedAt': demisto.get(analysis_json, 'metadata.sandcastle_env.analysis_end'),
        'Runtime': demisto.get(analysis_json, 'metadata.sandcastle_env.run_time'),
        'HeuristicScore': demisto.get(analysis_json, 'threat.heuristic_score'),
        'ThreatScore': get_with_limit(analysis_json, 'threat.threat_score', limit),
        'FilesDeleted': get_with_limit(sample_process, 'files_deleted', limit),
        'FilesCreated': get_with_limit(sample_process, 'files_created', limit),
        'FilesModified': get_with_limit(sample_process, 'files_modified', limit),
        'Directory': directory,
        'CMD': demisto.get(sample_process, 'startup_info.command_line'),
        'ProcessName': demisto.get(sample_process, 'process_name'),
        'Stream': extract_network_from_analysis_networks(get_with_limit(analysis_json, 'network', limit),
                                                         full_extraction=False),
        'VT': extract_vt_from_analysis_artifact(demisto.get(analysis_json, 'artifacts')),
        'Domain': [{'Name': str(key), 'Status': str(val.get('status'))} for key, val in domain_with_limit.iteritems()]
    }


def create_sample_hr_from_analysis_json(sample_ec, analysis_json, sample_process, limit):
    """
    Creates a human readable dictionary corresponding to required field from the analysis_json
    """
    res = dict(sample_ec)
    children = get_with_limit(sample_process, 'children', limit)
    memory = demisto.get(sample_process, 'memory')
    res.update(
        {
            'Mutants Created': get_with_limit(sample_process, 'mutants_created', limit),
            'Regitry Keys Deleted': get_with_limit(sample_process, 'registry_keys_deleted', limit),
            'Regisrty Keys Modified': get_with_limit(sample_process, 'registry_keys_modified', limit),
            'Regitry Keys Created': get_with_limit(sample_process, 'registry_keys_created', limit),
            'Threads': get_with_limit(sample_process, 'threads', limit),
            'Children': len(children) if children else 0,
            'Memory': len(memory) if memory and demisto.get(sample_process, 'new') == 'true' else 0,
            'Network': extract_network_from_analysis_networks(get_with_limit(analysis_json, 'network', limit),
                                                              full_extraction=True),
            'Enviornment Details': {
                'VM ID': sample_ec['VM']['ID'],
                'VM Name': sample_ec['VM']['Name'],
                'StartedAt': sample_ec['StartedAt'],
                'EndedAt': sample_ec['EndedAt'],
                'Runtime': sample_ec['Runtime']
            }
        }
    )
    # name of stream changes to network for human readable
    del res['Stream']
    del res['VM']
    del res['StartedAt']
    del res['EndedAt']
    del res['Runtime']
    return res


def extract_network_from_analysis_networks(networks, full_extraction=False):
    """
    Extract network representation from the networks arg
    """
    res = []
    if networks:
        for network_item in networks.values():
            res_item = {
                'Destination': str(demisto.get(network_item, 'dst')),
                'DestinationPort': demisto.get(network_item, 'dst_port'),
                'PacketSize': demisto.get(network_item, 'bytes_orig')
            }
            if full_extraction:
                res_item['Transport'] = str(demisto.get(network_item, 'transport'))
                res_item['Ts_Begin'] = demisto.get(network_item, 'ts_begin')
                res_item['Packets'] = demisto.get(network_item, 'packets')
            res.append(res_item)
    return res


def extract_vt_from_analysis_artifact(artifacts):
    """
    Extract virusTotal representation from the artifacts arg
    """
    if artifacts:
        for artifact in artifacts.values():
            if demisto.get(artifact, 'antivirus.virustotal'):
                vt = demisto.get(artifact, 'antivirus.virustotal')
                return {
                    'Hits': demisto.get(vt, 'hits'),
                    'Engines': demisto.get(vt, 'engines')
                }


def create_file_ec_from_analysis_json(analysis_json):
    """
    Creates a file entry array from the analysis json
    """
    malware_descs = demisto.get(analysis_json, 'metadata.malware_desc')
    res = []
    for desc in malware_descs:
        res.append(
            {
                'FileName': demisto.get(desc, 'filename'),
                'Size': demisto.get(desc, 'size'),
                'MD5': demisto.get(desc, 'md5'),
                'SHA1': demisto.get(desc, 'sha1'),
                'SHA256': demisto.get(desc, 'sha256'),
                'MagicType': demisto.get(desc, 'magic'),
                'Type': demisto.get(desc, 'type'),
            })
    return res


def ioc_to_readable(ioc):
    ioc_key_to_path_dict = {
        'Title': 'title',
        'Confidence': 'confidence',
        'Severity': 'severity',
        'IOC': 'ioc',
        'Tags': 'tags',
        'IOCCategory': 'category'
    }
    ioc_data_keys_set = {
        'URL',
        'Path',
        'SHA256',
        'IP'
    }
    res = {}
    # add ioc_key_to_path_dict values to result
    for k, v in ioc_key_to_path_dict.iteritems():
        val = demisto.get(ioc, v)
        if val:
            res[k] = val
    # add ioc_data_keys_set values to result.Data
    res['Data'] = {}
    for key in ioc_data_keys_set:
        res['Data'][key] = []
    if demisto.get(ioc, 'data'):
        for item in demisto.get(ioc, 'data'):
            for key in ioc_data_keys_set:
                if demisto.get(item, key):
                    res['Data'][key].append(demisto.get(item, key))
    return res


def get_analysis_iocs():
    """
    Get data about analysis iocs for a given sample or ioc
    """
    sample_id = demisto.getArg('id')
    ioc = demisto.getArg('ioc')
    url = SUB_API + 'samples/' + sample_id + '/analysis/iocs'
    if ioc:
        url += '/' + ioc
    params = {'api_key': API_KEY}
    if demisto.getArg('limit'):
        params['limit'] = demisto.getArg('limit')

    r = req('GET', url, params=params)
    iocs = []    # type: ignore
    dbots = []    # type: ignore
    items = demisto.get(r.json(), 'data.items')    # type: ignore
    if not items:
        append_to_analysis_iocs_arrays(iocs, dbots, demisto.get(r.json(), 'data'))
    else:
        for k in items:
            append_to_analysis_iocs_arrays(iocs, dbots, k)
    md = tableToMarkdown('ThreatGrid Behavioral Indicators for sample: ' + demisto.getArg('id'), iocs,
                         ['Title', 'Confidence', 'Severity', 'IOC', 'Tags', 'IOCCategory', 'Data'])
    md += tableToMarkdown('DBot', dbots, ['Indicator', 'Score', 'Type', 'Vendor'])
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.IOCs': iocs, 'DBotScore': dbots},
        'HumanReadable': md,
        'ContentsFormat': formats['json'],
        'Contents': r.json()
    })


def append_to_analysis_iocs_arrays(iocs, dbots, k):
    """
    Helper for appending analysis item to ioc an dbot arrays
    """
    iocs.append(ioc_to_readable(k))
    dbots.append({
        'Vendor': 'ThreatGrid',
        'Type': 'IOC',
        'Indicator': k['ioc'],
        'Score': calc_score(k['severity'])
    })


def apply_search_filters():
    """
    Helper for applying search filters
    """
    params = {'api_key': API_KEY}
    for k in demisto.args():
        if demisto.getArg(k):
            params['term'] = k
            params['query'] = demisto.getArg(k)
            break
    return params


def search_ips():
    """
    Search ips with the given filters
    """
    r = req('GET', SUB_API + 'search/ips', params=apply_search_filters())
    ips = []
    for ip in demisto.get(r.json(), 'data.items'):
        ips.append({
            'Result': demisto.get(ip, 'result'),
            'Details': demisto.get(ip, 'details')
        })
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.IPs': ips},
        'HumanReadable': tableToMarkdown('ThreatGrid - IP Search', ips, ['Result', 'Details']),
        'ContentsFormat': formats['json'],
        'Contents': r.json()
    })


def search_urls():
    """
    Search urls with the given filters
    """
    r = req('GET', SUB_API + 'search/urls', params=apply_search_filters())
    urls = []
    for url in demisto.get(r.json(), 'data.items'):
        urls.append({
            'Result': demisto.get(url, 'result'),
            'Details': demisto.get(url, 'details')
        })
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.URLs': urls},
        'HumanReadable': tableToMarkdown('ThreatGrid - URL Search', urls, ['Result', 'Details']),
        'ContentsFormat': formats['json'],
        'Contents': r.json()
    })


def search_samples():
    """
    Search samples with the given filters
    """
    r = req('GET', SUB_API + 'search/samples', params=apply_search_filters())
    samples = []
    for sample in demisto.get(r.json(), 'data.items'):
        samples.append({
            'ID': demisto.get(sample, 'result'),
            'Details': demisto.get(sample, 'details')
        })
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.Sample': samples},
        'HumanReadable': tableToMarkdown('ThreatGrid - Sample Search', samples, ['Result', 'Details']),
        'ContentsFormat': formats['json'],
        'Contents': r.json()
    })


def search_submissions():
    """
    Search submissions with the given filters
    """
    r = req('GET', SUB_API + 'search/submissions', params=handle_filters())
    submissions = []
    for submission in demisto.get(r.json(), 'data.items'):
        sample = sample_to_readable(demisto.get(submission, 'item'))
        sample['ID'] = demisto.get(submission, 'item.sample')
        sample['ThreatScore'] = demisto.get(submission, 'item.analysis.threat_score')
        submissions.append(sample)
    demisto.results({
        'Type': entryTypes['note'],
        'EntryContext': {'ThreatGrid.Sample(val.ID == obj.ID)': submissions},
        'HumanReadable': tableToMarkdown('ThreatGrid - Submission Search', submissions,
                                         ['ID', 'Filename', 'State', 'Status', 'MD5', 'SHA1',
                                          'SHA256', 'SubmittedAt', 'ThreatScore']),
        'ContentsFormat': formats['json'],
        'Contents': r.json()
    })


def url_to_file():
    """
    Convert a url to file for detonation
    """
    urls = argToList(demisto.getArg('urls'))
    files = []
    for i in range(len(urls)):
        fileEntry = fileResult('url_' + str(i + 1), '[InternetShortcut]\nURL=' + str(urls[i]))
        files.append(fileEntry)
    demisto.results(files)


def get_specific_feed():
    """
    Get specific feed
    """
    feed_name = demisto.getArg('feed-name')
    feed_period = '_' + demisto.getArg('feed-period') if demisto.getArg('feed-period') else ''
    output_type = demisto.getArg('output-type')
    r = req('GET', USER_API + 'feeds/' + feed_name + feed_period + '.' + output_type)
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': {},
            'HumanReadable': '### ThreatGrid Specific Feed File -\n'
                             + 'Your specific feed file download request has been completed successfully for '
                             + feed_name,
            'Contents': {},
            'ContentsFormat': formats['json']
        },
        fileResult(feed_name + output_type, r.content)
    ])


def feeds_helper(name):
    name_conversion = {
        'domain': 'domains',
        'ip': 'ips',
        'network-stream': 'network_streams',
        'registry-key': 'registry_keys',
        'url': 'urls',
        'path': 'paths'
    }
    requested_feed = name_conversion[name] if name in name_conversion else name
    url = SUB_API + 'iocs/feeds/' + requested_feed
    r = req('GET', url, params=handle_filters())
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': {},
            'HumanReadable': 'Your feeds ' + name + ' file download request has been completed successfully',
            'Contents': r.content,
            'ContentsFormat': formats['json']
        },
        fileResult(url, r.content)
    ])


def get_analysis_artifact():
    aid = demisto.getArg('aid')
    sample_id = demisto.getArg('id')
    url = SUB_API + 'samples/' + sample_id + '/analysis/artifacts'
    if aid:
        url += '/' + aid
    r = req('GET', url)
    ec = {'ThreatGrid.Sample(val.ID === {0})'.format(sample_id): r.json()}
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': ec,
            'HumanReadable': None,
            'Contents': r.json(),
            'ContentsFormat': formats['json']
        }
    ])


def get_analysis_metadata():
    sample_id = demisto.getArg('id')
    r = req('GET', SUB_API + 'samples/' + sample_id + '/analysis/metadata')
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': {},
            'HumanReadable': None,
            'Contents': r.json(),
            'ContentsFormat': formats['json']
        }
    ])


def get_analysis_network_stream():
    sample_id = demisto.getArg('id')
    nsid = demisto.getArg('nsid')
    url = SUB_API + 'samples/' + sample_id + '/analysis/artifacts'
    if nsid:
        url += '/' + nsid
    r = req('GET', url)
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': {},
            'HumanReadable': None,
            'Contents': r.json(),
            'ContentsFormat': formats['json']
        }
    ])


def get_analysis_process():
    sample_id = demisto.getArg('id')
    pid = demisto.getArg('pid')
    url = SUB_API + 'samples/' + sample_id + '/analysis/processes'
    if pid:
        url += '/' + pid
    r = req('GET', url)
    demisto.results([
        {
            'Type': entryTypes['note'],
            'EntryContext': {},
            'HumanReadable': None,
            'Contents': r.json(),
            'ContentsFormat': formats['json']
        },
        fileResult(sample_id + '-sample.zip', r.content)
    ])


if demisto.command() == 'test-module':
    request = req('GET', USER_API + 'session/whoami')
    demisto.results('ok')
elif demisto.command() == 'threat-grid-download-sample-by-id':
    download_sample()
elif demisto.command() == 'threat-grid-get-samples':
    get_samples()
elif demisto.command() == 'threat-grid-get-sample-by-id':
    get_sample_by_id()
elif demisto.command() == 'threat-grid-get-sample-state-by-id' or demisto.command() == 'threat-grid-get-samples-state':
    get_sample_state_by_id()
elif demisto.command() == 'threat-grid-upload-sample':
    upload_sample()
elif demisto.command() == 'threat-grid-get-html-report-by-id':
    get_html_report_by_id()
elif demisto.command() == 'threat-grid-get-pcap-by-id':
    get_pcap_by_id()
elif demisto.command() == 'threat-grid-get-processes-by-id':
    get_processes_by_id()
elif demisto.command() == 'threat-grid-get-summary-by-id':
    get_summary_by_id()
elif demisto.command() == 'threat-grid-get-threat-summary-by-id':
    get_threat_summary_by_id()
elif demisto.command() == 'threat-grid-get-video-by-id':
    get_video_by_id()
elif demisto.command() == 'threat-grid-get-warnings-by-id':
    get_warnings_by_id()
elif demisto.command() == 'threat-grid-user-get-rate-limit':
    user_get_rate_limit()
elif demisto.command() == 'threat-grid-organization-get-rate-limit':
    organization_get_rate_limit()
elif demisto.command() == 'threat-grid-who-am-i':
    who_am_i()
elif demisto.command() == 'threat-grid-get-analysis-annotations':
    get_analysis_annotations()
elif demisto.command() == 'threat-grid-get-analysis-by-id':
    get_analysis_by_id()
elif demisto.command() == 'threat-grid-get-analysis-iocs' or demisto.command() == 'threat-grid-get-analysis-ioc':
    get_analysis_iocs()
elif demisto.command() == 'threat-grid-url-to-file':
    url_to_file()
elif demisto.command() == 'threat-grid-search-samples':
    search_samples()
elif demisto.command() == 'threat-grid-search-ips':
    search_ips()
elif demisto.command() == 'threat-grid-search-urls':
    search_urls()
elif demisto.command() == 'threat-grid-search-submissions':
    search_submissions()
elif demisto.command() == 'threat-grid-get-specific-feed':
    get_specific_feed()
elif demisto.command() in ['threat-grid-feeds-artifacts', 'threat-grid-feeds-domain',
                           'threat-grid-feeds-ip', 'threat-grid-feeds-network-stream',
                           'threat-grid-feeds-registry-key', 'threat-grid-feeds-url', 'threat-grid-feeds-path']:
    feeds_helper(demisto.command()[18:])
elif demisto.command() == 'threat-grid-get-analysis-artifact' or \
        demisto.command() == 'threat-grid-get-analysis-artifacts':
    get_analysis_artifact()
elif demisto.command() == 'threat-grid-get-analysis-metadata':
    get_analysis_metadata()
elif demisto.command() == 'threat-grid-get-analysis-network-stream' or \
        demisto.command() == 'threat-grid-get-analysis-network-streams':
    get_analysis_network_stream()
elif demisto.command() == 'threat-grid-get-analysis-process' or \
        demisto.command() == 'threat-grid-get-analysis-processes':
    get_analysis_process()
elif demisto.command() in ['threat-grid-download-artifact', 'threat-grid-detonate-file']:
    return_error('Error: The API for this command is no longer supported')
else:
    return_error('Unrecognized command: ' + demisto.command())
