import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''
import requests
from io import StringIO
from typing import List

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
INTEGRATION_NAME = "Group-IB TDS Polygon"
LANGUAGE_TO_CODE = {
    "english": "en",
    "russian": "ru"
}
FILE_TYPE = "F"
URL_TYPE = "U"

API = 'api/'
ANALGIN_UPLOAD = API + 'analgin/upload/'
ATTACHES = API + 'attaches/'
ATTACH = ATTACHES + "?id={}"
REPORT = ATTACHES + "{}/{}/{}/polygon_report/"
REPORT_EXPORT = ATTACHES + "{}/{}/{}/polygon_report_export/"
PCAP_EXPORT = ATTACHES + '{}/{}/{}/dump.pcap/dump.pcap/polygon_report_file_download/'
VIDEO_EXPORT = ATTACHES + '{}/{}/{}/shots/video.webm/video.webm/polygon_report_file_download/'
HASH_REPUTATION = API + 'reports/check_hash/{}/{}/'


class RegistryKey(Common.Indicator):
    """
    Registry Key indicator class
    """
    def __init__(self, path, value, name=None):
        self.path = path
        self.name = name
        self.value = value

    def to_context(self):
        key_context = {
            'Path': self.path,
            'Name': self.name,
            'Value': self.value
        }
        return {"RegistryKey": key_context}


class Process(Common.Indicator):
    """
    Process indicator class
    """
    def __init__(self, name, pid, hostname=None, md5=None, sha1=None,
                 command_line=None, path=None, start_time=None, end_time=None,
                 parent=None, sibling=None, child=None):
        self.name = name
        self.pid = pid
        self.hostname = hostname
        self.md5 = md5
        self.sha1 = sha1
        self.command_line = command_line
        self.path = path
        self.start_time = start_time
        self.end_time = end_time
        self.parent = parent
        self.sibling = sibling
        self.child = child

    def to_context(self):
        process_context = {
            'Name': self.name,
            'PID': self.pid,
            'Hostname': self.hostname,
            'MD5': self.md5,
            'SHA1': self.sha1,
            'CommandLine': self.command_line,
            'Path': self.path,
            'StartTime': self.start_time,
            'EndTime': self.end_time,
            'Parent': self.parent,
            'Sibling': self.sibling,
            'Child': self.child
        }

        return {"Process": process_context}


class Client:
    def __init__(self, base_url, api_key, verify, proxies, language):
        self.base_url = base_url
        self.verify = verify
        self.proxies = proxies
        self.language = language
        self.headers = {'X-API-KEY': api_key}

    def _resp_handle(self, resp, decode=True):
        if resp.status_code != 200:
            if resp.status_code == 400:
                raise ValueError(f"Bad request: {resp.json()['messages']}")
            elif resp.status_code == 423:
                raise ValueError("TDS is being updated, please try again later")
            raise ValueError(f"Error in API call to TDS server: {resp.status_code}. Reason: {resp.text}")
        if decode:
            try:
                return resp.json()
            except Exception:
                raise ValueError("Incorrect TDS answer format")
        return resp.content

    def _http_request(self, method, url_suffix, params=None, data=None, files=None, decode=True):
        url = urljoin(self.base_url, url_suffix)
        resp = requests.request(
            method,
            url,
            headers=self.headers,
            verify=self.verify,
            params=params,
            data=data,
            files=files,
            proxies=self.proxies
        )
        return self._resp_handle(resp, decode)

    def _check_report_available(self, file_info):
        report = False
        if "analgin_result" in file_info:
            if "commit" in file_info["analgin_result"]:
                if "reports" in file_info["analgin_result"]:
                    if len(file_info["analgin_result"]["reports"]):
                        if "id" in file_info["analgin_result"]["reports"][0]:
                            report = True
        return report

    def _get_fids(self, resp):
        fids = resp["data"].get("ids", [])
        if not fids:
            raise ValueError("TDS server error")
        return fids[0]

    def upload_file(self, file_name, file_path, password=""):
        with open(file_path, 'rb') as f:
            resp = self._http_request(
                method='post',
                url_suffix=ANALGIN_UPLOAD,
                files={'files': (file_name, f)},
                data=dict(language=self.language, password=password)
            )
        return self._get_fids(resp)

    def upload_url(self, url):
        resp = self._http_request(
            method='post',
            url_suffix=ANALGIN_UPLOAD,
            files={'files': ("url.txt", StringIO(url))},
            data=dict(language=self.language)
        )
        return self._get_fids(resp)

    def get_attach(self, id=None):
        url = ATTACH.format(id) if id else ATTACHES
        resp = self._http_request('get', url)["data"]["results"]
        if id:
            try:
                resp = resp[0]
            except Exception:
                raise ValueError(f"File with ID={id} does not exist")
        return resp

    def get_analysis_info(self, tds_analysis_id):
        file = self.get_attach(tds_analysis_id)
        resp = dict(file=file)
        if self._check_report_available(file):
            try:
                report = self._http_request('get', REPORT.format(tds_analysis_id,
                                                                 file["analgin_result"]["commit"],
                                                                 file["analgin_result"]["reports"][0]["id"]))
                resp.update({'report': report['data']})
            except ValueError:
                pass
        return resp

    def get_url(self, tds_analysis_id):
        file = self.get_attach(tds_analysis_id)
        if self._check_report_available(file):
            return self._http_request(
                method='get',
                url_suffix=file["file_url"][1:],
                decode=False
            )
        raise ValueError("No reports found")

    def export_report(self, tds_analysis_id):
        file = self.get_attach(tds_analysis_id)
        if self._check_report_available(file):
            return self._http_request(
                method='get',
                url_suffix=REPORT_EXPORT.format(tds_analysis_id,
                                                file["analgin_result"]["commit"],
                                                file["analgin_result"]["reports"][0]["id"]),
                decode=False
            )
        raise ValueError("No reports found")

    def export_pcap(self, tds_analysis_id):
        file = self.get_attach(tds_analysis_id)
        if self._check_report_available(file):
            return self._http_request(
                method='get',
                url_suffix=PCAP_EXPORT.format(tds_analysis_id,
                                              file["analgin_result"]["commit"],
                                              file["analgin_result"]["reports"][0]["id"]),
                decode=False
            )
        raise ValueError("No dump files found")

    def export_video(self, tds_analysis_id):
        file = self.get_attach(tds_analysis_id)
        if self._check_report_available(file):
            try:
                return self._http_request(
                    method='get',
                    url_suffix=VIDEO_EXPORT.format(tds_analysis_id,
                                                   file["analgin_result"]["commit"],
                                                   file["analgin_result"]["reports"][0]["id"]),
                    decode=False
                )
            except ValueError:
                return None
        raise ValueError("No dump files found")

    def get_hash_reputation(self, hash_type, hash_value):
        return self._http_request(
            method='GET',
            url_suffix=HASH_REPUTATION.format(hash_type, hash_value)
        )["data"]


def drop_prefix(id_with_prefix):
    return id_with_prefix[1:]


def serialize_report_info(report, analysis_type):
    res = {
        "Verdict": "Malicious" if report["info"]["verdict"] else "Benign",
        "Started": report["info"]["started"],
        "Analyzed": report["info"]["ended"],
        "Internet-connection": "Available" if report["info"]["internet_available"] else "Unavailable",
    }
    if report['info']['verdict']:
        res.update({
            "Probability": "{:.2f}%".format(report["info"]["probability"]),
            "Families": ", ".join(report["info"]["families"]),
            "Score": report["info"]["score"],
            "DumpExists": any(map(lambda vals: len(vals) > 0, report["network"].values()))
        })
    if analysis_type == FILE_TYPE:
        res.update({
            "Type": report["target"]["file"]["type"]
        })
    else:
        res.update({
            "URL": report["target"]["url"]
        })
    return res


def serialize_analysis_info(info, analysis_type, report):
    res = {
        'ID': analysis_type + str(info["id"]),
        'Status': 'Finished' if report else 'In Progress',
        'Result': info['verdict']
    }
    if analysis_type == FILE_TYPE:
        res.update({
            'Name': info["original_filename"],
            'Size': info['file_size'],
            'MD5': info['md5'],
            'SHA1': info['sha1'],
            'SHA256': info['sha256'],
        })
    return res


def get_human_readable_analysis_info(analysis_info):
    return tableToMarkdown(
        f"Analysis {analysis_info['ID']}",
        analysis_info,
        removeNull=True
    )


def get_main_indicator(report, analysis_type):
    score = Common.DBotScore.GOOD
    malicious = None
    if report["info"]["verdict"]:
        score = Common.DBotScore.BAD
        malicious = "Verdict probability: {}%".format(
            report["info"]["probability"]
        )
        signatures = []
        for signature in report["signatures"]:
            if signature.get("name") == "yara_rules":
                signatures += [s.get('ioc') for s in signature.get('marks', [])]
        if signatures:
            malicious += ", iocs: {}".format(", ".join(signatures))
    if analysis_type == FILE_TYPE:
        return Common.File(
            name=report["target"]["file"]["name"],
            file_type=report["target"]["file"]["type"],
            md5=report["target"]["file"]["md5"],
            sha1=report["target"]["file"]["sha1"],
            sha256=report["target"]["file"]["sha256"],
            dbot_score=Common.DBotScore(
                indicator=report["target"]["file"]["md5"],
                indicator_type=DBotScoreType.FILE,
                integration_name=INTEGRATION_NAME,
                score=score,
                malicious_description=malicious
            )
        )
    else:
        return Common.URL(
            url=report['target']['url'],
            dbot_score=Common.DBotScore(
                indicator=report['target']['url'],
                indicator_type=DBotScoreType.URL,
                integration_name=INTEGRATION_NAME,
                score=score,
                malicious_description=malicious
            )
        )


def get_packages_indicators(report):
    ids = []
    for package in report["packages"]:
        info = package['file_info']
        file = Common.File(
            name=info['name'],
            file_type=info['type'],
            md5=info['md5'],
            sha1=info['sha1'],
            sha256=info['sha256'],
            dbot_score=Common.DBotScore(
                indicator=info['sha1'],
                indicator_type=DBotScoreType.FILE,
                integration_name=INTEGRATION_NAME,
                score=0
            )
        )
        ids.append(file)
    return ids


def get_network_indicators(report):
    ids: List[Common.Indicator] = []
    network = report['network']
    for dns in network['dns']:
        domain = Common.Domain(
            domain=dns['request'],
            dns=", ".join(list(map(lambda x: x['data'], dns['answers']))),
            dbot_score=Common.DBotScore(
                indicator=dns['request'],
                indicator_type=DBotScoreType.DOMAIN,
                integration_name=INTEGRATION_NAME,
                score=0
            )
        )
        ids.append(domain)
    for host in network['hosts'] + [h[0] for h in network['dead_hosts']]:
        ip = Common.IP(
            ip=host,
            dbot_score=Common.DBotScore(
                indicator=host,
                indicator_type=DBotScoreType.IP,
                integration_name=INTEGRATION_NAME,
                score=0
            )
        )
        ids.append(ip)
    for http in network['http']:
        url = Common.URL(
            url=http['uri'],
            dbot_score=Common.DBotScore(
                indicator=http['uri'],
                indicator_type=DBotScoreType.URL,
                integration_name=INTEGRATION_NAME,
                score=0
            )
        )
        ids.append(url)

    return ids


def get_monitor_indicators(report):
    ids: List[Common.Indicator] = []
    for p in report['goo_monitor']['processes']:
        process = Process(
            name=p['basename'],
            pid=str(p['pid']),
            command_line=p['cmdline'],
            start_time=p['started_at'],
            end_time=p['exited_at'],
            path=p['filename'],
        )
        ids.append(process)
        for regkey in p['regkeys']:
            if regkey['action'] == 'regkey_written':
                reg = RegistryKey(
                    path=regkey['ioc'],
                    value=str(regkey['value'])
                )
                ids.append(reg)

    return ids


def get_report_indicators(report, analysis_type):
    indicators = [get_main_indicator(report, analysis_type)]
    indicators += get_packages_indicators(report)
    indicators += get_network_indicators(report)
    indicators += get_monitor_indicators(report)

    return indicators


def analysis_info_command(client, args):
    tds_analysis_id_array = argToList(args.get('tds_analysis_id'))
    all_results = []
    for tds_analysis_id in tds_analysis_id_array:
        analysis_type = tds_analysis_id[0]
        res = client.get_analysis_info(drop_prefix(tds_analysis_id))
        analysis_info = serialize_analysis_info(res['file'], analysis_type, report='report' in res)
        indicators = []
        if 'report' in res:
            if analysis_type == URL_TYPE:
                res['report']['target']['url'] = client.get_url(drop_prefix(tds_analysis_id)).decode()
            analysis_info.update(serialize_report_info(res['report'], analysis_type))
            indicators = get_report_indicators(res["report"], analysis_type)
        human_readable = get_human_readable_analysis_info(analysis_info)
        results = CommandResults(
            readable_output=human_readable,
            outputs_prefix="Polygon.Analysis",
            outputs_key_field="ID",
            outputs=analysis_info,
            indicators=indicators
        )
        all_results.append(results)
        return_results(results)
    return all_results


def export_report_command(client, args):
    tds_analysis_id = drop_prefix(args.get('tds_analysis_id'))
    report = client.export_report(tds_analysis_id)
    demisto.results(fileResult(
        filename='report.tar',
        data=report,
        file_type=EntryType.ENTRY_INFO_FILE
    ))


def export_pcap_command(client, args):
    tds_analysis_id = drop_prefix(args.get('tds_analysis_id'))
    pcap = client.export_pcap(tds_analysis_id)
    demisto.results(fileResult(
        filename='dump.pcap',
        data=pcap,
        file_type=EntryType.ENTRY_INFO_FILE
    ))


def export_video_command(client, args):
    tds_analysis_id = drop_prefix(args.get('tds_analysis_id'))
    video = client.export_video(tds_analysis_id)
    if not video:
        return_results("No screen activity detected")
    else:
        demisto.results(fileResult(
            filename='video.webm',
            data=video,
            file_type=EntryType.ENTRY_INFO_FILE
        ))


def upload_url_command(client, args):
    url = args.get('url')
    res = client.upload_url(url)
    res = f"{URL_TYPE}{res}"
    outputs = {
        'ID': res,
        'URL': url,
        'Status': 'In Progress',
    }
    results = CommandResults(
        readable_output=f"Url uploaded successfully. Analysis ID: {res}",
        outputs_prefix='Polygon.Analysis',
        outputs_key_field='ID',
        outputs=outputs
    )
    return_results(results)
    return results


def upload_file_command(client, args):
    file_id = args.get('file_id')
    password = args.get('password')
    file_obj = demisto.getFilePath(file_id)
    # Ignoring non ASCII
    file_name = file_obj['name'].encode('ascii', 'ignore')
    file_path = file_obj['path']
    res = client.upload_file(file_name, file_path, password)
    res = f"{FILE_TYPE}{res}"
    outputs = {
        'ID': res,
        'EntryID': file_id,
        'FileName': file_obj['name'],
        'Status': 'In Progress'
    }
    results = CommandResults(
        readable_output=f"File uploaded successfully. Analysis ID: {res}",
        outputs_prefix='Polygon.Analysis',
        outputs_key_field='ID',
        outputs=outputs
    )
    return_results(results)
    return results


def file_command(client, args):
    files = argToList(args.get('file'))
    all_results = []
    for file in files:
        hash_type = get_hash_type(file)
        if hash_type != "Unknown":
            res = client.get_hash_reputation(hash_type, file)
            analysis_info = {
                hash_type.upper(): file,
                'Found': res.get('found'),
                'Verdict': res.get('verdict'),
                'Score': res.get('score'),
                'Malware-families': res.get('malware_families')
            }
            score = Common.DBotScore.NONE
            malicious = None
            if res["found"]:
                if res["verdict"]:
                    score = Common.DBotScore.BAD
                    malicious = "TDS Polygon score: {}".format(res['score'])
                    if res.get('malware_families'):
                        malicious += ", {}".format(", ".join(res["malware_families"]))
                else:
                    score = Common.DBotScore.GOOD
            dbot_score = Common.DBotScore(
                indicator=file,
                indicator_type=DBotScoreType.FILE,
                integration_name=INTEGRATION_NAME,
                score=score,
                malicious_description=malicious
            )
            indicator = Common.File(**{hash_type: file, "dbot_score": dbot_score})
            result = CommandResults(
                outputs_prefix="Polygon.Analysis",
                outputs_key_field=hash_type.upper(),
                outputs=analysis_info,
                indicators=[indicator]
            )
            return_results(result)
            all_results.append(result)
    return all_results


def test_module(client):
    client.get_attach()
    return 'ok'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    base_url = params.get('server')
    api_key = params.get('api_key')
    verify_certificate = not params.get('insecure', False)
    report_language = LANGUAGE_TO_CODE[params.get('report_language')]

    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            proxies=proxies,
            language=report_language
        )
        commands = {
            'polygon-upload-file': upload_file_command,
            'polygon-upload-url': upload_url_command,
            'polygon-analysis-info': analysis_info_command,
            'polygon-report-export': export_report_command,
            'polygon-pcap-export': export_pcap_command,
            'polygon-video-export': export_video_command,
            'file': file_command
        }

        if command == 'test-module':
            return_results(test_module(client))
        elif command in commands:
            commands[command](client, demisto.args())

    # Log exceptions
    except Exception as err:
        return_error(f'Failed to execute {command} command. Error: {str(err)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
