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


class Client(BaseClient):
    def __init__(self, base_url, verify, api_key, language):
        super().__init__(base_url=base_url, verify=verify)
        self._language = language
        self._headers = {'X-API-KEY': api_key}

    def _check_report_available(self, file_info):
        report = False
        if "analgin_result" in file_info:
            if "commit" in file_info.get("analgin_result", {}):
                if "reports" in file_info.get("analgin_result", {}):
                    if len(file_info["analgin_result"].get("reports", [])):
                        if "id" in file_info["analgin_result"]["reports"][0]:
                            report = True
        return report

    def _get_fids(self, resp):
        fids = resp.get("data", {}).get("ids", [])
        if not fids:
            err_msg = "There is no analysis ID in TDS response." \
                      "Try to upload file/url one more time."
            raise DemistoException(err_msg)
        return fids[0]

    def upload_file(self, file_name, file_path, password=""):
        with open(file_path, 'rb') as f:
            resp = self._http_request(
                method='post',
                url_suffix=ANALGIN_UPLOAD,
                files={'files': (file_name, f)},
                data=dict(language=self._language, password=password)
            )
        return self._get_fids(resp)

    def upload_url(self, url):
        resp = self._http_request(
            method='post',
            url_suffix=ANALGIN_UPLOAD,
            files={'files': ("url.txt", StringIO(url))},
            data=dict(language=self._language)
        )
        return self._get_fids(resp)

    def get_attach(self, id=None):
        url = ATTACH.format(id) if id else ATTACHES
        results = self._http_request('get', url).get("data", {}).get("results", [])
        if id:
            try:
                results = results[0]
            except Exception:
                raise DemistoException(f"File with ID={id} does not exist")
        return results

    def get_analysis_info(self, tds_analysis_id):
        file = self.get_attach(tds_analysis_id)
        resp = dict(file=file)
        if self._check_report_available(file):
            try:
                report = self._http_request('get', REPORT.format(tds_analysis_id,
                                                                 file["analgin_result"]["commit"],
                                                                 file["analgin_result"]["reports"][0]["id"]))
                if "data" in report:
                    resp.update({'report': report['data']})
            except Exception:
                pass
        return resp

    def get_url(self, file):
        if self._check_report_available(file):
            return self._http_request(
                method='get',
                url_suffix=file.get("file_url")[1:],
                resp_type="content"
            ).decode()
        raise DemistoException("No reports found")

    def export_report(self, tds_analysis_id):
        file = self.get_attach(tds_analysis_id)
        if self._check_report_available(file):
            return self._http_request(
                method='get',
                url_suffix=REPORT_EXPORT.format(tds_analysis_id,
                                                file["analgin_result"]["commit"],
                                                file["analgin_result"]["reports"][0]["id"]),
                resp_type="content"
            )
        raise DemistoException(f"No reports for analysis: {tds_analysis_id}")

    def export_pcap(self, tds_analysis_id):
        file = self.get_attach(tds_analysis_id)
        if self._check_report_available(file):
            return self._http_request(
                method='get',
                url_suffix=PCAP_EXPORT.format(tds_analysis_id,
                                              file["analgin_result"]["commit"],
                                              file["analgin_result"]["reports"][0]["id"]),
                resp_type="content"
            )
        raise DemistoException(f"No reports for analysis: {tds_analysis_id}")

    def export_video(self, tds_analysis_id):
        file = self.get_attach(tds_analysis_id)
        if self._check_report_available(file):
            return self._http_request(
                method='get',
                url_suffix=VIDEO_EXPORT.format(tds_analysis_id,
                                               file["analgin_result"]["commit"],
                                               file["analgin_result"]["reports"][0]["id"]),
                resp_type="content"
            )
        raise DemistoException(f"No reports for analysis: {tds_analysis_id}")

    def get_hash_reputation(self, hash_type, hash_value):
        return self._http_request(
            method='get',
            url_suffix=HASH_REPUTATION.format(hash_type, hash_value)
        ).get("data", {})


def drop_prefix(id_with_prefix):
    return id_with_prefix[1:]


def serialize_report_info(report, analysis_type):
    info = report.get('info', {})
    res = {
        "Verdict": "Malicious" if info.get("verdict") else "Benign",
        "Started": info.get("started"),
        "Analyzed": info.get("ended"),
        "Internet-connection": "Available" if info.get("internet_available") else "Unavailable",
    }
    if info.get('verdict'):
        res.update({
            "Probability": "{:.2f}%".format(info.get("probability", 0.0)),
            "Families": ", ".join(info.get("families", [])),
            "Score": info.get("score", 0),
            "DumpExists": any(map(lambda vals: len(vals) > 0, report.get("network", {}).values()))
        })
    if analysis_type == FILE_TYPE:
        res.update({
            "Type": report.get("target", {}).get("file", {}).get("type")
        })
    else:
        res.update({
            "URL": report.get("target", {}).get("url")
        })
    return res


def serialize_analysis_info(info, analysis_type, report):
    res = {
        'ID': analysis_type + str(info.get("id", "")),
        'Status': 'Finished' if report else 'In Progress',
        'Result': info.get('verdict')
    }
    if analysis_type == FILE_TYPE:
        res.update({
            'Name': info.get("original_filename"),
            'Size': info.get('file_size'),
            'MD5': info.get('md5'),
            'SHA1': info.get('sha1'),
            'SHA256': info.get('sha256'),
        })
    return res


def get_human_readable_analysis_info(analysis_info):
    return tableToMarkdown(
        f"Analysis {analysis_info.get('ID')}",
        analysis_info,
        removeNull=True
    )


def get_main_indicator(report, analysis_type):
    score = Common.DBotScore.GOOD
    malicious = None
    if report.get("info", {}).get("verdict"):
        score = Common.DBotScore.BAD
        malicious = "Verdict probability: {}%".format(
            report.get("info", {}).get("probability")
        )
        signatures: list = []
        for signature in report.get("signatures", []):
            if signature.get("name") == "yara_rules":
                signatures += [s.get('ioc') for s in signature.get('marks', [])]
        if signatures:
            malicious += ", iocs: {}".format(", ".join(signatures))
    if analysis_type == FILE_TYPE:
        tfile = report.get("target", {}).get("file", {})
        return Common.File(
            name=tfile.get("name"),
            file_type=tfile.get("type"),
            md5=tfile.get("md5"),
            sha1=tfile.get("sha1"),
            sha256=tfile.get("sha256"),
            dbot_score=Common.DBotScore(
                indicator=tfile.get("md5"),
                indicator_type=DBotScoreType.FILE,
                integration_name=INTEGRATION_NAME,
                score=score,
                malicious_description=malicious
            )
        )
    else:
        url = report.get("target", {}).get("url")
        return Common.URL(
            url=url,
            dbot_score=Common.DBotScore(
                indicator=url,
                indicator_type=DBotScoreType.URL,
                integration_name=INTEGRATION_NAME,
                score=score,
                malicious_description=malicious
            )
        )


def get_packages_indicators(res):
    report = res['report']
    command_results = []
    for package in report.get("packages", []):
        info = package.get('file_info', {})
        file = Common.File(
            name=info.get('name'),
            file_type=info.get('type'),
            md5=info.get('md5'),
            sha1=info.get('sha1'),
            sha256=info.get('sha256'),
            dbot_score=Common.DBotScore(
                indicator=info.get('sha1'),
                indicator_type=DBotScoreType.FILE,
                integration_name=INTEGRATION_NAME,
                score=0
            )
        )
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f"New File indicator was created {file.name}"),
            indicator=file,
            raw_response=res
        )
        )
    return command_results


def get_network_indicators(res):
    report = res['report']
    command_results = []
    network = report.get('network', {})
    for dns in network.get('dns', []):
        domain = Common.Domain(
            domain=dns.get('request'),
            dns=", ".join([answer.get('data') for answer in dns.get('answers')]),
            dbot_score=Common.DBotScore(
                indicator=dns.get('request'),
                indicator_type=DBotScoreType.DOMAIN,
                integration_name=INTEGRATION_NAME,
                score=0
            )
        )
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f"New Domain indicator was created {domain.domain}"),
            indicator=domain,
            raw_response=res
        )
        )
    for host in network.get('hosts', []) + [h[0] for h in network.get('dead_hosts', [])]:
        ip = Common.IP(
            ip=host,
            dbot_score=Common.DBotScore(
                indicator=host,
                indicator_type=DBotScoreType.IP,
                integration_name=INTEGRATION_NAME,
                score=0
            )
        )
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f"New IP indicator was created {ip.ip}"),
            indicator=ip,
            raw_response=res
        )
        )
    for http in network.get('http', []):
        url = Common.URL(
            url=http.get('uri'),
            dbot_score=Common.DBotScore(
                indicator=http.get('uri'),
                indicator_type=DBotScoreType.URL,
                integration_name=INTEGRATION_NAME,
                score=0
            )
        )
        command_results.append(CommandResults(
            readable_output=tableToMarkdown(f"New URL indicator was created {url.url}"),
            indicator=url,
            raw_response=res
        )
        )
    return command_results


def get_monitor_indicators(res):
    report = res['report']
    command_results = []
    for p in report.get('goo_monitor', {}).get('processes', []):
        process = Process(
            name=p.get('basename'),
            pid=str(p.get('pid')),
            command_line=p.get('cmdline'),
            start_time=p.get('started_at'),
            end_time=p.get('exited_at'),
            path=p.get('filename'),
        )
        command_results.append(CommandResults(
            human_readable=tableToMarkdown(f"New Process indicator was created {process.name}"),
            indicator=process,
            raw_response=res
        )
        )
        for regkey in p.get('regkeys', []):
            if regkey.get('action') == 'regkey_written':
                reg = RegistryKey(
                    path=regkey.get('ioc'),
                    value=str(regkey.get('value'))
                )
                command_results.append(CommandResults(
                    human_readable=tableToMarkdown(f"New RegistryKey indicator was created {reg.value}"),
                    indicator=reg,
                    raw_response=res
                )
                )
    return command_results


def get_report_indicators(res, analysis_type):
    report = res['report']
    command_results = []
    human_readable = ''
    indicator = get_main_indicator(report, analysis_type)
    if isinstance(indicator, Common.File):
        human_readable = tableToMarkdown(f"New File indicator was created {indicator.name}")
    elif isinstance(indicator, Common.url):
        human_readable = tableToMarkdown(f"New URL indicator was created {indicator.url}")
    command_results.append(CommandResults(
        readable_output=human_readable,
        indicator=indicator,
        raw_response=res
    )
    )
    command_results.extend(get_packages_indicators(res))
    command_results.extend(get_network_indicators(res))
    command_results.extend(get_monitor_indicators(res))

    return command_results


def analysis_info_command(client, args):
    tds_analysis_id_array = argToList(args.get('tds_analysis_id'))
    all_results = []
    for tds_analysis_id in tds_analysis_id_array:
        analysis_type = tds_analysis_id[0]
        res = client.get_analysis_info(drop_prefix(tds_analysis_id))
        analysis_info = serialize_analysis_info(res.get('file'), analysis_type, report='report' in res)
        command_results = []
        if 'report' in res:
            if analysis_type == URL_TYPE:
                res['report']['target']['url'] = client.get_url(res.get('file'))
            analysis_info.update(serialize_report_info(res['report'], analysis_type))
            command_results = get_report_indicators(res, analysis_type, analysis_info)
        all_results.extend(command_results)
    return all_results


def export_report_command(client, args):
    tds_analysis_id = drop_prefix(args.get('tds_analysis_id'))
    report = client.export_report(tds_analysis_id)
    demisto.results(fileResult(
        filename='report.tar',
        data=report
    ))


def export_pcap_command(client, args):
    tds_analysis_id = drop_prefix(args.get('tds_analysis_id'))
    pcap = client.export_pcap(tds_analysis_id)
    demisto.results(fileResult(
        filename='dump.pcap',
        data=pcap
    ))


def export_video_command(client, args):
    tds_analysis_id = drop_prefix(args.get('tds_analysis_id'))
    video = client.export_video(tds_analysis_id)
    if not video:
        return_results("No screen activity detected")
    else:
        demisto.results(fileResult(
            filename='video.webm',
            data=video
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
        readable_output=tableToMarkdown("Url uploaded successfully", outputs),
        outputs_prefix='Polygon.Analysis',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=res
    )
    return results


def upload_file_command(client, args):
    file_id = args.get('file_id')
    password = args.get('password')
    file_obj = demisto.getFilePath(file_id)
    # Ignoring non ASCII
    file_name = file_obj.get('name', '').encode('ascii', 'ignore')
    file_path = file_obj.get('path')
    res = client.upload_file(file_name, file_path, password)
    res = f"{FILE_TYPE}{res}"
    outputs = {
        'ID': res,
        'EntryID': file_id,
        'FileName': file_obj.get('name'),
        'Status': 'In Progress'
    }
    results = CommandResults(
        readable_output=tableToMarkdown("File uploaded successfully", outputs),
        outputs_prefix='Polygon.Analysis',
        outputs_key_field='ID',
        outputs=outputs,
        raw_response=res
    )
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
            if res.get("found"):
                if res.get("verdict"):
                    score = Common.DBotScore.BAD
                    malicious = "TDS Polygon score: {}".format(res.get('score'))
                    if res.get('malware_families'):
                        malicious += ", {}".format(", ".join(res.get("malware_families", [])))
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
                indicator=indicator,
                raw_response=res
            )
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
    handle_proxy()

    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify_certificate,
            language=report_language
        )
        commands = {
            'polygon-upload-file': upload_file_command,
            'polygon-upload-url': upload_url_command,
            'polygon-analysis-info': analysis_info_command,
            'polygon-export-report': export_report_command,
            'polygon-export-pcap': export_pcap_command,
            'polygon-export-video': export_video_command,
            'file': file_command
        }

        if command == 'test-module':
            return_results(test_module(client))
        elif command in ['polygon-export-report', 'polygon-export-pcap', 'polygon-export-video']:
            commands[command](client, demisto.args())
        elif command in ['polygon-analysis-info', 'file']:
            results = commands[command](client, demisto.args())
            for r in results:
                return_results(r)
        elif command in ['polygon-upload-file', 'polygon-upload-url']:
            return_results(commands[command](client, demisto.args()))

    # Log exceptions
    except Exception as err:
        return_error(f'Failed to execute {command} command. Error: {str(err)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
