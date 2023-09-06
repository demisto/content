import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from ReversingLabs.SDK.tiscale import TitaniumScale

import json

VERSION = "v1.1.0"
USER_AGENT = f"ReversingLabs XSOAR TitaniumScale {VERSION}"
HOST = demisto.params().get('host')
TOKEN = demisto.params().get('token')
VERIFY_CERT = demisto.params().get('verify')
RELIABILITY = demisto.params().get('reliability', 'C - Fairly reliable')
WAIT_TIME_SECONDS = demisto.params().get('wait_time_seconds')
NUM_OF_RETRIES = demisto.params().get('num_of_retries')

HTTP_PROXY = demisto.params().get("http_proxy", None)
HTTP_PROXY_USERNAME = demisto.params().get("http_credentials", {}).get("identifier", None)
HTTP_PROXY_PASSWORD = demisto.params().get("http_credentials", {}).get("password", None)

HTTPS_PROXY = demisto.params().get("https_proxy", None)
HTTPS_PROXY_USERNAME = demisto.params().get("https_credentials", {}).get("identifier", None)
HTTPS_PROXY_PASSWORD = demisto.params().get("https_credentials", {}).get("password", None)


def format_proxy(addr, username=None, password=None):
    if addr.startswith("http://"):
        protocol = addr[:7]
        proxy_name = addr[7:]
    elif addr.startswith("https://"):
        protocol = addr[:8]
        proxy_name = addr[8:]
    else:
        return_error("Proxy address needs to start with either 'http://' or 'https://'")

    if username:
        if password:
            proxy = f"{protocol}{username}:{password}@{proxy_name}"
        else:
            proxy = f"{protocol}{username}@{proxy_name}"
    else:
        proxy = f"{protocol}{proxy_name}"

    return proxy


def return_proxies():
    proxies = {}

    if HTTP_PROXY:
        http_proxy = format_proxy(
            addr=HTTP_PROXY,
            username=HTTP_PROXY_USERNAME,
            password=HTTP_PROXY_PASSWORD
        )

        proxies["http"] = http_proxy

    if HTTPS_PROXY:
        https_proxy = format_proxy(
            addr=HTTPS_PROXY,
            username=HTTPS_PROXY_USERNAME,
            password=HTTPS_PROXY_PASSWORD
        )

        proxies["https"] = https_proxy

    if proxies:
        return proxies
    else:
        return None


def classification_to_score(classification):
    score_dict = {
        "UNKNOWN": 0,
        "KNOWN": 1,
        "SUSPICIOUS": 2,
        "MALICIOUS": 3
    }
    return score_dict.get(classification, 0)


def test(tiscale):
    """
    Test credentials and connectivity
    """
    try:
        tiscale.test_connection()
        return "ok"
    except Exception as e:
        return_error(str(e))


def get_status_from_classification(classification_int):
    status_mapping = {
        3: "malicious",
        2: "suspicious",
        1: "known"
    }

    return status_mapping.get(classification_int, 'unknown')


def parse_upload_report_and_return_results(response_json):
    task_url = response_json.get('task_url')
    md = f'## ReversingLabs TitaniumScale upload sample\n **Titanium Scale task URL**: {task_url}'

    command_result = CommandResults(
        outputs_prefix='ReversingLabs',
        outputs={'tc_task_url': task_url},
        readable_output=md,
    )

    return command_result


def upload_file(tiscale):
    """
    Upload a file and return task url
    """
    try:
        file_entry = demisto.getFilePath(demisto.getArg('entryId'))
        with open(file_entry['path'], 'rb') as file:
            response_json = tiscale.upload_sample_from_file(file_source=file).json()
    except Exception as e:
        return_error(str(e))

    command_result = parse_upload_report_and_return_results(response_json)

    file_result = fileResult('Full report in JSON', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def parse_report_and_return_results(title, response_json):
    """
    Parse the report, return human-readable info, and the whole report as a file
    """
    md = title
    tc_report = response_json.get("tc_report")
    if tc_report:
        info = tc_report[0].get("info")
        if info:
            file = info.get("file")
            if file:
                file_type = file.get("file_type")
                file_subtype = file.get("file_subtype")
                file_size = file.get("size")
                md += f'''\n **Type:** {file_type}/{file_subtype}
                             **Size:** {file_size} bytes \n'''

                for h in file.get("hashes"):
                    name = h.get("name").upper()
                    value = h.get("value")

                    md += f"\n **{name}:** {value}"

        classification_obj = tc_report[0].get('classification')
        if classification_obj.get("scan_results"):
            scan_result = classification_obj.get("scan_results")[0]
            if "classification" in scan_result:
                classification = scan_result.get("classification")
                status = get_status_from_classification(classification)
                md += f"\n\n **Status:** {status}"

                name = scan_result.get("name")
                result = scan_result.get("result")

                desc = ""
                if result:
                    desc = f"\n **{name}:** {result}"
                    md += desc

                d_bot_score = classification_to_score(status.upper())

                md += f"\n **DBot score:** {d_bot_score}\n"

                if "indicators" in tc_report:
                    md += tableToMarkdown('Indicators', tc_report.get("indicators"))

                dbot_score = Common.DBotScore(
                    indicator=list(filter(lambda elem: elem.get("name") == "sha1", file.get("hashes")))[0].get("value"),
                    indicator_type=DBotScoreType.FILE,
                    integration_name='ReversingLabs TitaniumScale',
                    score=d_bot_score,
                    malicious_description=desc,
                    reliability=RELIABILITY
                )

                common_file = Common.File(
                    md5=list(filter(lambda elem: elem.get("name") == "md5", file.get("hashes")))[0].get("value"),
                    sha1=list(filter(lambda elem: elem.get("name") == "sha1", file.get("hashes")))[0].get("value"),
                    sha256=list(filter(lambda elem: elem.get("name") == "sha256", file.get("hashes")))[0].get("value"),
                    dbot_score=dbot_score
                )

                command_result = CommandResults(
                    outputs_prefix='ReversingLabs',
                    outputs={'tc_report': tc_report},
                    readable_output=md,
                    indicator=common_file
                )

                return command_result

            else:
                return_error("Scan result does not contain classifications")
        else:
            return_error("Report does not contain scan results")
    else:
        return_error("Response does not contain report")


def get_report(tiscale):
    """
    Get report by the task url
    """
    try:
        task_url = demisto.getArg('taskUrl')
        response = tiscale.get_results(task_url)
        if not response:
            raise Exception('No report could be obtained or maximum number of retries was exceeded.')
        response_json = response.json()
    except Exception as e:
        return_error(str(e))

    command_result = parse_report_and_return_results(title='## ReversingLabs TitaniumScale get results\n',
                                                     response_json=response_json)

    file_result = fileResult('Full report in JSON', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def upload_file_and_get_results(tiscale):
    """
    Upload a file and get report
    """

    try:
        file_entry = demisto.getFilePath(demisto.getArg('entryId'))
        with open(file_entry['path'], 'rb') as f:
            response_json = tiscale.upload_sample_and_get_results(file_source=f).json()
    except Exception as e:
        return_error(str(e))

    command_result = parse_report_and_return_results(
        title='## ReversingLabs TitaniumScale upload sample and get results\n',
        response_json=response_json)

    file_result = fileResult('Full report in JSON', json.dumps(response_json, indent=4),
                             file_type=EntryType.ENTRY_INFO_FILE)

    return [command_result, file_result]


def main():
    try:
        wait_time_seconds = int(WAIT_TIME_SECONDS)
    except ValueError:
        return_error("Integration parameter <Wait between retries> has to be of type integer.")

    try:
        num_of_retries = int(NUM_OF_RETRIES)
    except ValueError:
        return_error("Integration parameter <Number of retries> has to be of type integer.")

    proxies = return_proxies()

    tiscale = TitaniumScale(
        host=HOST,
        token=TOKEN,
        verify=VERIFY_CERT,
        user_agent=USER_AGENT,
        wait_time_seconds=wait_time_seconds,
        retries=num_of_retries,
        proxies=proxies
    )

    demisto.info(f'Command being called is {demisto.command()}')

    try:
        if demisto.command() == 'test-module':
            return_results(test(tiscale))
        elif demisto.command() == 'reversinglabs-titaniumscale-upload-sample-and-get-results':
            return_results(upload_file_and_get_results(tiscale))
        elif demisto.command() == 'reversinglabs-titaniumscale-upload-sample':
            return_results(upload_file(tiscale))
        elif demisto.command() == 'reversinglabs-titaniumscale-get-results':
            return_results(get_report(tiscale))
        else:
            return_error(f'Command [{demisto.command()}] not implemented')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
