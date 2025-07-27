import json
import time

import demistomock as demisto
import requests
from CommonServerPython import *

from anyrun import RunTimeException
from anyrun.connectors import SandboxConnector
from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector
from anyrun.connectors.sandbox.operation_systems import WindowsConnector, LinuxConnector, AndroidConnector


VERSION = "PA-XSOAR:2.0.0"

SCORE_TO_VERDICT = {0: "Unknown", 1: "Suspicious", 2: "Malicious"}

ANYRUN_TO_SOAR_INDICATOR = {"ip": "IP", "url": "URL", "domain": "Domain", "sha256": "File SHA-256"}


def test_module(params: dict) -> str:  # pragma: no cover
    """Performs ANY.RUN API call to verify integration is operational"""
    try:
        with BaseSandboxConnector(get_authentication(params)) as connector:
            connector.check_authorization()
            return "ok"
    except RunTimeException as exception:
        return str(exception)


def get_authentication(params: dict) -> str:
    """
    Builds API verification data using demisto params

    :param params: Demisto params
    :return: API-KEY verification string
    """
    return f"API-KEY {params.get('credentials', {}).get('password')}"


def get_file_content(args: dict) -> dict:  # pragma: no cover
    entry_id = args.pop("file")
    file_obj = demisto.getFilePath(entry_id)

    filepath = file_obj["path"]
    with open(filepath, "rb") as file:
        args["file_content"] = file.read()

    args["filename"] = file_obj["name"]
    return args


def make_api_call(params: dict, method: str, endpoint_url: str, payload: dict) -> None:  # pragma: no cover
    """
    Process api call to XSOAR endpoints

    :param params: Demisto params
    :param method: HTTP Request method
    :param endpoint_url: Target url
    :param payload: Request payload
    """
    fqdn = params.get("soar_fqdn")
    api_key_id = params.get("soar_api_key_id")
    api_key = params.get("soar_api_key")

    url = f"{fqdn}/xsoar/public/v1/{endpoint_url}"
    headers = {"Authorization": api_key, "x-xdr-auth-id": api_key_id}

    requests.request(method, url, headers=headers, json=payload)


def build_context_path(analysis_type: str, connector: WindowsConnector | LinuxConnector | AndroidConnector) -> str | None:
    if analysis_type == "file":
        if isinstance(connector, WindowsConnector):
            return "ANYRUN_DetonateFileWindows.TaskID"
        elif isinstance(connector, LinuxConnector):
            return "ANYRUN_DetonateFileLinux.TaskID"
        elif isinstance(connector, AndroidConnector):
            return "ANYRUN_DetonateFileAndroid.TaskID"
        return None
    elif analysis_type == "url":
        if isinstance(connector, WindowsConnector):
            return "ANYRUN_DetonateUrlWindows.TaskID"
        elif isinstance(connector, LinuxConnector):
            return "ANYRUN_DetonateUrlLinux.TaskID"
        elif isinstance(connector, AndroidConnector):
            return "ANYRUN_DetonateUrlAndroid.TaskID"
        return None
    return None


def wait_for_the_task_to_complete(
    args: dict, analysis_type: str, connector: WindowsConnector | LinuxConnector | AndroidConnector
) -> None:  # pragma: no cover
    """
    Process Sandbox analysis

    :param args: Demisto args
    :param analysis_type: ANY.RUN Sandbox submission type
    :param connector: ANY.RUN connector instance
    :return: Task uuid
    """
    if analysis_type == "file":
        args = get_file_content(args)
        task_uuid = connector.run_file_analysis(**args)
    else:
        task_uuid = connector.run_url_analysis(**args)

    time.sleep(10)
    for _ in connector.get_task_status(task_uuid):
        pass

    return_results(
        CommandResults(outputs_prefix=build_context_path(analysis_type, connector), outputs=task_uuid, ignore_auto_extract=True)
    )


def detonate_entity_windows(params: dict, args: dict, analysis_type: str) -> None:  # pragma: no cover
    with SandboxConnector.windows(get_authentication(params), integration=VERSION) as connector:
        wait_for_the_task_to_complete(args, analysis_type, connector)


def detonate_entity_linux(params: dict, args: dict, analysis_type: str) -> None:  # pragma: no cover
    with SandboxConnector.linux(get_authentication(params), integration=VERSION) as connector:
        wait_for_the_task_to_complete(args, analysis_type, connector)


def detonate_entity_android(params: dict, args: dict, analysis_type: str) -> None:  # pragma: no cover
    with SandboxConnector.android(get_authentication(params), integration=VERSION) as connector:
        wait_for_the_task_to_complete(args, analysis_type, connector)


def detonate_file_widows(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_windows(params, args, "file")


def detonate_url_widows(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_windows(params, args, "url")


def detonate_file_linux(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_linux(params, args, "file")


def detonate_url_linux(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_linux(params, args, "url")


def detonate_file_android(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_android(params, args, "file")


def detonate_url_android(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_android(params, args, "url")


def delete_task(params: dict, args: dict) -> None:  # pragma: no cover
    task_uuid = args.get("task_uuid")

    with SandboxConnector.windows(get_authentication(params), integration=VERSION) as connector:
        connector.delete_task(task_uuid)

    return_results(f"Task {task_uuid} successfully deleted")


def download_analysis_sample(params: dict, args: dict, download_type: str) -> None:  # pragma: no cover
    task_uuid = args.get("task_uuid")

    with SandboxConnector.windows(get_authentication(params), integration=VERSION) as connector:
        if download_type == "pcap":
            return_results(fileResult(f"{task_uuid}_traffic_dump.pcap", connector.download_pcap(task_uuid)))
        return_results(fileResult(f"{task_uuid}_sample.zip", connector.download_file_sample(task_uuid)))


def get_analysis_verdict(params: dict, args: dict) -> None:  # pragma: no cover
    task_uuid = args.get("task_uuid")

    with SandboxConnector.windows(get_authentication(params), integration=VERSION) as connector:
        verdict = connector.get_analysis_verdict(task_uuid)

        return_results(
            CommandResults(outputs_prefix="ANYRUN.SandboxAnalysisReportVerdict", outputs=verdict, ignore_auto_extract=True)
        )


def get_user_limits(params: dict) -> None:  # pragma: no cover
    with SandboxConnector.windows(get_authentication(params), integration=VERSION) as connector:
        user_limits = connector.get_user_limits().get("data").get("limits")

    return_results(CommandResults(outputs_prefix="ANYRUN.SandboxLimits", outputs=user_limits, ignore_auto_extract=True))


def get_analysis_history(params: dict, args: dict) -> None:  # pragma: no cover
    with SandboxConnector.windows(get_authentication(params), integration=VERSION) as connector:
        analysis_history = connector.get_analysis_history(**args)

    return_results(CommandResults(outputs_prefix="ANYRUN.SandboxHistory", outputs=analysis_history, ignore_auto_extract=True))


def process_indicators(params: dict, report: dict, task_uuid: str, incident_id: int) -> None:  # pragma: no cover
    """
    Excludes IOCs from the analysis report. Sends them to Threat Intel

    :param report: Analysis report
    """
    indicators: list[dict[str, str]] = []

    for indicator in report:
        reputation = indicator.get("reputation")

        if reputation == 0:
            score = Common.DBotScore.NONE
        elif reputation == 1:
            score = Common.DBotScore.SUSPICIOUS
        elif reputation == 2:
            score = Common.DBotScore.BAD
        else:
            continue

        indicator_type = ANYRUN_TO_SOAR_INDICATOR.get(indicator.get("type"), "")

        payload = {
            "indicator": {
                "indicator_type": indicator_type,
                "value": indicator.get("ioc"),
                "score": score,
                "vendor": "ANY.RUN",
                "CustomFields": {
                    "vendor": "ANY.RUN",
                    "service": "ANY.RUN Cloud Sandbox",
                    "description": f"https://app.any.run/tasks/{task_uuid}",
                },
                "investigationIDs": [incident_id],
            }
        }

        make_api_call(params, "POST", "indicator/create", payload)
        indicators.append(
            {"type": indicator_type, "value": indicator.get("ioc"), "verdict": SCORE_TO_VERDICT.get(reputation, "")}
        )

    return_results(
        CommandResults(
            readable_output=tableToMarkdown(
                "Indicators from ANY.RUN Cloud Sandbox",
                indicators,
                headers=["type", "value", "verdict"],
                headerTransform=string_to_table_header,
            ),
            ignore_auto_extract=True,
        )
    )


def get_analysis_report(params: dict, args: dict) -> None:  # pragma: no cover
    task_uuid = args.get("task_uuid", "")
    report_format = args.get("report_format")
    incident_info = args.get("incident_info")

    if isinstance(incident_info, str):
        incident_info = json.loads(incident_info)

    incident_id = incident_info.get("id")

    with SandboxConnector.windows(get_authentication(params), integration=VERSION) as connector:
        report = connector.get_analysis_report(task_uuid, report_format=report_format)

        if report_format == "html":
            return_results(fileResult(f"anyrun_report_{task_uuid}.html", report))
        elif report_format == "summary":
            return_results(CommandResults(outputs_prefix="ANYRUN.SandboxAnalysis", outputs=report, ignore_auto_extract=True))
        elif report_format == "ioc":
            process_indicators(params, report, task_uuid, incident_id)


def main():  # pragma: no cover
    """Main Execution block"""
    params = demisto.params()
    args = demisto.args()

    handle_proxy()

    try:
        if demisto.command() == "anyrun-delete-task":
            delete_task(params, args)
        elif demisto.command() == "anyrun-download-analysis-pcap":
            download_analysis_sample(params, args, "pcap")
        elif demisto.command() == "anyrun-download-analysis-sample":
            download_analysis_sample(params, args, "file")
        elif demisto.command() == "anyrun-get-analysis-verdict":
            get_analysis_verdict(params, args)
        elif demisto.command() == "anyrun-get-user-limits":
            get_user_limits(params)
        elif demisto.command() == "anyrun-get-analysis-history":
            get_analysis_history(params, args)
        elif demisto.command() == "anyrun-detonate-file-windows":
            detonate_file_widows(params, args)
        elif demisto.command() == "anyrun-detonate-url-windows":
            detonate_url_widows(params, args)
        elif demisto.command() == "anyrun-detonate-file-linux":
            detonate_file_linux(params, args)
        elif demisto.command() == "anyrun-detonate-url-linux":
            detonate_url_linux(params, args)
        elif demisto.command() == "anyrun-detonate-file-android":
            detonate_file_android(params, args)
        elif demisto.command() == "anyrun-detonate-url-android":
            detonate_url_android(params, args)
        elif demisto.command() == "anyrun-get-analysis-report":
            get_analysis_report(params, args)
        elif demisto.command() == "test-module":
            result = test_module(params)
            return_results(result)
        else:
            raise NotImplementedError(f"Command {demisto.command()} is not implemented")
    except RunTimeException as exception:
        return_error(exception.description, error=str(exception.json))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
